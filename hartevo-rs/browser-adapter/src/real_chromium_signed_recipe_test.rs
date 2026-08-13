#[test]
#[ignore = "requires macOS, HARTEVO_TEST_CHROME_BINARY, mock Keychain, and loopback; explicit missing prerequisites panic BLOCKED_ENV"]
fn real_chromium_signed_recipe_single_click_smoke() {
    #[cfg(target_os = "macos")]
    macos::run();

    #[cfg(not(target_os = "macos"))]
    panic!("BLOCKED_ENV: reason=macos_required");
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant};

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, BrowserActionBatchId,
        BrowserControlLeaseId, BrowserProfileId, BrowserRecipeId, BrowserSnapshotId, BrowserTabId,
        BrowserWorkspaceId, ConsentState, CurrencyCode, Effect, EffectClass, EffectId, EffectRisk,
        EffectStatus, Mission, MissionContract, MissionId, Money, Project, ProjectId, StorageMode,
        TenantId,
    };
    use hartevo_effect_broker::{EffectExecutor, ProviderFailure};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    use crate::{
        BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk,
        BrowserActionSurface, BrowserIdentity, BrowserLeaseProof, BrowserLocatorResolution,
        BrowserNavigationPolicy, BrowserProfile, BrowserRecipeCandidate,
        BrowserRecipeEvaluationEvidence, BrowserRecipeExecutionAuthorization,
        BrowserRecipeKeyPurpose, BrowserRecipeManifest, BrowserRecipePreparedPlan,
        BrowserRecipePromotion, BrowserRecipeRegistry, BrowserRecipeRelease,
        BrowserRecipeResolvedAction, BrowserRecipeStep, BrowserRecipeTrustStore,
        BrowserStableLocator, BrowserWorkspace, ChromiumCredentialStoreMode, ChromiumLaunchConfig,
        ManagedChromiumClickExecutor, ManagedChromiumHost, TrustedBrowserRecipeKey,
    };

    const CHROME_ENV: &str = "HARTEVO_TEST_CHROME_BINARY";
    const RECIPE_ID: &str = "real-chromium-signed-review";
    const CANDIDATE_KEY_ID: &str = "smoke-candidate-key";
    const RELEASE_KEY_ID: &str = "smoke-release-key";
    const CLICK_CAPABILITY: &str = "browser.semantic_click";
    const WAIT_LIMIT: StdDuration = StdDuration::from_secs(5);
    const QUIET_LIMIT: StdDuration = StdDuration::from_millis(75);

    pub(super) fn run() {
        let prerequisites = ExternalPrerequisites::acquire();
        let mut resources = SmokeResources::new(prerequisites);
        let body_result = catch_unwind(AssertUnwindSafe(|| run_smoke(&mut resources)));
        let cleanup_result = resources.cleanup();

        match (body_result, cleanup_result) {
            (Ok(()), Ok(())) => {}
            (Err(payload), Ok(())) => resume_unwind(payload),
            (body, Err(step)) => panic!(
                "RECIPE_SMOKE_CLEANUP_FAILED: step={step} has_prior_failure={}",
                body.is_err()
            ),
        }
    }

    struct ExternalPrerequisites {
        executable: PathBuf,
        temp: TempDir,
        listener: TcpListener,
    }

    impl ExternalPrerequisites {
        fn acquire() -> Self {
            let executable = std::env::var_os(CHROME_ENV).map_or_else(
                || panic!("BLOCKED_ENV: reason=chrome_env_missing"),
                PathBuf::from,
            );
            let executable_exists = executable
                .try_exists()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=chrome_path_unavailable"));
            assert!(executable_exists, "BLOCKED_ENV: reason=chrome_path_missing");
            let temp = TempDir::new()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=private_temp_root_unavailable"));
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=loopback_bind_unavailable"));
            Self {
                executable,
                temp,
                listener,
            }
        }
    }

    struct SmokeResources {
        executable: PathBuf,
        temp: Option<TempDir>,
        listener: Option<TcpListener>,
        server: Option<FixtureServer>,
        host: Option<ManagedChromiumHost>,
    }

    impl SmokeResources {
        fn new(prerequisites: ExternalPrerequisites) -> Self {
            Self {
                executable: prerequisites.executable,
                temp: Some(prerequisites.temp),
                listener: Some(prerequisites.listener),
                server: None,
                host: None,
            }
        }

        fn start_server(&mut self) {
            let listener = self
                .listener
                .take()
                .unwrap_or_else(|| fail("fixture_listener_missing"));
            self.server = Some(must(FixtureServer::start(listener), "fixture_thread_spawn"));
        }

        fn temp_root(&self) -> &Path {
            self.temp
                .as_ref()
                .map_or_else(|| fail("temp_root_missing"), TempDir::path)
        }

        fn server(&self) -> &FixtureServer {
            self.server
                .as_ref()
                .unwrap_or_else(|| fail("fixture_server_missing"))
        }

        fn host_mut(&mut self) -> &mut ManagedChromiumHost {
            self.host
                .as_mut()
                .unwrap_or_else(|| fail("chromium_host_missing"))
        }

        fn cleanup(&mut self) -> Result<(), &'static str> {
            let mut first_failure = None;
            if let Some(mut host) = self.host.take() {
                match host.shutdown() {
                    Ok(shutdown) if shutdown.success => {}
                    Ok(_) | Err(_) => first_failure = Some("chromium_host_shutdown"),
                }
            }
            if let Some(mut server) = self.server.take()
                && server.shutdown().is_err()
                && first_failure.is_none()
            {
                first_failure = Some("fixture_server_shutdown");
            }
            self.listener.take();
            if let Some(temp) = self.temp.take()
                && temp.close().is_err()
                && first_failure.is_none()
            {
                first_failure = Some("private_temp_root_release");
            }
            first_failure.map_or(Ok(()), Err)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ClickCounts {
        root: usize,
        iframe: usize,
    }

    struct FixtureState {
        root_clicks: AtomicUsize,
        iframe_clicks: AtomicUsize,
        iframe_loads: AtomicUsize,
        signal: Mutex<()>,
        changed: Condvar,
    }

    impl FixtureState {
        fn new() -> Self {
            Self {
                root_clicks: AtomicUsize::new(0),
                iframe_clicks: AtomicUsize::new(0),
                iframe_loads: AtomicUsize::new(0),
                signal: Mutex::new(()),
                changed: Condvar::new(),
            }
        }

        fn counts(&self) -> ClickCounts {
            ClickCounts {
                root: self.root_clicks.load(Ordering::Acquire),
                iframe: self.iframe_clicks.load(Ordering::Acquire),
            }
        }

        fn iframe_loads(&self) -> usize {
            self.iframe_loads.load(Ordering::Acquire)
        }

        fn record(&self, route: FixtureRoute) {
            match route {
                FixtureRoute::RootClicked => {
                    self.root_clicks.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::IframeClicked => {
                    self.iframe_clicks.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::IframeChild => {
                    self.iframe_loads.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::Page | FixtureRoute::Drift | FixtureRoute::Other => {}
            }
            self.changed.notify_all();
        }

        fn wait_until(&self, label: &'static str, predicate: impl Fn() -> bool) {
            let deadline = Instant::now() + WAIT_LIMIT;
            let mut guard = self
                .signal
                .lock()
                .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
            while !predicate() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    fail(label);
                }
                let (next_guard, timeout) = self
                    .changed
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
                guard = next_guard;
                if timeout.timed_out() && !predicate() {
                    fail(label);
                }
            }
        }

        fn assert_counts_stable(&self, expected: ClickCounts, label: &'static str) {
            let deadline = Instant::now() + QUIET_LIMIT;
            let mut guard = self
                .signal
                .lock()
                .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
            loop {
                if self.counts() != expected {
                    fail(label);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                let (next_guard, _) = self
                    .changed
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
                guard = next_guard;
            }
        }
    }

    struct ServerControl {
        stop: AtomicBool,
        signal: Mutex<()>,
        changed: Condvar,
        worker_failed: AtomicBool,
    }

    impl ServerControl {
        fn new() -> Self {
            Self {
                stop: AtomicBool::new(false),
                signal: Mutex::new(()),
                changed: Condvar::new(),
                worker_failed: AtomicBool::new(false),
            }
        }

        fn request_stop(&self) {
            self.stop.store(true, Ordering::Release);
            self.changed.notify_all();
        }
    }

    struct FixtureServer {
        address: std::net::SocketAddr,
        state: Arc<FixtureState>,
        control: Arc<ServerControl>,
        finished: Receiver<()>,
        thread: Option<JoinHandle<()>>,
    }

    impl FixtureServer {
        fn start(listener: TcpListener) -> std::io::Result<Self> {
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let state = Arc::new(FixtureState::new());
            let control = Arc::new(ServerControl::new());
            let worker_state = Arc::clone(&state);
            let worker_control = Arc::clone(&control);
            let (finished_tx, finished) = sync_channel(1);
            let thread = thread::Builder::new()
                .name("hartevo-recipe-smoke-loopback".into())
                .spawn(move || {
                    serve(&listener, &worker_state, &worker_control);
                    let _ = finished_tx.send(());
                })?;
            Ok(Self {
                address,
                state,
                control,
                finished,
                thread: Some(thread),
            })
        }

        fn origin(&self) -> String {
            format!("http://{}", self.address)
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.origin())
        }

        fn click_counts(&self) -> ClickCounts {
            self.state.counts()
        }

        fn iframe_loads(&self) -> usize {
            self.state.iframe_loads()
        }

        fn wait_for_iframe_after(&self, before: usize) {
            self.state
                .wait_until("iframe_load_timeout", || self.state.iframe_loads() > before);
        }

        fn wait_for_root_clicks(&self, expected: usize) {
            self.state.wait_until("root_click_timeout", || {
                self.state.counts().root >= expected
            });
        }

        fn assert_click_counts_stable(&self, expected: ClickCounts, label: &'static str) {
            self.state.assert_counts_stable(expected, label);
        }

        fn shutdown(&mut self) -> Result<(), ()> {
            self.control.request_stop();
            let completed = match self.finished.recv_timeout(StdDuration::from_secs(3)) {
                Ok(()) => true,
                Err(RecvTimeoutError::Disconnected) => false,
                Err(RecvTimeoutError::Timeout) => return Err(()),
            };
            let joined = self
                .thread
                .take()
                .is_some_and(|thread| thread.join().is_ok());
            if completed && joined && !self.control.worker_failed.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    impl Drop for FixtureServer {
        fn drop(&mut self) {
            self.control.request_stop();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[derive(Clone, Copy)]
    enum FixtureRoute {
        Page,
        IframeChild,
        RootClicked,
        IframeClicked,
        Drift,
        Other,
    }

    fn serve(listener: &TcpListener, state: &FixtureState, control: &ServerControl) {
        while !control.stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, state, control),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let guard = control
                        .signal
                        .lock()
                        .unwrap_or_else(|_| fail("fixture_control_poisoned"));
                    drop(
                        control
                            .changed
                            .wait_timeout(guard, StdDuration::from_millis(10)),
                    );
                }
                Err(_) => {
                    control.worker_failed.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, state: &FixtureState, control: &ServerControl) {
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let Some(path) = read_request_path(&mut stream, control) else {
            return;
        };
        let route = route_for(&path);
        state.record(route);
        let response = fixture_response(route);
        write_bounded(&mut stream, &response, control);
    }

    fn read_request_path(stream: &mut TcpStream, control: &ServerControl) -> Option<String> {
        const REQUEST_LIMIT: usize = 8 * 1_024;
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut request = Vec::with_capacity(512);
        let mut buffer = [0_u8; 512];
        loop {
            if control.stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return None;
            }
            match stream.read(&mut buffer) {
                Ok(0) => return None,
                Ok(read) => {
                    if request.len().saturating_add(read) > REQUEST_LIMIT {
                        return None;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.contains(&b'\n') {
                        let line_end = request.iter().position(|byte| *byte == b'\n')?;
                        let line = std::str::from_utf8(&request[..line_end]).ok()?;
                        return line.split_whitespace().nth(1).map(str::to_owned);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(StdDuration::from_millis(2));
                }
                Err(_) => return None,
            }
        }
    }

    fn write_bounded(stream: &mut TcpStream, response: &[u8], control: &ServerControl) {
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut written = 0;
        while written < response.len()
            && !control.stop.load(Ordering::Acquire)
            && Instant::now() < deadline
        {
            match stream.write(&response[written..]) {
                Ok(0) => return,
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(StdDuration::from_millis(2));
                }
                Err(_) => return,
            }
        }
        let _ = stream.flush();
    }

    fn route_for(path: &str) -> FixtureRoute {
        let path = path.split('?').next().unwrap_or(path);
        match path {
            "/page" => FixtureRoute::Page,
            "/iframe-child" => FixtureRoute::IframeChild,
            "/clicked" => FixtureRoute::RootClicked,
            "/iframe-clicked" => FixtureRoute::IframeClicked,
            "/drift" => FixtureRoute::Drift,
            _ => FixtureRoute::Other,
        }
    }

    fn fixture_response(route: FixtureRoute) -> Vec<u8> {
        let (status, body) = match route {
            FixtureRoute::Page => (
                "200 OK",
                "<html><body><form action=\"/clicked\" method=\"get\"><button type=\"submit\" style=\"width:200px;height:60px\">Review</button></form><iframe src=\"/iframe-child\" title=\"Embedded review\"></iframe></body></html>",
            ),
            FixtureRoute::IframeChild => (
                "200 OK",
                "<html><body><form action=\"/iframe-clicked\" method=\"get\"><button type=\"submit\">Review</button></form></body></html>",
            ),
            FixtureRoute::RootClicked => (
                "200 OK",
                "<html><body><h1>Review submitted</h1></body></html>",
            ),
            FixtureRoute::IframeClicked => (
                "200 OK",
                "<html><body><h1>Iframe submitted</h1></body></html>",
            ),
            FixtureRoute::Drift => (
                "200 OK",
                "<html><body><h1>Replacement document</h1></body></html>",
            ),
            FixtureRoute::Other => ("404 Not Found", "not found"),
        };
        http_response(status, body)
    }

    fn http_response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    struct BrowserScope {
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        proof: BrowserLeaseProof,
        tab_id: BrowserTabId,
        policy: BrowserNavigationPolicy,
        locator: BrowserStableLocator,
    }

    fn run_smoke(resources: &mut SmokeResources) {
        resources.start_server();
        let now = fixed_time();
        let (profile, workspace, proof, tab_id) = domain_scope(resources.temp_root(), now);
        let config = must(
            ChromiumLaunchConfig::new(
                &resources.executable,
                resources.temp_root().to_path_buf(),
                true,
            ),
            "launch_config_contract",
        );
        let config = must(
            config.with_macos_mock_keychain_for_test(),
            "mock_keychain_contract",
        );
        resources.host = Some(must(
            ManagedChromiumHost::spawn(profile.clone(), workspace.clone(), &config),
            "chromium_host_spawn",
        ));
        assert_host_health(resources.host_mut());
        must(
            resources
                .host_mut()
                .attach_about_blank_tab(&tab_id, &proof, now),
            "attach_about_blank_tab",
        );

        let origin = resources.server().origin();
        let policy = must(
            BrowserNavigationPolicy::with_loopback_http_for_test([origin.as_str()]),
            "loopback_navigation_policy",
        );
        let navigation = navigate_page(resources, &tab_id, &proof, &policy, now);
        let snapshot = must(
            resources.host_mut().observe_ax(
                &tab_id,
                &proof,
                BrowserSnapshotId::from("recipe-smoke-initial-observation"),
                now,
            ),
            "initial_production_observation",
        );
        assert_eq!(snapshot.document_generation, navigation.document_generation);
        let locator = must(
            BrowserStableLocator::exact_accessible_name(
                &workspace,
                tab_id.clone(),
                &policy,
                navigation.final_origin_digest,
                "button",
                "Review",
                now,
            ),
            "review_locator_contract",
        );
        let scope = BrowserScope {
            profile,
            workspace,
            proof,
            tab_id,
            policy,
            locator,
        };
        let keys = SigningKeys::new();
        assert_eq!(
            resources.server().click_counts(),
            ClickCounts { root: 0, iframe: 0 }
        );

        reject_version_swap(resources, &scope, &keys);
        reject_key_revoke(resources, &scope, &keys);
        reject_resolution_drift(resources, &scope, &keys);
        reject_effect_drift(resources, &scope, &keys);
        reject_document_drift(resources, &scope, &keys);
        execute_single_click(resources, &scope, &keys);
    }

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .unwrap_or_else(|| fail("fixed_time_invalid"))
    }

    fn domain_scope(
        private_root: &Path,
        now: DateTime<Utc>,
    ) -> (
        BrowserProfile,
        BrowserWorkspace,
        BrowserLeaseProof,
        BrowserTabId,
    ) {
        let project = must(
            Project::create_local(
                TenantId::from("tenant-recipe-smoke"),
                ProjectId::from("project-recipe-smoke"),
                "Signed Recipe Smoke",
                "",
                private_root,
                StorageMode::LocalExisting,
            ),
            "project_scope",
        );
        let mission = must(
            Mission::compile(
                project.tenant_id.clone(),
                MissionId::from("mission-recipe-smoke"),
                project.id.clone(),
                "Signed recipe real Chromium smoke",
                MissionContract::bootstrap(
                    "Execute one promoted and activated signed browser recipe",
                    [CLICK_CAPABILITY.into()],
                    now,
                ),
                now,
            ),
            "mission_scope",
        );
        let identity = must(
            BrowserIdentity::new(
                "real-chromium-recipe-smoke",
                AccountId::from("account-recipe-smoke"),
                sha('1'),
                sha('2'),
                now,
            ),
            "browser_identity",
        );
        let profile = must(
            BrowserProfile::create_managed(
                BrowserProfileId::from("profile-recipe-smoke"),
                &project,
                "keyring://browser/real-recipe-smoke",
                identity,
                now,
            ),
            "browser_profile",
        );
        let tab_id = BrowserTabId::from("tab-recipe-smoke");
        let workspace = must(
            BrowserWorkspace::create(
                BrowserWorkspaceId::from("workspace-recipe-smoke"),
                &project,
                &mission,
                &profile,
                tab_id.clone(),
                BrowserControlLeaseId::from("lease-recipe-smoke"),
                now + Duration::hours(1),
                sha('3'),
                now,
            ),
            "browser_workspace",
        );
        let proof = must(workspace.agent_lease_proof(now), "browser_lease_proof");
        (profile, workspace, proof, tab_id)
    }

    fn assert_host_health(host: &mut ManagedChromiumHost) {
        let health = must(host.health(), "chromium_health");
        if !health.product.contains("Chrome") && !health.product.contains("Chromium") {
            fail("chromium_product_contract");
        }
        assert_eq!(
            health.credential_store_mode,
            ChromiumCredentialStoreMode::MacOsMockForTest
        );
    }

    fn navigate_page(
        resources: &mut SmokeResources,
        tab_id: &BrowserTabId,
        proof: &BrowserLeaseProof,
        policy: &BrowserNavigationPolicy,
        now: DateTime<Utc>,
    ) -> crate::BrowserNavigationReceipt {
        let iframe_before = resources.server().iframe_loads();
        let target = must(
            policy.authorize(resources.server().url("/page")),
            "page_navigation_target",
        );
        let receipt = must(
            resources
                .host_mut()
                .navigate_allowlisted(tab_id, proof, policy, &target, now),
            "page_navigation",
        );
        if !receipt.script_execution_disabled {
            fail("page_script_execution_not_disabled");
        }
        resources.server().wait_for_iframe_after(iframe_before);
        receipt
    }

    struct SigningKeys {
        candidate: Ed25519KeyPair,
        release: Ed25519KeyPair,
    }

    impl SigningKeys {
        fn new() -> Self {
            Self {
                candidate: must(
                    Ed25519KeyPair::from_seed_unchecked(&[17; 32]),
                    "candidate_signing_key",
                ),
                release: must(
                    Ed25519KeyPair::from_seed_unchecked(&[29; 32]),
                    "release_signing_key",
                ),
            }
        }
    }

    struct RecipeAuthority {
        trust: BrowserRecipeTrustStore,
        registry: BrowserRecipeRegistry,
        recipe_id: BrowserRecipeId,
    }

    impl RecipeAuthority {
        fn fresh(
            keys: &SigningKeys,
            profile: &BrowserProfile,
            origin_digest: &str,
            selector_digest: &str,
            versions: &[u32],
            active_version: u32,
            now: DateTime<Utc>,
        ) -> Self {
            let trust = trust_store(keys, now);
            let recipe_id = BrowserRecipeId::from(RECIPE_ID);
            let mut registry = BrowserRecipeRegistry::default();
            for &version in versions {
                let release =
                    signed_release(keys, profile, origin_digest, selector_digest, version, now);
                must(
                    registry.register_candidate(release.candidate.clone(), &trust, now),
                    "candidate_registry_insert",
                );
                must(
                    registry.register_release(release, &trust, now),
                    "release_registry_insert",
                );
            }
            must(
                registry.activate_release(&recipe_id, active_version, None, &sha('e'), &trust, now),
                "recipe_activation",
            );
            Self {
                trust,
                registry,
                recipe_id,
            }
        }

        fn activate_successor(&mut self, version: u32, previous: u32, now: DateTime<Utc>) {
            must(
                self.registry.activate_release(
                    &self.recipe_id,
                    version,
                    Some(previous),
                    &sha('f'),
                    &self.trust,
                    now,
                ),
                "recipe_successor_activation",
            );
        }

        fn revoke_release_key(&mut self, now: DateTime<Utc>) {
            must(
                self.trust.revoke(RELEASE_KEY_ID, 1, now),
                "release_key_revoke",
            );
        }
    }

    fn trust_store(keys: &SigningKeys, now: DateTime<Utc>) -> BrowserRecipeTrustStore {
        let mut trust = BrowserRecipeTrustStore::default();
        must(
            trust.insert(must(
                TrustedBrowserRecipeKey::new(
                    CANDIDATE_KEY_ID,
                    BrowserRecipeKeyPurpose::CandidatePublisher,
                    keys.candidate.public_key().as_ref(),
                    now - Duration::days(1),
                    now + Duration::days(40),
                ),
                "candidate_trust_contract",
            )),
            "candidate_trust_insert",
        );
        must(
            trust.insert(must(
                TrustedBrowserRecipeKey::new(
                    RELEASE_KEY_ID,
                    BrowserRecipeKeyPurpose::ProductionRelease,
                    keys.release.public_key().as_ref(),
                    now - Duration::days(1),
                    now + Duration::days(40),
                ),
                "release_trust_contract",
            )),
            "release_trust_insert",
        );
        trust
    }

    fn signed_release(
        keys: &SigningKeys,
        profile: &BrowserProfile,
        origin_digest: &str,
        selector_digest: &str,
        version: u32,
        now: DateTime<Utc>,
    ) -> BrowserRecipeRelease {
        // `1` is the checked-in wire value. Public validation and signature APIs below,
        // rather than a copied private implementation constant, enforce the contract.
        let manifest = BrowserRecipeManifest {
            schema_version: 1,
            id: BrowserRecipeId::from(RECIPE_ID),
            version,
            provider: profile.identity.provider.clone(),
            origin_digest: origin_digest.to_owned(),
            capability: CLICK_CAPABILITY.into(),
            effect_class: EffectClass::ExternalWrite,
            steps: vec![BrowserRecipeStep {
                sequence: 1,
                kind: BrowserActionKind::Click,
                surface: BrowserActionSurface::Semantic,
                risk: BrowserActionRisk::PotentialExternalWrite,
                selector_digest: selector_digest.to_owned(),
            }],
            publisher_key_id: CANDIDATE_KEY_ID.into(),
            created_at: now - Duration::hours(1),
            expires_at: now + Duration::days(30),
        };
        must(manifest.validate(), "recipe_manifest_public_validation");
        let candidate_payload = must(
            BrowserRecipeCandidate::signing_payload(&manifest),
            "candidate_signing_payload",
        );
        let candidate = must(
            BrowserRecipeCandidate::new(
                manifest,
                hex::encode(keys.candidate.sign(&candidate_payload).as_ref()),
            ),
            "candidate_constructor",
        );
        let evidence = evaluation_evidence();
        let candidate_digest = must(candidate.digest(), "candidate_digest");
        let promoted_at = now - Duration::minutes(30);
        let expires_at = now + Duration::days(20);
        let promotion_payload = must(
            BrowserRecipePromotion::signing_payload(
                &candidate_digest,
                &evidence,
                RELEASE_KEY_ID,
                promoted_at,
                expires_at,
            ),
            "promotion_signing_payload",
        );
        let release = BrowserRecipeRelease {
            candidate,
            promotion: BrowserRecipePromotion {
                // This wire value is checked again by `BrowserRecipeRelease::verify`.
                schema_version: 1,
                candidate_digest,
                evidence,
                release_key_id: RELEASE_KEY_ID.into(),
                promoted_at,
                expires_at,
                signature_hex: hex::encode(keys.release.sign(&promotion_payload).as_ref()),
            },
        };
        let verification_trust = trust_store(keys, now);
        must(
            release.candidate.verify(&verification_trust, now),
            "candidate_public_verification",
        );
        must(
            release.verify(&verification_trust, now),
            "release_public_verification",
        );
        release
    }

    fn evaluation_evidence() -> BrowserRecipeEvaluationEvidence {
        BrowserRecipeEvaluationEvidence {
            v1_dataset_revision: "recipe-smoke-v1-holdout".into(),
            v1_result_digest: sha('4'),
            v1_passed: 9,
            v1_total: 10,
            v2_dataset_revision: "recipe-smoke-v2-shadow".into(),
            v2_result_digest: sha('5'),
            v2_passed: 4,
            v2_total: 5,
            safety_suite_digest: sha('6'),
            contamination_audit_digest: sha('7'),
            rollback_strategy_digest: sha('8'),
            promotion_approval_digest: sha('9'),
        }
    }

    struct PreparedExecution {
        plan: BrowserRecipePreparedPlan,
        batch: BrowserActionBatch,
        effect: Effect,
        resolution: BrowserLocatorResolution,
    }

    fn prepare_execution(
        authority: &RecipeAuthority,
        scope: &BrowserScope,
        resolution: BrowserLocatorResolution,
        case_id: &'static str,
    ) -> PreparedExecution {
        let now = resolution.resolved_at;
        let action = must(
            BrowserAction::semantic_click(1, &resolution),
            "semantic_click_action",
        );
        let actions = vec![action];
        let plan = must(
            authority.registry.prepare_active_plan(
                &authority.recipe_id,
                &authority.trust,
                &scope.profile,
                &scope.workspace,
                scope.policy.evidence_digest().to_owned(),
                &[BrowserRecipeResolvedAction {
                    action: &actions[0],
                    resolution: &resolution,
                }],
                now,
                now + Duration::minutes(5),
            ),
            "active_recipe_plan_prepare",
        );
        let effect = approved_effect(scope, &plan, case_id, now);
        let batch = must(
            BrowserActionBatch::for_recipe_effect(
                BrowserActionBatchId::from_stable(format!("batch-{case_id}")),
                &scope.profile,
                &scope.workspace,
                scope.proof.clone(),
                scope.policy.evidence_digest().to_owned(),
                actions,
                &plan,
                &authority.registry,
                &authority.trust,
                &effect,
                now,
                now + Duration::minutes(5),
            ),
            "recipe_effect_batch",
        );
        validate_prepared_contract(authority, &plan, &batch, &effect, now);
        PreparedExecution {
            plan,
            batch,
            effect,
            resolution,
        }
    }

    fn approved_effect(
        scope: &BrowserScope,
        plan: &BrowserRecipePreparedPlan,
        case_id: &'static str,
        now: DateTime<Utc>,
    ) -> Effect {
        let mut effect = Effect {
            id: EffectId::from_stable(format!("effect-{case_id}")),
            tenant_id: scope.workspace.tenant_id.clone(),
            project_id: scope.workspace.project_id.clone(),
            mission_id: scope.workspace.mission_id.clone(),
            actor_id: ActorId::from("actor-recipe-smoke"),
            capability: plan.capability.clone(),
            provider: plan.provider.clone(),
            connection_id: None,
            account_id: Some(scope.profile.identity.account_id.clone()),
            required_scopes: BTreeSet::from(["browser.click".into()]),
            effect_class: plan.effect_class.clone(),
            description: "Submit the exact synthetic Review control".into(),
            target_resource: "synthetic-review-control".into(),
            audience_digest: None,
            payload_digest: plan.effect_payload_digest.clone(),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "recipe-smoke-policy-v1".into(),
            risk: EffectRisk::Medium,
            idempotency_key: format!("recipe-smoke:{case_id}"),
            amount: Money::zero(must(CurrencyCode::parse("USD"), "currency_contract")),
            expires_at: now + Duration::minutes(10),
            status: EffectStatus::Approved,
            approval: None,
            receipt: None,
            verification: None,
        };
        let scope_digest = effect.approval_digest();
        effect.approval = Some(Approval {
            id: ApprovalId::from_stable(format!("approval-{case_id}")),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("approver-recipe-smoke"),
            decided_at: now,
            valid_until: now + Duration::minutes(10),
            scope_digest,
            permission_digest: sha('a'),
        });
        effect
    }

    fn validate_prepared_contract(
        authority: &RecipeAuthority,
        plan: &BrowserRecipePreparedPlan,
        batch: &BrowserActionBatch,
        effect: &Effect,
        now: DateTime<Utc>,
    ) {
        let authorization = must(
            BrowserRecipeExecutionAuthorization::new(
                plan.clone(),
                &authority.registry,
                &authority.trust,
                batch,
                now,
            ),
            "recipe_authorization_constructor",
        );
        must(
            authorization.validate_batch(batch, now),
            "recipe_authorization_validate_batch",
        );
        must(
            authorization.validate_effect(batch, effect, now),
            "recipe_authorization_validate_effect",
        );
        must(batch.validate_effect(effect, now), "batch_validate_effect");
        assert_named_digest(
            "batch_plan_vs_prepared_effect_payload",
            &batch.plan_digest,
            &plan.effect_payload_digest,
        );
        assert_named_digest(
            "prepared_effect_payload_vs_effect_payload",
            &plan.effect_payload_digest,
            &effect.payload_digest,
        );
    }

    fn resolve_case(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        snapshot_id: &'static str,
    ) -> BrowserLocatorResolution {
        must(
            resources.host_mut().resolve_stable_locator(
                &scope.tab_id,
                &scope.proof,
                &scope.locator,
                BrowserSnapshotId::from(snapshot_id),
                fixed_time(),
            ),
            "production_locator_resolution",
        )
    }

    fn reject_version_swap(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        keys: &SigningKeys,
    ) {
        let before = resources.server().click_counts();
        let resolution = resolve_case(resources, scope, "recipe-smoke-version-swap");
        let now = resolution.resolved_at;
        let mut authority = RecipeAuthority::fresh(
            keys,
            &scope.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            &[1, 2],
            1,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "version-swap");
        authority.activate_successor(2, 1, now);
        assert_constructor_rejected(
            resources.host_mut(),
            prepared,
            &authority,
            "BROWSER_RECIPE_SCOPE_MISMATCH",
            "version_swap_not_rejected",
        );
        resources
            .server()
            .assert_click_counts_stable(before, "version_swap_dispatched_input");
    }

    fn reject_key_revoke(resources: &mut SmokeResources, scope: &BrowserScope, keys: &SigningKeys) {
        let before = resources.server().click_counts();
        let resolution = resolve_case(resources, scope, "recipe-smoke-key-revoke");
        let now = resolution.resolved_at;
        let mut authority = RecipeAuthority::fresh(
            keys,
            &scope.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            &[1],
            1,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "key-revoke");
        authority.revoke_release_key(now);
        assert_constructor_rejected(
            resources.host_mut(),
            prepared,
            &authority,
            "BROWSER_RECIPE_KEY_REVOKED",
            "key_revoke_not_rejected",
        );
        resources
            .server()
            .assert_click_counts_stable(before, "key_revoke_dispatched_input");
    }

    fn reject_resolution_drift(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        keys: &SigningKeys,
    ) {
        let before = resources.server().click_counts();
        let original = resolve_case(resources, scope, "recipe-smoke-resolution-original");
        let authority = RecipeAuthority::fresh(
            keys,
            &scope.profile,
            &original.origin_digest,
            &original.selector_digest,
            &[1],
            1,
            original.resolved_at,
        );
        let mut prepared = prepare_execution(&authority, scope, original, "resolution-drift");
        prepared.resolution = resolve_case(resources, scope, "recipe-smoke-resolution-drifted");
        assert_constructor_rejected(
            resources.host_mut(),
            prepared,
            &authority,
            "BROWSER_REAL_ACTION_REJECTED",
            "resolution_drift_not_rejected",
        );
        resources
            .server()
            .assert_click_counts_stable(before, "resolution_drift_dispatched_input");
    }

    fn reject_effect_drift(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        keys: &SigningKeys,
    ) {
        let before = resources.server().click_counts();
        let resolution = resolve_case(resources, scope, "recipe-smoke-effect-drift");
        let now = resolution.resolved_at;
        let authority = RecipeAuthority::fresh(
            keys,
            &scope.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            &[1],
            1,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "effect-drift");
        let mut drifted_effect = prepared.effect.clone();
        drifted_effect.capability = "browser.semantic_click.drift".into();
        let drifted_scope = drifted_effect.approval_digest();
        drifted_effect
            .approval
            .as_mut()
            .unwrap_or_else(|| fail("drifted_approval_missing"))
            .scope_digest = drifted_scope;
        assert_eq!(
            drifted_effect
                .approval
                .as_ref()
                .unwrap_or_else(|| fail("drifted_approval_missing"))
                .scope_digest,
            drifted_effect.approval_digest()
        );
        assert_browser_error(
            prepared.batch.validate_effect(&drifted_effect, now),
            "BROWSER_EFFECT_SCOPE_MISMATCH",
            "batch_effect_drift_not_rejected",
        );
        let authorization = must(
            BrowserRecipeExecutionAuthorization::new(
                prepared.plan.clone(),
                &authority.registry,
                &authority.trust,
                &prepared.batch,
                now,
            ),
            "effect_drift_authorization_constructor",
        );
        assert_browser_error(
            authorization.validate_effect(&prepared.batch, &drifted_effect, now),
            "BROWSER_EFFECT_SCOPE_MISMATCH",
            "authorization_effect_drift_not_rejected",
        );
        drop(authorization);
        let PreparedExecution {
            plan,
            batch,
            resolution,
            ..
        } = prepared;
        let mut executor = must(
            ManagedChromiumClickExecutor::new_for_recipe(
                resources.host_mut(),
                batch,
                resolution,
                plan,
                &authority.registry,
                &authority.trust,
                now,
            ),
            "effect_drift_executor_constructor",
        );
        assert_provider_rejected(
            executor.execute(&drifted_effect),
            "BROWSER_EFFECT_SCOPE_MISMATCH",
            "effect_drift_execute_not_rejected",
        );
        drop(executor);
        resources
            .server()
            .assert_click_counts_stable(before, "effect_drift_dispatched_input");
    }

    fn reject_document_drift(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        keys: &SigningKeys,
    ) {
        let before = resources.server().click_counts();
        let resolution = resolve_case(resources, scope, "recipe-smoke-document-drift");
        let now = resolution.resolved_at;
        let authority = RecipeAuthority::fresh(
            keys,
            &scope.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            &[1],
            1,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "document-drift");
        let drift_target = must(
            scope.policy.authorize(resources.server().url("/drift")),
            "drift_navigation_target",
        );
        must(
            resources.host_mut().navigate_allowlisted(
                &scope.tab_id,
                &scope.proof,
                &scope.policy,
                &drift_target,
                now,
            ),
            "drift_navigation",
        );
        let PreparedExecution {
            plan,
            batch,
            effect,
            resolution,
        } = prepared;
        let mut executor = must(
            ManagedChromiumClickExecutor::new_for_recipe(
                resources.host_mut(),
                batch,
                resolution,
                plan,
                &authority.registry,
                &authority.trust,
                now,
            ),
            "document_drift_executor_constructor",
        );
        assert_provider_rejected(
            executor.execute(&effect),
            "BROWSER_STALE_SNAPSHOT",
            "document_drift_execute_not_rejected",
        );
        drop(executor);
        resources
            .server()
            .assert_click_counts_stable(before, "document_drift_dispatched_input");
    }

    fn execute_single_click(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        keys: &SigningKeys,
    ) {
        let before = resources.server().click_counts();
        assert_eq!(before, ClickCounts { root: 0, iframe: 0 });
        let navigation = navigate_page(
            resources,
            &scope.tab_id,
            &scope.proof,
            &scope.policy,
            fixed_time(),
        );
        let resolution = resolve_case(resources, scope, "recipe-smoke-success");
        assert_eq!(
            resolution.document_generation,
            navigation.document_generation
        );
        let now = resolution.resolved_at;
        let authority = RecipeAuthority::fresh(
            keys,
            &scope.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            &[1],
            1,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "success");
        let expected_request_digest = prepared.batch.plan_digest.clone();
        let PreparedExecution {
            plan,
            batch,
            effect,
            resolution,
        } = prepared;
        let mut executor = must(
            ManagedChromiumClickExecutor::new_for_recipe(
                resources.host_mut(),
                batch,
                resolution,
                plan,
                &authority.registry,
                &authority.trust,
                now,
            ),
            "success_executor_constructor",
        );
        let receipt = must(executor.execute(&effect), "success_click_dispatch");
        assert_named_digest(
            "receipt_request_vs_batch_plan",
            &receipt.request_digest,
            &expected_request_digest,
        );
        let evidence = executor
            .last_evidence()
            .unwrap_or_else(|| fail("success_evidence_missing"));
        assert_eq!(evidence.input_event_count, 2);
        assert!(!evidence.business_verified);
        assert_named_digest(
            "receipt_response_vs_dispatch_evidence",
            &receipt.response_digest,
            &must(evidence.evidence_digest(), "success_evidence_digest"),
        );
        assert_provider_uncertain(
            executor.execute(&effect),
            "BROWSER_REAL_ACTION_REJECTED",
            "second_execute_not_uncertain",
        );
        drop(executor);

        resources.server().wait_for_root_clicks(before.root + 1);
        let expected = ClickCounts {
            root: before.root + 1,
            iframe: before.iframe,
        };
        resources
            .server()
            .assert_click_counts_stable(expected, "success_click_count_drift");
        assert_eq!(resources.server().click_counts().root, 1);
        assert_eq!(resources.server().click_counts().iframe, 0);
    }

    fn assert_constructor_rejected(
        host: &mut ManagedChromiumHost,
        prepared: PreparedExecution,
        authority: &RecipeAuthority,
        expected_code: &'static str,
        label: &'static str,
    ) {
        let now = prepared.resolution.resolved_at;
        match ManagedChromiumClickExecutor::new_for_recipe(
            host,
            prepared.batch,
            prepared.resolution,
            prepared.plan,
            &authority.registry,
            &authority.trust,
            now,
        ) {
            Err(error) if error.code() == expected_code => {}
            Err(_) | Ok(_) => fail(label),
        }
    }

    fn assert_browser_error<T>(
        result: Result<T, crate::BrowserError>,
        expected_code: &'static str,
        label: &'static str,
    ) {
        match result {
            Err(error) if error.code() == expected_code => {}
            Err(_) | Ok(_) => fail(label),
        }
    }

    fn assert_provider_rejected<T>(
        result: Result<T, ProviderFailure>,
        expected_code: &'static str,
        label: &'static str,
    ) {
        match result {
            Err(ProviderFailure::Rejected(code)) if code == expected_code => {}
            Err(_) | Ok(_) => fail(label),
        }
    }

    fn assert_provider_uncertain<T>(
        result: Result<T, ProviderFailure>,
        expected_code: &'static str,
        label: &'static str,
    ) {
        match result {
            Err(ProviderFailure::Uncertain(code)) if code == expected_code => {}
            Err(_) | Ok(_) => fail(label),
        }
    }

    fn assert_named_digest(label: &'static str, left: &str, right: &str) {
        if left != right {
            fail(label);
        }
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn must<T, E>(result: Result<T, E>, label: &'static str) -> T {
        result.unwrap_or_else(|_| fail(label))
    }

    #[track_caller]
    fn fail(label: &'static str) -> ! {
        panic!("RECIPE_SMOKE_FAIL: step={label}")
    }
}

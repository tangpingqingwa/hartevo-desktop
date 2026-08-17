use std::collections::BTreeSet;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, BrowserActionBatchId,
    BrowserControlLeaseId, BrowserProfileId, BrowserRecipeId, BrowserSnapshotId, BrowserTabId,
    BrowserWorkspaceId, ConsentState, CurrencyCode, Effect, EffectClass, EffectId, EffectRisk,
    EffectStatus, Mission, MissionContract, MissionId, Money, Project, ProjectId, StorageMode,
    TenantId,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::{BrowserRecipeResumeContext, BrowserRecipeResumeCursor};
use crate::workspace::digest_json;
use crate::{
    BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk, BrowserActionSurface,
    BrowserElementRef, BrowserIdentity, BrowserLeaseProof, BrowserLocatorResolution,
    BrowserNavigationPolicy, BrowserProfile, BrowserRecipeCandidate,
    BrowserRecipeEvaluationEvidence, BrowserRecipeExecutionAuthorization, BrowserRecipeKeyPurpose,
    BrowserRecipeManifest, BrowserRecipePreparedPlan, BrowserRecipePromotion,
    BrowserRecipeRegistry, BrowserRecipeRelease, BrowserRecipeResolvedAction, BrowserRecipeStep,
    BrowserRecipeTrustStore, BrowserWorkspace, ChromiumClickDispatchEvidence,
    TrustedBrowserRecipeKey,
};

const RECIPE_ID: &str = "real-chromium-recipe-crash-resume";
const CANDIDATE_KEY_ID: &str = "crash-resume-candidate-key";
const RELEASE_KEY_ID: &str = "crash-resume-release-key";
const CLICK_CAPABILITY: &str = "browser.semantic_click";
const ROOT_AUTHORITY_DIGEST: char = 'f';

struct CursorSnapshot {
    json: String,
    digest: String,
    revision: u64,
}

fn cursor_snapshot(cursor: &BrowserRecipeResumeCursor) -> CursorSnapshot {
    CursorSnapshot {
        json: must(cursor.snapshot_json(), "cursor_snapshot_json"),
        digest: must(cursor.evidence_digest(), "cursor_snapshot_digest"),
        revision: cursor.revision(),
    }
}

#[test]
fn recipe_resume_cursor_rejects_tamper_and_preserves_ack_boundary() {
    let temp = tempfile::TempDir::new().expect("temporary test root");
    let now = Utc::now();
    let scope = domain_scope(temp.path(), now);
    let policy = BrowserNavigationPolicy::with_loopback_http_for_test(["http://127.0.0.1:1"])
        .expect("loopback policy");
    let origin_digest = policy
        .permitted_origin_digest("http://127.0.0.1:1/step-one")
        .expect("permitted origin");
    let resolutions = synthetic_resolutions(&scope, &policy, &origin_digest, now, 1);
    let authority = RecipeAuthority::fresh(
        &SigningKeys::new(),
        &scope.profile,
        &origin_digest,
        [
            &resolutions[0].selector_digest,
            &resolutions[1].selector_digest,
        ],
        now,
    );
    let first = prepare_execution(&authority, &scope, &policy, &resolutions, "unit-first", now);
    let root_digest = sha(ROOT_AUTHORITY_DIGEST);
    let first_context = resume_context(
        &root_digest,
        &first,
        &authority,
        &scope.profile,
        &scope.workspace,
    );
    let mut cursor = BrowserRecipeResumeCursor::start(first_context, now).expect("cursor start");
    let initial = cursor_snapshot(&cursor);

    cursor
        .acknowledge_chromium_click(
            first_context,
            synthetic_evidence(&first, &resolutions[0], 0, now),
            now,
        )
        .expect("first acknowledgement");
    assert_eq!(cursor.acknowledged_action_sequences(), vec![1]);
    assert_eq!(cursor.next_action_sequence(), Some(2));
    let persisted = cursor_snapshot(&cursor);
    assert_unit_restore_rejections(&initial, &persisted, first_context, now);

    let resumed_at = now + Duration::seconds(1);
    let rebound_resolutions = synthetic_resolutions(&scope, &policy, &origin_digest, resumed_at, 2);
    let second = prepare_execution(
        &authority,
        &scope,
        &policy,
        &rebound_resolutions,
        "unit-second",
        resumed_at,
    );
    let second_context = resume_context(
        &root_digest,
        &second,
        &authority,
        &scope.profile,
        &scope.workspace,
    );
    let mut restored = BrowserRecipeResumeCursor::restore_json(
        &persisted.json,
        &persisted.digest,
        persisted.revision,
        first_context,
        resumed_at,
    )
    .expect("valid restore");
    restored
        .rebind_after_restart(second_context, resumed_at)
        .expect("restart rebind");
    restored
        .acknowledge_chromium_click(
            second_context,
            synthetic_evidence(&second, &rebound_resolutions[1], 1, resumed_at),
            resumed_at,
        )
        .expect("second acknowledgement");
    assert!(restored.is_complete());
    assert_eq!(restored.acknowledged_action_sequences(), vec![1, 2]);
    assert_eq!(restored.authority_digest(), cursor.authority_digest());
    assert_eq!(restored.root_authority_snapshot_digest(), root_digest);
    assert_eq!(restored.profile_digest(), cursor.profile_digest());
    assert_eq!(restored.release_digest(), cursor.release_digest());
    assert_eq!(initial.revision, 1);
}

fn assert_unit_restore_rejections(
    initial: &CursorSnapshot,
    persisted: &CursorSnapshot,
    context: BrowserRecipeResumeContext<'_>,
    now: DateTime<Utc>,
) {
    let mut tampered: serde_json::Value =
        serde_json::from_str(&persisted.json).expect("cursor json value");
    tampered["nextActionIndex"] = serde_json::json!(0);
    assert_browser_error(
        BrowserRecipeResumeCursor::restore_json(
            &serde_json::to_string(&tampered).expect("tampered json"),
            &persisted.digest,
            persisted.revision,
            context,
            now,
        ),
        "BROWSER_RECIPE_SCOPE_MISMATCH",
    );
    assert_browser_error(
        BrowserRecipeResumeCursor::restore_json(
            &initial.json,
            &initial.digest,
            persisted.revision,
            context,
            now,
        ),
        "BROWSER_REVISION_MISMATCH",
    );
    let drifted_root = sha('e');
    assert_browser_error(
        BrowserRecipeResumeCursor::restore_json(
            &persisted.json,
            &persisted.digest,
            persisted.revision,
            BrowserRecipeResumeContext {
                root_authority_snapshot_digest: &drifted_root,
                ..context
            },
            now,
        ),
        "BROWSER_RECIPE_SCOPE_MISMATCH",
    );
}

#[test]
#[ignore = "requires macOS, HARTEVO_TEST_CHROME_BINARY, mock Keychain, and loopback; explicit missing prerequisites panic BLOCKED_ENV"]
fn real_chromium_signed_recipe_crash_resume_smoke() {
    #[cfg(target_os = "macos")]
    macos::run();

    #[cfg(not(target_os = "macos"))]
    panic!("BLOCKED_ENV: reason=macos_required");
}

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant};

    use chrono::{DateTime, Utc};
    use hartevo_domain_kernel::{BrowserSnapshotId, BrowserTabId};
    use hartevo_effect_broker::EffectExecutor;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        BrowserStableLocator, ChromiumCredentialStoreMode, ChromiumLaunchConfig,
        ManagedChromiumHost, ManagedChromiumRecipeClickStepExecutor,
    };

    const CHROME_ENV: &str = "HARTEVO_TEST_CHROME_BINARY";
    const WAIT_LIMIT: StdDuration = StdDuration::from_secs(5);
    const QUIET_LIMIT: StdDuration = StdDuration::from_millis(100);

    pub(super) fn run() {
        let prerequisites = ExternalPrerequisites::acquire();
        let mut resources = SmokeResources::new(prerequisites);
        let body_result = catch_unwind(AssertUnwindSafe(|| run_smoke(&mut resources)));
        let cleanup_result = resources.cleanup();
        match (body_result, cleanup_result) {
            (Ok(()), Ok(())) => {}
            (Err(payload), Ok(())) => resume_unwind(payload),
            (body, Err(step)) => panic!(
                "RECIPE_SMOKE_03_CLEANUP_FAILED: step={step} has_prior_failure={}",
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
            let exists = executable
                .try_exists()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=chrome_path_unavailable"));
            assert!(exists, "BLOCKED_ENV: reason=chrome_path_missing");
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
        profile_root: PathBuf,
        project_root: PathBuf,
        listener: Option<TcpListener>,
        server: Option<FixtureServer>,
        host: Option<ManagedChromiumHost>,
    }

    impl SmokeResources {
        fn new(prerequisites: ExternalPrerequisites) -> Self {
            let temp_path = prerequisites.temp.path().to_owned();
            let profile_root = private_child(&temp_path, "profiles");
            let project_root = private_child(&temp_path, "project");
            Self {
                executable: prerequisites.executable,
                temp: Some(prerequisites.temp),
                profile_root,
                project_root,
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

        fn profile_root(&self) -> &Path {
            &self.profile_root
        }

        fn project_root(&self) -> &Path {
            &self.project_root
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

        fn settle_click(
            &mut self,
            proof: &BrowserLeaseProof,
            tab_id: &BrowserTabId,
            expected_one: usize,
            expected_two: usize,
            label: &'static str,
        ) {
            let deadline = Instant::now() + WAIT_LIMIT;
            let mut attempt = 0_u64;
            loop {
                let counts = self.server().counts();
                if counts.clicks_one >= expected_one && counts.clicks_two >= expected_two {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "RECIPE_SMOKE_03_FAIL: step={label}_click_settle_timeout observed={counts:?}"
                );
                attempt = attempt.saturating_add(1);
                let snapshot_id = BrowserSnapshotId::from_stable(format!(
                    "recipe-crash-resume-{label}-click-settle-{attempt}"
                ));
                match self
                    .host_mut()
                    .observe_ax(tab_id, proof, snapshot_id, Utc::now())
                {
                    Ok(_) | Err(crate::BrowserError::StaleSnapshot) => {}
                    Err(error) => panic!(
                        "RECIPE_SMOKE_03_FAIL: step={label}_click_settle browser_error={}",
                        error.code()
                    ),
                }
            }
        }

        fn spawn_host(&mut self, scope: &BrowserScope) {
            if self.host.is_some() {
                fail("chromium_host_already_running");
            }
            let config = must(
                ChromiumLaunchConfig::new(
                    &self.executable,
                    self.profile_root().to_path_buf(),
                    true,
                ),
                "launch_config_contract",
            );
            let config = must(
                config.with_macos_mock_keychain_for_test(),
                "mock_keychain_contract",
            );
            self.host = Some(must_browser(
                ManagedChromiumHost::spawn(scope.profile.clone(), scope.workspace.clone(), &config),
                "chromium_host_spawn",
            ));
            let health = must(self.host_mut().health(), "chromium_health");
            if (!health.product.contains("Chrome") && !health.product.contains("Chromium"))
                || health.credential_store_mode != ChromiumCredentialStoreMode::MacOsMockForTest
            {
                fail("chromium_health_contract");
            }
            for tab_id in [&scope.first_tab_id, &scope.second_tab_id] {
                must(
                    self.host_mut()
                        .attach_about_blank_tab(tab_id, &scope.proof, Utc::now()),
                    "attach_about_blank_tab",
                );
            }
        }

        fn stop_host(&mut self) {
            let host = self
                .host
                .as_mut()
                .unwrap_or_else(|| fail("chromium_host_missing_for_stop"));
            match host.shutdown() {
                Ok(shutdown) if shutdown.success => {
                    self.host.take();
                }
                Ok(_) | Err(_) => fail("chromium_host_shutdown"),
            }
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

    fn private_child(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).unwrap_or_else(|_| fail("private_child_create"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| fail("private_child_permissions"));
        path
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FixtureCounts {
        loads_one: usize,
        loads_two: usize,
        clicks_one: usize,
        clicks_two: usize,
    }

    struct FixtureState {
        step_one_loads: AtomicUsize,
        step_two_loads: AtomicUsize,
        step_one_clicks: AtomicUsize,
        step_two_clicks: AtomicUsize,
        signal: Mutex<()>,
        changed: Condvar,
    }

    impl FixtureState {
        fn new() -> Self {
            Self {
                step_one_loads: AtomicUsize::new(0),
                step_two_loads: AtomicUsize::new(0),
                step_one_clicks: AtomicUsize::new(0),
                step_two_clicks: AtomicUsize::new(0),
                signal: Mutex::new(()),
                changed: Condvar::new(),
            }
        }

        fn counts(&self) -> FixtureCounts {
            FixtureCounts {
                loads_one: self.step_one_loads.load(Ordering::Acquire),
                loads_two: self.step_two_loads.load(Ordering::Acquire),
                clicks_one: self.step_one_clicks.load(Ordering::Acquire),
                clicks_two: self.step_two_clicks.load(Ordering::Acquire),
            }
        }

        fn record(&self, route: FixtureRoute) {
            match route {
                FixtureRoute::StepOne => {
                    self.step_one_loads.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::StepTwo => {
                    self.step_two_loads.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::StepOneClicked => {
                    self.step_one_clicks.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::StepTwoClicked => {
                    self.step_two_clicks.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::Other => {}
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

        fn assert_clicks_stable(&self, one: usize, two: usize, label: &'static str) {
            let deadline = Instant::now() + QUIET_LIMIT;
            let mut guard = self
                .signal
                .lock()
                .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
            loop {
                let counts = self.counts();
                if counts.clicks_one != one || counts.clicks_two != two {
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
                .name("hartevo-recipe-crash-resume-loopback".into())
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

        fn counts(&self) -> FixtureCounts {
            self.state.counts()
        }

        fn wait_for_load_after(&self, step: usize, before: usize) {
            self.state.wait_until("fixture_page_load_timeout", || {
                let counts = self.state.counts();
                match step {
                    1 => counts.loads_one > before,
                    2 => counts.loads_two > before,
                    _ => false,
                }
            });
        }

        fn wait_for_clicks(&self, one: usize, two: usize) {
            let deadline = Instant::now() + WAIT_LIMIT;
            let mut guard = self
                .state
                .signal
                .lock()
                .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
            loop {
                let counts = self.state.counts();
                if counts.clicks_one >= one && counts.clicks_two >= two {
                    return;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "RECIPE_SMOKE_03_FAIL: step=fixture_click_timeout observed={counts:?}"
                );
                let (next_guard, timeout) = self
                    .state
                    .changed
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
                guard = next_guard;
                if timeout.timed_out() {
                    let observed = self.state.counts();
                    assert!(
                        observed.clicks_one >= one && observed.clicks_two >= two,
                        "RECIPE_SMOKE_03_FAIL: step=fixture_click_timeout observed={observed:?}"
                    );
                    return;
                }
            }
        }

        fn assert_clicks_stable(&self, one: usize, two: usize, label: &'static str) {
            self.state.assert_clicks_stable(one, two, label);
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
        StepOne,
        StepTwo,
        StepOneClicked,
        StepTwoClicked,
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
        write_bounded(&mut stream, &fixture_response(route), control);
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
        match path.split('?').next().unwrap_or(path) {
            "/step-one" => FixtureRoute::StepOne,
            "/step-two" => FixtureRoute::StepTwo,
            "/step-one-clicked" => FixtureRoute::StepOneClicked,
            "/step-two-clicked" => FixtureRoute::StepTwoClicked,
            _ => FixtureRoute::Other,
        }
    }

    fn fixture_response(route: FixtureRoute) -> Vec<u8> {
        let (status, body) = match route {
            FixtureRoute::StepOne => (
                "200 OK",
                "<html><body><form action=\"/step-one-clicked\" method=\"get\"><button type=\"submit\" style=\"width:200px;height:60px\">Step One</button></form></body></html>",
            ),
            FixtureRoute::StepTwo => (
                "200 OK",
                "<html><body><form action=\"/step-two-clicked\" method=\"get\"><button type=\"submit\" style=\"width:200px;height:60px\">Step Two</button></form></body></html>",
            ),
            FixtureRoute::StepOneClicked => (
                "200 OK",
                "<html><body><h1>Step one acknowledged</h1></body></html>",
            ),
            FixtureRoute::StepTwoClicked => (
                "200 OK",
                "<html><body><h1>Step two acknowledged</h1></body></html>",
            ),
            FixtureRoute::Other => ("404 Not Found", "not found"),
        };
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    struct FirstGeneration {
        scope: BrowserScope,
        policy: BrowserNavigationPolicy,
        authority: RecipeAuthority,
        execution: PreparedExecution,
        resolutions: [BrowserLocatorResolution; 2],
        root_digest: String,
        cursor: BrowserRecipeResumeCursor,
    }

    struct InterruptedRun {
        scope: BrowserScope,
        policy: BrowserNavigationPolicy,
        authority: RecipeAuthority,
        root_digest: String,
        cursor: BrowserRecipeResumeCursor,
        authority_digest: String,
        profile_digest: String,
        release_digest: String,
    }

    fn run_smoke(resources: &mut SmokeResources) {
        let first = begin_first_generation(resources);
        let mut interrupted = interrupt_after_first_ack(resources, first);
        resume_second_generation(resources, &mut interrupted);
    }

    fn begin_first_generation(resources: &mut SmokeResources) -> FirstGeneration {
        resources.start_server();
        let started_at = Utc::now();
        let scope = domain_scope(resources.project_root(), started_at);
        resources.spawn_host(&scope);
        let origin = resources.server().origin();
        let policy = must(
            BrowserNavigationPolicy::with_loopback_http_for_test([origin.as_str()]),
            "loopback_navigation_policy",
        );
        let first_resolutions = resolve_live_generation(resources, &scope, &policy, "first");
        let prepared_at = latest_resolution_time(&first_resolutions);
        let keys = SigningKeys::new();
        let authority = RecipeAuthority::fresh(
            &keys,
            &scope.profile,
            &first_resolutions[0].origin_digest,
            [
                &first_resolutions[0].selector_digest,
                &first_resolutions[1].selector_digest,
            ],
            prepared_at,
        );
        let first = prepare_execution(
            &authority,
            &scope,
            &policy,
            &first_resolutions,
            "real-first-generation",
            prepared_at,
        );
        let root_digest = sha(ROOT_AUTHORITY_DIGEST);
        let first_context = resume_context(
            &root_digest,
            &first,
            &authority,
            &scope.profile,
            &scope.workspace,
        );
        let cursor = must(
            BrowserRecipeResumeCursor::start(first_context, prepared_at),
            "resume_cursor_start",
        );
        FirstGeneration {
            scope,
            policy,
            authority,
            execution: first,
            resolutions: first_resolutions,
            root_digest,
            cursor,
        }
    }

    fn interrupt_after_first_ack(
        resources: &mut SmokeResources,
        first: FirstGeneration,
    ) -> InterruptedRun {
        let FirstGeneration {
            scope,
            policy,
            authority,
            execution,
            resolutions,
            root_digest,
            mut cursor,
        } = first;
        let unacknowledged = cursor_snapshot(&cursor);
        let authority_digest = cursor.authority_digest().to_owned();
        let profile_digest = cursor.profile_digest().to_owned();
        let release_digest = cursor.release_digest().to_owned();
        let context = resume_context(
            &root_digest,
            &execution,
            &authority,
            &scope.profile,
            &scope.workspace,
        );

        let (first_receipt, first_evidence) = dispatch_next_step(
            resources,
            context,
            &cursor,
            resolutions[0].clone(),
            &execution.effect,
            execution.batch.created_at,
        );
        resources.settle_click(&scope.proof, &first_evidence.tab_id, 1, 0, "first_step");
        must(
            cursor.acknowledge_chromium_click(context, first_evidence.clone(), Utc::now()),
            "first_step_acknowledgement",
        );
        assert_dispatch_receipt(
            &first_receipt,
            &execution.batch,
            &first_evidence,
            "first_dispatch_receipt",
        );
        resources.server().wait_for_clicks(1, 0);
        resources
            .server()
            .assert_clicks_stable(1, 0, "first_step_duplicate_or_skipped");
        if cursor.acknowledged_action_sequences() != [1] || cursor.next_action_sequence() != Some(2)
        {
            fail("first_step_cursor_boundary");
        }
        let persisted = cursor_snapshot(&cursor);
        let restored_execution = execution.restore_from_json();
        let restored_authority = authority.restore_from_json();
        drop(cursor);
        drop(execution);
        drop(authority);

        resources.stop_host();
        reject_resume_drift_before_restart(
            resources,
            &scope,
            &restored_execution,
            &restored_authority,
            &root_digest,
            &unacknowledged,
            &persisted,
        );
        let restored_first_context = resume_context(
            &root_digest,
            &restored_execution,
            &restored_authority,
            &scope.profile,
            &scope.workspace,
        );
        let resumed = must(
            BrowserRecipeResumeCursor::restore_json(
                &persisted.json,
                &persisted.digest,
                persisted.revision,
                restored_first_context,
                Utc::now(),
            ),
            "valid_cursor_restore",
        );
        assert_resume_digests(
            &resumed,
            &authority_digest,
            &root_digest,
            &profile_digest,
            &release_digest,
            "restored_cursor_digests",
        );
        InterruptedRun {
            scope,
            policy,
            authority: restored_authority,
            root_digest,
            cursor: resumed,
            authority_digest,
            profile_digest,
            release_digest,
        }
    }

    fn resume_second_generation(resources: &mut SmokeResources, run: &mut InterruptedRun) {
        resources.spawn_host(&run.scope);
        let second_resolutions =
            resolve_live_generation(resources, &run.scope, &run.policy, "second");
        let rebound_at = latest_resolution_time(&second_resolutions);
        let second = prepare_execution(
            &run.authority,
            &run.scope,
            &run.policy,
            &second_resolutions,
            "real-second-generation",
            rebound_at,
        );
        let second_context = resume_context(
            &run.root_digest,
            &second,
            &run.authority,
            &run.scope.profile,
            &run.scope.workspace,
        );
        must(
            run.cursor.rebind_after_restart(second_context, rebound_at),
            "restart_cursor_rebind",
        );
        assert_resume_digests(
            &run.cursor,
            &run.authority_digest,
            &run.root_digest,
            &run.profile_digest,
            &run.release_digest,
            "rebound_cursor_digests",
        );
        let (second_receipt, second_evidence) = dispatch_next_step(
            resources,
            second_context,
            &run.cursor,
            second_resolutions[1].clone(),
            &second.effect,
            rebound_at,
        );
        resources.settle_click(
            &run.scope.proof,
            &second_evidence.tab_id,
            1,
            1,
            "second_step",
        );
        must(
            run.cursor.acknowledge_chromium_click(
                second_context,
                second_evidence.clone(),
                Utc::now(),
            ),
            "second_step_acknowledgement",
        );
        assert_dispatch_receipt(
            &second_receipt,
            &second.batch,
            &second_evidence,
            "second_dispatch_receipt",
        );
        resources.server().wait_for_clicks(1, 1);
        resources
            .server()
            .assert_clicks_stable(1, 1, "resume_duplicate_or_skipped_step");
        if !run.cursor.is_complete() || run.cursor.acknowledged_action_sequences() != [1, 2] {
            fail("completed_cursor_sequence");
        }
        assert_resume_digests(
            &run.cursor,
            &run.authority_digest,
            &run.root_digest,
            &run.profile_digest,
            &run.release_digest,
            "completed_cursor_digests",
        );
    }

    fn resolve_live_generation(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        policy: &BrowserNavigationPolicy,
        generation: &'static str,
    ) -> [BrowserLocatorResolution; 2] {
        [
            navigate_observe_and_resolve(
                resources,
                scope,
                policy,
                &scope.first_tab_id,
                1,
                "/step-one",
                "Step One",
                generation,
            ),
            navigate_observe_and_resolve(
                resources,
                scope,
                policy,
                &scope.second_tab_id,
                2,
                "/step-two",
                "Step Two",
                generation,
            ),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    fn navigate_observe_and_resolve(
        resources: &mut SmokeResources,
        scope: &BrowserScope,
        policy: &BrowserNavigationPolicy,
        tab_id: &BrowserTabId,
        step: usize,
        path: &'static str,
        accessible_name: &'static str,
        generation: &'static str,
    ) -> BrowserLocatorResolution {
        let before = resources.server().counts();
        let before_loads = if step == 1 {
            before.loads_one
        } else {
            before.loads_two
        };
        let target = must(
            policy.authorize(resources.server().url(path)),
            "fixture_navigation_target",
        );
        let navigation = must(
            resources.host_mut().navigate_allowlisted(
                tab_id,
                &scope.proof,
                policy,
                &target,
                Utc::now(),
            ),
            "fixture_navigation",
        );
        if !navigation.script_execution_disabled {
            fail("fixture_script_execution_not_disabled");
        }
        resources.server().wait_for_load_after(step, before_loads);
        let observation = must(
            resources.host_mut().observe_ax(
                tab_id,
                &scope.proof,
                BrowserSnapshotId::from_stable(format!(
                    "recipe-crash-resume-{generation}-{step}-observation"
                )),
                Utc::now(),
            ),
            "production_ax_observation",
        );
        if observation.document_generation != navigation.document_generation {
            fail("navigation_observation_generation");
        }
        let locator = must(
            BrowserStableLocator::exact_accessible_name(
                &scope.workspace,
                tab_id.clone(),
                policy,
                navigation.final_origin_digest,
                "button",
                accessible_name,
                Utc::now(),
            ),
            "stable_locator_contract",
        );
        must(
            resources.host_mut().resolve_stable_locator(
                tab_id,
                &scope.proof,
                &locator,
                BrowserSnapshotId::from_stable(format!(
                    "recipe-crash-resume-{generation}-{step}-resolution"
                )),
                Utc::now(),
            ),
            "production_locator_resolution",
        )
    }

    fn latest_resolution_time(resolutions: &[BrowserLocatorResolution; 2]) -> DateTime<Utc> {
        resolutions[0].resolved_at.max(resolutions[1].resolved_at)
    }

    fn dispatch_next_step(
        resources: &mut SmokeResources,
        context: BrowserRecipeResumeContext<'_>,
        cursor: &BrowserRecipeResumeCursor,
        resolution: BrowserLocatorResolution,
        effect: &Effect,
        now: DateTime<Utc>,
    ) -> (
        hartevo_domain_kernel::Receipt,
        ChromiumClickDispatchEvidence,
    ) {
        let mut executor = must(
            ManagedChromiumRecipeClickStepExecutor::new(
                resources.host_mut(),
                context,
                cursor,
                resolution,
                now,
            ),
            "recipe_step_executor_constructor",
        );
        let receipt = must(executor.execute(effect), "recipe_step_dispatch");
        let evidence = executor
            .last_evidence()
            .cloned()
            .unwrap_or_else(|| fail("recipe_step_evidence_missing"));
        if evidence.input_event_count != 2 || evidence.business_verified {
            fail("recipe_step_evidence_contract");
        }
        match executor.execute(effect) {
            Err(hartevo_effect_broker::ProviderFailure::Uncertain(code))
                if code == "BROWSER_REAL_ACTION_REJECTED" => {}
            Err(_) | Ok(_) => fail("recipe_step_executor_replay_fence"),
        }
        (receipt, evidence)
    }

    fn assert_dispatch_receipt(
        receipt: &hartevo_domain_kernel::Receipt,
        batch: &BrowserActionBatch,
        evidence: &ChromiumClickDispatchEvidence,
        label: &'static str,
    ) {
        if receipt.request_digest != batch.plan_digest
            || receipt.response_digest != must(evidence.evidence_digest(), label)
        {
            fail(label);
        }
    }

    fn reject_resume_drift_before_restart(
        resources: &SmokeResources,
        scope: &BrowserScope,
        first: &PreparedExecution,
        authority: &RecipeAuthority,
        root_digest: &str,
        unacknowledged: &CursorSnapshot,
        persisted: &CursorSnapshot,
    ) {
        if resources.host.is_some() {
            fail("negative_resume_host_still_running");
        }
        let now = Utc::now();
        let context = resume_context(
            root_digest,
            first,
            authority,
            &scope.profile,
            &scope.workspace,
        );
        reject_snapshot_and_root_drift(context, unacknowledged, persisted, now);
        reject_profile_release_and_key_drift(scope, first, authority, context, persisted, now);
        resources
            .server()
            .assert_clicks_stable(1, 0, "negative_resume_dispatched_host_input");
    }

    fn reject_snapshot_and_root_drift(
        context: BrowserRecipeResumeContext<'_>,
        unacknowledged: &CursorSnapshot,
        persisted: &CursorSnapshot,
        now: DateTime<Utc>,
    ) {
        let mut tampered: serde_json::Value = must(
            serde_json::from_str(&persisted.json),
            "tampered_cursor_parse",
        );
        tampered["nextActionIndex"] = serde_json::json!(0);
        assert_browser_error(
            BrowserRecipeResumeCursor::restore_json(
                &must(
                    serde_json::to_string(&tampered),
                    "tampered_cursor_serialize",
                ),
                &persisted.digest,
                persisted.revision,
                context,
                now,
            ),
            "BROWSER_RECIPE_SCOPE_MISMATCH",
        );
        assert_browser_error(
            BrowserRecipeResumeCursor::restore_json(
                &unacknowledged.json,
                &unacknowledged.digest,
                persisted.revision,
                context,
                now,
            ),
            "BROWSER_REVISION_MISMATCH",
        );
        let drifted_root = sha('d');
        assert_browser_error(
            BrowserRecipeResumeCursor::restore_json(
                &persisted.json,
                &persisted.digest,
                persisted.revision,
                BrowserRecipeResumeContext {
                    root_authority_snapshot_digest: &drifted_root,
                    ..context
                },
                now,
            ),
            "BROWSER_RECIPE_SCOPE_MISMATCH",
        );
    }

    fn reject_profile_release_and_key_drift(
        scope: &BrowserScope,
        first: &PreparedExecution,
        authority: &RecipeAuthority,
        context: BrowserRecipeResumeContext<'_>,
        persisted: &CursorSnapshot,
        now: DateTime<Utc>,
    ) {
        let mut drifted_profile = scope.profile.clone();
        drifted_profile.identity.probe_digest = sha('c');
        assert_browser_error(
            BrowserRecipeResumeCursor::restore_json(
                &persisted.json,
                &persisted.digest,
                persisted.revision,
                BrowserRecipeResumeContext {
                    profile: &drifted_profile,
                    ..context
                },
                now,
            ),
            "BROWSER_RECIPE_SCOPE_MISMATCH",
        );
        let mut drifted_plan = first.plan.clone();
        drifted_plan.release_digest = sha('b');
        assert_browser_error(
            BrowserRecipeResumeCursor::restore_json(
                &persisted.json,
                &persisted.digest,
                persisted.revision,
                BrowserRecipeResumeContext {
                    prepared_plan: &drifted_plan,
                    ..context
                },
                now,
            ),
            "BROWSER_RECIPE_SCOPE_MISMATCH",
        );
        let mut revoked_authority = authority.restore_from_json();
        must(
            revoked_authority.trust.revoke(RELEASE_KEY_ID, 1, now),
            "release_key_revoke",
        );
        assert_browser_error(
            BrowserRecipeResumeCursor::restore_json(
                &persisted.json,
                &persisted.digest,
                persisted.revision,
                BrowserRecipeResumeContext {
                    registry: &revoked_authority.registry,
                    trust: &revoked_authority.trust,
                    ..context
                },
                now,
            ),
            "BROWSER_RECIPE_KEY_REVOKED",
        );
    }

    fn assert_resume_digests(
        cursor: &BrowserRecipeResumeCursor,
        authority_digest: &str,
        root_digest: &str,
        profile_digest: &str,
        release_digest: &str,
        label: &'static str,
    ) {
        if cursor.authority_digest() != authority_digest
            || cursor.root_authority_snapshot_digest() != root_digest
            || cursor.profile_digest() != profile_digest
            || cursor.release_digest() != release_digest
        {
            fail(label);
        }
    }
}

struct BrowserScope {
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    proof: BrowserLeaseProof,
    first_tab_id: BrowserTabId,
    second_tab_id: BrowserTabId,
}

fn domain_scope(private_root: &Path, now: DateTime<Utc>) -> BrowserScope {
    let project = must(
        Project::create_local(
            TenantId::from("tenant-recipe-crash-resume"),
            ProjectId::from("project-recipe-crash-resume"),
            "Signed Recipe Crash Resume",
            "",
            private_root,
            StorageMode::LocalExisting,
        ),
        "project_scope",
    );
    let mission = must(
        Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-recipe-crash-resume"),
            project.id.clone(),
            "Signed Recipe crash and resume smoke",
            MissionContract::bootstrap(
                "Resume a signed two-step browser recipe without duplicate input",
                [CLICK_CAPABILITY.into()],
                now,
            ),
            now,
        ),
        "mission_scope",
    );
    let identity = must(
        BrowserIdentity::new(
            "real-chromium-recipe-crash-resume",
            AccountId::from("account-recipe-crash-resume"),
            sha('1'),
            sha('2'),
            now,
        ),
        "browser_identity",
    );
    let profile = must(
        BrowserProfile::create_managed(
            BrowserProfileId::from("profile-recipe-crash-resume"),
            &project,
            "keyring://browser/real-recipe-crash-resume",
            identity,
            now,
        ),
        "browser_profile",
    );
    let first_tab_id = BrowserTabId::from("tab-recipe-crash-resume-one");
    let second_tab_id = BrowserTabId::from("tab-recipe-crash-resume-two");
    let mut workspace = must(
        BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-recipe-crash-resume"),
            &project,
            &mission,
            &profile,
            first_tab_id.clone(),
            BrowserControlLeaseId::from("lease-recipe-crash-resume"),
            now + Duration::hours(1),
            sha('3'),
            now,
        ),
        "browser_workspace",
    );
    must(
        workspace.add_tab(
            workspace.revision,
            workspace.lease_generation,
            second_tab_id.clone(),
            now,
        ),
        "browser_second_tab",
    );
    let proof = must(workspace.agent_lease_proof(now), "browser_lease_proof");
    BrowserScope {
        profile,
        workspace,
        proof,
        first_tab_id,
        second_tab_id,
    }
}

struct SigningKeys {
    candidate: Ed25519KeyPair,
    release: Ed25519KeyPair,
}

impl SigningKeys {
    fn new() -> Self {
        Self {
            candidate: must(
                Ed25519KeyPair::from_seed_unchecked(&[37; 32]),
                "candidate_signing_key",
            ),
            release: must(
                Ed25519KeyPair::from_seed_unchecked(&[41; 32]),
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
        selector_digests: [&str; 2],
        now: DateTime<Utc>,
    ) -> Self {
        let trust = trust_store(keys, now);
        let recipe_id = BrowserRecipeId::from(RECIPE_ID);
        let release = signed_release(keys, profile, origin_digest, selector_digests, now);
        let mut registry = BrowserRecipeRegistry::default();
        must(
            registry.register_candidate(release.candidate.clone(), &trust, now),
            "candidate_registry_insert",
        );
        must(
            registry.register_release(release, &trust, now),
            "release_registry_insert",
        );
        must(
            registry.activate_release(&recipe_id, 1, None, &sha('e'), &trust, now),
            "recipe_activation",
        );
        Self {
            trust,
            registry,
            recipe_id,
        }
    }

    #[cfg(target_os = "macos")]
    fn restore_from_json(&self) -> Self {
        let trust_json = must(
            serde_json::to_string(&self.trust.snapshot()),
            "trust_serialize",
        );
        let trust = must(
            BrowserRecipeTrustStore::restore(must(
                serde_json::from_str(&trust_json),
                "trust_deserialize",
            )),
            "trust_restore",
        );
        let registry_json = must(
            serde_json::to_string(&must(self.registry.snapshot(), "registry_snapshot")),
            "registry_serialize",
        );
        let registry = must(
            BrowserRecipeRegistry::restore(
                must(serde_json::from_str(&registry_json), "registry_deserialize"),
                &trust,
            ),
            "registry_restore",
        );
        Self {
            trust,
            registry,
            recipe_id: self.recipe_id.clone(),
        }
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
    selector_digests: [&str; 2],
    now: DateTime<Utc>,
) -> BrowserRecipeRelease {
    // `1` is the checked-in wire value; public validation/signature APIs below
    // enforce the contract rather than a copied private constant.
    let manifest = BrowserRecipeManifest {
        schema_version: 1,
        id: BrowserRecipeId::from(RECIPE_ID),
        version: 1,
        provider: profile.identity.provider.clone(),
        origin_digest: origin_digest.to_owned(),
        capability: CLICK_CAPABILITY.into(),
        effect_class: EffectClass::ExternalWrite,
        steps: selector_digests
            .into_iter()
            .enumerate()
            .map(|(index, selector_digest)| BrowserRecipeStep {
                sequence: u32::try_from(index).expect("bounded step index") + 1,
                kind: BrowserActionKind::Click,
                surface: BrowserActionSurface::Semantic,
                risk: BrowserActionRisk::PotentialExternalWrite,
                selector_digest: selector_digest.to_owned(),
            })
            .collect(),
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
        v1_dataset_revision: "recipe-crash-resume-v1-holdout".into(),
        v1_result_digest: sha('4'),
        v1_passed: 9,
        v1_total: 10,
        v2_dataset_revision: "recipe-crash-resume-v2-shadow".into(),
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
}

impl PreparedExecution {
    #[cfg(target_os = "macos")]
    fn restore_from_json(&self) -> Self {
        Self {
            plan: round_trip_json(&self.plan, "prepared_plan_restore"),
            batch: round_trip_json(&self.batch, "action_batch_restore"),
            effect: round_trip_json(&self.effect, "effect_restore"),
        }
    }
}

#[cfg(target_os = "macos")]
fn round_trip_json<T>(value: &T, label: &'static str) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let encoded = must(serde_json::to_string(value), label);
    must(serde_json::from_str(&encoded), label)
}

fn prepare_execution(
    authority: &RecipeAuthority,
    scope: &BrowserScope,
    policy: &BrowserNavigationPolicy,
    resolutions: &[BrowserLocatorResolution; 2],
    case_id: &'static str,
    now: DateTime<Utc>,
) -> PreparedExecution {
    let actions = vec![
        must(
            BrowserAction::semantic_click(1, &resolutions[0]),
            "step_one_action",
        ),
        must(
            BrowserAction::semantic_click(2, &resolutions[1]),
            "step_two_action",
        ),
    ];
    let resolved = [
        BrowserRecipeResolvedAction {
            action: &actions[0],
            resolution: &resolutions[0],
        },
        BrowserRecipeResolvedAction {
            action: &actions[1],
            resolution: &resolutions[1],
        },
    ];
    let plan = must(
        authority.registry.prepare_active_plan(
            &authority.recipe_id,
            &authority.trust,
            &scope.profile,
            &scope.workspace,
            policy.evidence_digest().to_owned(),
            &resolved,
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
            policy.evidence_digest().to_owned(),
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
        actor_id: ActorId::from("actor-recipe-crash-resume"),
        capability: plan.capability.clone(),
        provider: plan.provider.clone(),
        connection_id: None,
        account_id: Some(scope.profile.identity.account_id.clone()),
        required_scopes: BTreeSet::from(["browser.click".into()]),
        effect_class: plan.effect_class.clone(),
        description: "Dispatch one exact synthetic multi-step Recipe".into(),
        target_resource: "synthetic-crash-resume-controls".into(),
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
        policy_version: "recipe-crash-resume-policy-v1".into(),
        risk: EffectRisk::Medium,
        idempotency_key: format!("recipe-crash-resume:{case_id}"),
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
        decided_by: ActorId::from("approver-recipe-crash-resume"),
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
    assert_digest(
        &batch.plan_digest,
        &plan.effect_payload_digest,
        "batch_plan_digest",
    );
    assert_digest(
        &plan.effect_payload_digest,
        &effect.payload_digest,
        "effect_payload_digest",
    );
}

fn resume_context<'a>(
    root_digest: &'a str,
    execution: &'a PreparedExecution,
    authority: &'a RecipeAuthority,
    profile: &'a BrowserProfile,
    workspace: &'a BrowserWorkspace,
) -> BrowserRecipeResumeContext<'a> {
    BrowserRecipeResumeContext {
        root_authority_snapshot_digest: root_digest,
        prepared_plan: &execution.plan,
        registry: &authority.registry,
        trust: &authority.trust,
        batch: &execution.batch,
        profile,
        workspace,
    }
}

fn synthetic_resolutions(
    scope: &BrowserScope,
    policy: &BrowserNavigationPolicy,
    origin_digest: &str,
    now: DateTime<Utc>,
    generation: u64,
) -> [BrowserLocatorResolution; 2] {
    [
        synthetic_resolution(
            scope,
            policy,
            &scope.first_tab_id,
            origin_digest,
            now,
            generation,
            1,
        ),
        synthetic_resolution(
            scope,
            policy,
            &scope.second_tab_id,
            origin_digest,
            now,
            generation,
            2,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn synthetic_resolution(
    scope: &BrowserScope,
    policy: &BrowserNavigationPolicy,
    tab_id: &BrowserTabId,
    origin_digest: &str,
    now: DateTime<Utc>,
    generation: u64,
    step: u64,
) -> BrowserLocatorResolution {
    must(
        BrowserLocatorResolution::new(
            scope.workspace.id.clone(),
            tab_id.clone(),
            BrowserSnapshotId::from_stable(format!("snapshot-{generation}-{step}")),
            scope.workspace.lease_generation,
            generation,
            sha(
                char::from_digit(u32::try_from(step + 1).expect("bounded step"), 10)
                    .expect("digit"),
            ),
            sha(
                char::from_digit(u32::try_from(step + 3).expect("bounded step"), 10)
                    .expect("digit"),
            ),
            sha(
                char::from_digit(u32::try_from(step + 5).expect("bounded step"), 10)
                    .expect("digit"),
            ),
            origin_digest.to_owned(),
            policy.evidence_digest().to_owned(),
            BrowserElementRef {
                reference: format!("ax-{generation}-{step}"),
                locator_digest: sha(char::from_digit(
                    u32::try_from(step + 7).expect("bounded step"),
                    10,
                )
                .expect("digit")),
                visible: true,
                unique: true,
            },
            now,
        ),
        "synthetic_resolution",
    )
}

fn synthetic_evidence(
    execution: &PreparedExecution,
    resolution: &BrowserLocatorResolution,
    action_index: usize,
    now: DateTime<Utc>,
) -> ChromiumClickDispatchEvidence {
    ChromiumClickDispatchEvidence {
        schema_version: 1,
        batch_id: execution.batch.id.clone(),
        effect_id: execution.effect.id.clone(),
        workspace_id: resolution.workspace_id.clone(),
        tab_id: resolution.tab_id.clone(),
        snapshot_id: resolution.snapshot_id.clone(),
        lease_generation: resolution.lease_generation,
        document_generation: resolution.document_generation,
        action_digest: must(
            digest_json(&execution.batch.actions[action_index]),
            "action_digest",
        ),
        locator_resolution_digest: must(resolution.evidence_digest(), "resolution_digest"),
        geometry_digest: sha('b'),
        hit_test_digest: sha('c'),
        url_digest: resolution.url_digest.clone(),
        origin_digest: resolution.origin_digest.clone(),
        policy_digest: resolution.policy_digest.clone(),
        input_event_count: 2,
        business_verified: false,
        dispatched_at: now,
    }
}

fn assert_browser_error<T>(result: Result<T, crate::BrowserError>, expected_code: &'static str) {
    match result {
        Err(error) if error.code() == expected_code => {}
        Err(error) => panic!("unexpected browser error code: {}", error.code()),
        Ok(_) => panic!("expected browser error: {expected_code}"),
    }
}

fn assert_digest(left: &str, right: &str, label: &'static str) {
    assert_eq!(left, right, "RECIPE_SMOKE_03_FAIL: step={label}");
}

fn sha(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn must<T, E>(result: Result<T, E>, label: &'static str) -> T {
    result.unwrap_or_else(|_| fail(label))
}

#[cfg(target_os = "macos")]
fn must_browser<T>(result: Result<T, crate::BrowserError>, label: &'static str) -> T {
    result.unwrap_or_else(|error| {
        panic!(
            "RECIPE_SMOKE_03_FAIL: step={label} browser_error={}",
            error.code()
        )
    })
}

#[track_caller]
fn fail(label: &'static str) -> ! {
    panic!("RECIPE_SMOKE_03_FAIL: step={label}")
}

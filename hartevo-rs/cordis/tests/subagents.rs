use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::FutureExt;
use hartevo_cordis::{
    AgentRef, Context, CordisHost, SessionCallConfig, SessionContentBlock, SessionId,
    SubagentCapabilities, SubagentCapability, SubagentError, SubagentProvider, SubagentResult,
    SubagentRun, SubagentRuntime, SubagentStartRequest, SubagentStopReason, SubagentToolFilter,
    register_subagent_provider,
};
use tokio::sync::Notify;

fn mapped() -> Context {
    let mut host = CordisHost::boot(false).unwrap();
    std::mem::take(host.context_mut())
}

fn request(parent: AgentRef) -> SubagentStartRequest {
    SubagentStartRequest::new(
        parent,
        vec![SessionContentBlock::Text {
            text: "delegate this".into(),
        }],
    )
}

struct StubRun {
    id: SessionId,
    result: SubagentResult,
    disposed: Arc<AtomicBool>,
}

impl StubRun {
    fn new(id: &str) -> Self {
        Self {
            id: SessionId::new(id).unwrap(),
            result: SubagentResult::new(
                vec![SessionContentBlock::Text {
                    text: "done".into(),
                }],
                SubagentStopReason::Completed,
            ),
            disposed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl SubagentRun for StubRun {
    fn id(&self) -> &SessionId {
        &self.id
    }

    fn local_agent(&self) -> Option<AgentRef> {
        None
    }

    fn result(
        &self,
    ) -> futures_util::future::BoxFuture<'static, Result<SubagentResult, SubagentError>> {
        let result = self.result.clone();
        async move { Ok(result) }.boxed()
    }

    fn dispose(&self) -> futures_util::future::BoxFuture<'static, Result<(), SubagentError>> {
        let disposed = Arc::clone(&self.disposed);
        async move {
            disposed.store(true, Ordering::SeqCst);
            Ok(())
        }
        .boxed()
    }
}

struct StubProvider {
    name: String,
    capabilities: SubagentCapabilities,
    starts: Arc<AtomicUsize>,
    last_request: Arc<Mutex<Option<SubagentStartRequest>>>,
    run: Arc<StubRun>,
    started: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
}

impl StubProvider {
    fn new(name: &str, capabilities: SubagentCapabilities) -> Self {
        Self {
            name: name.into(),
            capabilities,
            starts: Arc::new(AtomicUsize::new(0)),
            last_request: Arc::new(Mutex::new(None)),
            run: Arc::new(StubRun::new(&format!("child-{name}"))),
            started: None,
            release: None,
        }
    }

    fn gated(name: &str, started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self {
            started: Some(started),
            release: Some(release),
            ..Self::new(name, SubagentCapabilities::ALL)
        }
    }
}

impl SubagentProvider for StubProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> SubagentCapabilities {
        self.capabilities
    }

    fn inherits_parent_context(&self) -> bool {
        false
    }

    fn start(
        &self,
        request: SubagentStartRequest,
    ) -> futures_util::future::BoxFuture<'static, Result<Arc<dyn SubagentRun>, SubagentError>> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        *self.last_request.lock().unwrap() = Some(request);
        let run = Arc::clone(&self.run);
        let started = self.started.clone();
        let release = self.release.clone();
        async move {
            if let Some(started) = started {
                started.notify_one();
            }
            if let Some(release) = release {
                release.notified().await;
            }
            let run: Arc<dyn SubagentRun> = run;
            Ok(run)
        }
        .boxed()
    }
}

#[test]
fn providers_register_in_order_and_exact_generation_disposal_is_idempotent() {
    let mut ctx = mapped();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let alpha: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("alpha", SubagentCapabilities::NONE));
    let beta: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("beta", SubagentCapabilities::ALL));
    let alpha_registration = register_subagent_provider(&mut ctx, Arc::clone(&alpha)).unwrap();
    let beta_registration = register_subagent_provider(&mut ctx, Arc::clone(&beta)).unwrap();

    assert_eq!(runtime.list().unwrap(), ["alpha", "beta"]);
    assert!(Arc::ptr_eq(
        &runtime.get_provider("alpha").unwrap().unwrap(),
        &alpha
    ));
    assert_eq!(
        register_subagent_provider(
            &mut ctx,
            Arc::new(StubProvider::new("alpha", SubagentCapabilities::NONE,))
        )
        .unwrap_err(),
        SubagentError::DuplicateProvider {
            name: "alpha".into()
        }
    );

    assert!(alpha_registration.dispose());
    assert!(!alpha_registration.dispose());
    assert_eq!(runtime.list().unwrap(), ["beta"]);
    let replacement: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("alpha", SubagentCapabilities::NONE));
    let replacement_registration =
        register_subagent_provider(&mut ctx, Arc::clone(&replacement)).unwrap();
    assert_eq!(runtime.list().unwrap(), ["beta", "alpha"]);
    assert!(Arc::ptr_eq(
        &runtime.get_provider("alpha").unwrap().unwrap(),
        &replacement
    ));

    assert!(beta_registration.dispose());
    assert!(replacement_registration.dispose());
    assert!(runtime.list().unwrap().is_empty());
}

#[test]
fn invalid_and_unavailable_registrations_fail_with_stable_codes() {
    let mut ctx = mapped();
    let blank: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("  ", SubagentCapabilities::NONE));
    let error = register_subagent_provider(&mut ctx, blank).unwrap_err();
    assert_eq!(error, SubagentError::InvalidProviderName);
    assert_eq!(error.code(), "INVALID_PROVIDER");

    let mut unmapped = Context::new();
    let provider: Arc<dyn SubagentProvider> = Arc::new(StubProvider::new(
        "missing-runtime",
        SubagentCapabilities::NONE,
    ));
    assert_eq!(
        register_subagent_provider(&mut unmapped, provider).unwrap_err(),
        SubagentError::RuntimeUnavailable
    );
}

#[test]
fn context_teardown_reverses_fiber_owned_provider_registration() {
    let mut ctx = mapped();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let provider: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("scoped", SubagentCapabilities::NONE));
    let registration = register_subagent_provider(&mut ctx, provider).unwrap();
    assert_eq!(runtime.list().unwrap(), ["scoped"]);

    ctx.teardown();

    assert!(registration.is_disposed());
    assert!(runtime.list().unwrap().is_empty());
    assert!(ctx.subagents::<SubagentRuntime>().is_none());
}

#[tokio::test]
async fn capability_checks_fail_before_provider_start_and_plain_request_dispatches() {
    let mut ctx = mapped();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let provider = Arc::new(StubProvider::new("weak", SubagentCapabilities::NONE));
    let erased: Arc<dyn SubagentProvider> = provider.clone();
    register_subagent_provider(&mut ctx, erased).unwrap();
    let parent = AgentRef::new("parent");

    let mut requests = Vec::new();
    let mut candidate = request(parent.clone());
    candidate.agent_options = Some(SessionCallConfig {
        provider: "child-provider".into(),
        model: "child-model".into(),
        reasoning_effort: None,
        temperature: None,
        max_tokens: None,
        stop: None,
    });
    requests.push((SubagentCapability::AgentOptions, candidate));
    let mut candidate = request(parent.clone());
    candidate.output_schema = Some(serde_json::Map::new());
    requests.push((SubagentCapability::OutputSchema, candidate));
    let mut candidate = request(parent.clone());
    candidate.max_depth = Some(2);
    requests.push((SubagentCapability::DepthLimit, candidate));
    let mut candidate = request(parent.clone());
    candidate.tool_filter = Some(SubagentToolFilter {
        allow: vec!["read".into()],
        deny: vec!["bash".into()],
    });
    requests.push((SubagentCapability::ToolFilter, candidate));
    let mut candidate = request(parent.clone());
    candidate.persona = Some("reviewer".into());
    requests.push((SubagentCapability::Persona, candidate));

    for (capability, candidate) in requests {
        let error = runtime
            .start("weak", candidate)
            .await
            .err()
            .expect("unsupported capability must fail");
        assert_eq!(
            error,
            SubagentError::UnsupportedCapability {
                provider: "weak".into(),
                capability,
            }
        );
    }
    assert_eq!(provider.starts.load(Ordering::SeqCst), 0);

    let run = runtime
        .start("weak", request(parent.clone()))
        .await
        .unwrap();
    assert_eq!(provider.starts.load(Ordering::SeqCst), 1);
    {
        let forwarded = provider.last_request.lock().unwrap();
        let forwarded = forwarded.as_ref().unwrap();
        assert!(forwarded.parent.is_same_lifecycle(&parent));
        assert_eq!(forwarded.prompt.len(), 1);
    }
    assert_eq!(run.id().as_str(), "child-weak");
    assert_eq!(
        run.result().await.unwrap().stop_reason,
        SubagentStopReason::Completed
    );
    let error = runtime
        .start("absent", request(parent))
        .await
        .err()
        .expect("absent provider must fail");
    assert_eq!(error.code(), "NO_PROVIDER");
}

#[tokio::test]
async fn unregister_during_start_blocks_new_calls_but_preserves_selected_provider_and_run() {
    let mut ctx = mapped();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let provider = Arc::new(StubProvider::gated(
        "deferred",
        Arc::clone(&started),
        Arc::clone(&release),
    ));
    let erased: Arc<dyn SubagentProvider> = provider.clone();
    let registration = register_subagent_provider(&mut ctx, erased).unwrap();

    let starting_runtime = Arc::clone(&runtime);
    let starting = tokio::spawn(async move {
        starting_runtime
            .start("deferred", request(AgentRef::new("parent")))
            .await
    });
    started.notified().await;
    assert!(registration.dispose());
    assert!(runtime.list().unwrap().is_empty());
    assert!(matches!(
        runtime
            .start("deferred", request(AgentRef::new("later-parent")))
            .await,
        Err(SubagentError::NoProvider { .. })
    ));

    release.notify_one();
    let run = starting.await.unwrap().unwrap();
    assert_eq!(run.id().as_str(), "child-deferred");
    assert_eq!(
        run.result().await.unwrap().stop_reason,
        SubagentStopReason::Completed
    );
    run.dispose().await.unwrap();
    assert!(provider.run.disposed.load(Ordering::SeqCst));
}

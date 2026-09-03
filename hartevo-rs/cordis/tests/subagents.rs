use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::FutureExt;
use hartevo_cordis::{
    AgentRef, Context, CordisHost, OneShotSubagentDescriptor, ResolvedSubagentStartRequest,
    SUBAGENT_DESCRIPTOR_VERSION, SessionCallConfig, SessionContentBlock, SessionId,
    SubagentCapabilities, SubagentCapability, SubagentDescriptorMode, SubagentError,
    SubagentProvider, SubagentResult, SubagentRun, SubagentRunEndInfo, SubagentRunInfo,
    SubagentRuntime, SubagentStartRequest, SubagentStopReason, SubagentToolFilter,
    register_subagent_provider, subagent_events,
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
    result: Result<SubagentResult, SubagentError>,
    disposed: Arc<AtomicBool>,
}

impl StubRun {
    fn new(id: &str) -> Self {
        Self {
            id: SessionId::new(id).unwrap(),
            result: Ok(SubagentResult::new(
                vec![SessionContentBlock::Text {
                    text: "done".into(),
                }],
                SubagentStopReason::Completed,
            )),
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
        async move { result }.boxed()
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
    last_request: Arc<Mutex<Option<ResolvedSubagentStartRequest>>>,
    run: Arc<StubRun>,
    started: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
    start_error: Option<SubagentError>,
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
            start_error: None,
        }
    }

    fn gated(name: &str, started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self {
            started: Some(started),
            release: Some(release),
            ..Self::new(name, SubagentCapabilities::ALL)
        }
    }

    fn failing(name: &str) -> Self {
        Self {
            start_error: Some(SubagentError::ProviderStart {
                provider: name.into(),
                detail: "setup rolled back".into(),
            }),
            ..Self::new(name, SubagentCapabilities::NONE)
        }
    }

    fn with_result(name: &str, result: Result<SubagentResult, SubagentError>) -> Self {
        Self {
            run: Arc::new(StubRun {
                id: SessionId::new(format!("child-{name}")).unwrap(),
                result,
                disposed: Arc::new(AtomicBool::new(false)),
            }),
            ..Self::new(name, SubagentCapabilities::NONE)
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
        request: ResolvedSubagentStartRequest,
    ) -> futures_util::future::BoxFuture<'static, Result<Arc<dyn SubagentRun>, SubagentError>> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        *self.last_request.lock().unwrap() = Some(request);
        let run = Arc::clone(&self.run);
        let started = self.started.clone();
        let release = self.release.clone();
        let start_error = self.start_error.clone();
        async move {
            if let Some(started) = started {
                started.notify_one();
            }
            if let Some(release) = release {
                release.notified().await;
            }
            if let Some(error) = start_error {
                return Err(error);
            }
            let run: Arc<dyn SubagentRun> = run;
            Ok(run)
        }
        .boxed()
    }
}

#[test]
fn one_shot_descriptor_is_exact_versioned_and_omits_absent_label() {
    let minimal = OneShotSubagentDescriptor::new("spawn", None);
    assert_eq!(minimal.version, SUBAGENT_DESCRIPTOR_VERSION);
    assert_eq!(minimal.mode, SubagentDescriptorMode::OneShot);
    assert_eq!(
        serde_json::to_value(&minimal).unwrap(),
        serde_json::json!({
            "version": SUBAGENT_DESCRIPTOR_VERSION,
            "mode": "one-shot",
            "provider": "spawn"
        })
    );
    assert_eq!(
        serde_json::to_value(OneShotSubagentDescriptor::new(
            "spawn",
            Some("child work".into())
        ))
        .unwrap(),
        serde_json::json!({
            "version": SUBAGENT_DESCRIPTOR_VERSION,
            "mode": "one-shot",
            "provider": "spawn",
            "label": "child work"
        })
    );
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
        assert_eq!(
            forwarded.descriptor,
            OneShotSubagentDescriptor::new("weak", None)
        );
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

#[tokio::test]
async fn established_run_emits_one_ordered_exact_parent_lifecycle_pair() {
    let mut ctx = mapped();
    let order = Arc::new(Mutex::new(Vec::new()));
    let starts = Arc::new(Mutex::new(Vec::<SubagentRunInfo>::new()));
    let ends = Arc::new(Mutex::new(Vec::<SubagentRunEndInfo>::new()));
    let _panicking_start = ctx
        .on_emit(subagent_events::SUBAGENT_START, |_| {
            panic!("observer must be contained")
        })
        .unwrap();
    let _panicking_end = ctx
        .on_emit(subagent_events::SUBAGENT_END, |_| {
            panic!("observer must be contained")
        })
        .unwrap();
    let _start_listener = ctx
        .on_emit(subagent_events::SUBAGENT_START, {
            let order = Arc::clone(&order);
            let starts = Arc::clone(&starts);
            move |info| {
                order.lock().unwrap().push("start");
                starts.lock().unwrap().push(info.clone());
            }
        })
        .unwrap();
    let _end_listener = ctx
        .on_emit(subagent_events::SUBAGENT_END, {
            let order = Arc::clone(&order);
            let ends = Arc::clone(&ends);
            move |info| {
                order.lock().unwrap().push("end");
                ends.lock().unwrap().push(info.clone());
            }
        })
        .unwrap();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let provider: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("observed", SubagentCapabilities::NONE));
    register_subagent_provider(&mut ctx, provider).unwrap();
    let parent = AgentRef::new("parent");

    let run = runtime
        .start("observed", request(parent.clone()))
        .await
        .unwrap();
    assert_eq!(starts.lock().unwrap().len(), 1);
    assert_eq!(
        run.result().await.unwrap().stop_reason,
        SubagentStopReason::Completed
    );
    assert_eq!(
        run.result().await.unwrap().stop_reason,
        SubagentStopReason::Completed
    );

    let starts = starts.lock().unwrap();
    let ends = ends.lock().unwrap();
    assert_eq!(*order.lock().unwrap(), ["start", "end"]);
    assert_eq!(starts.len(), 1);
    assert_eq!(ends.len(), 1);
    assert_eq!(starts[0].run_id, ends[0].run_id);
    assert_eq!(starts[0].provider, "observed");
    assert_eq!(starts[0].id.as_str(), "child-observed");
    assert!(!starts[0].local);
    assert!(starts[0].parent.is_same_lifecycle(&parent));
    assert!(ends[0].parent.is_same_lifecycle(&parent));
    assert_eq!(ends[0].stop_reason, SubagentStopReason::Completed);
    assert_eq!(
        ends[0].last_assistant_message,
        Some(vec![SessionContentBlock::Text {
            text: "done".into()
        }])
    );
}

#[tokio::test]
async fn failed_start_has_no_lifecycle_and_result_rejection_emits_error_once() {
    let mut ctx = mapped();
    let starts = Arc::new(AtomicUsize::new(0));
    let ends = Arc::new(Mutex::new(Vec::<SubagentRunEndInfo>::new()));
    let _start_listener = ctx
        .on_emit(subagent_events::SUBAGENT_START, {
            let starts = Arc::clone(&starts);
            move |_| {
                starts.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    let _end_listener = ctx
        .on_emit(subagent_events::SUBAGENT_END, {
            let ends = Arc::clone(&ends);
            move |info| ends.lock().unwrap().push(info.clone())
        })
        .unwrap();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let failed: Arc<dyn SubagentProvider> = Arc::new(StubProvider::failing("failed"));
    register_subagent_provider(&mut ctx, failed).unwrap();

    assert!(
        runtime
            .start("failed", request(AgentRef::new("failed-parent")))
            .await
            .is_err()
    );
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert!(ends.lock().unwrap().is_empty());

    let rejected: Arc<dyn SubagentProvider> = Arc::new(StubProvider::with_result(
        "rejected",
        Err(SubagentError::ProviderStart {
            provider: "rejected".into(),
            detail: "transport".into(),
        }),
    ));
    register_subagent_provider(&mut ctx, rejected).unwrap();
    let run = runtime
        .start("rejected", request(AgentRef::new("rejected-parent")))
        .await
        .unwrap();
    assert!(run.result().await.is_err());
    assert!(run.result().await.is_err());

    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let ends = ends.lock().unwrap();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].provider, "rejected");
    assert_eq!(ends[0].stop_reason, SubagentStopReason::Error);
    assert!(ends[0].last_assistant_message.is_none());
}

#[tokio::test]
async fn repeated_provider_and_child_ids_get_distinct_run_ids() {
    let mut ctx = mapped();
    let run_ids = Arc::new(Mutex::new(Vec::new()));
    let _listener = ctx
        .on_emit(subagent_events::SUBAGENT_START, {
            let run_ids = Arc::clone(&run_ids);
            move |info| run_ids.lock().unwrap().push(info.run_id.clone())
        })
        .unwrap();
    let runtime = ctx.subagents::<SubagentRuntime>().unwrap();
    let provider: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("reused", SubagentCapabilities::NONE));
    register_subagent_provider(&mut ctx, provider).unwrap();

    let first = runtime
        .start("reused", request(AgentRef::new("parent")))
        .await
        .unwrap();
    let second = runtime
        .start("reused", request(AgentRef::new("parent")))
        .await
        .unwrap();
    first.result().await.unwrap();
    second.result().await.unwrap();

    let run_ids = run_ids.lock().unwrap();
    assert_eq!(run_ids.len(), 2);
    assert_ne!(run_ids[0], run_ids[1]);
}

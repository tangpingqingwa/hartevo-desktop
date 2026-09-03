use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use futures_util::FutureExt;
use hartevo_cordis::{
    AgentRef, AgentStatus, AgentStatusChange, AgentsSurface, AuthorityScope, Context, CordisError,
    CordisHost, KernelConsentState, OneShotSubagentDescriptor, ResolvedSubagentStartRequest,
    RuntimeBinding, SPAWN_SUBAGENT_PROVIDER_NAME, SUBAGENT_DESCRIPTOR_VERSION, SUBAGENT_TOOL_NAME,
    SessionCallConfig, SessionContentBlock, SessionEventKind, SessionFinishReason, SessionId,
    SessionMessage, SessionMessageRole, SessionMessageSource, SessionStore, SessionStreamBlockType,
    SessionStreamChunk, SessionToolSchema, SubagentCapabilities, SubagentCapability,
    SubagentDescriptorMode, SubagentError, SubagentProvider, SubagentResult, SubagentRun,
    SubagentRunEndInfo, SubagentRunInfo, SubagentRuntime, SubagentStartRequest, SubagentStopReason,
    SubagentToolFilter, TurnEndReason, events as agent_events, register_subagent_provider,
    subagent_events,
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

fn runtime_scope(mission: &str) -> AuthorityScope {
    AuthorityScope::new("tenant-a", "project-a", mission, 1)
        .unwrap()
        .with_runtime(RuntimeBinding::new(1, None, None, "a".repeat(64)).unwrap())
}

fn call_config(provider: &str, model: &str) -> SessionCallConfig {
    SessionCallConfig {
        provider: provider.into(),
        model: model.into(),
        reasoning_effort: None,
        temperature: None,
        max_tokens: None,
        stop: None,
    }
}

type ObservedCall = (
    Option<SessionId>,
    Vec<SessionMessage>,
    Vec<SessionToolSchema>,
    SessionCallConfig,
);

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

    assert_eq!(runtime.list().unwrap(), ["spawn", "alpha", "beta"]);
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
    assert_eq!(runtime.list().unwrap(), ["spawn", "beta"]);
    let replacement: Arc<dyn SubagentProvider> =
        Arc::new(StubProvider::new("alpha", SubagentCapabilities::NONE));
    let replacement_registration =
        register_subagent_provider(&mut ctx, Arc::clone(&replacement)).unwrap();
    assert_eq!(runtime.list().unwrap(), ["spawn", "beta", "alpha"]);
    assert!(Arc::ptr_eq(
        &runtime.get_provider("alpha").unwrap().unwrap(),
        &replacement
    ));

    assert!(beta_registration.dispose());
    assert!(replacement_registration.dispose());
    assert_eq!(runtime.list().unwrap(), ["spawn"]);
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
    assert_eq!(runtime.list().unwrap(), ["spawn", "scoped"]);

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
    assert_eq!(runtime.list().unwrap(), ["spawn"]);
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one journey proves establishment, durable ordering, result mapping, and exact disposal together"
)]
async fn default_spawn_provider_runs_one_fresh_child_through_the_authorized_host() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("parent-session");
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap(),
    )
    .unwrap();
    let parent_session_id = SessionId::new("parent-session").unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let parent_session = sessions.create(parent_session_id.clone()).unwrap();
    parent_session
        .append_user_message(hartevo_cordis::SessionMessage {
            id: "parent-only".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "do not inherit me".into(),
            }],
            source: SessionMessageSource::User,
        })
        .unwrap();

    let lifecycle = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let starts = Arc::new(Mutex::new(Vec::<SubagentRunInfo>::new()));
    let ends = Arc::new(Mutex::new(Vec::<SubagentRunEndInfo>::new()));
    let statuses = Arc::new(Mutex::new(Vec::<AgentStatusChange>::new()));
    let disposed = Arc::new(Mutex::new(Vec::<AgentRef>::new()));
    host.context_mut()
        .on_emit(subagent_events::SUBAGENT_START, {
            let lifecycle = Arc::clone(&lifecycle);
            let starts = Arc::clone(&starts);
            move |info| {
                lifecycle.lock().unwrap().push("start");
                starts.lock().unwrap().push(info.clone());
            }
        })
        .unwrap();
    host.context_mut()
        .on_emit(agent_events::AGENT_STATUS, {
            let statuses = Arc::clone(&statuses);
            move |status| statuses.lock().unwrap().push(status.clone())
        })
        .unwrap();
    host.context_mut()
        .on_emit(agent_events::AGENT_DISPOSED, {
            let disposed = Arc::clone(&disposed);
            move |agent| disposed.lock().unwrap().push(agent.clone())
        })
        .unwrap();
    host.context_mut()
        .on_emit(subagent_events::SUBAGENT_END, {
            let lifecycle = Arc::clone(&lifecycle);
            let ends = Arc::clone(&ends);
            move |info| {
                lifecycle.lock().unwrap().push("end");
                ends.lock().unwrap().push(info.clone());
            }
        })
        .unwrap();
    host.context_mut()
        .on_waterfall(agent_events::LLM_STREAM, |stream, _next| {
            stream.with_chunk_stream(Box::pin(futures_util::stream::iter([
                SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                },
                SessionStreamChunk::TextDelta {
                    index: 0,
                    text: "child done".into(),
                },
                SessionStreamChunk::BlockEnd {
                    index: 0,
                    block: SessionContentBlock::Text {
                        text: "child done".into(),
                    },
                },
                SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                },
            ])))
        })
        .unwrap();

    let runtime = host.context().subagents::<SubagentRuntime>().unwrap();
    assert_eq!(runtime.list().unwrap(), [SPAWN_SUBAGENT_PROVIDER_NAME]);
    let provider = runtime
        .get_provider(SPAWN_SUBAGENT_PROVIDER_NAME)
        .unwrap()
        .unwrap();
    assert!(!provider.inherits_parent_context());
    assert!(
        provider
            .capabilities()
            .supports(SubagentCapability::AgentOptions)
    );
    assert!(
        !provider
            .capabilities()
            .supports(SubagentCapability::Persona)
    );

    let mut permit = host.authorize_runtime(&scope).unwrap();
    permit.announce_started().unwrap();
    let parent = permit.agent().clone();
    let request = SubagentStartRequest::new(
        parent.clone(),
        vec![SessionContentBlock::Text {
            text: "delegate this".into(),
        }],
    )
    .with_parent_session(parent_session_id.clone());
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    let run = host
        .run_authorized_local_subagent(
            &permit,
            SPAWN_SUBAGENT_PROVIDER_NAME,
            request,
            call_config("mock", "model"),
        )
        .await
        .unwrap();

    let child_agent = run.local_agent().unwrap();
    assert_eq!(child_agent.status(), AgentStatus::Idle);
    assert!(
        agents
            .list()
            .iter()
            .any(|agent| agent.is_same_lifecycle(&child_agent))
    );
    assert_eq!(*lifecycle.lock().unwrap(), ["start"]);
    let result = run.result().await.unwrap();
    assert_eq!(result.stop_reason, SubagentStopReason::Completed);
    assert_eq!(
        result.output,
        [SessionContentBlock::Text {
            text: "child done".into()
        }]
    );
    assert_eq!(*lifecycle.lock().unwrap(), ["start", "end"]);
    assert_eq!(
        statuses
            .lock()
            .unwrap()
            .iter()
            .filter(|status| status.agent().is_same_lifecycle(&child_agent))
            .map(AgentStatusChange::status)
            .collect::<Vec<_>>(),
        [AgentStatus::Running, AgentStatus::Idle]
    );

    let child = sessions.get(run.id()).unwrap().unwrap();
    let header = child.header().unwrap();
    assert_eq!(header.parent_session, Some(parent_session_id));
    assert_eq!(header.seed_length, Some(0));
    assert_eq!(
        child.request_header().unwrap().unwrap().config,
        call_config("mock", "model")
    );
    let events = child.events().unwrap();
    let descriptor_positions = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(
                &event.kind,
                SessionEventKind::SubagentDescriptor { descriptor }
                    if descriptor == &OneShotSubagentDescriptor::new("spawn", None)
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(descriptor_positions.len(), 1);
    let turn_start = events
        .iter()
        .position(|event| matches!(event.kind, SessionEventKind::TurnStart { .. }))
        .unwrap();
    let request_header = events
        .iter()
        .position(|event| matches!(event.kind, SessionEventKind::RequestHeader { .. }))
        .unwrap();
    assert!(turn_start < descriptor_positions[0]);
    assert!(descriptor_positions[0] < request_header);
    let messages = child.derive_messages().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[0].content,
        [SessionContentBlock::Text {
            text: "delegate this".into()
        }]
    );
    assert!(messages.iter().all(|message| message.id != "parent-only"));

    {
        let starts = starts.lock().unwrap();
        let ends = ends.lock().unwrap();
        assert_eq!(starts.len(), 1);
        assert_eq!(ends.len(), 1);
        assert_eq!(starts[0].run_id, ends[0].run_id);
        assert!(starts[0].local);
        assert!(starts[0].parent.is_same_lifecycle(&parent));
        assert_eq!(ends[0].last_assistant_message, Some(result.output));
    }

    run.dispose().await.unwrap();
    assert!(
        !agents
            .list()
            .iter()
            .any(|agent| agent.is_same_lifecycle(&child_agent))
    );
    assert!(
        disposed
            .lock()
            .unwrap()
            .iter()
            .any(|agent| agent.is_same_lifecycle(&child_agent))
    );
    host.finish_runtime(permit).unwrap().announce().unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end journey proves model binding, fresh child context, result return, and disposal"
)]
async fn authorized_runtime_subagent_tool_returns_a_fresh_child_result_to_its_parent() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("parent-session");
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap(),
    )
    .unwrap();
    let parent_session_id = SessionId::new("parent-session").unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let parent_session = sessions.create(parent_session_id.clone()).unwrap();
    parent_session
        .inbox()
        .append_next_turn(SessionMessage {
            id: "parent-prompt".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "delegate the focused check".into(),
            }],
            source: SessionMessageSource::User,
        })
        .unwrap();

    let observed = Arc::new(Mutex::new(Vec::<ObservedCall>::new()));
    let calls = Arc::new(AtomicUsize::new(0));

    host.context_mut()
        .on_waterfall(agent_events::LLM_STREAM, {
            let observed = Arc::clone(&observed);
            let calls = Arc::clone(&calls);
            move |stream, _next| {
                let request = stream.request().expect("generated Agent request");
                observed.lock().unwrap().push((
                    request.session_id().cloned(),
                    request.messages().to_vec(),
                    request.tools().unwrap_or_default().to_vec(),
                    request.config().clone(),
                ));
                let chunks = match calls.fetch_add(1, Ordering::SeqCst) {
                    0 => vec![
                        SessionStreamChunk::BlockStart {
                            index: 0,
                            block_type: SessionStreamBlockType::ToolCall,
                        },
                        SessionStreamChunk::BlockEnd {
                            index: 0,
                            block: SessionContentBlock::ToolCall {
                                id: "delegate-1".into(),
                                name: SUBAGENT_TOOL_NAME.into(),
                                arguments: serde_json::json!({
                                    "prompt": "perform the independent focused check"
                                })
                                .to_string(),
                            },
                        },
                        SessionStreamChunk::BlockStart {
                            index: 1,
                            block_type: SessionStreamBlockType::ToolCall,
                        },
                        SessionStreamChunk::BlockEnd {
                            index: 1,
                            block: SessionContentBlock::ToolCall {
                                id: "delegate-blank".into(),
                                name: SUBAGENT_TOOL_NAME.into(),
                                arguments: serde_json::json!({ "prompt": "   " }).to_string(),
                            },
                        },
                        SessionStreamChunk::Finish {
                            reason: SessionFinishReason::ToolCalls,
                            replay_state: None,
                        },
                    ],
                    1 => vec![
                        SessionStreamChunk::BlockStart {
                            index: 0,
                            block_type: SessionStreamBlockType::Text,
                        },
                        SessionStreamChunk::BlockEnd {
                            index: 0,
                            block: SessionContentBlock::Text {
                                text: "child answer".into(),
                            },
                        },
                        SessionStreamChunk::Finish {
                            reason: SessionFinishReason::Stop,
                            replay_state: None,
                        },
                    ],
                    2 => vec![
                        SessionStreamChunk::BlockStart {
                            index: 0,
                            block_type: SessionStreamBlockType::Text,
                        },
                        SessionStreamChunk::BlockEnd {
                            index: 0,
                            block: SessionContentBlock::Text {
                                text: "parent completed".into(),
                            },
                        },
                        SessionStreamChunk::Finish {
                            reason: SessionFinishReason::Stop,
                            replay_state: None,
                        },
                    ],
                    index => panic!("unexpected model call {index}"),
                };
                stream.with_chunk_stream(Box::pin(futures_util::stream::iter(chunks)))
            }
        })
        .unwrap();

    let mut permit = host.authorize_runtime(&scope).unwrap();
    permit.announce_started().unwrap();
    let outcome = host
        .run_authorized_runtime_agent_turn(
            &permit,
            &parent_session_id,
            call_config("mock", "model"),
            &hartevo_cordis::LifecycleCancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(outcome.reason(), TurnEndReason::Completed);
    assert_eq!(outcome.steps(), 2);

    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 3);
    let schema = observed[0]
        .2
        .iter()
        .find(|schema| schema.name == SUBAGENT_TOOL_NAME)
        .expect("subagent schema must be model-visible");
    assert_eq!(schema.parameters["required"], serde_json::json!(["prompt"]));
    assert_eq!(
        observed[1].1.len(),
        1,
        "child must receive no parent history"
    );
    assert_eq!(
        observed[1].1[0].content,
        [SessionContentBlock::Text {
            text: "perform the independent focused check".into()
        }]
    );
    assert_eq!(observed[1].3, call_config("mock", "model"));
    assert!(observed[2].1.iter().any(|message| {
        matches!(
            message.content.as_slice(),
            [SessionContentBlock::ToolResult {
                tool_call_id,
                content,
                is_error: false,
            }] if tool_call_id == "delegate-1"
                && content == &[SessionContentBlock::Text { text: "child answer".into() }]
        )
    }));
    assert!(observed[2].1.iter().any(|message| {
        matches!(
            message.content.as_slice(),
            [SessionContentBlock::ToolResult {
                tool_call_id,
                content,
                is_error: true,
            }] if tool_call_id == "delegate-blank"
                && content == &[SessionContentBlock::Text {
                    text: "Error: subagent prompt must not be blank".into()
                }]
        )
    }));
    let child_session_id = observed[1].0.clone().expect("child session id");
    drop(observed);

    let child = sessions.get(&child_session_id).unwrap().unwrap();
    assert_eq!(
        child.header().unwrap().parent_session,
        Some(parent_session_id.clone())
    );
    assert_eq!(sessions.len().unwrap(), 2);
    assert!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .iter()
            .all(|agent| agent.id != child_session_id.as_str()),
        "foreground child Agent must be disposed after collection"
    );
    host.finish_runtime(permit).unwrap().announce().unwrap();
}

#[tokio::test]
async fn local_spawn_fails_closed_before_publication_without_exact_admission() {
    let mut host = CordisHost::boot(false).unwrap();
    let runtime = host.context().subagents::<SubagentRuntime>().unwrap();
    let detached = runtime
        .start(
            SPAWN_SUBAGENT_PROVIDER_NAME,
            request(AgentRef::new("parent")),
        )
        .await
        .err()
        .expect("detached local provider must fail closed");
    assert_eq!(detached.code(), "HOST_DRIVER_REQUIRED");

    let scope = runtime_scope("parent-session");
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap(),
    )
    .unwrap();
    host.context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("parent-session").unwrap())
        .unwrap();
    let mut permit = host.authorize_runtime(&scope).unwrap();
    permit.announce_started().unwrap();

    let wrong_parent = SubagentStartRequest::new(
        AgentRef::new(permit.agent().id.clone()),
        vec![SessionContentBlock::Text { text: "x".into() }],
    )
    .with_parent_session(SessionId::new("parent-session").unwrap());
    assert_eq!(
        host.run_authorized_local_subagent(
            &permit,
            SPAWN_SUBAGENT_PROVIDER_NAME,
            wrong_parent,
            call_config("mock", "model"),
        )
        .await
        .err()
        .expect("lookalike parent lifecycle must fail"),
        CordisError::RuntimePermitMismatch
    );

    let mut unsupported = SubagentStartRequest::new(
        permit.agent().clone(),
        vec![SessionContentBlock::Text { text: "x".into() }],
    )
    .with_parent_session(SessionId::new("parent-session").unwrap());
    unsupported.persona = Some("not implemented".into());
    let before = host
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .len()
        .unwrap();
    let error = host
        .run_authorized_local_subagent(
            &permit,
            SPAWN_SUBAGENT_PROVIDER_NAME,
            unsupported,
            call_config("mock", "model"),
        )
        .await
        .err()
        .expect("unsupported local capability must fail");
    assert_eq!(
        error,
        CordisError::Subagent(SubagentError::UnsupportedCapability {
            provider: SPAWN_SUBAGENT_PROVIDER_NAME.into(),
            capability: SubagentCapability::Persona,
        })
    );
    assert_eq!(
        host.context()
            .sessions::<SessionStore>()
            .unwrap()
            .len()
            .unwrap(),
        before
    );

    host.finish_runtime(permit).unwrap().announce().unwrap();
}

#[tokio::test]
async fn local_spawn_rolls_back_a_child_session_when_establishment_fails() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("parent-session");
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap(),
    )
    .unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    sessions
        .create(SessionId::new("parent-session").unwrap())
        .unwrap();
    let before = sessions.len().unwrap();
    let mut permit = host.authorize_runtime(&scope).unwrap();
    permit.announce_started().unwrap();
    let invalid_prompt = SubagentStartRequest::new(
        permit.agent().clone(),
        vec![SessionContentBlock::ToolCall {
            id: String::new(),
            name: "tool".into(),
            arguments: "{}".into(),
        }],
    )
    .with_parent_session(SessionId::new("parent-session").unwrap());

    let error = host
        .run_authorized_local_subagent(
            &permit,
            SPAWN_SUBAGENT_PROVIDER_NAME,
            invalid_prompt,
            call_config("mock", "model"),
        )
        .await
        .err()
        .expect("invalid prompt must fail establishment");

    assert!(matches!(
        error,
        CordisError::Subagent(SubagentError::ProviderStart { provider, .. })
            if provider == SPAWN_SUBAGENT_PROVIDER_NAME
    ));
    assert_eq!(
        sessions.len().unwrap(),
        before,
        "failed establishment must remove its exact child Session"
    );
    host.finish_runtime(permit).unwrap().announce().unwrap();
}

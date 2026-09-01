use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::StreamExt;
use hartevo_cordis::{
    CordisHost, LifecycleCancellation, LlmAdapter, LlmAdapterStream, LlmError, LlmGenerateRequest,
    LlmResolvedModel, ManualCompactionErrorCode, SessionCallConfig, SessionContentBlock,
    SessionEpochHeader, SessionEventKind, SessionFinishReason, SessionHandle, SessionId,
    SessionLlmFailure, SessionMessage, SessionMessageRole, SessionMessageSource,
    SessionRequestHeaderReason, SessionStore, SessionStreamBlockType, SessionStreamChunk,
    TurnEndReason, compact_now, is_compact_checkpoint_source, register_llm_adapter, session_events,
};
use tokio::sync::Notify;

#[derive(Clone)]
enum SummaryMode {
    Text,
    MaxTokens,
    Gated {
        started: Arc<Notify>,
        release: Arc<Notify>,
    },
}

#[derive(Clone)]
struct ManualAdapter {
    mode: SummaryMode,
    calls: Arc<AtomicUsize>,
}

impl LlmAdapter for ManualAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        Ok(LlmResolvedModel::new(provider, model).with_context_window(100_000))
    }

    fn stream(&self, _request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let finish = SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        };
        match &self.mode {
            SummaryMode::Text => Ok(Box::pin(futures_util::stream::iter(
                text_summary().into_iter().map(Ok),
            ))),
            SummaryMode::MaxTokens => Ok(Box::pin(futures_util::stream::iter([Ok(
                SessionStreamChunk::Finish {
                    reason: SessionFinishReason::MaxTokens,
                    replay_state: None,
                },
            )]))),
            SummaryMode::Gated { started, release } => {
                let started = Arc::clone(started);
                let release = Arc::clone(release);
                started.notify_one();
                let first = futures_util::stream::once(async move {
                    release.notified().await;
                    Ok::<_, SessionLlmFailure>(SessionStreamChunk::BlockStart {
                        index: 0,
                        block_type: SessionStreamBlockType::Text,
                    })
                });
                let rest = futures_util::stream::iter([
                    Ok(SessionStreamChunk::BlockEnd {
                        index: 0,
                        block: SessionContentBlock::Text {
                            text: "durable checkpoint".into(),
                        },
                    }),
                    Ok(finish),
                ]);
                Ok(Box::pin(first.chain(rest)))
            }
        }
    }
}

fn mapped() -> hartevo_cordis::Context {
    let mut host = CordisHost::boot(false).unwrap();
    std::mem::take(host.context_mut())
}

fn call_config() -> SessionCallConfig {
    SessionCallConfig {
        provider: "mock".into(),
        model: "model".into(),
        reasoning_effort: None,
        temperature: None,
        max_tokens: None,
        stop: None,
    }
}

fn user_message(id: &str, text: impl Into<String>) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

fn plugin_message(id: &str, text: impl Into<String>) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::Plugin {
            plugin: "manual-test".into(),
            compaction_id: None,
            source_command_id: None,
        },
    }
}

fn assistant_message(id: &str, text: impl Into<String>) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::Assistant,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::Model {
            provider: "mock".into(),
            model: "model".into(),
        },
    }
}

fn text_summary() -> Vec<SessionStreamChunk> {
    vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Text {
                text: "durable checkpoint".into(),
            },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        },
    ]
}

fn register_adapter(ctx: &mut hartevo_cordis::Context, mode: SummaryMode) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    register_llm_adapter(
        ctx,
        ["mock"],
        ManualAdapter {
            mode,
            calls: Arc::clone(&calls),
        },
    )
    .unwrap();
    calls
}

fn seed_history(ctx: &hartevo_cordis::Context, id: &str) -> SessionHandle {
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new(id).unwrap())
        .unwrap();
    let turn = session.start_turn().unwrap();
    session
        .append_request_header(
            SessionEpochHeader {
                config: call_config(),
                adapter_defaults: None,
                system: Some("Be precise.".into()),
                tools: None,
            },
            SessionRequestHeaderReason::Initial,
            false,
        )
        .unwrap();
    let step = session.start_step(turn).unwrap();
    session
        .append_user_message(user_message("old-user", "older history ".repeat(400)))
        .unwrap();
    session
        .append_assistant_message(
            turn,
            step,
            assistant_message("recent-assistant", "recent answer"),
        )
        .unwrap();
    session.finish_step(turn, step).unwrap();
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
    session
}

fn observe_flush(ctx: &mut hartevo_cordis::Context) -> Arc<AtomicUsize> {
    let flushes = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&flushes);
    ctx.on_parallel(session_events::SESSION_FLUSH, move |_| {
        let observed = Arc::clone(&observed);
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok::<(), Infallible>(())
        }
    })
    .unwrap();
    flushes
}

fn compaction_events(session: &SessionHandle) -> Vec<SessionEventKind> {
    session
        .events()
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            matches!(
                event.kind,
                SessionEventKind::CompactionStart { .. }
                    | SessionEventKind::CompactionSummary { .. }
                    | SessionEventKind::CompactionEnd { .. }
            )
            .then_some(event.kind)
        })
        .collect()
}

#[tokio::test]
async fn manual_compaction_commits_a_standalone_correlated_checkpoint_and_flushes() {
    let mut ctx = mapped();
    let calls = register_adapter(&mut ctx, SummaryMode::Text);
    let flushes = observe_flush(&mut ctx);
    let session = seed_history(&ctx, "manual-success");

    let result = compact_now(
        &mut ctx,
        &session,
        Some("command-1".into()),
        &LifecycleCancellation::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(flushes.load(Ordering::SeqCst), 1);
    assert_eq!(result.source_command_id.as_deref(), Some("command-1"));
    assert_eq!(result.shadowed_seqs.len(), 1);
    assert_eq!(session.surface().unwrap().replace_generation, 1);
    let events = compaction_events(&session);
    assert_eq!(events.len(), 3);
    assert!(matches!(
        &events[0],
        SessionEventKind::CompactionStart { compaction }
            if compaction.turn.is_none()
                && compaction.source_command_id.as_deref() == Some("command-1")
    ));
    assert!(matches!(
        &events[2],
        SessionEventKind::CompactionEnd { compaction }
            if compaction.turn.is_none()
                && compaction.source_command_id.as_deref() == Some("command-1")
                && compaction.error.is_none()
    ));
    assert!(
        session
            .derive_messages()
            .unwrap()
            .iter()
            .any(|message| is_compact_checkpoint_source(&message.source))
    );
}

#[tokio::test]
async fn no_compactable_history_is_a_true_noop() {
    let mut ctx = mapped();
    let calls = register_adapter(&mut ctx, SummaryMode::Text);
    let flushes = observe_flush(&mut ctx);
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("manual-empty").unwrap())
        .unwrap();

    let result = compact_now(&mut ctx, &session, None, &LifecycleCancellation::default())
        .await
        .unwrap();

    assert!(result.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(flushes.load(Ordering::SeqCst), 0);
    assert!(session.events().unwrap().is_empty());
}

#[tokio::test]
async fn an_open_turn_rejects_manual_compaction_as_busy_without_a_marker() {
    let mut ctx = mapped();
    register_adapter(&mut ctx, SummaryMode::Text);
    let session = seed_history(&ctx, "manual-busy");
    let turn = session.start_turn().unwrap();

    let error = compact_now(&mut ctx, &session, None, &LifecycleCancellation::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), ManualCompactionErrorCode::Busy);
    assert!(compaction_events(&session).is_empty());
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
}

#[tokio::test]
async fn append_only_context_may_land_while_the_selected_span_is_summarized() {
    let mut ctx = mapped();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    register_adapter(
        &mut ctx,
        SummaryMode::Gated {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        },
    );
    let session = seed_history(&ctx, "manual-append");
    let append_session = session.clone();
    let append = async move {
        started.notified().await;
        append_session
            .append_user_message(plugin_message("injected", "injected context"))
            .unwrap();
        release.notify_one();
    };
    let cancellation = LifecycleCancellation::default();
    let compact = compact_now(&mut ctx, &session, None, &cancellation);

    let (result, ()) = tokio::join!(compact, append);
    result.unwrap().unwrap();

    let messages = session.derive_messages().unwrap();
    assert!(is_compact_checkpoint_source(&messages[0].source));
    assert_eq!(messages.last().unwrap().id, "injected");
    assert_eq!(session.surface().unwrap().replace_generation, 1);
}

#[tokio::test]
async fn a_closed_summary_failure_is_recorded_and_flushed_without_surface_change() {
    let mut ctx = mapped();
    register_adapter(&mut ctx, SummaryMode::MaxTokens);
    let flushes = observe_flush(&mut ctx);
    let session = seed_history(&ctx, "manual-summary-failure");
    let before = session.surface().unwrap();

    let error = compact_now(&mut ctx, &session, None, &LifecycleCancellation::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), ManualCompactionErrorCode::Summary);
    assert_eq!(flushes.load(Ordering::SeqCst), 1);
    assert_eq!(session.surface().unwrap(), before);
    let events = compaction_events(&session);
    assert_eq!(events.len(), 2);
    assert!(matches!(
        &events[1],
        SessionEventKind::CompactionEnd { compaction } if compaction.error.is_some()
    ));
}

#[tokio::test]
async fn cancellation_after_start_closes_and_flushes_the_attempt() {
    let mut ctx = mapped();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    register_adapter(
        &mut ctx,
        SummaryMode::Gated {
            started: Arc::clone(&started),
            release,
        },
    );
    let flushes = observe_flush(&mut ctx);
    let session = seed_history(&ctx, "manual-cancelled");
    let cancellation = LifecycleCancellation::default();
    let cancel = {
        let cancellation = cancellation.clone();
        async move {
            started.notified().await;
            cancellation.cancel();
        }
    };
    let compact = compact_now(&mut ctx, &session, None, &cancellation);

    let (result, ()) = tokio::join!(compact, cancel);
    let error = result.unwrap_err();

    assert_eq!(error.code(), ManualCompactionErrorCode::Cancelled);
    assert_eq!(flushes.load(Ordering::SeqCst), 1);
    let events = compaction_events(&session);
    assert_eq!(events.len(), 2);
    assert!(matches!(
        &events[1],
        SessionEventKind::CompactionEnd { compaction } if compaction.error.is_some()
    ));
}

#[derive(Debug, thiserror::Error)]
#[error("persistence unavailable")]
struct PersistenceFailure;

#[tokio::test]
async fn a_flush_failure_is_persistence_after_the_surface_commit() {
    let mut ctx = mapped();
    register_adapter(&mut ctx, SummaryMode::Text);
    ctx.on_parallel(session_events::SESSION_FLUSH, |_| async {
        Err::<(), _>(PersistenceFailure)
    })
    .unwrap();
    let session = seed_history(&ctx, "manual-persistence");

    let error = compact_now(&mut ctx, &session, None, &LifecycleCancellation::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), ManualCompactionErrorCode::Persistence);
    assert_eq!(session.surface().unwrap().replace_generation, 1);
    assert!(matches!(
        compaction_events(&session).last(),
        Some(SessionEventKind::CompactionEnd { compaction }) if compaction.error.is_none()
    ));
}

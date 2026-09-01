use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    CONTEXT_WINDOW_EXCEEDED_CODE, CordisHost, KernelApproval, KernelApprovalDecision,
    KernelConsentState, LifecycleCancellation, LlmAdapter, LlmAdapterStream, LlmError,
    LlmGenerateRequest, LlmRequestPurpose, LlmResolvedModel, SessionCallConfig,
    SessionContentBlock, SessionEpochHeader, SessionEventKind, SessionFinishReason, SessionHandle,
    SessionId, SessionLlmFailure, SessionMessage, SessionMessageRole, SessionMessageSource,
    SessionRequestContext, SessionRequestHeaderReason, SessionStore, SessionStreamBlockType,
    SessionStreamChunk, TurnEndReason, is_compact_checkpoint_source, register_llm_adapter,
    run_agent_turn,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 2, 5, 0, 0).unwrap()
}

fn mapped() -> hartevo_cordis::Context {
    let mut host = CordisHost::boot(false).unwrap();
    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Approved,
            valid_until: now() + Duration::minutes(5),
        }),
        now(),
    )
    .unwrap();
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

fn text_finish(text: &str) -> Vec<SessionStreamChunk> {
    vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Text { text: text.into() },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        },
    ]
}

fn overflow_finish() -> Vec<SessionStreamChunk> {
    vec![SessionStreamChunk::Finish {
        reason: SessionFinishReason::Error {
            failure: SessionLlmFailure {
                message: "request exceeds context capacity".into(),
                code: CONTEXT_WINDOW_EXCEEDED_CODE.into(),
                status: Some(400),
                provider_retry_after_ms: None,
                request_id: None,
            },
        },
        replay_state: None,
    }]
}

#[derive(Clone)]
struct AutomaticAdapter {
    context_window: u64,
    overflow_first_agent_call: bool,
    agent_calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<LlmGenerateRequest>>>,
}

impl LlmAdapter for AutomaticAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        Ok(LlmResolvedModel::new(provider, model).with_context_window(self.context_window))
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        let purpose = request.purpose();
        self.seen.lock().unwrap().push(request);
        let chunks = match purpose {
            LlmRequestPurpose::Compaction => text_finish("Durable facts and current work."),
            LlmRequestPurpose::Agent
                if self.overflow_first_agent_call
                    && self.agent_calls.fetch_add(1, Ordering::SeqCst) == 0 =>
            {
                overflow_finish()
            }
            LlmRequestPurpose::Agent => {
                if !self.overflow_first_agent_call {
                    self.agent_calls.fetch_add(1, Ordering::SeqCst);
                }
                text_finish("done")
            }
        };
        Ok(Box::pin(futures_util::stream::iter(
            chunks.into_iter().map(Ok),
        )))
    }
}

fn register_adapter(
    ctx: &mut hartevo_cordis::Context,
    context_window: u64,
    overflow_first_agent_call: bool,
) -> (Arc<Mutex<Vec<LlmGenerateRequest>>>, Arc<AtomicUsize>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let agent_calls = Arc::new(AtomicUsize::new(0));
    register_llm_adapter(
        ctx,
        ["mock"],
        AutomaticAdapter {
            context_window,
            overflow_first_agent_call,
            agent_calls: Arc::clone(&agent_calls),
            seen: Arc::clone(&seen),
        },
    )
    .unwrap();
    (seen, agent_calls)
}

fn seed_history(
    ctx: &hartevo_cordis::Context,
    id: &str,
    context_window: u64,
    older_text: String,
) -> SessionHandle {
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
    session
        .append_request_context(SessionRequestContext {
            provider: "mock".into(),
            model: "model".into(),
            context_window: Some(context_window),
        })
        .unwrap();
    let step = session.start_step(turn).unwrap();
    session
        .append_user_message(user_message("old-user", older_text))
        .unwrap();
    session
        .append_assistant_message(
            turn,
            step,
            assistant_message("old-assistant", "y".repeat(800)),
        )
        .unwrap();
    session.finish_step(turn, step).unwrap();
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
    session
}

#[tokio::test]
async fn pressure_compacts_before_deriving_the_next_agent_request() {
    let mut ctx = mapped();
    let (seen, agent_calls) = register_adapter(&mut ctx, 1_000, false);
    let session = seed_history(&ctx, "automatic-pressure", 1_000, "x".repeat(5_000));
    session
        .inbox()
        .append_next_turn(user_message("next-user", "continue"))
        .unwrap();

    let outcome = run_agent_turn(
        &mut ctx,
        session.id(),
        call_config(),
        &LifecycleCancellation::default(),
    )
    .await
    .unwrap();

    assert_eq!(outcome.reason(), TurnEndReason::Completed);
    assert_eq!(agent_calls.load(Ordering::SeqCst), 1);
    let requests = seen.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(LlmGenerateRequest::purpose)
            .collect::<Vec<_>>(),
        [LlmRequestPurpose::Compaction, LlmRequestPurpose::Agent]
    );
    assert!(
        requests[1]
            .messages()
            .iter()
            .any(|message| is_compact_checkpoint_source(&message.source))
    );
    assert!(
        !requests[1]
            .messages()
            .iter()
            .any(|message| message.id == "old-user")
    );
    drop(requests);
    assert_eq!(session.surface().unwrap().replace_generation, 1);
    assert_eq!(
        session
            .events()
            .unwrap()
            .iter()
            .filter(|event| matches!(event.kind, SessionEventKind::CompactionStart { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn confirmed_overflow_retries_once_only_after_durable_surface_progress() {
    let mut ctx = mapped();
    let (seen, agent_calls) = register_adapter(&mut ctx, 100_000, true);
    let session = seed_history(&ctx, "automatic-overflow", 100_000, "x".repeat(2_000));
    session
        .inbox()
        .append_next_turn(user_message("overflow-user", "continue"))
        .unwrap();

    let outcome = run_agent_turn(
        &mut ctx,
        session.id(),
        call_config(),
        &LifecycleCancellation::default(),
    )
    .await
    .unwrap();

    assert_eq!(outcome.reason(), TurnEndReason::Completed);
    assert_eq!(agent_calls.load(Ordering::SeqCst), 2);
    let requests = seen.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(LlmGenerateRequest::purpose)
            .collect::<Vec<_>>(),
        [
            LlmRequestPurpose::Agent,
            LlmRequestPurpose::Compaction,
            LlmRequestPurpose::Agent,
        ]
    );
    assert!(
        requests[2]
            .messages()
            .iter()
            .any(|message| is_compact_checkpoint_source(&message.source))
    );
    assert!(
        !requests[2]
            .messages()
            .iter()
            .any(|message| message.id == "old-user")
    );
    drop(requests);
    assert_eq!(session.surface().unwrap().replace_generation, 1);
    assert!(
        !session
            .events()
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, SessionEventKind::LlmRetry { .. }))
    );
}

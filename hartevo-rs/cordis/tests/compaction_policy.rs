use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    CompactionId, CompactionPolicyConfig, CompactionPolicyError, CompactionRetention,
    CompactionTarget, CompactionTrigger, CordisHost, LifecycleCancellation, LlmAdapter,
    LlmAdapterStream, LlmError, LlmGenerateRequest, LlmRequestPurpose, LlmResolvedModel,
    ModelCompactionPolicyConfig, SessionCallConfig, SessionContentBlock, SessionEpochHeader,
    SessionEventKind, SessionFinishReason, SessionId, SessionLlmFailure, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionRequestContext, SessionRequestHeaderReason,
    SessionStore, SessionStreamBlockType, SessionStreamChunk, SessionTokenUsage,
    estimate_content_tokens, estimate_message_tokens, execute_compaction_plan,
    is_compact_checkpoint_source, measure_compaction_session, plan_compaction,
    register_llm_adapter, resolve_compaction_config, resolve_compaction_policy,
    resolve_compaction_spec,
};

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

fn user_message(id: &str, text: impl Into<String>) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

fn assistant_tool_call(id: &str, call_id: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::Assistant,
        content: vec![SessionContentBlock::ToolCall {
            id: call_id.into(),
            name: "echo".into(),
            arguments: "{}".into(),
        }],
        source: SessionMessageSource::Model {
            provider: "chat".into(),
            model: "main".into(),
        },
    }
}

fn tool_result(id: &str, call_id: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::ToolResult {
            tool_call_id: call_id.into(),
            content: vec![SessionContentBlock::Text { text: "ok".into() }],
            is_error: false,
        }],
        source: SessionMessageSource::Tool {
            call_id: call_id.into(),
        },
    }
}

fn routed_session(
    id: &str,
    context_window: Option<u64>,
) -> (SessionStore, hartevo_cordis::SessionHandle, u64) {
    let sessions = SessionStore::new();
    let session = sessions.create(SessionId::new(id).unwrap()).unwrap();
    let turn = session.start_turn().unwrap();
    session
        .append_request_header(
            SessionEpochHeader {
                config: call_config("chat", "main"),
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
            provider: "chat".into(),
            model: "main".into(),
            context_window,
        })
        .unwrap();
    (sessions, session, turn)
}

fn exact_override() -> ModelCompactionPolicyConfig {
    ModelCompactionPolicyConfig {
        provider: "chat".into(),
        model: "main".into(),
        threshold_ratio: Some(0.9),
        retain_ratio: None,
        retain_tokens: Some(100),
        summarization_provider: Some("summary".into()),
        summarization_model: Some("small".into()),
        max_tokens: Some(512),
        compaction_retries: Some(2),
        max_overflow_retries: Some(3),
    }
}

#[test]
fn defaults_and_exact_target_overrides_resolve_before_capacity_scaling() {
    let defaults = resolve_compaction_config(CompactionPolicyConfig::default()).unwrap();
    assert!((defaults.threshold_ratio - 0.8).abs() < f64::EPSILON);
    assert!(
        matches!(defaults.retention, CompactionRetention::Ratio(ratio)
            if (ratio - 0.16).abs() < f64::EPSILON)
    );
    assert_eq!(defaults.max_tokens, 8_192);
    assert_eq!(defaults.compaction_retries, 1);
    assert_eq!(defaults.max_overflow_retries, 1);
    assert!(defaults.auto);

    let resolved = resolve_compaction_config(CompactionPolicyConfig {
        model_policies: vec![exact_override()],
        ..CompactionPolicyConfig::default()
    })
    .unwrap();
    let policy = resolve_compaction_policy(
        &resolved,
        CompactionTarget {
            provider: "chat".into(),
            model: "main".into(),
        },
    );
    let spec = resolve_compaction_spec(policy, 1_000).unwrap();
    assert_eq!(spec.threshold_tokens, 900);
    assert_eq!(spec.retain_tokens, 100);
    assert_eq!(spec.policy.summarization_provider, "summary");
    assert_eq!(spec.policy.summarization_model, "small");
    assert_eq!(spec.policy.max_tokens, 512);
    assert_eq!(spec.policy.compaction_retries, 2);
    assert_eq!(spec.policy.max_overflow_retries, 3);

    let duplicate = resolve_compaction_config(CompactionPolicyConfig {
        model_policies: vec![exact_override(), exact_override()],
        ..CompactionPolicyConfig::default()
    })
    .unwrap_err();
    assert!(matches!(
        duplicate,
        CompactionPolicyError::DuplicateTarget { .. }
    ));
    assert!(
        resolve_compaction_config(CompactionPolicyConfig {
            threshold_ratio: Some(0.5),
            retain_ratio: Some(0.5),
            ..CompactionPolicyConfig::default()
        })
        .is_err()
    );
}

#[test]
fn fixed_density_measurement_prices_utf16_blocks_and_latest_header() {
    assert_eq!(
        estimate_content_tokens(&[SessionContentBlock::Text {
            text: "abcde".into()
        }]),
        6
    );
    assert_eq!(
        estimate_content_tokens(&[SessionContentBlock::Text {
            text: "😀".into()
        }]),
        5
    );
    assert_eq!(
        estimate_content_tokens(&[SessionContentBlock::ToolCall {
            id: "call".into(),
            name: "echo".into(),
            arguments: "{}".into(),
        }]),
        6
    );
    assert_eq!(
        estimate_content_tokens(&[SessionContentBlock::ToolResult {
            tool_call_id: "call".into(),
            content: vec![SessionContentBlock::Text {
                text: "abcde".into()
            }],
            is_error: false,
        }]),
        10
    );

    let (_sessions, session, _turn) = routed_session("measure", Some(1_000));
    let message = user_message("user-1", "abcde");
    session.append_user_message(message.clone()).unwrap();
    let measurement = measure_compaction_session(&session).unwrap();
    assert_eq!(measurement.nodes.len(), 1);
    assert_eq!(
        measurement.nodes[0].tokens,
        estimate_message_tokens(&message)
    );
    assert!(measurement.header_tokens > 0);
    assert_eq!(
        measurement.total_tokens,
        measurement.header_tokens + measurement.surface_tokens
    );
}

#[test]
fn pressure_plan_keeps_a_recent_tail_and_never_splits_tool_pairing() {
    let (_sessions, session, turn) = routed_session("pressure", Some(100));
    session
        .append_user_message(user_message("user-1", "x".repeat(400)))
        .unwrap();
    let step = session.start_step(turn).unwrap();
    session
        .append_assistant_message(turn, step, assistant_tool_call("assistant-1", "call-1"))
        .unwrap();
    session
        .append_tool_call(turn, step, "call-1", "echo", "{}")
        .unwrap();
    session
        .append_tool_result(turn, step, tool_result("tool-1", "call-1"))
        .unwrap();
    session
        .append_user_message(user_message("user-2", "tail"))
        .unwrap();

    let config = resolve_compaction_config(CompactionPolicyConfig {
        threshold_ratio: Some(0.5),
        retain_tokens: Some(1),
        ..CompactionPolicyConfig::default()
    })
    .unwrap();
    let plan = plan_compaction(&session, &config, CompactionTrigger::Pressure)
        .unwrap()
        .unwrap();
    let nodes = session.surface().unwrap().nodes;
    assert_eq!(plan.region.shadowed_seqs, nodes[..3]);
    assert_eq!(plan.region.end, nodes[2]);
    assert_eq!(plan.selected_messages.len(), 3);
    assert_eq!(plan.threshold_tokens, Some(50));
    assert_eq!(plan.retained_tokens, 1);
}

#[test]
fn overflow_plan_bypasses_capacity_and_retention_but_keeps_newest_node() {
    let (_sessions, session, _turn) = routed_session("overflow", None);
    session
        .append_user_message(user_message("user-1", "first"))
        .unwrap();
    session
        .append_user_message(user_message("user-2", "second"))
        .unwrap();
    session
        .append_user_message(user_message("user-3", "newest"))
        .unwrap();
    let config = resolve_compaction_config(CompactionPolicyConfig::default()).unwrap();
    let plan = plan_compaction(&session, &config, CompactionTrigger::Overflow)
        .unwrap()
        .unwrap();
    let nodes = session.surface().unwrap().nodes;
    assert_eq!(plan.region.shadowed_seqs, nodes[..2]);
    assert_eq!(plan.retained_tokens, 0);
    assert_eq!(plan.threshold_tokens, None);
}

#[derive(Clone)]
struct RecordingSummaryAdapter {
    seen: Arc<Mutex<Vec<LlmGenerateRequest>>>,
    chunks: Vec<Result<SessionStreamChunk, SessionLlmFailure>>,
}

impl LlmAdapter for RecordingSummaryAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        Ok(LlmResolvedModel::new(provider, model))
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        self.seen.lock().expect("seen").push(request);
        Ok(Box::pin(futures_util::stream::iter(self.chunks.clone())))
    }
}

fn summary_chunks(text: &str) -> Vec<Result<SessionStreamChunk, SessionLlmFailure>> {
    vec![
        Ok(SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        }),
        Ok(SessionStreamChunk::TextDelta {
            index: 0,
            text: text.into(),
        }),
        Ok(SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Text { text: text.into() },
        }),
        Ok(SessionStreamChunk::Usage {
            usage: SessionTokenUsage {
                input_tokens: 100,
                output_tokens: 4,
                total_tokens: Some(104),
                cache_read_tokens: None,
                cache_write_tokens: None,
                reasoning_tokens: None,
            },
        }),
        Ok(SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        }),
    ]
}

#[tokio::test]
async fn execution_marks_summary_purpose_and_atomically_lands_a_smaller_checkpoint() {
    let mut host = CordisHost::boot(false).unwrap();
    let ctx = host.context_mut();
    let seen = Arc::new(Mutex::new(Vec::new()));
    register_llm_adapter(
        ctx,
        ["chat"],
        RecordingSummaryAdapter {
            seen: Arc::clone(&seen),
            chunks: summary_chunks("compact facts"),
        },
    )
    .unwrap();

    let (_sessions, session, turn) = routed_session("execute-success", None);
    for (index, id) in ["one", "two", "three"].into_iter().enumerate() {
        session
            .append_user_message(user_message(id, format!("{index}:{}", "x".repeat(1_200))))
            .unwrap();
    }
    let config = resolve_compaction_config(CompactionPolicyConfig::default()).unwrap();
    let plan = plan_compaction(&session, &config, CompactionTrigger::Overflow)
        .unwrap()
        .unwrap();
    let result = execute_compaction_plan(
        ctx,
        &session,
        &plan,
        CompactionId::new("policy-success").unwrap(),
        None,
        Some(turn),
        LifecycleCancellation::default(),
    )
    .await
    .unwrap();

    assert_eq!(result.shadowed_seqs, plan.region.shadowed_seqs);
    assert_eq!(session.surface().unwrap().nodes.len(), 2);
    let messages = session.derive_messages().unwrap();
    assert!(is_compact_checkpoint_source(&messages[0].source));
    let requests = seen.lock().expect("seen");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].purpose(), LlmRequestPurpose::Compaction);
    assert_eq!(requests[0].system(), Some("Be precise."));
    assert_eq!(
        requests[0].messages().last().unwrap().content,
        [SessionContentBlock::Text {
            text: hartevo_cordis::COMPACTION_INSTRUCTION.into()
        }]
    );
}

#[tokio::test]
async fn failed_summary_closes_the_durable_lease_without_mutating_surface() {
    let mut host = CordisHost::boot(false).unwrap();
    let ctx = host.context_mut();
    register_llm_adapter(
        ctx,
        ["chat"],
        RecordingSummaryAdapter {
            seen: Arc::new(Mutex::new(Vec::new())),
            chunks: vec![Ok(SessionStreamChunk::Finish {
                reason: SessionFinishReason::MaxTokens,
                replay_state: None,
            })],
        },
    )
    .unwrap();

    let (_sessions, session, turn) = routed_session("execute-failure", None);
    session
        .append_user_message(user_message("one", "x".repeat(1_200)))
        .unwrap();
    session
        .append_user_message(user_message("two", "y".repeat(1_200)))
        .unwrap();
    let config = resolve_compaction_config(CompactionPolicyConfig::default()).unwrap();
    let plan = plan_compaction(&session, &config, CompactionTrigger::Overflow)
        .unwrap()
        .unwrap();
    let original_surface = session.surface().unwrap();
    let error = execute_compaction_plan(
        ctx,
        &session,
        &plan,
        CompactionId::new("policy-failure").unwrap(),
        None,
        Some(turn),
        LifecycleCancellation::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, CompactionPolicyError::SummaryTruncated);
    assert_eq!(session.surface().unwrap(), original_surface);
    assert!(matches!(
        session.events().unwrap().last().map(|event| &event.kind),
        Some(SessionEventKind::CompactionEnd { compaction })
            if compaction.error.is_some()
    ));
}

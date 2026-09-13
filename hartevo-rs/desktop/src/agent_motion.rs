//! Presentation of observed execution state. Animation never advances a task.
use dioxus::prelude::*;
use hartevo_domain_kernel::RuntimeTurnStatus;

use crate::{DesktopRuntimeProgressPhase as Phase, UiIcon, UiIconName};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AgentMotionState {
    #[default]
    Idle,
    Preparing,
    Thinking,
    Composing,
    Waiting,
    Stopping,
    Complete,
    Cancelled,
    Failed,
    Uncertain,
}

impl AgentMotionState {
    // These independent observations may coexist (for example buffered text
    // while waiting for approval); they are not mutually exclusive UI modes.
    #[allow(clippy::fn_params_excessive_bools)]
    pub(crate) fn from_observation(
        busy: bool,
        waiting: bool,
        stopping: bool,
        phase: Option<Phase>,
        turn: Option<RuntimeTurnStatus>,
        has_text: bool,
    ) -> Self {
        // A pending decision or stop takes precedence over the last streamed
        // paragraph. Transport activity alone cannot imply task completion.
        if waiting {
            return Self::Waiting;
        }
        if stopping && busy {
            return Self::Stopping;
        }
        if busy {
            if phase.is_none() {
                match turn {
                    Some(RuntimeTurnStatus::Completed) => return Self::Complete,
                    Some(RuntimeTurnStatus::Failed) => return Self::Failed,
                    Some(RuntimeTurnStatus::Interrupted) => return Self::Cancelled,
                    Some(RuntimeTurnStatus::Uncertain) => return Self::Uncertain,
                    _ => {}
                }
            }
            return match phase {
                Some(Phase::WaitingLocalApproval | Phase::WaitingCordisApproval) => Self::Waiting,
                Some(Phase::StopRequested | Phase::InterruptSent) => Self::Stopping,
                Some(Phase::Failed) => Self::Failed,
                Some(Phase::Uncertain) => Self::Uncertain,
                Some(Phase::Interrupted) => Self::Cancelled,
                Some(Phase::Completed) => Self::Complete,
                Some(Phase::Preparing | Phase::Dispatched) => Self::Preparing,
                _ if has_text => Self::Composing,
                _ => Self::Thinking,
            };
        }
        match turn {
            Some(RuntimeTurnStatus::Completed) => Self::Complete,
            Some(RuntimeTurnStatus::Interrupted) => Self::Cancelled,
            Some(RuntimeTurnStatus::Failed) => Self::Failed,
            Some(RuntimeTurnStatus::Uncertain) => Self::Uncertain,
            Some(RuntimeTurnStatus::WaitingLocalApproval) => Self::Waiting,
            _ => Self::Idle,
        }
    }

    pub(crate) const fn key(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Preparing => "preparing",
            Self::Thinking => "thinking",
            Self::Composing => "composing",
            Self::Waiting => "waiting",
            Self::Stopping => "stopping",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Uncertain => "uncertain",
        }
    }

    pub(crate) const fn animated(self) -> bool {
        matches!(self, Self::Preparing | Self::Thinking | Self::Composing)
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Idle => "准备好继续",
            Self::Preparing => "正在准备这次任务",
            Self::Thinking => "正在处理你的要求",
            Self::Composing => "正在整理回复",
            Self::Waiting => "等待你确认",
            Self::Stopping => "正在停止",
            Self::Complete => "本次回复已保存",
            Self::Cancelled => "本次处理已停止",
            Self::Failed => "这次处理未完成",
            Self::Uncertain => "处理结果待核实",
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::Idle => "补充要求，继续完善这项任务。",
            Self::Preparing => "准备完成后，进展会出现在会话中。",
            Self::Thinking => "收到内容后会直接显示，可随时请求停止。",
            Self::Composing => "内容会持续更新，你可以先阅读已出现的部分。",
            Self::Waiting => "查看待确认事项后，再决定是否继续。",
            Self::Stopping => "已提交停止请求，正在等待执行结果。",
            Self::Complete => "可以审阅成果，或补充下一步修改要求。",
            Self::Cancelled => "已保存的内容仍然保留，可以调整要求后继续。",
            Self::Failed => "请查看错误说明；你的输入和已有成果会保留。",
            Self::Uncertain => "结果尚未确认，请先核实，再决定下一步。",
        }
    }
}

/// Keep the current (still permission-checked) children during a short exit.
/// Closing removes keyboard and accessibility access immediately; reopening
/// cancels the obsolete removal, without caching an old task or private VNode.
#[component]
pub(crate) fn WorkpadPresence(open: bool, children: Element) -> Element {
    let mut mounted = use_signal(|| open);
    let mut generation = use_signal(|| 0_u64);
    use_effect(use_reactive((&open,), move |(open,)| {
        let next = generation.peek().wrapping_add(1);
        generation.set(next);
        if open {
            mounted.set(true);
        } else {
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(240)).await;
                if *generation.peek() == next {
                    mounted.set(false);
                }
            });
        }
    }));
    rsx! {
        if open || mounted() {
            div { class: "workpad-motion-slot", "data-open": if open { "true" } else { "false" },
                "inert": (!open).then_some(""), aria_hidden: (!open).then_some("true"),
                {children}
            }
        }
    }
}

#[component]
pub(crate) fn AgentOrb(state: AgentMotionState) -> Element {
    let icon = match state {
        AgentMotionState::Complete => UiIconName::Check,
        AgentMotionState::Waiting | AgentMotionState::Uncertain => UiIconName::Shield,
        AgentMotionState::Cancelled | AgentMotionState::Stopping => UiIconName::Square,
        AgentMotionState::Failed => UiIconName::X,
        _ => UiIconName::Sparkles,
    };
    rsx! {
        span { class: "agent-orb", "data-agent-state": state.key(), aria_hidden: "true",
            span { class: "agent-orb-canvas", "data-orb-state": state.key() }
            span { class: "agent-orb-symbol", UiIcon { name: icon, size: 16 } }
        }
    }
}

#[component]
pub(crate) fn AgentActivity(
    state: AgentMotionState,
    #[props(default)] fixture: bool,
    title: Option<String>,
    detail: Option<String>,
) -> Element {
    let title = title.unwrap_or_else(|| state.label().to_owned());
    let detail = detail.unwrap_or_else(|| state.detail().to_owned());
    rsx! {
        section { class: "agent-activity", "data-agent-state": state.key(),
            AgentOrb { state }
            div { class: "agent-activity-copy",
                // Only a phase change remounts the status line. Token appends
                // neither replay the entrance nor cause per-token announcements.
                strong { key: "{state.key()}", role: "status", aria_live: "polite", aria_atomic: "true", "{title}" }
                small { "{detail}" }
            }
            if fixture { span { class: "agent-activity-fixture", "交互样例" } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(node: &VNode, dom: &VirtualDom, output: &mut String) {
        use dioxus::dioxus_core::DynamicNode;
        use std::fmt::Write as _;
        write!(output, "{:?} {:?}", node.template, node.dynamic_attrs).unwrap();
        for (index, child) in node.dynamic_nodes.iter().enumerate() {
            match child {
                DynamicNode::Component(component) => {
                    if let Some(scope) = component.mounted_scope(index, node, dom) {
                        inspect(scope.root_node(), dom, output);
                    }
                }
                DynamicNode::Fragment(children) => {
                    for child in children {
                        inspect(child, dom, output);
                    }
                }
                DynamicNode::Text(text) => output.push_str(&text.value),
                DynamicNode::Placeholder(_) => {}
            }
        }
    }

    fn rendered(dom: &VirtualDom) -> String {
        let mut output = String::new();
        inspect(dom.base_scope().root_node(), dom, &mut output);
        output
    }

    #[test]
    fn every_activity_has_readable_status_independent_of_canvas() {
        for state in [
            AgentMotionState::Idle,
            AgentMotionState::Preparing,
            AgentMotionState::Thinking,
            AgentMotionState::Composing,
            AgentMotionState::Waiting,
            AgentMotionState::Stopping,
            AgentMotionState::Complete,
            AgentMotionState::Cancelled,
            AgentMotionState::Failed,
            AgentMotionState::Uncertain,
        ] {
            let mut dom = VirtualDom::new_with_props(
                AgentActivity,
                AgentActivityProps {
                    state,
                    fixture: false,
                    title: None,
                    detail: None,
                },
            );
            dom.rebuild_to_vec();
            let output = rendered(&dom);
            for expected in [
                state.label(),
                state.detail(),
                state.key(),
                "aria-live",
                "polite",
                "svg",
            ] {
                assert!(output.contains(expected), "{state:?} missing {expected}");
            }
            assert!(!output.contains("dangerous_inner_html"));
        }
    }

    #[test]
    fn paused_or_terminal_stream_never_keeps_a_streaming_caret() {
        for status in [
            RuntimeTurnStatus::WaitingLocalApproval,
            RuntimeTurnStatus::InterruptRequested,
            RuntimeTurnStatus::Completed,
            RuntimeTurnStatus::Failed,
            RuntimeTurnStatus::Interrupted,
            RuntimeTurnStatus::Uncertain,
            RuntimeTurnStatus::Running,
        ] {
            let stream = crate::DesktopRuntimeTextStreamProjection {
                project_id: "motion-project".into(),
                mission_id: "motion-mission".into(),
                worker_generation: 1,
                turn_revision: 1,
                turn_status: status,
                last_evidence_sequence: None,
                delta_count: 0,
                items: vec![],
                updated_at: "2026-09-13T00:00:00Z".parse().unwrap(),
            };
            let mut dom = VirtualDom::new_with_props(
                crate::PersistedRuntimeStreamTurn,
                crate::PersistedRuntimeStreamTurnProps {
                    stream,
                    runtime_busy: true,
                    observed_motion: (status == RuntimeTurnStatus::Running)
                        .then_some(AgentMotionState::Stopping),
                    visual_fixture: false,
                    transport_caught_up: false,
                },
            );
            dom.rebuild_to_vec();
            let output = rendered(&dom);
            assert!(!output.contains("runtime-stream-caret"), "{status:?}");
            assert!(!output.contains("正在响应"), "{status:?}");
        }
    }

    #[tokio::test]
    async fn closing_workpad_is_inert_and_fast_reopen_cancels_old_removal() {
        use std::{cell::RefCell, rc::Rc};
        type Control = Rc<RefCell<Option<Signal<bool>>>>;
        // VirtualDom root components receive owned props.
        #[allow(clippy::needless_pass_by_value)]
        fn fixture(control: Control) -> Element {
            let open = use_signal(|| true);
            *control.borrow_mut() = Some(open);
            rsx! { WorkpadPresence { open: open(), button { "current-permission-checked-content" } } }
        }
        async fn settle(dom: &mut VirtualDom, millis: u64) {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(millis), async {
                loop {
                    dom.wait_for_work().await;
                    dom.render_immediate_to_vec();
                }
            })
            .await;
        }
        let control = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(fixture, control.clone());
        dom.rebuild_to_vec();
        settle(&mut dom, 10).await;
        assert!(rendered(&dom).contains("current-permission-checked-content"));
        dom.in_runtime(|| control.borrow().unwrap().set(false));
        dom.render_immediate_to_vec();
        let closing = rendered(&dom);
        assert!(closing.contains("current-permission-checked-content"));
        assert!(closing.contains("inert"));
        assert!(closing.contains("aria-hidden"));
        settle(&mut dom, 25).await;
        dom.in_runtime(|| control.borrow().unwrap().set(true));
        dom.render_immediate_to_vec();
        settle(&mut dom, 280).await;
        assert!(rendered(&dom).contains("current-permission-checked-content"));
        dom.in_runtime(|| control.borrow().unwrap().set(false));
        dom.render_immediate_to_vec();
        settle(&mut dom, 280).await;
        assert!(!rendered(&dom).contains("current-permission-checked-content"));
    }

    #[test]
    fn motion_follows_execution_and_terminal_facts() {
        assert_eq!(
            AgentMotionState::from_observation(false, false, false, None, None, true),
            AgentMotionState::Idle
        );
        assert_eq!(
            AgentMotionState::from_observation(
                true,
                false,
                false,
                Some(Phase::TurnStarted),
                None,
                false
            ),
            AgentMotionState::Thinking
        );
        assert_eq!(
            AgentMotionState::from_observation(
                true,
                false,
                false,
                Some(Phase::ItemStarted),
                None,
                true
            ),
            AgentMotionState::Composing
        );
        assert_eq!(
            AgentMotionState::from_observation(true, true, false, None, None, true),
            AgentMotionState::Waiting
        );
        assert_eq!(
            AgentMotionState::from_observation(true, false, true, None, None, true),
            AgentMotionState::Stopping
        );
        for (phase, state) in [
            (Phase::Failed, AgentMotionState::Failed),
            (Phase::Uncertain, AgentMotionState::Uncertain),
            (Phase::Interrupted, AgentMotionState::Cancelled),
            (Phase::Completed, AgentMotionState::Complete),
        ] {
            assert_eq!(
                AgentMotionState::from_observation(true, false, false, Some(phase), None, true),
                state
            );
            assert!(!state.animated());
        }
        // An old active turn after reopening is readable, but not a live job.
        assert_eq!(
            AgentMotionState::from_observation(
                false,
                false,
                false,
                Some(Phase::TurnStarted),
                None,
                true
            ),
            AgentMotionState::Idle
        );
    }
}

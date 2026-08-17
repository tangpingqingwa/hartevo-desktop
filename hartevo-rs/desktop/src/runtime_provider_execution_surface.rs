//! Contextual inline execution-log surface for a mounted Runtime provider plugin.
//!
//! The module is deliberately a Desktop consumer boundary. It does not create a Runtime,
//! persist an event, approve an Effect, or infer provider identity from health/configuration.
//! A surface exists only after an Application-owned provider projection and matching durable
//! execution events have crossed this boundary.

use std::fmt;

use dioxus::prelude::*;
use hartevo_application::WorkProductProjection;
use hartevo_domain_kernel::{MissionId, ProjectId, WorkProductId, WorkProductStatus};
use hartevo_runtime_adapter::RuntimePluginScope;

use crate::runtime_provider_surface::{
    RuntimeProviderInlineNode, RuntimeProviderNodeStatus, RuntimeProviderProjection,
    node_for_selected_scope,
};

/// The durable event classes that can expand an inline provider node on demand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProviderExecutionKind {
    Planning,
    Tool,
    Approval,
    Takeover,
    Recovery,
    Configuration,
    Stream,
    Result,
}

impl RuntimeProviderExecutionKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Planning => "PLANNING",
            Self::Tool => "TOOL",
            Self::Approval => "APPROVAL",
            Self::Takeover => "TAKEOVER",
            Self::Recovery => "RECOVERY",
            Self::Configuration => "CONFIGURATION",
            Self::Stream => "STREAM",
            Self::Result => "RESULT",
        }
    }
}

/// Content-free durable provider event metadata. The provider supplies the public kind/status
/// and stable digest; private prompt/output bodies never enter this consumer projection.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProviderExecutionEvent {
    pub scope: RuntimePluginScope,
    pub runtime_generation: u64,
    pub revision: u64,
    pub sequence: u64,
    pub kind: RuntimeProviderExecutionKind,
    pub status: RuntimeProviderNodeStatus,
    pub event_digest: String,
}

impl fmt::Debug for RuntimeProviderExecutionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderExecutionEvent")
            .field("scope_digest", &short_digest(&self.scope.scope_digest))
            .field("runtime_generation", &self.runtime_generation)
            .field("revision", &self.revision)
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("event_digest", &short_digest(&self.event_digest))
            .finish()
    }
}

impl RuntimeProviderExecutionEvent {
    pub fn new(
        scope: RuntimePluginScope,
        runtime_generation: u64,
        revision: u64,
        sequence: u64,
        kind: RuntimeProviderExecutionKind,
        status: RuntimeProviderNodeStatus,
        event_digest: impl Into<String>,
    ) -> Result<Self, RuntimeProviderExecutionSurfaceError> {
        let event_digest = event_digest.into();
        if runtime_generation == 0 || revision == 0 || sequence == 0 || !is_digest(&event_digest) {
            return Err(RuntimeProviderExecutionSurfaceError::InvalidEvent);
        }
        scope
            .validate()
            .map_err(|_| RuntimeProviderExecutionSurfaceError::InvalidScope)?;
        Ok(Self {
            scope,
            runtime_generation,
            revision,
            sequence,
            kind,
            status,
            event_digest,
        })
    }
}

/// A selected WorkProduct handed to the existing Workpad/adoption flow. This is a read-only
/// binding: Desktop never calls an adoption command or invents a local adoption state.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProviderSelectedResult {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub runtime_generation: u64,
    pub provider_revision: u64,
    pub work_product_id: WorkProductId,
    pub title: String,
    pub work_product_revision: u64,
    pub manifest_digest: String,
    pub adoption_status: WorkProductStatus,
    pub evidence_count: usize,
}

impl fmt::Debug for RuntimeProviderSelectedResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderSelectedResult")
            .field("project", &short_digest(self.project_id.as_str()))
            .field("mission", &short_digest(self.mission_id.as_str()))
            .field("runtime_generation", &self.runtime_generation)
            .field("provider_revision", &self.provider_revision)
            .field("work_product", &short_digest(self.work_product_id.as_str()))
            .field("title", &"[REDACTED]")
            .field("work_product_revision", &self.work_product_revision)
            .field("manifest_digest", &short_digest(&self.manifest_digest))
            .field("adoption_status", &self.adoption_status)
            .field("evidence_count", &self.evidence_count)
            .finish()
    }
}

impl RuntimeProviderSelectedResult {
    pub fn from_work_product(
        project_id: &ProjectId,
        mission_id: &MissionId,
        runtime_generation: u64,
        provider_revision: u64,
        product: &WorkProductProjection,
    ) -> Result<Self, RuntimeProviderExecutionSurfaceError> {
        if runtime_generation == 0
            || provider_revision == 0
            || product.work_product_revision == 0
            || product.manifest_version == 0
            || !is_digest(&product.manifest_digest)
        {
            return Err(RuntimeProviderExecutionSurfaceError::InvalidResult);
        }
        Ok(Self {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            runtime_generation,
            provider_revision,
            work_product_id: product.work_product_id.clone(),
            title: product.title.clone(),
            work_product_revision: product.work_product_revision,
            manifest_digest: product.manifest_digest.clone(),
            adoption_status: product.adoption_status.clone(),
            evidence_count: product.evidence_count,
        })
    }

    pub fn is_adoptable(&self) -> bool {
        self.adoption_status == WorkProductStatus::ReadyForReview
    }
}

/// Durable, content-free execution log bound to one exact provider invocation.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProviderExecutionLogProjection {
    pub node: RuntimeProviderInlineNode,
    pub events: Vec<RuntimeProviderExecutionEvent>,
    pub selected_result: Option<RuntimeProviderSelectedResult>,
}

impl fmt::Debug for RuntimeProviderExecutionLogProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderExecutionLogProjection")
            .field("node", &self.node)
            .field("event_count", &self.events.len())
            .field("events", &self.events)
            .field("selected_result", &self.selected_result)
            .finish()
    }
}

impl RuntimeProviderExecutionLogProjection {
    /// Assemble a renderable log only from exact Application projection material.
    pub fn from_exact_projection(
        projection: &RuntimeProviderProjection,
        events: Vec<RuntimeProviderExecutionEvent>,
        selected_result: Option<RuntimeProviderSelectedResult>,
        selected_project: &ProjectId,
        selected_mission: &MissionId,
        typed_command_port_available: bool,
    ) -> Result<Self, RuntimeProviderExecutionSurfaceError> {
        let node =
            node_for_selected_scope(Some(projection.clone()), selected_project, selected_mission)
                .ok_or(RuntimeProviderExecutionSurfaceError::ScopeMismatch)?;
        if matches!(
            projection.status,
            RuntimeProviderNodeStatus::Revoked | RuntimeProviderNodeStatus::Unknown
        ) || (projection.status == RuntimeProviderNodeStatus::RecoveryRequired
            && !typed_command_port_available)
        {
            return Err(RuntimeProviderExecutionSurfaceError::Unavailable);
        }
        if events.is_empty() {
            return Err(RuntimeProviderExecutionSurfaceError::NoDurableEvents);
        }
        let mut previous_sequence = 0;
        for event in &events {
            if event.scope.scope_digest != projection.scope.scope_digest
                || event.runtime_generation != projection.runtime_generation
                || event.revision != projection.revision
                || event.sequence <= previous_sequence
            {
                return Err(RuntimeProviderExecutionSurfaceError::EventMismatch);
            }
            previous_sequence = event.sequence;
        }
        let Some(last_event) = events.last() else {
            return Err(RuntimeProviderExecutionSurfaceError::NoDurableEvents);
        };
        if last_event.sequence != projection.last_sequence
            || last_event.event_digest != projection.last_event_digest
        {
            return Err(RuntimeProviderExecutionSurfaceError::EventMismatch);
        }
        if let Some(result) = &selected_result
            && (result.project_id != *selected_project
                || result.mission_id != *selected_mission
                || result.runtime_generation != projection.runtime_generation
                || result.provider_revision != projection.revision)
        {
            return Err(RuntimeProviderExecutionSurfaceError::ResultMismatch);
        }
        Ok(Self {
            node,
            events,
            selected_result,
        })
    }

    pub fn is_visible_for(&self, project_id: &ProjectId, mission_id: &MissionId) -> bool {
        self.node.is_visible_for(project_id, mission_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProviderExecutionSurfaceError {
    InvalidScope,
    InvalidEvent,
    InvalidResult,
    ScopeMismatch,
    EventMismatch,
    ResultMismatch,
    NoDurableEvents,
    Unavailable,
}

/// Inline task/tool/result node. It is mounted by the Mission Conversation only when the
/// projection constructor above succeeds; there is no global provider panel or placeholder.
#[component]
pub fn RuntimeProviderExecutionInlineSurface(
    log: RuntimeProviderExecutionLogProjection,
    on_open_result: EventHandler<WorkProductId>,
) -> Element {
    let identity = log.node.identity();
    let status = log.node.status();
    rsx! {
        article {
            class: "persisted-system-notice runtime-provider-execution-inline",
            role: "status",
            aria_label: "Runtime provider execution",
            div { class: "runtime-provider-execution-heading",
                strong { class: format!("operations-status {}", status.tone()), "Runtime task · {status.label()}" }
                small { "{identity.provider_id} · {identity.model_id} · {identity.harness_id}" }
                small { "{log.events.len()} durable execution events · Mission scoped" }
            }
            ol { class: "runtime-provider-execution-log", aria_label: "Runtime execution log",
                for event in log.events.iter() {
                    li {
                        details { class: "runtime-provider-execution-entry",
                            summary {
                                span { class: "runtime-provider-execution-kind", "{event.kind.label()}" }
                                span { "{event.status.label()}" }
                                small { "sequence {event.sequence} · revision {event.revision}" }
                            }
                            code { "event {short_digest(&event.event_digest)} · generation {event.runtime_generation}" }
                        }
                    }
                }
            }
            if let Some(result) = &log.selected_result {
                div { class: "runtime-provider-selected-result", aria_label: "Selected Runtime result",
                    span { class: "honesty-badge", "SELECTED RESULT" }
                    strong { "{result.title}" }
                    small { "{work_product_status_label(&result.adoption_status)} · revision {result.work_product_revision} · {result.evidence_count} evidence" }
                    button {
                        class: "quiet-button",
                        aria_label: "打开选中的 Runtime 结果",
                        onclick: {
                            let work_product_id = result.work_product_id.clone();
                            move |_| on_open_result.call(work_product_id.clone())
                        },
                        if result.is_adoptable() { "查看并采用" } else { "打开结果" }
                    }
                }
            }
        }
    }
}

fn work_product_status_label(status: &WorkProductStatus) -> &'static str {
    match status {
        WorkProductStatus::Draft => "DRAFT",
        WorkProductStatus::ReadyForReview => "READY_FOR_REVIEW",
        WorkProductStatus::Accepted => "ACCEPTED",
        WorkProductStatus::Superseded => "SUPERSEDED",
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn short_digest(value: &str) -> String {
    value.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_provider_surface::{
        RuntimeProviderIdentity, RuntimeProviderIdentityParts, RuntimeProviderRecovery,
    };

    fn projection(project_id: &str, mission_id: &str) -> RuntimeProviderProjection {
        RuntimeProviderProjection {
            scope: RuntimePluginScope::new(project_id, mission_id, "session-a").expect("scope"),
            identity: RuntimeProviderIdentity::from_parts(RuntimeProviderIdentityParts {
                provider_id: "openinterpreter".into(),
                provider_revision: "provider-revision".into(),
                model_id: "model".into(),
                model_revision: "model-revision".into(),
                harness_id: "harness".into(),
                harness_revision: "harness-revision".into(),
                manifest_digest: "a".repeat(64),
                config_digest: "b".repeat(64),
                catalog_digest: "c".repeat(64),
                policy_digest: "d".repeat(64),
            })
            .expect("identity"),
            runtime_generation: 3,
            cursor_digest: "e".repeat(64),
            revision: 7,
            status: RuntimeProviderNodeStatus::Streaming,
            delta_count: 1,
            last_event_digest: "f".repeat(64),
            last_sequence: 2,
            result_digest: None,
            recovery: None,
        }
    }

    fn events(scope: &RuntimePluginScope) -> Vec<RuntimeProviderExecutionEvent> {
        vec![
            RuntimeProviderExecutionEvent::new(
                scope.clone(),
                3,
                7,
                1,
                RuntimeProviderExecutionKind::Planning,
                RuntimeProviderNodeStatus::Starting,
                "1".repeat(64),
            )
            .expect("planning event"),
            RuntimeProviderExecutionEvent::new(
                scope.clone(),
                3,
                7,
                2,
                RuntimeProviderExecutionKind::Stream,
                RuntimeProviderNodeStatus::Streaming,
                "f".repeat(64),
            )
            .expect("stream event"),
        ]
    }

    #[test]
    fn absent_projection_keeps_execution_surface_unmounted() {
        let selected_project = ProjectId::from("project-a");
        let selected_mission = MissionId::from("mission-a");
        assert!(node_for_selected_scope(None, &selected_project, &selected_mission).is_none());
    }

    #[test]
    fn exact_log_binds_events_and_result_to_selected_scope() {
        let selected_project = ProjectId::from("project-a");
        let selected_mission = MissionId::from("mission-a");
        let provider_projection = projection(selected_project.as_str(), selected_mission.as_str());
        let log = RuntimeProviderExecutionLogProjection::from_exact_projection(
            &provider_projection,
            events(&provider_projection.scope),
            None,
            &selected_project,
            &selected_mission,
            false,
        )
        .expect("exact log");
        assert!(log.is_visible_for(&selected_project, &selected_mission));
        assert!(!log.is_visible_for(&selected_project, &MissionId::from("mission-b")));
        assert!(!log.is_visible_for(&ProjectId::from("project-b"), &selected_mission));
        assert!(!format!("{log:?}").contains("project-a"));
    }

    #[test]
    fn selected_ready_result_is_handed_to_existing_workpad_adoption_flow() {
        let selected_project = ProjectId::from("project-a");
        let selected_mission = MissionId::from("mission-a");
        let provider_projection = projection(selected_project.as_str(), selected_mission.as_str());
        let product = WorkProductProjection {
            work_product_id: WorkProductId::from("provider-result"),
            title: "Germany market evidence".into(),
            work_product_type: "market_evidence_pack".into(),
            manifest_version: 1,
            work_product_revision: 4,
            preview_media_type: "application/json".into(),
            preview_text: "private preview".into(),
            preview_digest: "1".repeat(64),
            manifest_digest: "2".repeat(64),
            adoption_status: WorkProductStatus::ReadyForReview,
            editable_scope_count: 1,
            evidence_count: 3,
        };
        let result = RuntimeProviderSelectedResult::from_work_product(
            &selected_project,
            &selected_mission,
            provider_projection.runtime_generation,
            provider_projection.revision,
            &product,
        )
        .expect("selected result");
        assert!(result.is_adoptable());
        let log = RuntimeProviderExecutionLogProjection::from_exact_projection(
            &provider_projection,
            events(&provider_projection.scope),
            Some(result),
            &selected_project,
            &selected_mission,
            false,
        )
        .expect("result-bound log");
        assert!(log.selected_result.is_some());
        assert!(!format!("{:?}", log.selected_result).contains("private preview"));
    }

    #[test]
    fn stale_event_or_reselect_cannot_mount_log() {
        let selected_project = ProjectId::from("project-a");
        let selected_mission = MissionId::from("mission-a");
        let mut provider_projection =
            projection(selected_project.as_str(), selected_mission.as_str());
        let mut stale_events = events(&provider_projection.scope);
        stale_events[1].revision = 8;
        assert_eq!(
            RuntimeProviderExecutionLogProjection::from_exact_projection(
                &provider_projection,
                stale_events,
                None,
                &selected_project,
                &selected_mission,
                false,
            ),
            Err(RuntimeProviderExecutionSurfaceError::EventMismatch)
        );
        provider_projection.status = RuntimeProviderNodeStatus::Revoked;
        assert_eq!(
            RuntimeProviderExecutionLogProjection::from_exact_projection(
                &provider_projection,
                events(
                    &RuntimePluginScope::new(
                        selected_project.as_str(),
                        selected_mission.as_str(),
                        "session-a",
                    )
                    .expect("scope")
                ),
                None,
                &selected_project,
                &selected_mission,
                false,
            ),
            Err(RuntimeProviderExecutionSurfaceError::Unavailable)
        );
    }

    #[test]
    fn durable_log_rebuild_is_stable_after_reselect_and_reopen() {
        let selected_project = ProjectId::from("project-a");
        let selected_mission = MissionId::from("mission-a");
        let provider_projection = projection(selected_project.as_str(), selected_mission.as_str());
        let first = RuntimeProviderExecutionLogProjection::from_exact_projection(
            &provider_projection,
            events(&provider_projection.scope),
            None,
            &selected_project,
            &selected_mission,
            false,
        )
        .expect("first log");
        let reopened = RuntimeProviderExecutionLogProjection::from_exact_projection(
            &provider_projection,
            events(&provider_projection.scope),
            None,
            &selected_project,
            &selected_mission,
            false,
        )
        .expect("reopened log");
        assert_eq!(first, reopened);
        assert!(!reopened.is_visible_for(&selected_project, &MissionId::from("mission-b")));
        assert!(!reopened.is_visible_for(&ProjectId::from("project-b"), &selected_mission));
    }

    #[test]
    fn recovery_requires_a_real_typed_command_port() {
        let selected_project = ProjectId::from("project-a");
        let selected_mission = MissionId::from("mission-a");
        let mut provider_projection =
            projection(selected_project.as_str(), selected_mission.as_str());
        provider_projection.status = RuntimeProviderNodeStatus::RecoveryRequired;
        provider_projection.recovery = Some(RuntimeProviderRecovery {
            code: "RUNTIME_RECOVERY",
            action: hartevo_runtime_adapter::RuntimeRecoveryAction::UserReview,
        });
        assert_eq!(
            RuntimeProviderExecutionLogProjection::from_exact_projection(
                &provider_projection,
                events(&provider_projection.scope),
                None,
                &selected_project,
                &selected_mission,
                false,
            ),
            Err(RuntimeProviderExecutionSurfaceError::Unavailable)
        );
        assert!(
            RuntimeProviderExecutionLogProjection::from_exact_projection(
                &provider_projection,
                events(&provider_projection.scope),
                None,
                &selected_project,
                &selected_mission,
                true,
            )
            .is_ok()
        );
    }
}

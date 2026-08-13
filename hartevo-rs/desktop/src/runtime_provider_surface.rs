//! Mission-conversation projection for the Runtime service-provider plugin.
//!
//! This is a consumer boundary. It owns no Runtime process, Effect authority, Mission state, or
//! storage write. A provider session can produce a command-capable node, while Mission-shell
//! rendering requires an exact durable Application projection and matching selected scope.

use std::fmt;

use hartevo_domain_kernel::{MissionId, ProjectId};
use hartevo_runtime_adapter::{
    DurableModelVisibleEvent, DurableModelVisibleEventKind, RuntimePluginMountState,
    RuntimePluginScope, RuntimeProviderSession, RuntimeProviderStreamEvent, RuntimeRecoveryAction,
    RuntimeTurnCompletionStatus,
};

const SHORT_DIGEST_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProviderNodeStatus {
    Starting,
    Streaming,
    RunningCaughtUp,
    Completed,
    Interrupted,
    Failed,
    RecoveryRequired,
    Revoked,
    Unknown,
}

impl RuntimeProviderNodeStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Starting => "STARTING",
            Self::Streaming => "STREAMING",
            Self::RunningCaughtUp => "RUNNING_CAUGHT_UP",
            Self::Completed => "COMPLETED",
            Self::Interrupted => "INTERRUPTED",
            Self::Failed => "FAILED",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
            Self::Revoked => "REVOKED",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub const fn tone(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::Failed | Self::Revoked | Self::RecoveryRequired => "warning",
            Self::Unknown => "neutral",
            Self::Starting | Self::Streaming | Self::RunningCaughtUp | Self::Interrupted => {
                "active"
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProviderIdentity {
    pub provider_id: String,
    pub provider_revision: String,
    pub model_id: String,
    pub model_revision: String,
    pub harness_id: String,
    pub harness_revision: String,
    manifest_digest: String,
    config_digest: String,
    catalog_digest: String,
    policy_digest: String,
}

impl fmt::Debug for RuntimeProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderIdentity")
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("model_id", &self.model_id)
            .field("model_revision", &self.model_revision)
            .field("harness_id", &self.harness_id)
            .field("harness_revision", &self.harness_revision)
            .field("manifest_digest", &short_digest(&self.manifest_digest))
            .field("config_digest", &short_digest(&self.config_digest))
            .field("catalog_digest", &short_digest(&self.catalog_digest))
            .field("policy_digest", &short_digest(&self.policy_digest))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProviderCommandBinding {
    scope: RuntimePluginScope,
    runtime_generation: u64,
    cursor_digest: String,
    revision: u64,
}

impl fmt::Debug for RuntimeProviderCommandBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderCommandBinding")
            .field("scope", &self.scope)
            .field("runtime_generation", &self.runtime_generation)
            .field("cursor_digest", &short_digest(&self.cursor_digest))
            .field("revision", &self.revision)
            .finish()
    }
}

impl RuntimeProviderCommandBinding {
    pub fn matches_selection(&self, project_id: &ProjectId, mission_id: &MissionId) -> bool {
        self.scope.project_id == project_id.as_str() && self.scope.mission_id == mission_id.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProviderSurfaceAction {
    Stop,
    Continue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProviderCommandError {
    ScopeMismatch,
    CommandUnavailable,
}

/// Application supplies this port when its typed Runtime command contract is available.
pub trait RuntimeProviderCommandPort {
    fn stop(
        &mut self,
        binding: &RuntimeProviderCommandBinding,
    ) -> Result<(), RuntimeProviderCommandError>;

    fn continue_after_recovery(
        &mut self,
        binding: &RuntimeProviderCommandBinding,
    ) -> Result<(), RuntimeProviderCommandError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProviderRecovery {
    pub code: &'static str,
    pub action: RuntimeRecoveryAction,
}

/// Exact Application-owned provider projection required before an inline node can be rendered.
/// The projection must already contain a durable model-visible event and its signed cursor; the
/// Desktop consumer never derives these values from environment discovery or Runtime health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProviderProjection {
    pub scope: RuntimePluginScope,
    pub identity: RuntimeProviderIdentity,
    pub runtime_generation: u64,
    pub cursor_digest: String,
    pub revision: u64,
    pub status: RuntimeProviderNodeStatus,
    pub delta_count: usize,
    pub last_event_digest: String,
    pub last_sequence: u64,
    pub result_digest: Option<String>,
    pub recovery: Option<RuntimeProviderRecovery>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProviderInlineNode {
    project_id: ProjectId,
    mission_id: MissionId,
    binding: Option<RuntimeProviderCommandBinding>,
    identity: RuntimeProviderIdentity,
    status: RuntimeProviderNodeStatus,
    delta_count: usize,
    last_event_digest: Option<String>,
    last_sequence: u64,
    result_digest: Option<String>,
    recovery: Option<RuntimeProviderRecovery>,
}

impl fmt::Debug for RuntimeProviderInlineNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderInlineNode")
            .field("project", &short_digest(self.project_id.as_str()))
            .field("mission", &short_digest(self.mission_id.as_str()))
            .field("binding", &self.binding)
            .field("identity", &self.identity)
            .field("status", &self.status)
            .field("delta_count", &self.delta_count)
            .field(
                "last_event_digest",
                &self.last_event_digest.as_deref().map(short_digest),
            )
            .field("last_sequence", &self.last_sequence)
            .field(
                "result_digest",
                &self.result_digest.as_deref().map(short_digest),
            )
            .field("recovery", &self.recovery)
            .finish()
    }
}

impl RuntimeProviderInlineNode {
    /// Build a command-capable node from the real provider session without re-signing its scope.
    pub fn from_session(
        session: &RuntimeProviderSession,
        cursor_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, &'static str> {
        let cursor_digest = cursor_digest.into();
        if !is_digest(&cursor_digest) || revision == 0 {
            return Err("runtime command binding is not exact");
        }
        let config = session.config();
        let identity = RuntimeProviderIdentity {
            provider_id: config.provider_id.clone(),
            provider_revision: config.provider_revision.clone(),
            model_id: config.model_id.clone(),
            model_revision: config.model_revision.clone(),
            harness_id: config.harness_id.clone(),
            harness_revision: config.harness_revision.clone(),
            manifest_digest: session
                .manifest()
                .digest()
                .map_err(|_| "provider manifest is invalid")?,
            config_digest: config.digest().map_err(|_| "runtime config is invalid")?,
            catalog_digest: config.catalog_digest.clone(),
            policy_digest: session
                .policy()
                .digest()
                .map_err(|_| "runtime policy is invalid")?,
        };
        let mapping = session.mapping();
        let scope = session.scope().clone();
        Ok(Self {
            project_id: ProjectId::from(scope.project_id.as_str()),
            mission_id: MissionId::from(scope.mission_id.as_str()),
            binding: Some(RuntimeProviderCommandBinding {
                scope,
                runtime_generation: mapping.runtime_generation,
                cursor_digest,
                revision,
            }),
            identity,
            status: match session.mount_state() {
                RuntimePluginMountState::Mounted => RuntimeProviderNodeStatus::Starting,
                RuntimePluginMountState::Unmounted => RuntimeProviderNodeStatus::RecoveryRequired,
                RuntimePluginMountState::Revoked => RuntimeProviderNodeStatus::Revoked,
            },
            delta_count: 0,
            last_event_digest: None,
            last_sequence: 0,
            result_digest: None,
            recovery: None,
        })
    }

    /// Build a renderable node only from the exact durable Application projection.
    pub fn from_projection(projection: RuntimeProviderProjection) -> Result<Self, &'static str> {
        if projection.runtime_generation == 0
            || projection.revision == 0
            || !is_digest(&projection.cursor_digest)
            || !is_digest(&projection.last_event_digest)
            || projection.last_sequence == 0
            || projection
                .result_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            return Err("runtime provider projection is not exact");
        }
        projection
            .scope
            .validate()
            .map_err(|_| "runtime scope is invalid")?;
        Ok(Self {
            project_id: ProjectId::from(projection.scope.project_id.as_str()),
            mission_id: MissionId::from(projection.scope.mission_id.as_str()),
            binding: Some(RuntimeProviderCommandBinding {
                scope: projection.scope,
                runtime_generation: projection.runtime_generation,
                cursor_digest: projection.cursor_digest,
                revision: projection.revision,
            }),
            identity: projection.identity,
            status: projection.status,
            delta_count: projection.delta_count,
            last_event_digest: Some(projection.last_event_digest),
            last_sequence: projection.last_sequence,
            result_digest: projection.result_digest,
            recovery: projection.recovery,
        })
    }

    pub fn is_visible_for(&self, project_id: &ProjectId, mission_id: &MissionId) -> bool {
        self.project_id == *project_id && self.mission_id == *mission_id
    }

    pub fn identity(&self) -> &RuntimeProviderIdentity {
        &self.identity
    }

    pub fn status(&self) -> RuntimeProviderNodeStatus {
        self.status
    }

    pub fn delta_count(&self) -> usize {
        self.delta_count
    }

    pub fn result_digest(&self) -> Option<&str> {
        self.result_digest.as_deref()
    }

    pub fn recovery(&self) -> Option<&RuntimeProviderRecovery> {
        self.recovery.as_ref()
    }

    pub fn command_available(&self, action: RuntimeProviderSurfaceAction) -> bool {
        self.binding.is_some()
            && match action {
                RuntimeProviderSurfaceAction::Stop => matches!(
                    self.status,
                    RuntimeProviderNodeStatus::Starting
                        | RuntimeProviderNodeStatus::Streaming
                        | RuntimeProviderNodeStatus::RunningCaughtUp
                ),
                RuntimeProviderSurfaceAction::Continue => {
                    self.status == RuntimeProviderNodeStatus::RecoveryRequired
                }
            }
    }

    pub fn dispatch<P: RuntimeProviderCommandPort>(
        &self,
        action: RuntimeProviderSurfaceAction,
        selected_project: &ProjectId,
        selected_mission: &MissionId,
        port: &mut P,
    ) -> Result<(), RuntimeProviderCommandError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or(RuntimeProviderCommandError::CommandUnavailable)?;
        if !binding.matches_selection(selected_project, selected_mission) {
            return Err(RuntimeProviderCommandError::ScopeMismatch);
        }
        match action {
            RuntimeProviderSurfaceAction::Stop => port.stop(binding),
            RuntimeProviderSurfaceAction::Continue => port.continue_after_recovery(binding),
        }
    }

    pub fn apply_durable_event(
        &mut self,
        event: &DurableModelVisibleEvent,
    ) -> Result<(), RuntimeProviderProjectionError> {
        event
            .validate()
            .map_err(|_| RuntimeProviderProjectionError::InvalidEvent)?;
        let binding = self
            .binding
            .as_ref()
            .ok_or(RuntimeProviderProjectionError::BindingUnavailable)?;
        if event.scope_digest != binding.scope.scope_digest
            || event.provider_manifest_digest != self.identity.manifest_digest
            || event.runtime_config_digest != self.identity.config_digest
            || event.catalog_digest != self.identity.catalog_digest
            || event.policy_digest != self.identity.policy_digest
        {
            return Err(RuntimeProviderProjectionError::ScopeOrIdentityMismatch);
        }
        if event.sequence < self.last_sequence
            || (event.sequence == self.last_sequence
                && self.last_event_digest.as_deref() != Some(event.event_digest.as_str()))
        {
            return Err(RuntimeProviderProjectionError::SequenceConflict);
        }
        if event.sequence == self.last_sequence {
            return Ok(());
        }
        self.last_sequence = event.sequence;
        self.last_event_digest = Some(event.event_digest.clone());
        match event.kind {
            DurableModelVisibleEventKind::Input => {
                self.status = RuntimeProviderNodeStatus::Starting;
            }
            DurableModelVisibleEventKind::AssistantDelta => {
                self.status = RuntimeProviderNodeStatus::Streaming;
                self.delta_count = self.delta_count.saturating_add(1);
            }
            DurableModelVisibleEventKind::AssistantResult => {
                self.status = RuntimeProviderNodeStatus::Completed;
                self.result_digest = Some(event.content_digest.clone());
            }
        }
        Ok(())
    }

    pub fn apply_stream_event(
        &mut self,
        event: &RuntimeProviderStreamEvent,
        durable_event: Option<&DurableModelVisibleEvent>,
    ) -> Result<(), RuntimeProviderProjectionError> {
        match event {
            RuntimeProviderStreamEvent::TurnStarted { .. } => {
                self.status = RuntimeProviderNodeStatus::Starting;
            }
            RuntimeProviderStreamEvent::ItemStarted { .. } => {
                self.status = RuntimeProviderNodeStatus::Streaming;
            }
            RuntimeProviderStreamEvent::AgentMessageDelta { .. }
            | RuntimeProviderStreamEvent::ItemCompleted { .. } => {
                self.apply_durable_event(
                    durable_event.ok_or(RuntimeProviderProjectionError::DurableEventRequired)?,
                )?;
            }
            RuntimeProviderStreamEvent::TurnCompleted { status, .. } => {
                self.status = match status {
                    RuntimeTurnCompletionStatus::Completed => RuntimeProviderNodeStatus::Completed,
                    RuntimeTurnCompletionStatus::Interrupted => {
                        RuntimeProviderNodeStatus::Interrupted
                    }
                    RuntimeTurnCompletionStatus::Failed => RuntimeProviderNodeStatus::Failed,
                };
            }
            RuntimeProviderStreamEvent::LocalApprovalRequested { .. } => {
                self.status = RuntimeProviderNodeStatus::RecoveryRequired;
                self.recovery = Some(RuntimeProviderRecovery {
                    code: "RUNTIME_LOCAL_APPROVAL_REQUIRED",
                    action: RuntimeRecoveryAction::UserReview,
                });
            }
            RuntimeProviderStreamEvent::Diagnostic { .. }
            | RuntimeProviderStreamEvent::Other { .. } => {
                self.status = RuntimeProviderNodeStatus::RunningCaughtUp;
            }
        }
        Ok(())
    }
}

/// Convert an optional Application projection into a node only when the projection is exact and
/// still belongs to the selected Mission. Missing, malformed, or cross-scope projections are
/// intentionally absent from the minimal Mission shell.
pub fn node_for_selected_scope(
    projection: Option<RuntimeProviderProjection>,
    selected_project: &ProjectId,
    selected_mission: &MissionId,
) -> Option<RuntimeProviderInlineNode> {
    let node = RuntimeProviderInlineNode::from_projection(projection?).ok()?;
    node.is_visible_for(selected_project, selected_mission)
        .then_some(node)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProviderProjectionError {
    BindingUnavailable,
    InvalidEvent,
    ScopeOrIdentityMismatch,
    SequenceConflict,
    DurableEventRequired,
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn short_digest(value: &str) -> String {
    value.chars().take(SHORT_DIGEST_LENGTH).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingCommandPort {
        stopped: usize,
        continued: usize,
    }

    impl RuntimeProviderCommandPort for RecordingCommandPort {
        fn stop(
            &mut self,
            _binding: &RuntimeProviderCommandBinding,
        ) -> Result<(), RuntimeProviderCommandError> {
            self.stopped += 1;
            Ok(())
        }

        fn continue_after_recovery(
            &mut self,
            _binding: &RuntimeProviderCommandBinding,
        ) -> Result<(), RuntimeProviderCommandError> {
            self.continued += 1;
            Ok(())
        }
    }

    fn exact_projection(project_id: &str, mission_id: &str) -> RuntimeProviderProjection {
        RuntimeProviderProjection {
            scope: RuntimePluginScope::new(project_id, mission_id, "session-a").expect("scope"),
            identity: RuntimeProviderIdentity {
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
            },
            runtime_generation: 3,
            cursor_digest: "e".repeat(64),
            revision: 7,
            status: RuntimeProviderNodeStatus::Streaming,
            delta_count: 1,
            last_event_digest: "f".repeat(64),
            last_sequence: 1,
            result_digest: None,
            recovery: None,
        }
    }

    #[test]
    fn unavailable_application_projection_is_hidden_from_minimal_shell() {
        let project_id = ProjectId::from("project-a");
        let mission_id = MissionId::from("mission-a");
        assert!(node_for_selected_scope(None, &project_id, &mission_id).is_none());
    }

    #[test]
    fn exact_application_projection_is_visible_only_for_matching_scope() {
        let project_id = ProjectId::from("project-a");
        let mission_id = MissionId::from("mission-a");
        let projection = exact_projection(project_id.as_str(), mission_id.as_str());
        assert!(
            node_for_selected_scope(Some(projection.clone()), &project_id, &mission_id).is_some()
        );
        assert!(
            node_for_selected_scope(
                Some(projection.clone()),
                &project_id,
                &MissionId::from("mission-b")
            )
            .is_none()
        );
        assert!(
            node_for_selected_scope(Some(projection), &ProjectId::from("project-b"), &mission_id)
                .is_none()
        );
    }

    #[test]
    fn provider_surface_source_has_no_internal_fallback_copy_or_fake_controls() {
        let source = include_str!("lib.rs");
        let unavailable = ["RUNTIME", "_PROVIDER", "_PROJECTION", "_UNAVAILABLE"].concat();
        assert!(!source.contains(&unavailable));
        let internal_copy = ["当前没有本地", "伪造按钮"].concat();
        assert!(!source.contains(&internal_copy));
        assert!(!source.contains("RuntimeProviderInlineNodeSurface"));
    }

    #[test]
    fn stream_content_requires_a_durable_event_receipt() {
        let project_id = ProjectId::from("project-a");
        let mission_id = MissionId::from("mission-a");
        let mut node = node_for_selected_scope(
            Some(exact_projection(project_id.as_str(), mission_id.as_str())),
            &project_id,
            &mission_id,
        )
        .expect("exact projection");
        let event = RuntimeProviderStreamEvent::AgentMessageDelta {
            event_digest: "event".into(),
            item_id_digest: "item".into(),
            content: "private body".into(),
        };
        assert_eq!(
            node.apply_stream_event(&event, None),
            Err(RuntimeProviderProjectionError::DurableEventRequired)
        );
        assert!(!format!("{node:?}").contains("private body"));
    }

    #[test]
    fn command_port_receives_only_exact_selected_scope() {
        let project_id = ProjectId::from("project-a");
        let mission_id = MissionId::from("mission-a");
        let node = node_for_selected_scope(
            Some(exact_projection(project_id.as_str(), mission_id.as_str())),
            &project_id,
            &mission_id,
        )
        .expect("exact projection");
        let mut port = RecordingCommandPort::default();
        assert_eq!(
            node.dispatch(
                RuntimeProviderSurfaceAction::Stop,
                &project_id,
                &mission_id,
                &mut port,
            ),
            Ok(())
        );
        assert_eq!(port.stopped, 1);
        assert_eq!(
            node.dispatch(
                RuntimeProviderSurfaceAction::Stop,
                &ProjectId::from("project-b"),
                &mission_id,
                &mut port,
            ),
            Err(RuntimeProviderCommandError::ScopeMismatch)
        );
        assert_eq!(port.stopped, 1);
    }
}

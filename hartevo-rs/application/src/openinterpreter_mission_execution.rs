//! Application-owned Mission consumer for the typed OpenInterpreter Runtime service.
//!
//! The Runtime adapter owns protocol/process/plugin lifecycle. This module owns the exact
//! Project/Mission invocation fence and projects only through the existing Mission Conversation
//! and Work Product stores. Provider implementations never receive a `ProjectStore` or Effect
//! authority; the narrow provider trait is the only Application/Runtime seam.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    MissionConversationError, MissionConversationMessage, MissionConversationMessageId,
    MissionConversationMessageKind, MissionConversationRole, MissionError, MissionId, MissionStage,
    Project, ProjectId, WorkProduct, WorkProductDependencies, WorkProductId, WorkProductManifest,
    WorkProductManifestError, WorkProductPreview,
};
use hartevo_runtime_adapter::{
    AdapterError, DurableModelVisibleEvent, DurableModelVisibleEventKind, MissionSessionLog,
    OpenInterpreterRuntimeProvider, RuntimeCatalog, RuntimeCommand, RuntimeExecutionConfig,
    RuntimeLocalApprovalRequest, RuntimePluginMountState, RuntimePluginScope,
    RuntimeProtocolWriteReceipt, RuntimeProviderError, RuntimeProviderPolicy,
    RuntimeProviderSession, RuntimeProviderStreamEvent, RuntimeResultPacket,
    RuntimeTurnCompletionStatus as AdapterTurnStatus, SecretResolver,
};
use hartevo_storage::{PendingEvent, ProjectStore, StorageError};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_CONVERSATION_CONTENT_BYTES: usize = 1024 * 1024;

/// Exact Runtime selection supplied by the Application caller.
///
/// Provider/model/harness identity is represented by the #226 catalog/config digests and
/// revisions. There is no registry lookup in this consumer.
#[derive(Clone)]
pub struct OpenInterpreterMissionRuntimeSelection {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub session_id: String,
    pub provider_manifest_digest: String,
    pub runtime_command: RuntimeCommand,
    pub workspace_root: PathBuf,
    pub catalog: RuntimeCatalog,
    pub config: RuntimeExecutionConfig,
    pub policy: RuntimeProviderPolicy,
    pub runtime_generation: u64,
    pub timeout: Duration,
}

impl fmt::Debug for OpenInterpreterMissionRuntimeSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenInterpreterMissionRuntimeSelection")
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("session_id", &digest(self.session_id.as_bytes()))
            .field("provider_manifest_digest", &self.provider_manifest_digest)
            .field(
                "runtime_command_intent_digest",
                &self.runtime_command.intent_digest().ok(),
            )
            .field("workspace_root", &self.workspace_root)
            .field("catalog_digest", &self.catalog.digest().ok())
            .field("runtime_config_digest", &self.config.digest().ok())
            .field("policy_digest", &self.policy.digest().ok())
            .field("runtime_generation", &self.runtime_generation)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OpenInterpreterMissionRuntimeSelection {
    pub fn scope(&self) -> Result<RuntimePluginScope, MissionExecutionError> {
        RuntimePluginScope::new(
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.session_id.trim(),
        )
        .map_err(|_| MissionExecutionError::InvalidInput)
    }

    pub fn validate(&self) -> Result<(), MissionExecutionError> {
        if self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.session_id.trim().is_empty()
            || self.runtime_generation == 0
            || !is_digest(&self.provider_manifest_digest)
            || self.timeout.is_zero()
        {
            return Err(MissionExecutionError::InvalidInput);
        }
        self.scope()?;
        self.catalog.validate()?;
        self.config.validate()?;
        self.policy.validate()?;
        if self.config.catalog_digest != self.catalog.digest()? {
            return Err(MissionExecutionError::SelectionDrift);
        }
        self.runtime_command.intent_digest()?;
        Ok(())
    }

    fn binding_digest(&self) -> Result<String, MissionExecutionError> {
        self.validate()?;
        let value = json!({
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "sessionId": self.session_id,
            "providerManifestDigest": self.provider_manifest_digest,
            "runtimeCommandIntentDigest": self.runtime_command.intent_digest()?,
            "workspaceRoot": self.workspace_root.to_string_lossy(),
            "catalogDigest": self.catalog.digest()?,
            "runtimeConfigDigest": self.config.digest()?,
            "policyDigest": self.policy.digest()?,
            "runtimeGeneration": self.runtime_generation,
            "timeoutMillis": self.timeout.as_millis(),
        });
        Ok(canonical_digest(&value)?)
    }
}

/// Command that starts one exact Mission invocation.
#[derive(Clone, Debug)]
pub struct StartOpenInterpreterMission {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub invocation_id: String,
    pub objective: String,
    pub expected_project_revision: u64,
    pub expected_mission_revision: u64,
    pub expected_conversation_revision: u64,
    pub runtime: OpenInterpreterMissionRuntimeSelection,
}

/// Provider identity returned by the typed Application/Runtime seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRuntimeProviderIdentity {
    pub project_id: String,
    pub mission_id: String,
    pub scope_digest: String,
    pub provider_manifest_digest: String,
    pub runtime_config_digest: String,
    pub catalog_digest: String,
    pub policy_digest: String,
    pub runtime_generation: u64,
    pub runtime_instance_digest: String,
    pub mapping_digest: String,
    pub mount_digest: String,
}

impl MissionRuntimeProviderIdentity {
    fn validate(&self) -> Result<(), MissionExecutionError> {
        if self.project_id.trim().is_empty()
            || self.mission_id.trim().is_empty()
            || self.runtime_generation == 0
            || !is_digest(&self.scope_digest)
            || !is_digest(&self.provider_manifest_digest)
            || !is_digest(&self.runtime_config_digest)
            || !is_digest(&self.catalog_digest)
            || !is_digest(&self.policy_digest)
            || !is_digest(&self.runtime_instance_digest)
            || !is_digest(&self.mapping_digest)
            || !is_digest(&self.mount_digest)
        {
            return Err(MissionExecutionError::ProviderIdentityMismatch);
        }
        Ok(())
    }

    fn matches_selection(
        &self,
        selection: &OpenInterpreterMissionRuntimeSelection,
    ) -> Result<(), MissionExecutionError> {
        self.validate()?;
        let scope = selection.scope()?;
        if self.project_id != selection.project_id.as_str()
            || self.mission_id != selection.mission_id.as_str()
            || self.scope_digest != scope.scope_digest
            || self.provider_manifest_digest != selection.provider_manifest_digest
            || self.runtime_config_digest != selection.config.digest()?
            || self.catalog_digest != selection.catalog.digest()?
            || self.policy_digest != selection.policy.digest()?
            || self.runtime_generation != selection.runtime_generation
        {
            return Err(MissionExecutionError::ProviderIdentityMismatch);
        }
        Ok(())
    }
}

/// One provider stream packet with an Application-owned cursor and identity fence.
#[derive(Clone, Debug)]
pub struct MissionRuntimeStreamPacket {
    pub identity: MissionRuntimeProviderIdentity,
    pub cursor: u64,
    pub event: RuntimeProviderStreamEvent,
}

/// Narrow provider boundary. No store, browser, consent, or effect authority crosses it.
pub trait MissionExecutionProvider {
    fn current_identity(&self) -> Result<MissionRuntimeProviderIdentity, MissionExecutionError>;

    fn start_invocation(
        &mut self,
        invocation_id: &str,
        objective: &str,
        timeout: Duration,
    ) -> Result<(), MissionExecutionError>;

    fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<MissionRuntimeStreamPacket, MissionExecutionError>;

    fn interrupt(
        &mut self,
        timeout: Duration,
    ) -> Result<MissionExecutionWriteReceipt, MissionExecutionError>;

    fn revoke(&mut self) -> Result<(), MissionExecutionError>;
}

/// Mount seam used by Application. A production factory is supplied below; tests can provide a
/// deterministic fake without changing the provider or storage crates.
pub trait MissionExecutionProviderFactory {
    fn mount(
        &self,
        selection: &OpenInterpreterMissionRuntimeSelection,
        log: Box<dyn MissionSessionLog>,
        resolver: &dyn SecretResolver,
    ) -> Result<Box<dyn MissionExecutionProvider>, MissionExecutionError>;
}

/// The real #226 OpenInterpreter provider adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenInterpreterRuntimeProviderFactory;

impl MissionExecutionProviderFactory for OpenInterpreterRuntimeProviderFactory {
    fn mount(
        &self,
        selection: &OpenInterpreterMissionRuntimeSelection,
        log: Box<dyn MissionSessionLog>,
        resolver: &dyn SecretResolver,
    ) -> Result<Box<dyn MissionExecutionProvider>, MissionExecutionError> {
        let provider = OpenInterpreterRuntimeProvider::new()?;
        if provider.manifest().manifest_digest != selection.provider_manifest_digest {
            return Err(MissionExecutionError::SelectionDrift);
        }
        let session = provider.mount(
            selection.runtime_command.clone(),
            &selection.workspace_root,
            selection.scope()?,
            selection.catalog.clone(),
            selection.config.clone(),
            selection.policy.clone(),
            resolver,
            log,
            selection.runtime_generation,
            selection.timeout,
        )?;
        if session.mount_state() != RuntimePluginMountState::Mounted {
            return Err(MissionExecutionError::ProviderIdentityMismatch);
        }
        Ok(Box::new(OpenInterpreterProviderAdapter {
            session: Some(session),
            cursor: 0,
        }))
    }
}

struct OpenInterpreterProviderAdapter {
    session: Option<RuntimeProviderSession>,
    cursor: u64,
}

impl OpenInterpreterProviderAdapter {
    fn session(&self) -> Result<&RuntimeProviderSession, MissionExecutionError> {
        self.session
            .as_ref()
            .ok_or(MissionExecutionError::ProviderUnavailable)
    }

    fn session_mut(&mut self) -> Result<&mut RuntimeProviderSession, MissionExecutionError> {
        self.session
            .as_mut()
            .ok_or(MissionExecutionError::ProviderUnavailable)
    }

    fn identity_for(
        session: &RuntimeProviderSession,
    ) -> Result<MissionRuntimeProviderIdentity, MissionExecutionError> {
        let mapping_digest = session.mapping().digest()?;
        Ok(MissionRuntimeProviderIdentity {
            project_id: session.scope().project_id.clone(),
            mission_id: session.scope().mission_id.clone(),
            scope_digest: session.scope().scope_digest.clone(),
            provider_manifest_digest: session.manifest().manifest_digest.clone(),
            runtime_config_digest: session.config().digest()?,
            catalog_digest: session.catalog().digest()?,
            policy_digest: session.policy().digest()?,
            runtime_generation: session.mapping().runtime_generation,
            runtime_instance_digest: session.mapping().runtime_instance_digest.clone(),
            mapping_digest,
            mount_digest: session.mount_digest().to_owned(),
        })
    }
}

impl MissionExecutionProvider for OpenInterpreterProviderAdapter {
    fn current_identity(&self) -> Result<MissionRuntimeProviderIdentity, MissionExecutionError> {
        Self::identity_for(self.session()?)
    }

    fn start_invocation(
        &mut self,
        invocation_id: &str,
        objective: &str,
        timeout: Duration,
    ) -> Result<(), MissionExecutionError> {
        self.session_mut()?
            .start_turn(invocation_id, objective, timeout)?;
        Ok(())
    }

    fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<MissionRuntimeStreamPacket, MissionExecutionError> {
        let event = self.session_mut()?.stream_next(timeout)?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(MissionExecutionError::CursorDrift)?;
        let identity = Self::identity_for(self.session()?)?;
        Ok(MissionRuntimeStreamPacket {
            identity,
            cursor: self.cursor,
            event,
        })
    }

    fn interrupt(
        &mut self,
        timeout: Duration,
    ) -> Result<MissionExecutionWriteReceipt, MissionExecutionError> {
        let receipt = self.session_mut()?.interrupt(timeout)?;
        Ok(MissionExecutionWriteReceipt::from_runtime(&receipt))
    }

    fn revoke(&mut self) -> Result<(), MissionExecutionError> {
        let session = self
            .session
            .take()
            .ok_or(MissionExecutionError::ProviderUnavailable)?;
        session.revoke()?;
        Ok(())
    }
}

/// Content-free result of a protocol write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionExecutionWriteReceipt {
    pub request_digest: String,
    pub response_digest: String,
}

impl MissionExecutionWriteReceipt {
    fn from_runtime(receipt: &RuntimeProtocolWriteReceipt) -> Self {
        Self {
            request_digest: receipt.request_digest.clone(),
            response_digest: receipt.response_digest.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionExecutionState {
    Running,
    InterruptRequested,
    Completed,
    Interrupted,
    Failed,
    Revoked,
    Fenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenInterpreterMissionInvocation {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub invocation_id: String,
    pub session_id: String,
    pub selection_digest: String,
    pub provider: MissionRuntimeProviderIdentity,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub conversation_revision: u64,
    pub cursor: u64,
    pub last_event_digest: Option<String>,
    pub selected_work_product_id: Option<WorkProductId>,
    pub state: MissionExecutionState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenInterpreterMissionProjection {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub invocation_id: String,
    pub session_id: String,
    pub selection_digest: String,
    pub provider_manifest_digest: String,
    pub runtime_config_digest: String,
    pub catalog_digest: String,
    pub runtime_generation: u64,
    pub runtime_instance_digest: String,
    pub cursor: u64,
    pub conversation_revision: u64,
    pub selected_work_product_id: Option<WorkProductId>,
    pub state: MissionExecutionState,
}

impl OpenInterpreterMissionInvocation {
    fn projection(&self) -> OpenInterpreterMissionProjection {
        OpenInterpreterMissionProjection {
            project_id: self.project_id.clone(),
            mission_id: self.mission_id.clone(),
            invocation_id: self.invocation_id.clone(),
            session_id: self.session_id.clone(),
            selection_digest: self.selection_digest.clone(),
            provider_manifest_digest: self.provider.provider_manifest_digest.clone(),
            runtime_config_digest: self.provider.runtime_config_digest.clone(),
            catalog_digest: self.provider.catalog_digest.clone(),
            runtime_generation: self.provider.runtime_generation,
            runtime_instance_digest: self.provider.runtime_instance_digest.clone(),
            cursor: self.cursor,
            conversation_revision: self.conversation_revision,
            selected_work_product_id: self.selected_work_product_id.clone(),
            state: self.state,
        }
    }
}

pub struct OpenInterpreterMissionExecution {
    invocation: OpenInterpreterMissionInvocation,
    selection: OpenInterpreterMissionRuntimeSelection,
    provider: Box<dyn MissionExecutionProvider>,
    runtime_log: RuntimeEventBuffer,
    next_runtime_log_sequence: u64,
}

impl fmt::Debug for OpenInterpreterMissionExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenInterpreterMissionExecution")
            .field("invocation", &self.invocation)
            .field("selection", &self.selection)
            .field("next_runtime_log_sequence", &self.next_runtime_log_sequence)
            .finish_non_exhaustive()
    }
}

impl OpenInterpreterMissionExecution {
    pub fn invocation(&self) -> &OpenInterpreterMissionInvocation {
        &self.invocation
    }

    pub fn projection(&self) -> OpenInterpreterMissionProjection {
        self.invocation.projection()
    }

    pub fn selection(&self) -> &OpenInterpreterMissionRuntimeSelection {
        &self.selection
    }
}

/// Application-facing stream result. Content is persisted in Mission Conversation/Work Product;
/// this return value contains only bounded metadata and selected-result identity.
#[derive(Clone, Debug, PartialEq)]
pub enum MissionExecutionObservation {
    TurnStarted {
        event_digest: String,
    },
    ItemStarted {
        event_digest: String,
    },
    Delta {
        event_digest: String,
        item_id_digest: String,
        content_digest: String,
        byte_count: u64,
    },
    Result {
        event_digest: String,
        work_product_id: WorkProductId,
    },
    TurnCompleted {
        event_digest: String,
        status: AdapterTurnStatus,
    },
    LocalApprovalRequested {
        event_digest: String,
        kind: hartevo_runtime_adapter::RuntimeLocalApprovalKind,
        request: RuntimeLocalApprovalRequest,
    },
    Diagnostic {
        event_digest: String,
    },
    Other {
        event_digest: String,
    },
    ReplayIgnored {
        event_digest: String,
    },
}

#[derive(Debug, Error)]
pub enum MissionExecutionError {
    #[error("OpenInterpreter Mission execution input is invalid")]
    InvalidInput,
    #[error("OpenInterpreter Mission execution Project/Mission/session scope mismatched")]
    ScopeMismatch,
    #[error("OpenInterpreter Mission execution selection drifted")]
    SelectionDrift,
    #[error("OpenInterpreter Mission execution Project revision changed")]
    ProjectRevisionMismatch { expected: u64, actual: u64 },
    #[error("OpenInterpreter Mission execution Mission revision changed")]
    MissionRevisionMismatch { expected: u64, actual: u64 },
    #[error("OpenInterpreter Mission execution Conversation revision changed")]
    ConversationRevisionMismatch { expected: u64, actual: u64 },
    #[error("OpenInterpreter Mission execution objective does not match the Mission contract")]
    ObjectiveMismatch,
    #[error("OpenInterpreter Mission execution workspace is outside Project scope")]
    RuntimeWorkspaceOutOfScope,
    #[error("OpenInterpreter provider is unavailable")]
    ProviderUnavailable,
    #[error("OpenInterpreter provider identity or generation drifted")]
    ProviderIdentityMismatch,
    #[error("OpenInterpreter provider log did not match the typed stream packet")]
    ProviderLogMismatch,
    #[error("OpenInterpreter provider output was not durably represented")]
    ProviderOutputNotDurable,
    #[error("OpenInterpreter Mission execution cursor drifted")]
    CursorDrift,
    #[error("late or cross-Mission OpenInterpreter packet rejected")]
    LatePacket,
    #[error("OpenInterpreter Mission execution is already terminal")]
    TerminalExecution,
    #[error("OpenInterpreter Mission execution was revoked")]
    RevokedExecution,
    #[error("OpenInterpreter Mission execution was fenced")]
    FencedExecution,
    #[error("reselect requires a new OpenInterpreter invocation")]
    ReselectRequiresNewInvocation,
    #[error("duplicate OpenInterpreter output did not match the persisted result")]
    DuplicateOutputMismatch,
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error(transparent)]
    RuntimeProvider(#[from] RuntimeProviderError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Mission(#[from] MissionError),
    #[error(transparent)]
    Conversation(#[from] MissionConversationError),
    #[error(transparent)]
    Manifest(#[from] WorkProductManifestError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Default)]
struct RuntimeEventBuffer {
    events: Arc<Mutex<Vec<DurableModelVisibleEvent>>>,
}

impl MissionSessionLog for RuntimeEventBuffer {
    fn append_model_visible_event(
        &mut self,
        event: DurableModelVisibleEvent,
    ) -> Result<(), String> {
        event.validate().map_err(|error| error.to_string())?;
        self.events
            .lock()
            .map_err(|_| "runtime event log lock poisoned".to_owned())?
            .push(event);
        Ok(())
    }
}

impl RuntimeEventBuffer {
    fn drain(&self) -> Result<Vec<DurableModelVisibleEvent>, MissionExecutionError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| MissionExecutionError::ProviderLogMismatch)?;
        Ok(std::mem::take(&mut *events))
    }

    fn clear(&self) -> Result<(), MissionExecutionError> {
        self.events
            .lock()
            .map_err(|_| MissionExecutionError::ProviderLogMismatch)?
            .clear();
        Ok(())
    }
}

impl super::ApplicationService {
    /// Mounts the exact provider selection, durably records the model-visible input, then starts
    /// one invocation. No provider call is made before the input Conversation transaction.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "Application command ownership follows the existing command-handler convention"
    )]
    pub fn start_openinterpreter_mission(
        &mut self,
        command: StartOpenInterpreterMission,
        factory: &dyn MissionExecutionProviderFactory,
        resolver: &dyn SecretResolver,
        now: DateTime<Utc>,
    ) -> Result<OpenInterpreterMissionExecution, super::ApplicationError> {
        let mut execution = self.mount_openinterpreter_mission(&command, factory, resolver)?;
        let input_digest = runtime_input_digest(&command.invocation_id, &command.objective);
        let conversation_revision = append_runtime_notice(
            &mut self.store,
            &command.project_id,
            &command.mission_id,
            command.expected_conversation_revision,
            &execution.invocation,
            "runtime.model_visible_input",
            &input_digest,
            &command.objective,
            now,
            &json!({
                "runtimeEventSourceDigest": sha256(
                    format!("turn-input:{}", command.invocation_id).as_bytes()
                ),
                "contentDigest": sha256(command.objective.as_bytes()),
                "contentByteCount": command.objective.len(),
            }),
        )?;
        execution.invocation.conversation_revision = conversation_revision;

        let provider_result = execution.provider.start_invocation(
            &command.invocation_id,
            &command.objective,
            command.runtime.timeout,
        );
        let runtime_events = execution.runtime_log.drain()?;
        validate_runtime_input_log(&runtime_events, &execution.selection, &command)?;
        if let Err(error) = provider_result {
            execution.runtime_log.clear()?;
            return Err(error.into());
        }
        let provider_identity = execution.provider.current_identity()?;
        provider_identity.matches_selection(&execution.selection)?;
        execution.invocation.provider = provider_identity;
        execution.next_runtime_log_sequence = 2;
        Ok(execution)
    }

    /// Reads one typed provider packet and atomically projects it into the existing Mission
    /// Conversation/Work Product surface. Invalid identity/cursor packets are discarded before
    /// any store write and fence the execution.
    #[allow(
        clippy::too_many_lines,
        reason = "the consumer keeps typed stream mapping and the single-write projection fence together"
    )]
    pub fn observe_openinterpreter_mission(
        &mut self,
        execution: &mut OpenInterpreterMissionExecution,
        expected_cursor: u64,
        timeout: Duration,
        now: DateTime<Utc>,
    ) -> Result<MissionExecutionObservation, super::ApplicationError> {
        self.validate_openinterpreter_execution(execution)?;
        if execution.invocation.cursor != expected_cursor {
            return Err(MissionExecutionError::CursorDrift.into());
        }
        let packet = match execution.provider.next_event(timeout) {
            Ok(packet) => packet,
            Err(error) => {
                execution.invocation.state = MissionExecutionState::Fenced;
                execution.runtime_log.clear()?;
                return Err(error.into());
            }
        };
        let event_digest = provider_event_digest(&packet.event);
        if packet.identity != execution.invocation.provider {
            execution.invocation.state = MissionExecutionState::Fenced;
            execution.runtime_log.clear()?;
            return Err(MissionExecutionError::LatePacket.into());
        }
        if packet.cursor == execution.invocation.cursor
            && execution.invocation.last_event_digest.as_deref() == Some(event_digest)
        {
            execution.runtime_log.clear()?;
            return Ok(MissionExecutionObservation::ReplayIgnored {
                event_digest: event_digest.to_owned(),
            });
        }
        if packet.cursor != execution.invocation.cursor.saturating_add(1) {
            execution.invocation.state = MissionExecutionState::Fenced;
            execution.runtime_log.clear()?;
            return Err(MissionExecutionError::CursorDrift.into());
        }
        if let Err(error) = validate_packet_result(&packet, &execution.invocation.provider) {
            execution.invocation.state = MissionExecutionState::Fenced;
            execution.runtime_log.clear()?;
            return Err(error.into());
        }
        let runtime_events = execution.runtime_log.drain()?;
        let runtime_sequence = match validate_runtime_log_for_packet(
            &runtime_events,
            &execution.selection,
            &execution.invocation.provider,
            &packet,
            execution.next_runtime_log_sequence,
        ) {
            Ok(sequence) => sequence,
            Err(error) => {
                execution.invocation.state = MissionExecutionState::Fenced;
                return Err(error.into());
            }
        };

        let packet_event_digest = event_digest.to_owned();
        let observation = (|| -> Result<MissionExecutionObservation, MissionExecutionError> {
            Ok(match packet.event {
                RuntimeProviderStreamEvent::TurnStarted { ref event_digest } => {
                    self.append_stream_notice(
                        execution,
                        "runtime.turn_started",
                        event_digest,
                        "Runtime turn started",
                        now,
                    )?;
                    MissionExecutionObservation::TurnStarted {
                        event_digest: event_digest.clone(),
                    }
                }
                RuntimeProviderStreamEvent::ItemStarted { ref event_digest } => {
                    self.append_stream_notice(
                        execution,
                        "runtime.item_started",
                        event_digest,
                        "Runtime item started",
                        now,
                    )?;
                    MissionExecutionObservation::ItemStarted {
                        event_digest: event_digest.clone(),
                    }
                }
                RuntimeProviderStreamEvent::AgentMessageDelta {
                    ref event_digest,
                    ref item_id_digest,
                    ref content,
                } => {
                    self.append_stream_notice(
                        execution,
                        "runtime.model_visible_delta",
                        event_digest,
                        content,
                        now,
                    )?;
                    if let Some(sequence) = runtime_sequence {
                        execution.next_runtime_log_sequence = sequence
                            .checked_add(1)
                            .ok_or(MissionExecutionError::CursorDrift)?;
                    }
                    MissionExecutionObservation::Delta {
                        event_digest: event_digest.clone(),
                        item_id_digest: item_id_digest.clone(),
                        content_digest: sha256(content.as_bytes()),
                        byte_count: u64::try_from(content.len())
                            .map_err(|_| MissionExecutionError::ProviderOutputNotDurable)?,
                    }
                }
                RuntimeProviderStreamEvent::ItemCompleted {
                    ref event_digest,
                    ref result,
                    ..
                } => {
                    if let Some(packet) = result.as_deref() {
                        let work_product_id =
                            self.project_runtime_result(execution, packet, runtime_sequence, now)?;
                        MissionExecutionObservation::Result {
                            event_digest: event_digest.clone(),
                            work_product_id,
                        }
                    } else {
                        self.append_stream_notice(
                            execution,
                            "runtime.item_completed",
                            event_digest,
                            "Runtime item completed without an adoptable result",
                            now,
                        )?;
                        MissionExecutionObservation::Other {
                            event_digest: event_digest.clone(),
                        }
                    }
                }
                RuntimeProviderStreamEvent::TurnCompleted {
                    ref event_digest,
                    status,
                } => {
                    self.append_stream_notice(
                        execution,
                        "runtime.turn_completed",
                        event_digest,
                        &format!("Runtime turn terminal status: {status:?}"),
                        now,
                    )?;
                    execution.invocation.state = match status {
                        AdapterTurnStatus::Completed => MissionExecutionState::Completed,
                        AdapterTurnStatus::Interrupted => MissionExecutionState::Interrupted,
                        AdapterTurnStatus::Failed => MissionExecutionState::Failed,
                    };
                    MissionExecutionObservation::TurnCompleted {
                        event_digest: event_digest.clone(),
                        status,
                    }
                }
                RuntimeProviderStreamEvent::LocalApprovalRequested {
                    ref event_digest,
                    kind,
                    ref request,
                } => {
                    self.append_stream_notice(
                    execution,
                    "runtime.local_approval_requested",
                    event_digest,
                    "Runtime requested local approval; Application has not granted Effect authority",
                    now,
                )?;
                    MissionExecutionObservation::LocalApprovalRequested {
                        event_digest: event_digest.clone(),
                        kind,
                        request: request.clone(),
                    }
                }
                RuntimeProviderStreamEvent::Diagnostic { ref event_digest } => {
                    self.append_stream_notice(
                        execution,
                        "runtime.diagnostic",
                        event_digest,
                        "Runtime diagnostic",
                        now,
                    )?;
                    MissionExecutionObservation::Diagnostic {
                        event_digest: event_digest.clone(),
                    }
                }
                RuntimeProviderStreamEvent::Other { ref event_digest } => {
                    self.append_stream_notice(
                        execution,
                        "runtime.other",
                        event_digest,
                        "Runtime event",
                        now,
                    )?;
                    MissionExecutionObservation::Other {
                        event_digest: event_digest.clone(),
                    }
                }
            })
        })();
        let observation = match observation {
            Ok(observation) => observation,
            Err(error) => {
                execution.invocation.state = MissionExecutionState::Fenced;
                return Err(error.into());
            }
        };
        execution.invocation.cursor = packet.cursor;
        execution.invocation.last_event_digest = Some(packet_event_digest);
        Ok(observation)
    }

    /// Requests a provider interrupt. The request itself is projected atomically; it does not
    /// approve or execute an external Effect.
    pub fn interrupt_openinterpreter_mission(
        &mut self,
        execution: &mut OpenInterpreterMissionExecution,
        timeout: Duration,
        now: DateTime<Utc>,
    ) -> Result<MissionExecutionWriteReceipt, super::ApplicationError> {
        self.validate_openinterpreter_execution(execution)?;
        if execution.invocation.state == MissionExecutionState::InterruptRequested {
            return Err(MissionExecutionError::TerminalExecution.into());
        }
        let receipt = match execution.provider.interrupt(timeout) {
            Ok(receipt) => receipt,
            Err(error) => {
                execution.invocation.state = MissionExecutionState::Fenced;
                execution.runtime_log.clear()?;
                return Err(error.into());
            }
        };
        let event_digest = sha256(
            format!(
                "runtime-interrupt:{}:{}",
                execution.invocation.invocation_id, receipt.request_digest
            )
            .as_bytes(),
        );
        self.append_stream_notice(
            execution,
            "runtime.interrupt_requested",
            &event_digest,
            "Runtime interrupt requested",
            now,
        )?;
        execution.invocation.state = MissionExecutionState::InterruptRequested;
        Ok(receipt)
    }

    /// Revokes the exact provider mount. Replaying revoke is a zero-growth no-op; old packets are
    /// rejected by the state fence before the provider is consulted.
    pub fn revoke_openinterpreter_mission(
        &mut self,
        execution: &mut OpenInterpreterMissionExecution,
        now: DateTime<Utc>,
    ) -> Result<OpenInterpreterMissionProjection, super::ApplicationError> {
        if execution.invocation.state == MissionExecutionState::Revoked {
            return Ok(execution.projection());
        }
        self.validate_openinterpreter_execution(execution)?;
        if let Err(error) = execution.provider.revoke() {
            execution.invocation.state = MissionExecutionState::Fenced;
            execution.runtime_log.clear()?;
            return Err(error.into());
        }
        execution.runtime_log.clear()?;
        let event_digest =
            sha256(format!("runtime-revoked:{}", execution.invocation.invocation_id).as_bytes());
        self.append_stream_notice(
            execution,
            "runtime.mount_revoked",
            &event_digest,
            "Runtime mount revoked",
            now,
        )?;
        execution.invocation.state = MissionExecutionState::Revoked;
        Ok(execution.projection())
    }

    /// A reselect cannot mutate a live invocation. The caller must create a new exact invocation.
    pub fn reselect_openinterpreter_mission(
        &self,
        execution: &OpenInterpreterMissionExecution,
        selection: &OpenInterpreterMissionRuntimeSelection,
    ) -> Result<(), super::ApplicationError> {
        if selection.binding_digest()? != execution.invocation.selection_digest {
            return Err(MissionExecutionError::ReselectRequiresNewInvocation.into());
        }
        Err(MissionExecutionError::ReselectRequiresNewInvocation.into())
    }

    fn mount_openinterpreter_mission(
        &mut self,
        command: &StartOpenInterpreterMission,
        factory: &dyn MissionExecutionProviderFactory,
        resolver: &dyn SecretResolver,
    ) -> Result<OpenInterpreterMissionExecution, super::ApplicationError> {
        command.runtime.validate()?;
        if command.project_id != command.runtime.project_id
            || command.mission_id != command.runtime.mission_id
        {
            return Err(MissionExecutionError::ScopeMismatch.into());
        }
        if command.invocation_id.trim().is_empty()
            || command.objective.trim().is_empty()
            || command.objective.len() > MAX_CONVERSATION_CONTENT_BYTES
            || command.expected_project_revision == 0
            || command.expected_mission_revision == 0
            || command.expected_conversation_revision == 0
        {
            return Err(MissionExecutionError::InvalidInput.into());
        }
        let project = self.store.load_project(&command.project_id)?;
        let mission = self
            .store
            .load_mission(&command.project_id, &command.mission_id)?;
        let conversation = self
            .store
            .load_mission_conversation(&command.project_id, &command.mission_id)?;
        if project.revision != command.expected_project_revision {
            return Err(MissionExecutionError::ProjectRevisionMismatch {
                expected: command.expected_project_revision,
                actual: project.revision,
            }
            .into());
        }
        if mission.revision != command.expected_mission_revision {
            return Err(MissionExecutionError::MissionRevisionMismatch {
                expected: command.expected_mission_revision,
                actual: mission.revision,
            }
            .into());
        }
        if conversation.revision != command.expected_conversation_revision {
            return Err(MissionExecutionError::ConversationRevisionMismatch {
                expected: command.expected_conversation_revision,
                actual: conversation.revision,
            }
            .into());
        }
        if mission.project_id != project.id
            || conversation.project_id != project.id
            || conversation.mission_id != mission.id
            || mission.stage != MissionStage::Running
            || mission.contract.goal.trim() != command.objective.trim()
        {
            return Err(MissionExecutionError::ScopeMismatch.into());
        }
        let working_directory = validate_workspace(&project, &command.runtime.runtime_command)?;
        let requested_root = command
            .runtime
            .workspace_root
            .canonicalize()
            .map_err(|_| MissionExecutionError::RuntimeWorkspaceOutOfScope)?;
        if working_directory != requested_root {
            return Err(MissionExecutionError::RuntimeWorkspaceOutOfScope.into());
        }
        let selection_digest = command.runtime.binding_digest()?;
        let runtime_log = RuntimeEventBuffer::default();
        let provider = factory.mount(&command.runtime, Box::new(runtime_log.clone()), resolver)?;
        let identity = provider.current_identity()?;
        identity.matches_selection(&command.runtime)?;
        Ok(OpenInterpreterMissionExecution {
            invocation: OpenInterpreterMissionInvocation {
                project_id: command.project_id.clone(),
                mission_id: command.mission_id.clone(),
                invocation_id: command.invocation_id.clone(),
                session_id: command.runtime.session_id.clone(),
                selection_digest,
                provider: identity,
                project_revision: project.revision,
                mission_revision: mission.revision,
                conversation_revision: conversation.revision,
                cursor: 0,
                last_event_digest: None,
                selected_work_product_id: None,
                state: MissionExecutionState::Running,
            },
            selection: command.runtime.clone(),
            provider,
            runtime_log,
            next_runtime_log_sequence: 1,
        })
    }

    fn validate_openinterpreter_execution(
        &self,
        execution: &mut OpenInterpreterMissionExecution,
    ) -> Result<(), MissionExecutionError> {
        match execution.invocation.state {
            MissionExecutionState::Revoked => return Err(MissionExecutionError::RevokedExecution),
            MissionExecutionState::Fenced => return Err(MissionExecutionError::FencedExecution),
            MissionExecutionState::Completed
            | MissionExecutionState::Interrupted
            | MissionExecutionState::Failed => {
                return Err(MissionExecutionError::TerminalExecution);
            }
            MissionExecutionState::Running | MissionExecutionState::InterruptRequested => {}
        }
        let project = self.store.load_project(&execution.invocation.project_id)?;
        let mission = self.store.load_mission(
            &execution.invocation.project_id,
            &execution.invocation.mission_id,
        )?;
        let conversation = self.store.load_mission_conversation(
            &execution.invocation.project_id,
            &execution.invocation.mission_id,
        )?;
        if project.id != execution.invocation.project_id
            || project.revision != execution.invocation.project_revision
            || mission.project_id != project.id
            || mission.revision != execution.invocation.mission_revision
            || conversation.project_id != project.id
            || conversation.mission_id != mission.id
            || conversation.revision != execution.invocation.conversation_revision
        {
            execution.invocation.state = MissionExecutionState::Fenced;
            return Err(MissionExecutionError::ScopeMismatch);
        }
        let identity = execution.provider.current_identity()?;
        if identity != execution.invocation.provider {
            execution.invocation.state = MissionExecutionState::Fenced;
            return Err(MissionExecutionError::ProviderIdentityMismatch);
        }
        Ok(())
    }

    fn append_stream_notice(
        &mut self,
        execution: &mut OpenInterpreterMissionExecution,
        event_type: &str,
        event_digest: &str,
        body: &str,
        now: DateTime<Utc>,
    ) -> Result<(), MissionExecutionError> {
        let conversation_revision = match append_runtime_notice(
            &mut self.store,
            &execution.invocation.project_id,
            &execution.invocation.mission_id,
            execution.invocation.conversation_revision,
            &execution.invocation,
            event_type,
            event_digest,
            body,
            now,
            &json!({
                "contentDigest": sha256(body.as_bytes()),
                "contentByteCount": body.len(),
            }),
        ) {
            Ok(revision) => revision,
            Err(error) => {
                execution.invocation.state = MissionExecutionState::Fenced;
                return Err(error);
            }
        };
        execution.invocation.conversation_revision = conversation_revision;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "result adoption names the Mission, manifest, Conversation, and Event/Outbox CAS closure"
    )]
    fn project_runtime_result(
        &mut self,
        execution: &mut OpenInterpreterMissionExecution,
        packet: &RuntimeResultPacket,
        runtime_sequence: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<WorkProductId, MissionExecutionError> {
        let mut mission = self.store.load_mission(
            &execution.invocation.project_id,
            &execution.invocation.mission_id,
        )?;
        let mut conversation = self.store.load_mission_conversation(
            &execution.invocation.project_id,
            &execution.invocation.mission_id,
        )?;
        let work_product_id = WorkProductId::from_stable(format!(
            "runtime-result:{}:{}",
            execution.invocation.invocation_id, packet.source_item_id_digest
        ));
        let message_id = MissionConversationMessageId::from_stable(format!(
            "mission-message:runtime-result:{}:{}",
            execution.invocation.invocation_id, packet.source_item_id_digest
        ));
        let idempotency_key = format!(
            "runtime-result:{}:{}",
            execution.invocation.invocation_id, packet.content_digest
        );
        if let Some(existing) = mission
            .work_products
            .iter()
            .find(|product| product.id == work_product_id)
            .cloned()
        {
            let message = conversation
                .messages
                .iter()
                .find(|message| message.id == message_id)
                .ok_or(MissionExecutionError::DuplicateOutputMismatch)?;
            if existing.body != packet.content
                || existing.content_digest != packet.content_digest
                || message.body != packet.content
                || message.content_digest != packet.content_digest
                || message.idempotency_key != idempotency_key
                || message.work_product_id.as_ref() != Some(&work_product_id)
            {
                return Err(MissionExecutionError::DuplicateOutputMismatch);
            }
            if let Some(sequence) = runtime_sequence {
                execution.next_runtime_log_sequence = sequence
                    .checked_add(1)
                    .ok_or(MissionExecutionError::CursorDrift)?;
            }
            execution.invocation.selected_work_product_id = Some(work_product_id.clone());
            return Ok(work_product_id);
        }
        if mission.revision != execution.invocation.mission_revision
            || conversation.revision != execution.invocation.conversation_revision
        {
            return Err(MissionExecutionError::ScopeMismatch);
        }
        let expected_mission_revision = mission.revision;
        let expected_conversation_revision = conversation.revision;
        mission.record_work_product(
            WorkProduct::draft(
                work_product_id.clone(),
                "OpenInterpreter Runtime result",
                packet.content.clone(),
                BTreeSet::new(),
            ),
            now,
        )?;
        let product = mission
            .work_products
            .iter()
            .find(|product| product.id == work_product_id)
            .cloned()
            .ok_or(MissionExecutionError::DuplicateOutputMismatch)?;
        let preview = packet.content.chars().take(4_000).collect::<String>();
        let manifest = WorkProductManifest::create(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            &product,
            "runtime_result",
            WorkProductDependencies::default(),
            None,
            WorkProductPreview::new("text/plain", preview)?,
            BTreeSet::from(["/body".to_owned()]),
            now,
        )?;
        let (message, appended) = conversation.append_runtime_draft(
            message_id,
            packet.content.clone(),
            work_product_id.clone(),
            idempotency_key,
            &mission,
            now,
        )?;
        if !appended {
            return Err(MissionExecutionError::DuplicateOutputMismatch);
        }
        let mut events = vec![
            PendingEvent::new(
                "runtime.result_projected",
                json!({
                    "invocationId": execution.invocation.invocation_id,
                    "projectId": packet.project_id,
                    "missionId": packet.mission_id,
                    "runtimeGeneration": packet.runtime_generation,
                    "runtimeInstanceDigest": packet.runtime_instance_digest,
                    "mappingDigest": packet.mapping_digest,
                    "sourceItemIdDigest": packet.source_item_id_digest,
                    "sourceEventDigest": packet.source_event_digest,
                    "contentDigest": packet.content_digest,
                    "runtimeLogSequence": runtime_sequence,
                    "externalEffectReplayed": false,
                }),
                now,
            ),
            PendingEvent::new(
                "work_product.created",
                json!({
                    "workProductId": manifest.work_product_id,
                    "workProductType": manifest.work_product_type,
                    "manifestVersion": manifest.version,
                    "manifestDigest": manifest.manifest_digest,
                    "resultDigest": packet.content_digest,
                    "invocationId": execution.invocation.invocation_id,
                }),
                now,
            ),
            PendingEvent::new(
                "mission.conversation_message_recorded",
                json!({
                    "conversationId": conversation.id,
                    "messageId": message.id,
                    "sequence": message.sequence,
                    "role": message.role,
                    "kind": message.kind,
                    "contentDigest": message.content_digest,
                    "workProductId": message.work_product_id,
                    "invocationId": execution.invocation.invocation_id,
                }),
                now,
            ),
        ];
        self.store.create_runtime_draft_with_conversation_atomic(
            &mission,
            expected_mission_revision,
            &manifest,
            &conversation,
            expected_conversation_revision,
            &events,
        )?;
        events.clear();
        execution.invocation.mission_revision = mission.revision;
        execution.invocation.conversation_revision = conversation.revision;
        execution.invocation.selected_work_product_id = Some(work_product_id.clone());
        if let Some(sequence) = runtime_sequence {
            execution.next_runtime_log_sequence = sequence
                .checked_add(1)
                .ok_or(MissionExecutionError::CursorDrift)?;
        }
        Ok(work_product_id)
    }
}

fn validate_workspace(
    project: &Project,
    runtime_command: &RuntimeCommand,
) -> Result<PathBuf, MissionExecutionError> {
    runtime_command.intent_digest()?;
    let working_directory = runtime_command
        .current_dir
        .canonicalize()
        .map_err(|_| MissionExecutionError::RuntimeWorkspaceOutOfScope)?;
    if !project.workspace_roots.iter().any(|root| {
        root.canonicalize()
            .is_ok_and(|canonical_root| working_directory.starts_with(canonical_root))
    }) {
        return Err(MissionExecutionError::RuntimeWorkspaceOutOfScope);
    }
    Ok(working_directory)
}

fn validate_runtime_input_log(
    events: &[DurableModelVisibleEvent],
    selection: &OpenInterpreterMissionRuntimeSelection,
    command: &StartOpenInterpreterMission,
) -> Result<(), MissionExecutionError> {
    for event in events {
        event.validate()?;
        validate_runtime_event_binding(event, selection)?;
        if event.kind != DurableModelVisibleEventKind::Input
            || event.sequence != 1
            || event.content != command.objective
            || event.source_item_id_digest != sha256(command.invocation_id.as_bytes())
            || event.source_event_digest
                != sha256(format!("turn-input:{}", command.invocation_id).as_bytes())
        {
            return Err(MissionExecutionError::ProviderLogMismatch);
        }
    }
    Ok(())
}

fn validate_runtime_log_for_packet(
    events: &[DurableModelVisibleEvent],
    selection: &OpenInterpreterMissionRuntimeSelection,
    identity: &MissionRuntimeProviderIdentity,
    packet: &MissionRuntimeStreamPacket,
    expected_sequence: u64,
) -> Result<Option<u64>, MissionExecutionError> {
    if events.is_empty() {
        return Ok(None);
    }
    if events.len() != 1 {
        return Err(MissionExecutionError::ProviderLogMismatch);
    }
    let event = &events[0];
    event.validate()?;
    validate_runtime_event_binding(event, selection)?;
    if event.sequence != expected_sequence {
        return Err(MissionExecutionError::ProviderLogMismatch);
    }
    match &packet.event {
        RuntimeProviderStreamEvent::AgentMessageDelta {
            event_digest,
            item_id_digest,
            content,
        } if event.kind == DurableModelVisibleEventKind::AssistantDelta
            && event.source_event_digest == *event_digest
            && event.source_item_id_digest == *item_id_digest
            && event.content == *content => {}
        RuntimeProviderStreamEvent::ItemCompleted {
            event_digest,
            result: Some(result),
            ..
        } if event.kind == DurableModelVisibleEventKind::AssistantResult
            && event.source_event_digest == *event_digest
            && event.source_item_id_digest == result.source_item_id_digest
            && event.content == result.content
            && result.runtime_generation == identity.runtime_generation => {}
        _ => return Err(MissionExecutionError::ProviderLogMismatch),
    }
    Ok(Some(event.sequence))
}

fn validate_runtime_event_binding(
    event: &DurableModelVisibleEvent,
    selection: &OpenInterpreterMissionRuntimeSelection,
) -> Result<(), MissionExecutionError> {
    let scope = selection.scope()?;
    if event.scope_digest != scope.scope_digest
        || event.provider_manifest_digest != selection.provider_manifest_digest
        || event.runtime_config_digest != selection.config.digest()?
        || event.catalog_digest != selection.catalog.digest()?
        || event.policy_digest != selection.policy.digest()?
    {
        return Err(MissionExecutionError::ProviderLogMismatch);
    }
    Ok(())
}

fn validate_packet_result(
    packet: &MissionRuntimeStreamPacket,
    identity: &MissionRuntimeProviderIdentity,
) -> Result<(), MissionExecutionError> {
    if let RuntimeProviderStreamEvent::ItemCompleted {
        event_digest,
        result: Some(result),
        ..
    } = &packet.event
    {
        result.validate()?;
        if result.project_id != identity.project_id
            || result.mission_id != identity.mission_id
            || result.runtime_generation != identity.runtime_generation
            || result.runtime_instance_digest != identity.runtime_instance_digest
            || result.mapping_digest != identity.mapping_digest
            || result.runtime_config_digest != identity.runtime_config_digest
            || result.catalog_digest != identity.catalog_digest
            || result.source_event_digest != *event_digest
        {
            return Err(MissionExecutionError::LatePacket);
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one notice helper binds the exact invocation, Conversation revision, content digest, and event payload"
)]
fn append_runtime_notice(
    store: &mut ProjectStore,
    project_id: &ProjectId,
    mission_id: &MissionId,
    expected_conversation_revision: u64,
    invocation: &OpenInterpreterMissionInvocation,
    event_type: &str,
    event_digest: &str,
    body: &str,
    now: DateTime<Utc>,
    additional_payload: &serde_json::Value,
) -> Result<u64, MissionExecutionError> {
    if body.trim().is_empty() || body.len() > MAX_CONVERSATION_CONTENT_BYTES {
        return Err(MissionExecutionError::ProviderOutputNotDurable);
    }
    let mission = store.load_mission(project_id, mission_id)?;
    let mut conversation = store.load_mission_conversation(project_id, mission_id)?;
    if conversation.project_id != *project_id
        || conversation.mission_id != *mission_id
        || mission.project_id != *project_id
    {
        return Err(MissionExecutionError::ScopeMismatch);
    }
    let message_id = MissionConversationMessageId::from_stable(format!(
        "mission-message:runtime:{event_digest}"
    ));
    let idempotency_key = format!("runtime-event:{event_digest}");
    if let Some(existing) = conversation
        .messages
        .iter()
        .find(|message| message.id == message_id)
    {
        if existing.role != MissionConversationRole::System
            || existing.kind != MissionConversationMessageKind::SystemNotice
            || existing.body != body
            || existing.content_digest != sha256(body.as_bytes())
            || existing.idempotency_key != idempotency_key
        {
            return Err(MissionExecutionError::DuplicateOutputMismatch);
        }
        return Ok(conversation.revision);
    }
    if conversation.revision != expected_conversation_revision {
        return Err(MissionExecutionError::ConversationRevisionMismatch {
            expected: expected_conversation_revision,
            actual: conversation.revision,
        });
    }
    let sequence = conversation
        .revision
        .checked_add(1)
        .ok_or(MissionExecutionError::CursorDrift)?;
    let checkpoint_id = mission.definition.as_ref().and_then(|definition| {
        definition
            .current_checkpoint()
            .filter(|checkpoint| {
                !matches!(
                    checkpoint.status,
                    hartevo_domain_kernel::MissionCheckpointStatus::Completed
                        | hartevo_domain_kernel::MissionCheckpointStatus::Skipped
                )
            })
            .map(|checkpoint| checkpoint.id.clone())
    });
    let message = MissionConversationMessage {
        id: message_id,
        sequence,
        role: MissionConversationRole::System,
        kind: MissionConversationMessageKind::SystemNotice,
        body: body.to_owned(),
        content_digest: sha256(body.as_bytes()),
        idempotency_key,
        mission_revision: mission.revision,
        checkpoint_id,
        work_product_id: None,
        recorded_at: now,
    };
    conversation.messages.push(message.clone());
    conversation.revision = sequence;
    conversation.updated_at = now;
    conversation.validate_for(&mission, now)?;
    let mut payload = json!({
        "invocationId": invocation.invocation_id,
        "projectId": invocation.project_id,
        "missionId": invocation.mission_id,
        "sessionIdDigest": digest(invocation.session_id.as_bytes()),
        "eventDigest": event_digest,
        "eventType": event_type,
        "runtimeGeneration": invocation.provider.runtime_generation,
        "runtimeInstanceDigest": invocation.provider.runtime_instance_digest,
        "providerManifestDigest": invocation.provider.provider_manifest_digest,
        "runtimeConfigDigest": invocation.provider.runtime_config_digest,
        "catalogDigest": invocation.provider.catalog_digest,
        "conversationId": conversation.id,
        "messageId": message.id,
        "sequence": message.sequence,
        "contentDigest": message.content_digest,
        "externalEffectReplayed": false,
    });
    merge_json_object(&mut payload, additional_payload)?;
    store.append_mission_conversation_atomic(
        &conversation,
        expected_conversation_revision,
        &[PendingEvent::new(event_type, payload, now)],
    )?;
    Ok(conversation.revision)
}

fn merge_json_object(
    target: &mut serde_json::Value,
    additional: &serde_json::Value,
) -> Result<(), MissionExecutionError> {
    let Some(target) = target.as_object_mut() else {
        return Err(MissionExecutionError::InvalidInput);
    };
    let Some(additional) = additional.as_object() else {
        return Err(MissionExecutionError::InvalidInput);
    };
    for (key, value) in additional {
        target.insert(key.clone(), value.clone());
    }
    Ok(())
}

fn provider_event_digest(event: &RuntimeProviderStreamEvent) -> &str {
    match event {
        RuntimeProviderStreamEvent::TurnStarted { event_digest }
        | RuntimeProviderStreamEvent::ItemStarted { event_digest }
        | RuntimeProviderStreamEvent::AgentMessageDelta { event_digest, .. }
        | RuntimeProviderStreamEvent::ItemCompleted { event_digest, .. }
        | RuntimeProviderStreamEvent::TurnCompleted { event_digest, .. }
        | RuntimeProviderStreamEvent::LocalApprovalRequested { event_digest, .. }
        | RuntimeProviderStreamEvent::Diagnostic { event_digest }
        | RuntimeProviderStreamEvent::Other { event_digest } => event_digest,
    }
}

fn runtime_input_digest(invocation_id: &str, objective: &str) -> String {
    sha256(
        format!(
            "runtime-input:{invocation_id}:{}",
            sha256(objective.as_bytes())
        )
        .as_bytes(),
    )
}

fn canonical_digest(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    Ok(sha256(&serde_json::to_vec(value)?))
}

fn digest(bytes: &[u8]) -> String {
    sha256(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        Mission, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor,
        MissionCheckpointRoute, MissionContract, MissionConversation, MissionDefinition,
        OperatingMode, Project, StorageMode, Task, TaskId, TenantId,
    };
    use hartevo_runtime_adapter::{
        APP_SERVER_SCHEMA_SHA256, OPENINTERPRETER_COMMIT, OPENINTERPRETER_RELEASE,
        RUNTIME_RESULT_PACKET_SCHEMA, ResolvedSecret, RuntimeBudget, RuntimeDataBoundary,
        RuntimeEndpointClass, RuntimeHarnessDescriptor, RuntimeModelDescriptor,
        RuntimeProviderDescriptor, RuntimeResultAuthority, RuntimeResultKind, SecretReference,
    };
    use hartevo_storage::PendingEvent;
    use tempfile::TempDir;

    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    struct FakeResolver;

    impl SecretResolver for FakeResolver {
        fn resolve(&self, _reference: &SecretReference) -> Result<ResolvedSecret, AdapterError> {
            ResolvedSecret::new("fake-secret")
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum FakeFault {
        None,
        LateIdentity,
        CursorDrift,
    }

    #[derive(Clone, Debug)]
    struct FakeFactory {
        fault: FakeFault,
    }

    struct FakeProvider {
        identity: MissionRuntimeProviderIdentity,
        events: VecDeque<MissionRuntimeStreamPacket>,
        revoked: bool,
    }

    impl MissionExecutionProviderFactory for FakeFactory {
        #[allow(
            clippy::too_many_lines,
            reason = "the fake factory constructs one complete typed stream journey"
        )]
        fn mount(
            &self,
            selection: &OpenInterpreterMissionRuntimeSelection,
            _log: Box<dyn MissionSessionLog>,
            _resolver: &dyn SecretResolver,
        ) -> Result<Box<dyn MissionExecutionProvider>, MissionExecutionError> {
            let scope = selection.scope()?;
            let identity = MissionRuntimeProviderIdentity {
                project_id: selection.project_id.to_string(),
                mission_id: selection.mission_id.to_string(),
                scope_digest: scope.scope_digest,
                provider_manifest_digest: selection.provider_manifest_digest.clone(),
                runtime_config_digest: selection.config.digest()?,
                catalog_digest: selection.catalog.digest()?,
                policy_digest: selection.policy.digest()?,
                runtime_generation: selection.runtime_generation,
                runtime_instance_digest: "1".repeat(64),
                mapping_digest: "2".repeat(64),
                mount_digest: "3".repeat(64),
            };
            let start_digest = digest(b"fake-turn-started");
            let delta_digest = digest(b"fake-delta");
            let result_digest = digest(b"fake-result-event");
            let item_id_digest = digest(b"fake-item");
            let result_body = "adoptable result from fake provider";
            let result = RuntimeResultPacket {
                schema: RUNTIME_RESULT_PACKET_SCHEMA.to_owned(),
                authority: RuntimeResultAuthority::LocalExecutionEvidence,
                result_kind: RuntimeResultKind::AgentMessage,
                project_id: identity.project_id.clone(),
                mission_id: identity.mission_id.clone(),
                runtime_generation: identity.runtime_generation,
                runtime_instance_digest: identity.runtime_instance_digest.clone(),
                runtime_commit: OPENINTERPRETER_COMMIT.to_owned(),
                runtime_release: OPENINTERPRETER_RELEASE.to_owned(),
                mapping_digest: identity.mapping_digest.clone(),
                runtime_thread_id_digest: "4".repeat(64),
                runtime_turn_id_digest: "5".repeat(64),
                app_server_schema_digest: format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
                runtime_config_digest: identity.runtime_config_digest.clone(),
                catalog_digest: identity.catalog_digest.clone(),
                source_item_id_digest: item_id_digest.clone(),
                source_event_digest: result_digest.clone(),
                content_digest: digest(result_body.as_bytes()),
                content_byte_count: result_body.len() as u64,
                content: result_body.to_owned(),
            };
            result.validate()?;
            let event_identity = if matches!(self.fault, FakeFault::LateIdentity) {
                let mut late = identity.clone();
                late.runtime_generation += 1;
                late
            } else {
                identity.clone()
            };
            let first_cursor = if matches!(self.fault, FakeFault::CursorDrift) {
                2
            } else {
                1
            };
            let events = VecDeque::from([
                MissionRuntimeStreamPacket {
                    identity: event_identity.clone(),
                    cursor: first_cursor,
                    event: RuntimeProviderStreamEvent::TurnStarted {
                        event_digest: start_digest,
                    },
                },
                MissionRuntimeStreamPacket {
                    identity: identity.clone(),
                    cursor: 2,
                    event: RuntimeProviderStreamEvent::AgentMessageDelta {
                        event_digest: delta_digest,
                        item_id_digest,
                        content: "partial result".to_owned(),
                    },
                },
                MissionRuntimeStreamPacket {
                    identity: identity.clone(),
                    cursor: 3,
                    event: RuntimeProviderStreamEvent::ItemCompleted {
                        event_digest: result_digest.clone(),
                        result: Some(Box::new(result.clone())),
                        recovery_hint: None,
                    },
                },
                MissionRuntimeStreamPacket {
                    identity: identity.clone(),
                    cursor: 3,
                    event: RuntimeProviderStreamEvent::ItemCompleted {
                        event_digest: result_digest,
                        result: Some(Box::new(result)),
                        recovery_hint: None,
                    },
                },
                MissionRuntimeStreamPacket {
                    identity: identity.clone(),
                    cursor: 4,
                    event: RuntimeProviderStreamEvent::TurnCompleted {
                        event_digest: digest(b"fake-terminal"),
                        status: AdapterTurnStatus::Completed,
                    },
                },
            ]);
            Ok(Box::new(FakeProvider {
                identity,
                events,
                revoked: false,
            }))
        }
    }

    impl MissionExecutionProvider for FakeProvider {
        fn current_identity(
            &self,
        ) -> Result<MissionRuntimeProviderIdentity, MissionExecutionError> {
            Ok(self.identity.clone())
        }

        fn start_invocation(
            &mut self,
            _invocation_id: &str,
            _objective: &str,
            _timeout: Duration,
        ) -> Result<(), MissionExecutionError> {
            Ok(())
        }

        fn next_event(
            &mut self,
            _timeout: Duration,
        ) -> Result<MissionRuntimeStreamPacket, MissionExecutionError> {
            if self.revoked {
                return Err(MissionExecutionError::ProviderUnavailable);
            }
            self.events
                .pop_front()
                .ok_or(MissionExecutionError::ProviderUnavailable)
        }

        fn interrupt(
            &mut self,
            _timeout: Duration,
        ) -> Result<MissionExecutionWriteReceipt, MissionExecutionError> {
            Ok(MissionExecutionWriteReceipt {
                request_digest: digest(b"fake-interrupt-request"),
                response_digest: digest(b"fake-interrupt-response"),
            })
        }

        fn revoke(&mut self) -> Result<(), MissionExecutionError> {
            self.revoked = true;
            Ok(())
        }
    }

    struct Fixture {
        service: super::super::ApplicationService,
        project_id: ProjectId,
        mission_id: MissionId,
        root: TempDir,
        now: DateTime<Utc>,
    }

    impl Fixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the fixture builds the exact Project/Mission/Conversation storage boundary"
        )]
        fn new() -> Self {
            let now = Utc
                .with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
                .single()
                .expect("valid fixture time");
            let root = tempfile::tempdir().expect("fixture workspace");
            let project_id = ProjectId::from("openinterpreter-project");
            let mission_id = MissionId::from("openinterpreter-mission");
            let project = Project::create_local(
                TenantId::from("openinterpreter-tenant"),
                project_id.clone(),
                "OpenInterpreter fixture",
                "Application consumer fixture",
                root.path(),
                StorageMode::LocalExisting,
            )
            .expect("project");
            let mut store = ProjectStore::in_memory().expect("store");
            store
                .create_project_atomic(
                    &project,
                    &[PendingEvent::new(
                        "project.created",
                        json!({"fixture": true}),
                        now,
                    )],
                )
                .expect("project persisted");
            let contract = MissionContract::bootstrap(
                "Return a concise adoption-ready result.",
                ["runtime.execute".to_owned()],
                now,
            );
            let catalog_digest = "a".repeat(64);
            let route = MissionCheckpointRoute::contracted(
                "runtime.execute",
                MissionCheckpointExecutor::Runtime,
                ["runtime.result".to_owned()],
                MissionCheckpointCompletionPolicy::WorkProduct,
            )
            .expect("route");
            let definition = MissionDefinition::from_routed_linear_manifest(
                "VM-00",
                1,
                catalog_digest,
                OperatingMode::BuildOnce,
                ["runtime.execute".to_owned()],
                ["runtime_result".to_owned()],
                ["runtime.result".to_owned()],
                [("runtime".to_owned(), route)],
            )
            .expect("definition");
            let mut mission = Mission::compile_catalog(
                project.tenant_id.clone(),
                mission_id.clone(),
                project_id.clone(),
                "OpenInterpreter fixture Mission",
                contract,
                definition,
                now,
            )
            .expect("mission");
            mission
                .start_research(
                    [Task {
                        id: TaskId::from("openinterpreter-task"),
                        title: "Run Runtime provider".to_owned(),
                        status: hartevo_domain_kernel::TaskStatus::Running,
                        capability: "runtime.execute".to_owned(),
                    }],
                    now,
                )
                .expect("mission started");
            let conversation = MissionConversation::start(
                hartevo_domain_kernel::MissionConversationId::from("openinterpreter-conversation"),
                hartevo_domain_kernel::MissionConversationMessageId::from(
                    "openinterpreter-goal-message",
                ),
                &mission,
                mission.contract.goal.clone(),
                "fixture:mission-start",
                now,
            )
            .expect("conversation");
            store
                .create_catalog_mission_with_conversation_atomic(
                    &mission,
                    &conversation,
                    &[PendingEvent::new(
                        "mission.started",
                        json!({"fixture": true}),
                        now,
                    )],
                )
                .expect("mission persisted");
            Self {
                service: super::super::ApplicationService::new(store),
                project_id,
                mission_id,
                root,
                now,
            }
        }

        fn selection(&self) -> OpenInterpreterMissionRuntimeSelection {
            let provider_revision = "b".repeat(64);
            let model_revision = "c".repeat(64);
            let harness_revision = "d".repeat(64);
            let catalog = RuntimeCatalog::new(
                "fake-runtime-v1",
                format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
                vec![RuntimeProviderDescriptor {
                    id: "fake-provider".to_owned(),
                    revision: provider_revision.clone(),
                    endpoint_class: RuntimeEndpointClass::Local,
                    credential_environment_key: None,
                    configured: true,
                }],
                vec![RuntimeModelDescriptor {
                    provider_id: "fake-provider".to_owned(),
                    id: "fake-model".to_owned(),
                    revision: model_revision.clone(),
                    supported_reasoning_efforts: vec!["medium".to_owned()],
                    service_tiers: Vec::new(),
                }],
                vec![RuntimeHarnessDescriptor {
                    provider_id: "fake-provider".to_owned(),
                    model_id: Some("fake-model".to_owned()),
                    id: "fake-harness".to_owned(),
                    revision: harness_revision.clone(),
                    recommended: true,
                }],
            )
            .expect("runtime catalog");
            let config = RuntimeExecutionConfig::new(
                "fake-provider",
                provider_revision,
                "fake-model",
                model_revision,
                "fake-harness",
                harness_revision,
                Some("medium".to_owned()),
                None,
                RuntimeEndpointClass::Local,
                RuntimeBudget::new(8_192, 4_096, 4, 60_000).expect("budget"),
                RuntimeDataBoundary::ProjectLocal,
                SecretReference::new(
                    "fake-provider",
                    "fake-account",
                    "keyring/fake",
                    "f".repeat(64),
                    1,
                )
                .expect("secret reference"),
                catalog.digest().expect("catalog digest"),
            )
            .expect("runtime config");
            OpenInterpreterMissionRuntimeSelection {
                project_id: self.project_id.clone(),
                mission_id: self.mission_id.clone(),
                session_id: "fake-session".to_owned(),
                provider_manifest_digest: "e".repeat(64),
                runtime_command: RuntimeCommand::new("/bin/sh", self.root.path()),
                workspace_root: self.root.path().to_path_buf(),
                catalog,
                config,
                policy: RuntimeProviderPolicy::new(32, 16_384, 10_000, "USD").expect("policy"),
                runtime_generation: 1,
                timeout: Duration::from_secs(1),
            }
        }

        fn start(&mut self, factory: &FakeFactory) -> OpenInterpreterMissionExecution {
            self.selection().validate().expect("selection valid");
            let mission = self
                .service
                .load_mission(&self.project_id, &self.mission_id)
                .expect("mission");
            let conversation = self
                .service
                .mission_conversation(&self.project_id, &self.mission_id)
                .expect("conversation");
            self.service
                .start_openinterpreter_mission(
                    StartOpenInterpreterMission {
                        project_id: self.project_id.clone(),
                        mission_id: self.mission_id.clone(),
                        invocation_id: "fake-invocation".to_owned(),
                        objective: mission.contract.goal.clone(),
                        expected_project_revision: 1,
                        expected_mission_revision: mission.revision,
                        expected_conversation_revision: conversation.revision,
                        runtime: self.selection(),
                    },
                    factory,
                    &FakeResolver,
                    self.now,
                )
                .expect("execution started")
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression journey intentionally covers input, stream, adoption, replay, and terminal projection"
    )]
    fn fake_provider_journey_persists_input_stream_and_selected_result_once() {
        let mut fixture = Fixture::new();
        let factory = FakeFactory {
            fault: FakeFault::None,
        };
        let mut execution = fixture.start(&factory);
        let after_input = fixture
            .service
            .mission_conversation(&fixture.project_id, &fixture.mission_id)
            .expect("input conversation");
        assert_eq!(after_input.revision, 2);
        assert_eq!(
            after_input.messages.last().expect("input message").body,
            "Return a concise adoption-ready result."
        );

        assert!(matches!(
            fixture
                .service
                .observe_openinterpreter_mission(
                    &mut execution,
                    0,
                    Duration::from_secs(1),
                    fixture.now
                )
                .expect("turn started"),
            MissionExecutionObservation::TurnStarted { .. }
        ));
        assert!(matches!(
            fixture
                .service
                .observe_openinterpreter_mission(
                    &mut execution,
                    1,
                    Duration::from_secs(1),
                    fixture.now
                )
                .expect("delta"),
            MissionExecutionObservation::Delta { .. }
        ));
        let result = fixture
            .service
            .observe_openinterpreter_mission(&mut execution, 2, Duration::from_secs(1), fixture.now)
            .expect("result");
        let selected = match result {
            MissionExecutionObservation::Result {
                work_product_id, ..
            } => work_product_id,
            other => panic!("unexpected result: {other:?}"),
        };
        let events_after_result = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("events")
            .len();
        assert!(matches!(
            fixture
                .service
                .observe_openinterpreter_mission(
                    &mut execution,
                    3,
                    Duration::from_secs(1),
                    fixture.now
                )
                .expect("exact result replay"),
            MissionExecutionObservation::ReplayIgnored { .. }
        ));
        assert_eq!(
            fixture
                .service
                .mission_events(&fixture.project_id, &fixture.mission_id)
                .expect("replayed events")
                .len(),
            events_after_result
        );
        assert!(matches!(
            fixture
                .service
                .observe_openinterpreter_mission(
                    &mut execution,
                    3,
                    Duration::from_secs(1),
                    fixture.now
                )
                .expect("terminal"),
            MissionExecutionObservation::TurnCompleted {
                status: AdapterTurnStatus::Completed,
                ..
            }
        ));
        let mission = fixture
            .service
            .load_mission(&fixture.project_id, &fixture.mission_id)
            .expect("projected mission");
        assert_eq!(mission.work_products.len(), 1);
        assert_eq!(mission.work_products[0].id, selected);
        let conversation = fixture
            .service
            .mission_conversation(&fixture.project_id, &fixture.mission_id)
            .expect("projected conversation");
        assert!(conversation.messages.iter().any(|message| {
            message.kind == MissionConversationMessageKind::RuntimeDraft
                && message.work_product_id.as_ref() == Some(&selected)
                && message.body == "adoptable result from fake provider"
        }));
        assert!(
            conversation
                .messages
                .iter()
                .any(|message| message.body == "partial result")
        );
        let event_types = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("final events")
            .into_iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>();
        assert!(
            event_types
                .iter()
                .any(|event| event == "runtime.result_projected")
        );
        assert!(
            event_types
                .iter()
                .any(|event| event == "work_product.created")
        );
        assert!(
            event_types
                .iter()
                .any(|event| event == "runtime.turn_completed")
        );
    }

    #[test]
    fn interrupt_is_durable_and_does_not_grant_effect_authority() {
        let mut fixture = Fixture::new();
        let mut execution = fixture.start(&FakeFactory {
            fault: FakeFault::None,
        });
        let before = fixture
            .service
            .mission_conversation(&fixture.project_id, &fixture.mission_id)
            .expect("before interrupt")
            .revision;

        let receipt = fixture
            .service
            .interrupt_openinterpreter_mission(&mut execution, Duration::from_secs(1), fixture.now)
            .expect("interrupt");

        assert!(is_digest(&receipt.request_digest));
        assert!(is_digest(&receipt.response_digest));
        assert_eq!(
            execution.invocation().state,
            MissionExecutionState::InterruptRequested
        );
        let conversation = fixture
            .service
            .mission_conversation(&fixture.project_id, &fixture.mission_id)
            .expect("interrupted conversation");
        assert_eq!(conversation.revision, before + 1);
        assert_eq!(
            conversation
                .messages
                .last()
                .expect("interrupt message")
                .body,
            "Runtime interrupt requested"
        );
        let events = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("interrupt events");
        let interrupt_event = events
            .iter()
            .find(|event| event.event_type == "runtime.interrupt_requested")
            .expect("interrupt event");
        assert_eq!(
            interrupt_event
                .payload
                .get("externalEffectReplayed")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn reselect_revoke_and_late_packets_fail_closed_without_growth() {
        let mut fixture = Fixture::new();
        let factory = FakeFactory {
            fault: FakeFault::None,
        };
        let mut execution = fixture.start(&factory);
        let before_reselect = fixture
            .service
            .mission_conversation(&fixture.project_id, &fixture.mission_id)
            .expect("before reselect")
            .revision;
        let mut changed = execution.selection().clone();
        changed.runtime_generation = 2;
        assert!(matches!(
            fixture
                .service
                .reselect_openinterpreter_mission(&execution, &changed),
            Err(super::super::ApplicationError::MissionExecution(
                MissionExecutionError::ReselectRequiresNewInvocation
            ))
        ));
        assert_eq!(
            fixture
                .service
                .mission_conversation(&fixture.project_id, &fixture.mission_id)
                .expect("reselect conversation")
                .revision,
            before_reselect
        );
        fixture
            .service
            .revoke_openinterpreter_mission(&mut execution, fixture.now)
            .expect("revoke");
        let after_revoke = fixture
            .service
            .mission_conversation(&fixture.project_id, &fixture.mission_id)
            .expect("after revoke")
            .revision;
        fixture
            .service
            .revoke_openinterpreter_mission(&mut execution, fixture.now)
            .expect("idempotent revoke");
        assert_eq!(
            fixture
                .service
                .mission_conversation(&fixture.project_id, &fixture.mission_id)
                .expect("replayed revoke")
                .revision,
            after_revoke
        );
        assert!(matches!(
            fixture.service.observe_openinterpreter_mission(
                &mut execution,
                0,
                Duration::from_secs(1),
                fixture.now
            ),
            Err(super::super::ApplicationError::MissionExecution(
                MissionExecutionError::RevokedExecution
            ))
        ));
    }

    #[test]
    fn cross_scope_and_cursor_or_generation_drift_write_nothing() {
        let mut cross_scope = Fixture::new();
        let mut command_selection = cross_scope.selection();
        command_selection.mission_id = MissionId::from("other-mission");
        let mission = cross_scope
            .service
            .load_mission(&cross_scope.project_id, &cross_scope.mission_id)
            .expect("mission");
        let conversation = cross_scope
            .service
            .mission_conversation(&cross_scope.project_id, &cross_scope.mission_id)
            .expect("conversation");
        let result = cross_scope.service.start_openinterpreter_mission(
            StartOpenInterpreterMission {
                project_id: cross_scope.project_id.clone(),
                mission_id: cross_scope.mission_id.clone(),
                invocation_id: "cross-scope-invocation".to_owned(),
                objective: mission.contract.goal,
                expected_project_revision: 1,
                expected_mission_revision: mission.revision,
                expected_conversation_revision: conversation.revision,
                runtime: command_selection,
            },
            &FakeFactory {
                fault: FakeFault::None,
            },
            &FakeResolver,
            cross_scope.now,
        );
        assert!(matches!(
            result,
            Err(super::super::ApplicationError::MissionExecution(
                MissionExecutionError::ScopeMismatch
            ))
        ));
        assert_eq!(
            cross_scope
                .service
                .mission_events(&cross_scope.project_id, &cross_scope.mission_id)
                .expect("cross-scope events")
                .len(),
            1
        );

        let mut drift = Fixture::new();
        let mut execution = drift.start(&FakeFactory {
            fault: FakeFault::LateIdentity,
        });
        let before = drift
            .service
            .mission_conversation(&drift.project_id, &drift.mission_id)
            .expect("drift conversation")
            .revision;
        assert!(matches!(
            drift.service.observe_openinterpreter_mission(
                &mut execution,
                0,
                Duration::from_secs(1),
                drift.now
            ),
            Err(super::super::ApplicationError::MissionExecution(
                MissionExecutionError::LatePacket
            ))
        ));
        assert_eq!(
            drift
                .service
                .mission_conversation(&drift.project_id, &drift.mission_id)
                .expect("late packet conversation")
                .revision,
            before
        );

        let mut cursor = Fixture::new();
        let mut execution = cursor.start(&FakeFactory {
            fault: FakeFault::CursorDrift,
        });
        let before = cursor
            .service
            .mission_conversation(&cursor.project_id, &cursor.mission_id)
            .expect("cursor conversation")
            .revision;
        assert!(matches!(
            cursor.service.observe_openinterpreter_mission(
                &mut execution,
                0,
                Duration::from_secs(1),
                cursor.now
            ),
            Err(super::super::ApplicationError::MissionExecution(
                MissionExecutionError::CursorDrift
            ))
        ));
        assert_eq!(
            cursor
                .service
                .mission_conversation(&cursor.project_id, &cursor.mission_id)
                .expect("cursor packet conversation")
                .revision,
            before
        );
    }
}

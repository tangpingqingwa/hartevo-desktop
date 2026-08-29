use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use hartevo_application::{
    AcceptWorkProduct, AdoptRuntimeTurnDraft, AppendMissionConversationMessage, ApplicationError,
    ApplicationMissionCheckpointExecution, ApplicationService, ApproveProposedEffect,
    CatalogMissionExecutionHandle, ConfirmHumanMissionCheckpoint, ContinueBrowserWorkspace,
    CreateProject, DecideVm11OutcomeReview, DesktopInventoryProjection,
    DesktopUnlockedProjectProjection, DispatchContextRuntimeTurn,
    EnsureFailedLocalMissionRuntimeGenerationRetired, ExecuteApplicationMissionCheckpoint,
    FenceOrphanedContextRuntimeTurn, InterruptContextRuntimeTurn, KeyAdministrationAuthorization,
    MissionCheckpointDispatchState, MissionRuntimeProjection, ObserveContextRuntimeTurn,
    PrepareLocalMissionRuntimeContext, ProjectContextMaterialSession, ProjectEncryptionReadiness,
    ProvisionProjectEncryption, RecoverContextWorkerRuntime, RecoverPersonalProjectDevice,
    RelationshipConversationProjection, ResearchPacket, ResolveVm11NextContractOrValidTerminal,
    RespondContextRuntimeLocalApproval, RetryContextWorkerRuntime, ReviewCreatorDeliverable,
    RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionCursor, RuntimeTextSubscriptionError,
    RuntimeTurnDispatchDisposition, StartCatalogMission, StartMission,
    Vm11NextContractOrValidTerminalResult,
};
use hartevo_browser_adapter::{
    BrowserControlHost, BrowserControlState, BrowserError, BrowserWorkspace,
};
use hartevo_catalog::{
    Catalog, CatalogError, EvidenceLevel, MissionEvidenceStatus, ReleaseEvidence,
};
use hartevo_context_fabric::{ConservativeByteBudgetTokenizer, ContextAssemblyStatus};
#[cfg(test)]
use hartevo_cordis::{AgentStep, AgentStepResult};
use hartevo_cordis::{
    AuthorityDispatchError, AuthorityScope, CordisError, CordisHost, RuntimeBinding,
    RuntimeRecordBinding,
};
use hartevo_domain_kernel::{
    AcceptanceCheck, AccountId, ActorId, Approval, ApprovalDecision, BrowserControlLeaseId,
    BrowserWorkspaceId, CompanyId, ConnectionId, ConsentRecord, ConsentState, ConsentStatus,
    ContactChannel, Conversation, ConversationId, CreatorTaskId, CurrencyCode, DeliverableId,
    DeviceId, EffectClass, EffectId, KeyManagementError, KeyRecipient, KpiContract,
    MessagingGateway, Mission, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor,
    MissionConversationMessageId, MissionConversationMessageKind, MissionConversationRole,
    MissionId, MissionStage, Money, OperatingMode, OutcomeDecision, PersonId,
    ProjectEncryptionMode, ProjectId, ProjectKeyring, ReviewDecision, ReviewId,
    RuntimeRecoveryAttempt, RuntimeRecoveryStatus, RuntimeResumeStrategy, RuntimeTurnAttempt,
    RuntimeTurnAttemptId, RuntimeTurnStatus, StorageMode, TaskId, TenantId, WorkProductId,
    WorkerHandleStatus,
};
use hartevo_effect_broker::{EffectBroker, EffectPolicy, EffectRateLimit};
use hartevo_runtime_adapter::{MappedTurnEventKind, RuntimeCommand, RuntimeLocalApprovalKind};
use hartevo_storage::{
    ContextMaterialStoreError, DatabaseKey, KeyMaterial, OsSecretStore, ProjectStore,
    RuntimeTurnStartupReconciliation, SecretBytes, SecretReference, SecretStore, SecretStoreError,
    StorageError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(test)]
use crate::cordis_host::{
    bind_live_domain_kernel, bind_live_domain_kernel_scope as bind_host_live_domain_kernel_scope,
};
use crate::cordis_host::{dispatch_live_runtime, mount_cordis_host};
use crate::runtime_plane::{
    DesktopRuntimeAvailabilityStatus, DesktopRuntimeConfiguration, DesktopRuntimeProjection,
    discover_runtime, ensure_project_runtime_home,
};
use crate::runtime_subscription::DesktopCatalogRuntimeDispatchAuthority;

const DATA_DIRECTORY_ENV: &str = "HARTEVO_DESKTOP_DATA_DIR";
const DATABASE_FILE_NAME: &str = "hartevo.sqlite3";
const OS_SECRET_SERVICE: &str = "com.hartevo.desktop";

/// One process-wide Cordis/DataPlane coordinator for all production UI paths.
static DESKTOP_DATA_PLANE: OnceLock<DesktopDataPlane> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionContractEvidenceProjection {
    pub mission_id: String,
    pub title: String,
    pub modes: Vec<String>,
    pub default_cadence: String,
    pub evidence_level: EvidenceLevel,
    pub status: MissionEvidenceStatus,
    pub failure_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductEvidenceProjection {
    pub catalog_digest: String,
    pub release_passed: bool,
    pub missions: Vec<MissionContractEvidenceProjection>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DesktopSnapshot {
    pub inventory: DesktopInventoryProjection,
    pub context_access: Vec<ProjectContextAccessProjection>,
    pub runtime_reconciliation: RuntimeTurnStartupReconciliation,
    pub runtime: DesktopRuntimeProjection,
    pub runtime_activity: Vec<MissionRuntimeProjection>,
    pub product_evidence: ProductEvidenceProjection,
}

/// One assistant text item reconstructed from the encrypted, integrity-checked
/// Runtime delta ledger. The raw Runtime item identifier never crosses this
/// boundary; only its digest is exposed so Dioxus can keep stable paragraph
/// identity while a stream grows.
#[derive(Clone, Eq, PartialEq)]
pub struct DesktopRuntimeTextItemProjection {
    pub item_id_digest: String,
    pub text: String,
    pub delta_count: usize,
    pub last_stream_sequence: u64,
    pub cumulative_byte_count: u64,
    pub observed_at: DateTime<Utc>,
}

impl fmt::Debug for DesktopRuntimeTextItemProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeTextItemProjection")
            .field("item_id_digest", &self.item_id_digest)
            .field("text_byte_count", &self.text.len())
            .field("delta_count", &self.delta_count)
            .field("last_stream_sequence", &self.last_stream_sequence)
            .field("cumulative_byte_count", &self.cumulative_byte_count)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// Context-gated private text for the newest Runtime turn of one exact
/// Project/Mission. This is deliberately separate from `DesktopSnapshot`: an
/// inventory refresh must never hydrate private text for every project, and a
/// locked Device context must continue to expose metadata only.
#[derive(Clone, Eq, PartialEq)]
pub struct DesktopRuntimeTextStreamProjection {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub worker_generation: u64,
    pub turn_revision: u64,
    pub turn_status: RuntimeTurnStatus,
    pub last_evidence_sequence: Option<u64>,
    pub delta_count: usize,
    pub items: Vec<DesktopRuntimeTextItemProjection>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for DesktopRuntimeTextStreamProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeTextStreamProjection")
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("worker_generation", &self.worker_generation)
            .field("turn_revision", &self.turn_revision)
            .field("turn_status", &self.turn_status)
            .field("last_evidence_sequence", &self.last_evidence_sequence)
            .field("delta_count", &self.delta_count)
            .field("item_count", &self.items.len())
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesktopMissionRuntimeOutcome {
    CheckpointRouted {
        checkpoint_id: String,
        capability_id: String,
        executor: MissionCheckpointExecutor,
        oracle_ids: BTreeSet<String>,
        completion_policy: MissionCheckpointCompletionPolicy,
        state: MissionCheckpointDispatchState,
    },
    ApplicationCheckpointCompleted {
        checkpoint_id: String,
        evidence_digest: String,
    },
    ApplicationCheckpointNotImplemented {
        checkpoint_id: String,
        capability_id: String,
    },
    NotStarted {
        availability: DesktopRuntimeAvailabilityStatus,
    },
    ContextBlocked {
        status: ContextAssemblyStatus,
    },
    RuntimeStartFailed,
    DispatchFailed,
    Uncertain,
    ReplaySuppressed {
        turn_status: RuntimeTurnStatus,
    },
    Failed,
    Interrupted,
    CompletedWithoutArtifact,
    DraftReady {
        work_product_id: WorkProductId,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct DesktopMissionSubmission {
    pub snapshot: DesktopSnapshot,
    pub mission_id: MissionId,
    pub runtime_outcome: DesktopMissionRuntimeOutcome,
}

/// Cooperative UI-to-coordinator stop request for one bounded local Runtime
/// turn. Requesting stop never hides the task or kills a process by PID; the
/// coordinator converts it into the version-fenced Runtime interrupt command
/// while it still owns the exact managed process and turn attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopRuntimeProgressPhase {
    Preparing,
    Dispatched,
    TurnStarted,
    ItemStarted,
    ItemCompleted,
    LocalActionDeclined,
    WaitingLocalApproval,
    LocalActionApproved,
    StopRequested,
    InterruptSent,
    Completed,
    Interrupted,
    Failed,
    Uncertain,
}

impl DesktopRuntimeProgressPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Interrupted | Self::Failed | Self::Uncertain
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopRuntimeProgressEvent {
    pub sequence: u64,
    pub phase: DesktopRuntimeProgressPhase,
}

#[derive(Debug, Default)]
struct DesktopRuntimeProgressFeed {
    next_sequence: u64,
    events: VecDeque<DesktopRuntimeProgressEvent>,
}

#[derive(Clone, Debug, Default)]
pub struct DesktopRuntimeCancellation {
    requested: Arc<AtomicBool>,
    progress: Arc<Mutex<DesktopRuntimeProgressFeed>>,
    local_approval: Arc<Mutex<Option<DesktopHeldLocalApproval>>>,
    local_approval_decision: Arc<Mutex<Option<bool>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopHeldLocalApproval {
    pub project_id: ProjectId,
    pub turn_id: RuntimeTurnAttemptId,
    pub expected_revision: u64,
    pub request_digest: String,
    pub kind: RuntimeLocalApprovalKind,
}

impl DesktopRuntimeCancellation {
    pub fn request(&self) {
        if !self.requested.swap(true, Ordering::AcqRel) {
            self.record_progress(DesktopRuntimeProgressPhase::StopRequested);
        }
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub fn held_local_approval(&self) -> Option<DesktopHeldLocalApproval> {
        self.local_approval
            .lock()
            .ok()
            .and_then(|held| held.clone())
    }

    pub fn approve_held_local_write(
        &self,
        project_id: &ProjectId,
        turn_id: &RuntimeTurnAttemptId,
        expected_revision: u64,
        request_digest: &str,
    ) -> Result<(), DesktopDataError> {
        self.decide_held_local_write(project_id, turn_id, expected_revision, request_digest, true)
    }

    fn decide_held_local_write(
        &self,
        project_id: &ProjectId,
        turn_id: &RuntimeTurnAttemptId,
        expected_revision: u64,
        request_digest: &str,
        approved: bool,
    ) -> Result<(), DesktopDataError> {
        let held = self
            .held_local_approval()
            .ok_or(DesktopDataError::RuntimeLocalApprovalUnavailable)?;
        if &held.project_id != project_id
            || &held.turn_id != turn_id
            || held.expected_revision != expected_revision
            || held.request_digest != request_digest
        {
            return Err(DesktopDataError::RuntimeLocalApprovalMismatch);
        }
        let mut decision = self
            .local_approval_decision
            .lock()
            .map_err(|_| DesktopDataError::RuntimeLocalApprovalUnavailable)?;
        if decision.is_some() {
            return Err(DesktopDataError::RuntimeLocalApprovalUnavailable);
        }
        *decision = Some(approved);
        Ok(())
    }

    fn hold_local_approval(&self, held: DesktopHeldLocalApproval) {
        if let Ok(mut slot) = self.local_approval.lock() {
            *slot = Some(held);
        }
        if let Ok(mut decision) = self.local_approval_decision.lock() {
            *decision = None;
        }
        self.record_progress(DesktopRuntimeProgressPhase::WaitingLocalApproval);
    }

    fn take_local_approval_decision(&self) -> Option<bool> {
        self.local_approval_decision
            .lock()
            .ok()
            .and_then(|mut decision| decision.take())
    }

    fn clear_held_local_approval(&self) {
        if let Ok(mut slot) = self.local_approval.lock() {
            *slot = None;
        }
        if let Ok(mut decision) = self.local_approval_decision.lock() {
            *decision = None;
        }
    }

    pub fn progress_since(&self, sequence: u64) -> Vec<DesktopRuntimeProgressEvent> {
        self.progress
            .lock()
            .map(|feed| {
                feed.events
                    .iter()
                    .filter(|event| event.sequence > sequence)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn record_progress(&self, phase: DesktopRuntimeProgressPhase) {
        let Ok(mut feed) = self.progress.lock() else {
            return;
        };
        if phase.is_terminal() && feed.events.iter().any(|event| event.phase.is_terminal()) {
            return;
        }
        feed.next_sequence = feed.next_sequence.saturating_add(1);
        let sequence = feed.next_sequence;
        feed.events
            .push_back(DesktopRuntimeProgressEvent { sequence, phase });
        while feed.events.len() > 128 {
            feed.events.pop_front();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopCatalogMissionRequest {
    pub project_id: ProjectId,
    pub manifest_id: String,
    pub mode: OperatingMode,
    pub parent_mission_id: Option<MissionId>,
    pub title: Option<String>,
    pub goal: String,
    pub market: String,
    pub language: String,
    pub audience: String,
    pub timezone: String,
    pub kpis: BTreeMap<String, KpiContract>,
    pub budget_minor: i64,
    pub currency: String,
}

/// Result of the atomic Catalog Mission start only. A durable, content-free
/// handle is available for later Runtime-text pulls, but no Runtime or Effect
/// has been dispatched and the handle is not execution-start evidence.
#[derive(Clone, PartialEq)]
pub struct DesktopCatalogMissionExecutionStart {
    pub snapshot: DesktopSnapshot,
    pub handle: CatalogMissionExecutionHandle,
}

impl fmt::Debug for DesktopCatalogMissionExecutionStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopCatalogMissionExecutionStart")
            .field("handle", &self.handle)
            .field("project_count", &self.snapshot.inventory.projects.len())
            .field("runtime_dispatched", &false)
            .field("external_effect_executed", &false)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopMissionContinuationRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub message_id: MissionConversationMessageId,
    pub kind: MissionConversationMessageKind,
    pub body: String,
    pub idempotency_key: String,
    pub expected_conversation_revision: u64,
}

enum DesktopMissionContinuationRuntimeAuthority<'a> {
    Legacy(Option<&'a DesktopRuntimeCancellation>),
    Catalog(Box<DesktopCatalogRuntimeDispatchAuthority>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopHumanCheckpointConfirmationRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub checkpoint_id: String,
    pub message_id: MissionConversationMessageId,
    pub body: String,
    pub idempotency_key: String,
    pub work_product_ids: BTreeSet<WorkProductId>,
    pub expected_mission_revision: u64,
    pub expected_checkpoint_revision: u64,
    pub expected_conversation_revision: u64,
}

/// Exact Desktop-to-Application fence for adopting one projected WorkProduct.
/// The Desktop surface carries these values from the current Mission read
/// model; Application remains the authority that validates and persists the
/// transition.
#[derive(Clone, Eq, PartialEq)]
pub struct DesktopWorkProductAdoptionRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub expected_mission_revision: u64,
    pub expected_work_product_revision: u64,
    pub expected_manifest_version: u64,
}

impl fmt::Debug for DesktopWorkProductAdoptionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopWorkProductAdoptionRequest")
            .field("project_id", &"[REDACTED]")
            .field("mission_id", &"[REDACTED]")
            .field("work_product_id", &"[REDACTED]")
            .field("expected_mission_revision", &self.expected_mission_revision)
            .field(
                "expected_work_product_revision",
                &self.expected_work_product_revision,
            )
            .field("expected_manifest_version", &self.expected_manifest_version)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DesktopVm11OutcomeDecisionRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub action: OutcomeDecision,
    pub message_id: MissionConversationMessageId,
    pub rationale: String,
    pub idempotency_key: String,
    pub expected_review_projection_digest: String,
    pub expected_review_completion_digest: String,
    pub expected_mission_revision: u64,
    pub expected_checkpoint_revision: u64,
    pub expected_conversation_revision: u64,
}

impl fmt::Debug for DesktopVm11OutcomeDecisionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopVm11OutcomeDecisionRequest")
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("action", &self.action)
            .field("message_id", &self.message_id)
            .field("rationale", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field(
                "expected_review_projection_digest",
                &self.expected_review_projection_digest,
            )
            .field(
                "expected_review_completion_digest",
                &self.expected_review_completion_digest,
            )
            .field("expected_mission_revision", &self.expected_mission_revision)
            .field(
                "expected_checkpoint_revision",
                &self.expected_checkpoint_revision,
            )
            .field(
                "expected_conversation_revision",
                &self.expected_conversation_revision,
            )
            .finish()
    }
}

/// Route-specific CAS for VM-11 `next_contract_or_valid_terminal`. The frozen
/// decision digest and parent-contract digest must come from the SQLCipher
/// projection; the window cannot substitute a replacement contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopVm11NextContractResolutionRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub expected_mission_revision: u64,
    pub expected_checkpoint_revision: u64,
    pub expected_decision_digest: String,
    pub expected_parent_mission_revision: u64,
    pub expected_parent_contract_digest: String,
}

/// Window-bound ApprovalGrant for one Proposed Effect. The frozen digest and
/// Mission revision must come from the SQLCipher projection; the window cannot
/// stamp a SAMPLE digest or execute the Effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopWaitingApprovalGrantRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub effect_id: EffectId,
    pub expected_scope_digest: String,
    pub expected_mission_revision: u64,
}

/// Window Continue for one Mission-bound Browser Workspace. The ids, revision
/// and generation must come from the SQLCipher projection; Desktop never
/// invents a workspace or treats Continue as Verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopContinueBrowserWorkspaceRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: BrowserWorkspaceId,
    pub expected_revision: u64,
    pub expected_generation: u64,
}

/// Window Open Conversation for one Mission-bound CRM identity. Person,
/// Connection, gateway, and route digest must come from SQLCipher; Desktop
/// never invents a Conversation or treats Open as Effect or Verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopOpenConversationRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub person_id: PersonId,
    pub company_id: Option<CompanyId>,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub provider: String,
    pub gateway: MessagingGateway,
    pub contact_channel: ContactChannel,
    pub market: String,
    pub route_digest: String,
}

/// Window Review of one exact uploaded Creator Deliverable. Decision is a typed
/// ReviewDecision; Desktop never stamps Verification or prepares a payout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopReviewCreatorDeliverableRequest {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub task_id: CreatorTaskId,
    pub deliverable_id: DeliverableId,
    pub expected_task_revision: u64,
    pub expected_deliverable_revision: u32,
    pub decision: ReviewDecision,
    pub acceptance_checks: Vec<AcceptanceCheck>,
}

#[cfg(any(test, feature = "native-journey"))]
pub(crate) type DesktopRuntimeCommandBuilder = Box<dyn FnOnce(&Path, &Path) -> RuntimeCommand>;

pub(crate) enum DesktopRuntimeSource {
    Pinned(Box<DesktopRuntimeConfiguration>),
    #[cfg(any(test, feature = "native-journey"))]
    Fixture {
        provider: String,
        model: String,
        command_builder: DesktopRuntimeCommandBuilder,
    },
}

struct LocalRuntimeResumePlan {
    generation: u64,
    strategy: RuntimeResumeStrategy,
    resume_thread_id: Option<String>,
}

impl DesktopRuntimeSource {
    fn provider(&self) -> &str {
        match self {
            Self::Pinned(configuration) => &configuration.provider,
            #[cfg(any(test, feature = "native-journey"))]
            Self::Fixture { provider, .. } => provider,
        }
    }

    fn model(&self) -> &str {
        match self {
            Self::Pinned(configuration) => &configuration.model,
            #[cfg(any(test, feature = "native-journey"))]
            Self::Fixture { model, .. } => model,
        }
    }

    fn into_command(
        self,
        project_root: &Path,
        runtime_home: &Path,
    ) -> Result<RuntimeCommand, DesktopDataError> {
        match self {
            Self::Pinned(configuration) => configuration
                .artifact
                .runtime_command(project_root, runtime_home)
                .map_err(|error| DesktopDataError::Application(ApplicationError::Runtime(error))),
            #[cfg(any(test, feature = "native-journey"))]
            Self::Fixture {
                command_builder, ..
            } => Ok(command_builder(project_root, runtime_home)),
        }
    }
}

impl DesktopSnapshot {
    pub fn context_access_for(
        &self,
        project_id: &ProjectId,
    ) -> Option<&ProjectContextAccessProjection> {
        self.context_access
            .iter()
            .find(|projection| &projection.project_id == project_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectContextAccessProjection {
    pub project_id: ProjectId,
    pub status: ProjectContextAccessStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectContextAccessStatus {
    NotProvisioned,
    RotationRequired,
    Ready {
        keyring_revision: u64,
        active_key_version: u64,
        readable_key_versions: Vec<u64>,
    },
    Degraded {
        keyring_revision: u64,
        active_key_version: u64,
        readable_key_versions: Vec<u64>,
        unavailable_historical_key_versions: Vec<u64>,
    },
    RecoveryRequired,
    BlockedEnvironment,
    IntegrityError,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DesktopLoadState {
    Uninitialized {
        product_evidence: ProductEvidenceProjection,
    },
    Ready(Box<DesktopSnapshot>),
}

pub struct RecoveryKitDraft {
    encoded_key: Zeroizing<String>,
}

impl RecoveryKitDraft {
    pub fn generate() -> Result<Self, DesktopDataError> {
        let key = KeyMaterial::generate()?;
        let secret = key.to_secret();
        Ok(Self {
            encoded_key: Zeroizing::new(hex::encode(secret.as_slice())),
        })
    }

    pub fn expose_for_user_export(&self) -> &str {
        self.encoded_key.as_str()
    }
}

impl fmt::Debug for RecoveryKitDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryKitDraft")
            .field("encoded_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct DesktopDataPlane {
    data_root: PathBuf,
    data_root_identity: DataRootIdentity,
    database_path: PathBuf,
    database_key_reference: SecretReference,
    device_id: DeviceId,
    cordis: Arc<Mutex<CordisHost>>,
}

impl DesktopDataPlane {
    fn discover() -> Result<Self, DesktopDataError> {
        Self::at_data_root(default_data_root()?)
    }

    /// Return the single process-wide production DataPlane/Cordis coordinator.
    ///
    /// Tests and native fixtures may still construct isolated planes with
    /// [`Self::at_data_root`]; Dioxus entry points must use this accessor. The
    /// Desktop data root/profile is immutable for the lifetime of the process;
    /// changing it requires an application restart.
    pub fn persistent() -> Result<Self, DesktopDataError> {
        if let Some(plane) = DESKTOP_DATA_PLANE.get() {
            return Ok(plane.clone());
        }
        let candidate = Self::discover()?;
        Ok(Self::install_persistent(&DESKTOP_DATA_PLANE, candidate))
    }

    fn install_persistent(cell: &OnceLock<Self>, candidate: Self) -> Self {
        if cell.set(candidate.clone()).is_ok() {
            return candidate;
        }
        cell.get().cloned().unwrap_or(candidate)
    }

    #[cfg(test)]
    fn shares_cordis_coordinator(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cordis, &other.cordis)
    }

    /// Test-only inspection seam for the isolated Cordis host.
    #[cfg(test)]
    pub fn with_cordis_host<T>(&self, f: impl FnOnce(&mut CordisHost) -> T) -> T {
        f(&mut self.lock_cordis())
    }

    /// Test-only unscoped Domain Kernel fact binding.
    ///
    /// Production `desktop_surfaces()` stays fail-closed. `step` / `apply_effect`
    /// still require these facts; this never stamps `true` at boot.
    #[cfg(test)]
    pub fn bind_live_domain_kernel(
        &self,
        consent: &ConsentState,
        record: Option<&ConsentRecord>,
        approval: Option<&Approval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        bind_live_domain_kernel(&mut self.lock_cordis(), consent, record, approval, now)
    }

    /// Test-only exact Domain Kernel fact binding.
    #[cfg(test)]
    pub fn bind_live_domain_kernel_scope(
        &self,
        scope: AuthorityScope,
        consent: &ConsentState,
        record: Option<&ConsentRecord>,
        approval: Option<&Approval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        bind_host_live_domain_kernel_scope(
            &mut self.lock_cordis(),
            scope,
            consent,
            record,
            approval,
            now,
        )
    }

    /// Test-only legacy symbolic AgentStep; never a production Runtime route.
    #[cfg(test)]
    pub fn step(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        step: AgentStep,
        now: DateTime<Utc>,
    ) -> Result<AgentStepResult, DesktopDataError> {
        self.bind_live_domain_kernel_from_store(secret_store, project_id, mission_id, now)?;
        Ok(self.lock_cordis().step(step)?)
    }

    /// Test-only Effect invariant probe; it never executes an external Effect.
    #[cfg(test)]
    pub fn apply_effect(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<(), DesktopDataError> {
        self.bind_live_domain_kernel_from_store(secret_store, project_id, mission_id, now)?;
        Ok(self.lock_cordis().apply_effect()?)
    }

    pub(crate) fn at_data_root(root: impl AsRef<Path>) -> Result<Self, DesktopDataError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(DesktopDataError::InvalidDataRoot(root.to_path_buf()));
        }
        reject_symlink(root)?;
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        let data_root = root.canonicalize()?;
        let data_root_identity = DataRootIdentity::capture(&data_root)?;
        let database_path = data_root.join(DATABASE_FILE_NAME);
        reject_symlink(&database_path)?;
        let root_digest = format!(
            "{:x}",
            Sha256::digest(data_root.as_os_str().as_encoded_bytes())
        );
        let database_key_reference = SecretReference {
            tenant_id: TenantId::from("local-desktop-installation"),
            project_id: ProjectId::from("desktop-sqlcipher"),
            provider: "os-native".into(),
            account_scope: format!("data-root:{root_digest}"),
            purpose: "desktop_sqlcipher_database_key".into(),
            version: 1,
        };
        let device_id = DeviceId::from_stable(format!("desktop-device:{root_digest}"));
        let cordis = Arc::new(Mutex::new(mount_cordis_host(
            &discover_runtime().projection,
        )?));
        Ok(Self {
            data_root,
            data_root_identity,
            database_path,
            database_key_reference,
            device_id,
            cordis,
        })
    }

    pub fn load_os(&self, now: DateTime<Utc>) -> Result<DesktopLoadState, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.load_with(&secret_store, now)
    }

    pub fn initialize_os(&self, now: DateTime<Utc>) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.initialize_with(&secret_store, now)
    }

    pub fn load_with(
        &self,
        secret_store: &impl SecretStore,
        now: DateTime<Utc>,
    ) -> Result<DesktopLoadState, DesktopDataError> {
        self.revalidate_database_entry()?;
        let product_evidence = load_product_evidence(now)?;
        match secret_store.get(&self.database_key_reference) {
            Ok(secret) => {
                let (service, runtime_reconciliation) =
                    self.open_application_from_secret(&secret, now)?;
                Ok(DesktopLoadState::Ready(Box::new(self.build_snapshot(
                    &service,
                    secret_store,
                    runtime_reconciliation,
                    product_evidence,
                    now,
                )?)))
            }
            Err(SecretStoreError::SecretNotFound) if !self.database_path.exists() => {
                Ok(DesktopLoadState::Uninitialized { product_evidence })
            }
            Err(SecretStoreError::SecretNotFound) => Err(DesktopDataError::MissingDatabaseKey),
            Err(error) => Err(error.into()),
        }
    }

    /// Reads the newest persisted assistant-text stream for one exact Mission.
    ///
    /// This query intentionally does not run startup reconciliation or mutate
    /// Mission/Runtime state. It first proves that the current Device can open
    /// the encrypted Project Context, then reads the latest turn and its
    /// integrity-checked delta chain. A caller that only has inventory access
    /// receives the same recovery/blocked error as every other private-content
    /// path rather than an empty string that could be mistaken for a valid
    /// response.
    pub fn runtime_text_stream_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<Option<DesktopRuntimeTextStreamProjection>, DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_secret = secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })?;
        let service = self.open_read_application_from_secret(&database_secret)?;
        self.require_project_context_access(&service, secret_store, project_id, now)?;
        let Some(attempt) = service.latest_runtime_turn_for_mission(project_id, mission_id)? else {
            return Ok(None);
        };
        let deltas = service.runtime_turn_private_text_deltas(project_id, &attempt.id)?;
        let mut item_indexes = BTreeMap::<String, usize>::new();
        let mut items = Vec::<DesktopRuntimeTextItemProjection>::new();
        for delta in &deltas {
            if let Some(index) = item_indexes.get(&delta.item_id_digest).copied() {
                let item = &mut items[index];
                item.text.push_str(&delta.delta);
                item.delta_count = item.delta_count.saturating_add(1);
                item.last_stream_sequence = delta.stream_sequence;
                item.cumulative_byte_count = delta.cumulative_byte_count;
                item.observed_at = delta.observed_at;
            } else {
                item_indexes.insert(delta.item_id_digest.clone(), items.len());
                items.push(DesktopRuntimeTextItemProjection {
                    item_id_digest: delta.item_id_digest.clone(),
                    text: delta.delta.clone(),
                    delta_count: 1,
                    last_stream_sequence: delta.stream_sequence,
                    cumulative_byte_count: delta.cumulative_byte_count,
                    observed_at: delta.observed_at,
                });
            }
        }
        Ok(Some(DesktopRuntimeTextStreamProjection {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            worker_generation: attempt.scope.worker_generation,
            turn_revision: attempt.revision,
            turn_status: attempt.status,
            last_evidence_sequence: deltas.last().map(|delta| delta.evidence_sequence),
            delta_count: deltas.len(),
            items,
            updated_at: attempt.updated_at,
        }))
    }

    pub fn runtime_text_stream_os(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<Option<DesktopRuntimeTextStreamProjection>, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.runtime_text_stream_with(&secret_store, project_id, mission_id, now)
    }

    /// Creates the installation SQLCipher key only after an explicit Desktop
    /// onboarding action. A key that survived an interrupted first open is
    /// reused; an existing database is never silently rebound to a new key.
    pub fn initialize_with(
        &self,
        secret_store: &impl SecretStore,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        self.revalidate_database_entry()?;
        let secret = match secret_store.get(&self.database_key_reference) {
            Ok(secret) => secret,
            Err(SecretStoreError::SecretNotFound) if self.database_path.exists() => {
                return Err(DesktopDataError::MissingDatabaseKey);
            }
            Err(SecretStoreError::SecretNotFound) => {
                let material = KeyMaterial::generate()?;
                let secret = material.to_secret();
                secret_store.put(&self.database_key_reference, &secret)?;
                secret
            }
            Err(error) => return Err(error.into()),
        };
        let (service, runtime_reconciliation) = self.open_application_from_secret(&secret, now)?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    pub fn start_mission_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        goal: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let goal = goal.trim();
        if goal.is_empty() {
            return Err(DesktopDataError::EmptyMissionGoal);
        }
        let secret = secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })?;
        let (mut service, runtime_reconciliation) =
            self.open_application_from_secret(&secret, now)?;
        let inventory = service.desktop_inventory()?;
        let project = inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
            .ok_or_else(|| DesktopDataError::ProjectNotFound(project_id.clone()))?;
        if !matches!(project.encryption, ProjectEncryptionReadiness::Ready { .. }) {
            return Err(DesktopDataError::ProjectEncryptionNotReady(
                project_id.clone(),
            ));
        }
        self.require_project_context_access(&service, secret_store, project_id, now)?;
        service.start_mission(
            StartMission {
                id: MissionId::new(),
                research_task_id: TaskId::new(),
                project_id: project_id.clone(),
                title: None,
                prompt: goal.into(),
            },
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    pub fn start_mission_os(
        &self,
        project_id: &ProjectId,
        goal: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.start_mission_with(&secret_store, project_id, goal, now)
    }

    /// Creates one durable Mission and, only when a release-pinned Runtime plus
    /// explicit provider/model selection are available, runs its first bounded
    /// local Context turn. Runtime completion never completes the Mission; a
    /// completed agent message is adopted only as a reviewable draft.
    pub fn start_mission_and_run_os(
        &self,
        project_id: &ProjectId,
        goal: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.start_mission_and_run_with(
            &secret_store,
            project_id,
            goal,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    /// Atomically creates one exact Catalog Mission and returns its durable
    /// content-free subscription handle. This path deliberately performs no
    /// startup reconciliation, Runtime dispatch/execution, or Effect work;
    /// the returned snapshot may include a read-only Runtime availability
    /// probe.
    pub fn start_catalog_mission_execution_os(
        &self,
        request: DesktopCatalogMissionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopCatalogMissionExecutionStart, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.start_catalog_mission_execution_with(&secret_store, request, now)
    }

    fn start_catalog_mission_execution_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopCatalogMissionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopCatalogMissionExecutionStart, DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_secret = self.database_secret(secret_store)?;
        let mut service = self.open_read_application_from_secret(&database_secret)?;
        self.require_project_context_access(&service, secret_store, &request.project_id, now)?;
        let command = Self::catalog_mission_start_command(&service, request)?;
        let started = service.start_catalog_mission_execution(command, now)?;
        let handle = started.handle().clone();
        let snapshot = self.build_snapshot(
            &service,
            secret_store,
            no_runtime_turn_startup_reconciliation(),
            load_product_evidence(now)?,
            now,
        )?;
        Ok(DesktopCatalogMissionExecutionStart { snapshot, handle })
    }

    /// Prepare an existing Catalog Mission for a new paint-authorized Runtime
    /// attempt. This read-only phase returns the exact current durable handle;
    /// it never starts a process, reconciles Runtime state, or mints authority.
    pub fn prepare_catalog_mission_runtime_resume_os(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<DesktopCatalogMissionExecutionStart, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.prepare_catalog_mission_runtime_resume_with(&secret_store, project_id, mission_id, now)
    }

    fn prepare_catalog_mission_runtime_resume_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<DesktopCatalogMissionExecutionStart, DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_secret = self.database_secret(secret_store)?;
        let service = self.open_read_application_from_secret(&database_secret)?;
        self.require_project_context_access(&service, secret_store, project_id, now)?;
        let mission = service.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id
            || mission.id != *mission_id
            || mission.definition.is_none()
            || mission.stage.is_terminal()
        {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        let handle = service.mission_execution_handle(project_id, mission_id)?;
        let snapshot = self.build_snapshot(
            &service,
            secret_store,
            no_runtime_turn_startup_reconciliation(),
            load_product_evidence(now)?,
            now,
        )?;
        Ok(DesktopCatalogMissionExecutionStart { snapshot, handle })
    }

    #[cfg(feature = "native-journey")]
    pub(crate) fn start_catalog_mission_execution_native(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopCatalogMissionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopCatalogMissionExecutionStart, DesktopDataError> {
        self.start_catalog_mission_execution_with(secret_store, request, now)
    }

    /// Pulls one integrity-checked page from the encrypted Runtime text ledger
    /// after exact Tenant/Project/Device context authorization. The signed
    /// Application handle and cursor are returned unchanged; this read cannot
    /// reconcile startup state or mutate Mission, Event, Outbox, or Runtime.
    pub fn runtime_text_subscription_os(
        &self,
        handle: &CatalogMissionExecutionHandle,
        cursor: Option<&RuntimeTextSubscriptionCursor>,
        page_size: usize,
        now: DateTime<Utc>,
    ) -> Result<RuntimeTextSubscriptionBatch, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.runtime_text_subscription_with(&secret_store, handle, cursor, page_size, now)
    }

    fn runtime_text_subscription_with(
        &self,
        secret_store: &impl SecretStore,
        handle: &CatalogMissionExecutionHandle,
        cursor: Option<&RuntimeTextSubscriptionCursor>,
        page_size: usize,
        now: DateTime<Utc>,
    ) -> Result<RuntimeTextSubscriptionBatch, DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_secret = self.database_secret(secret_store)?;
        let service = self.open_read_application_from_secret(&database_secret)?;
        self.require_runtime_subscription_context_access(&service, secret_store, handle, now)?;
        Ok(service.read_runtime_text_subscription(handle, cursor, page_size)?)
    }

    #[cfg(feature = "native-journey")]
    pub(crate) fn runtime_text_subscription_native(
        &self,
        secret_store: &impl SecretStore,
        handle: &CatalogMissionExecutionHandle,
        cursor: Option<&RuntimeTextSubscriptionCursor>,
        page_size: usize,
        now: DateTime<Utc>,
    ) -> Result<RuntimeTextSubscriptionBatch, DesktopDataError> {
        self.runtime_text_subscription_with(secret_store, handle, cursor, page_size, now)
    }

    /// Adopts one exact projected WorkProduct through the existing typed
    /// Application consumer.  The Desktop layer adds a product-revision fence
    /// before delegating; it never mutates a Mission or manifest directly.
    pub fn adopt_work_product_os(
        &self,
        request: DesktopWorkProductAdoptionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.adopt_work_product_with(&secret_store, request, now)
    }

    #[cfg(feature = "native-journey")]
    pub(crate) fn adopt_work_product_native(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopWorkProductAdoptionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        self.adopt_work_product_with(secret_store, request, now)
    }

    fn adopt_work_product_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopWorkProductAdoptionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.expected_mission_revision == 0
            || request.expected_work_product_revision == 0
            || request.expected_manifest_version == 0
        {
            return Err(DesktopDataError::WorkProductActionStale);
        }
        let project_id = request.project_id.clone();
        let database_secret = self.database_secret(secret_store)?;
        let read_service = self.open_read_application_from_secret(&database_secret)?;
        self.require_project_context_access(&read_service, secret_store, &project_id, now)?;
        let read_mission = read_service.load_mission(&request.project_id, &request.mission_id)?;
        let read_product = read_mission
            .work_products
            .iter()
            .find(|product| product.id == request.work_product_id)
            .ok_or(DesktopDataError::WorkProductActionStale)?;
        if read_mission.revision != request.expected_mission_revision
            || read_product.revision != request.expected_work_product_revision
        {
            return Err(DesktopDataError::WorkProductActionStale);
        }
        let read_manifest = read_service
            .load_work_product_manifest(&request.project_id, &request.work_product_id)?;
        if read_manifest.version != request.expected_manifest_version {
            return Err(DesktopDataError::WorkProductActionStale);
        }
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        service.accept_work_product(
            &AcceptWorkProduct {
                project_id: request.project_id,
                mission_id: request.mission_id,
                work_product_id: request.work_product_id,
                expected_mission_revision: request.expected_mission_revision,
                expected_manifest_version: request.expected_manifest_version,
            },
            now,
        )?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            load_product_evidence(now)?,
            now,
        )
    }

    /// Test-only direct Catalog runner. Production Catalog execution must use
    /// start-only -> paint -> acknowledge -> exact-handle resume.
    #[cfg(test)]
    fn start_catalog_mission_and_run_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopCatalogMissionRequest,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        self.start_catalog_mission_and_run_with_cancellation(
            secret_store,
            request,
            runtime,
            availability,
            None,
            now,
        )
    }

    #[cfg(test)]
    fn start_catalog_mission_and_run_with_cancellation(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopCatalogMissionRequest,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        cancellation: Option<&DesktopRuntimeCancellation>,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let command = Self::catalog_mission_start_command(&service, request)?;
        let mission = service.start_catalog_mission(command, now)?;
        self.run_existing_mission_runtime_with_cancellation(
            &mut service,
            secret_store,
            runtime_reconciliation,
            &context_session,
            &project_id,
            mission.id,
            runtime,
            availability,
            cancellation,
            now,
        )
    }

    fn catalog_mission_start_command(
        service: &ApplicationService,
        request: DesktopCatalogMissionRequest,
    ) -> Result<StartCatalogMission, DesktopDataError> {
        let vm11 = request.manifest_id == "VM-11";
        if request.goal.trim().is_empty()
            || request.manifest_id.trim().is_empty()
            || (vm11 && request.parent_mission_id.is_none())
            || (!vm11
                && (request.market.trim().is_empty()
                    || request.language.trim().is_empty()
                    || request.audience.trim().is_empty()
                    || request.timezone.trim().is_empty()
                    || request.budget_minor < 0
                    || request.kpis.is_empty()))
        {
            return Err(DesktopDataError::InvalidCatalogMissionContract);
        }
        let project_id = request.project_id;
        let (mode, parent_mission_id, market, language, audience, timezone, kpis, budget) = if vm11
        {
            let parent_mission_id = request
                .parent_mission_id
                .ok_or(DesktopDataError::InvalidCatalogMissionContract)?;
            let parent = service.load_mission(&project_id, &parent_mission_id)?;
            (
                parent.contract.mode.clone(),
                Some(parent_mission_id),
                parent.contract.market.clone(),
                parent.contract.language.clone(),
                parent.contract.audience.clone(),
                parent.contract.timezone.clone(),
                parent.contract.kpis.clone(),
                parent.contract.budget.clone(),
            )
        } else {
            let currency = CurrencyCode::parse(request.currency.trim())
                .map_err(|_| DesktopDataError::InvalidCatalogMissionContract)?;
            (
                request.mode,
                None,
                request.market,
                request.language,
                request.audience,
                request.timezone,
                request.kpis,
                Money::new(request.budget_minor, currency),
            )
        };
        Ok(StartCatalogMission {
            id: MissionId::new(),
            first_task_id: TaskId::new(),
            project_id,
            manifest_id: request.manifest_id,
            mode,
            parent_mission_id,
            title: request.title,
            goal: request.goal,
            market,
            language,
            audience,
            timezone,
            kpis,
            budget,
        })
    }

    fn start_mission_and_run_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        goal: &str,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let goal = goal.trim();
        if goal.is_empty() {
            return Err(DesktopDataError::EmptyMissionGoal);
        }
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, project_id, now)?;
        let mission = service.start_mission(
            StartMission {
                id: MissionId::new(),
                research_task_id: TaskId::new(),
                project_id: project_id.clone(),
                title: None,
                prompt: goal.into(),
            },
            now,
        )?;
        self.run_existing_mission_runtime_with(
            &mut service,
            secret_store,
            runtime_reconciliation,
            &context_session,
            project_id,
            mission.id,
            runtime,
            availability,
            now,
        )
    }

    /// Safely resumes the bounded local Runtime work for one existing Mission.
    /// The durable recovery and turn ledgers decide whether this retries the
    /// current generation, retires an exhausted generation, or suppresses an
    /// unsafe replay; this method never creates a second Mission.
    pub fn resume_mission_runtime_os(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.require_id_only_runtime_resume(&secret_store, project_id, mission_id)?;
        let runtime = discover_runtime();
        self.resume_mission_runtime_with(
            &secret_store,
            project_id,
            mission_id,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    pub fn resume_mission_runtime_cancellable_os(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        cancellation: &DesktopRuntimeCancellation,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.require_id_only_runtime_resume(&secret_store, project_id, mission_id)?;
        let runtime = discover_runtime();
        self.resume_mission_runtime_with_cancellation(
            &secret_store,
            project_id,
            mission_id,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            Some(cancellation),
            now,
        )
    }

    /// Resume one Catalog Mission only by consuming the non-cloneable
    /// capability minted after the exact handle was painted and acknowledged.
    /// The durable handle returned by start/prepare remains read-only.
    pub(crate) fn resume_catalog_mission_runtime_cancellable_os(
        &self,
        authority: DesktopCatalogRuntimeDispatchAuthority,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.resume_catalog_mission_runtime_with_cancellation(
            &secret_store,
            authority,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    #[cfg(feature = "native-journey")]
    pub(crate) fn resume_mission_runtime_native(
        &self,
        secret_store: &impl SecretStore,
        authority: DesktopCatalogRuntimeDispatchAuthority,
        runtime: DesktopRuntimeSource,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        self.resume_catalog_mission_runtime_with_cancellation(
            secret_store,
            authority,
            Some(runtime),
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
            now,
        )
    }

    /// Runs only the current registered Application Checkpoint handler. The
    /// call deliberately supplies no Runtime source; if the route changed
    /// concurrently, dispatch returns the newly fenced route without starting
    /// a model process or external Effect.
    pub fn execute_application_mission_checkpoint_os(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(&secret_store, project_id, now)?;
        let mission = service.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id
            || mission.id != *mission_id
            || mission.definition.is_none()
            || mission.stage.is_terminal()
        {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        if let Some(submission) = self.advance_application_checkpoint_before_runtime(
            &mut service,
            &secret_store,
            &runtime_reconciliation,
            project_id,
            mission_id,
            now,
        )? {
            return Ok(submission);
        }
        let dispatch = service.dispatch_current_mission_checkpoint(project_id, mission_id, now)?;
        self.finish_mission_submission(
            &service,
            &secret_store,
            runtime_reconciliation,
            mission_id.clone(),
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: dispatch.checkpoint_id,
                capability_id: dispatch.capability_id,
                executor: dispatch.executor,
                oracle_ids: dispatch.oracle_ids,
                completion_policy: dispatch.completion_policy,
                state: dispatch.state,
            },
            now,
        )
    }

    /// Appends one user message to an existing legacy local Mission and runs a
    /// new bounded generation for that same Mission. Catalog continuation uses
    /// the sealed post-render capability path below instead of this public
    /// Project/Mission-id entry point.
    pub fn continue_mission_and_run_os(
        &self,
        request: DesktopMissionContinuationRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.continue_mission_and_run_with(
            &secret_store,
            request,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    pub fn continue_mission_and_run_cancellable_os(
        &self,
        request: DesktopMissionContinuationRequest,
        cancellation: &DesktopRuntimeCancellation,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.continue_mission_and_run_with_cancellation(
            &secret_store,
            request,
            DesktopMissionContinuationRuntimeAuthority::Legacy(Some(cancellation)),
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    /// Catalog continuation is a separate sealed path: it consumes the exact
    /// post-render capability and cannot be reached with the cloneable durable
    /// subscription handle returned by start/prepare.
    pub(crate) fn continue_catalog_mission_and_run_cancellable_os(
        &self,
        authority: DesktopCatalogRuntimeDispatchAuthority,
        request: DesktopMissionContinuationRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.continue_mission_and_run_with_cancellation(
            &secret_store,
            request,
            DesktopMissionContinuationRuntimeAuthority::Catalog(Box::new(authority)),
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    /// Confirms one exact Human-routed Checkpoint without starting a Runtime
    /// or issuing a Provider Effect. The private confirmation message and the
    /// Mission transition are committed atomically before the refreshed
    /// Desktop projection is returned.
    pub fn confirm_human_mission_checkpoint_os(
        &self,
        request: DesktopHumanCheckpointConfirmationRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.confirm_human_mission_checkpoint_with(&secret_store, request, now)
    }

    pub fn confirm_human_mission_checkpoint_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopHumanCheckpointConfirmationRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.checkpoint_id.trim().is_empty()
            || request.body.trim().is_empty()
            || request.idempotency_key.trim().is_empty()
        {
            return Err(DesktopDataError::InvalidHumanCheckpointConfirmation);
        }
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        service.confirm_human_mission_checkpoint(
            ConfirmHumanMissionCheckpoint {
                project_id,
                mission_id: request.mission_id,
                checkpoint_id: request.checkpoint_id,
                message_id: request.message_id,
                body: request.body,
                idempotency_key: request.idempotency_key,
                work_product_ids: request.work_product_ids,
                expected_mission_revision: request.expected_mission_revision,
                expected_checkpoint_revision: request.expected_checkpoint_revision,
                expected_conversation_revision: request.expected_conversation_revision,
            },
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    /// Persists VM-11's exact Continue/Stop/Scale/Test choice without Runtime
    /// or Provider execution. The SQLCipher transaction binds the frozen
    /// review, private rationale message, Mission/Conversation CAS and next
    /// Application route before this refreshed projection is returned.
    pub fn decide_vm11_outcome_review_os(
        &self,
        request: DesktopVm11OutcomeDecisionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.decide_vm11_outcome_review_with(&secret_store, request, now)
    }

    pub fn decide_vm11_outcome_review_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopVm11OutcomeDecisionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.rationale.trim().is_empty()
            || request.idempotency_key.trim().is_empty()
            || request.expected_review_projection_digest.len() != 64
            || request.expected_review_completion_digest.len() != 64
        {
            return Err(DesktopDataError::InvalidVm11OutcomeDecision);
        }
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        service.decide_vm11_outcome_review(
            DecideVm11OutcomeReview {
                project_id,
                mission_id: request.mission_id,
                action: request.action,
                decided_by: ActorId::from_stable(format!(
                    "desktop-local-operator:{}",
                    self.device_id
                )),
                message_id: request.message_id,
                rationale: request.rationale,
                idempotency_key: request.idempotency_key,
                expected_review_projection_digest: request.expected_review_projection_digest,
                expected_review_completion_digest: request.expected_review_completion_digest,
                expected_mission_revision: request.expected_mission_revision,
                expected_checkpoint_revision: request.expected_checkpoint_revision,
                expected_conversation_revision: request.expected_conversation_revision,
            },
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    /// Resolves VM-11's frozen Continue/Stop/Scale/Test into the typed next
    /// contract or valid terminal. This is a first-class Desktop action: the
    /// generic Application completion path is rejected for this route, and no
    /// Runtime or Provider Effect is constructed.
    pub fn resolve_vm11_next_contract_or_valid_terminal_os(
        &self,
        request: DesktopVm11NextContractResolutionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.resolve_vm11_next_contract_or_valid_terminal_with(&secret_store, request, now)
    }

    pub fn resolve_vm11_next_contract_or_valid_terminal_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopVm11NextContractResolutionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        if request.expected_decision_digest.len() != 64
            || request.expected_parent_contract_digest.len() != 64
            || request.expected_mission_revision == 0
            || request.expected_checkpoint_revision == 0
            || request.expected_parent_mission_revision == 0
        {
            return Err(DesktopDataError::InvalidVm11NextContractResolution);
        }
        let project_id = request.project_id.clone();
        let mission_id = request.mission_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let runtime_outcome =
            match service.resolve_vm11_next_contract_or_valid_terminal(
                ResolveVm11NextContractOrValidTerminal {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    expected_mission_revision: request.expected_mission_revision,
                    expected_checkpoint_revision: request.expected_checkpoint_revision,
                    expected_decision_digest: request.expected_decision_digest,
                    expected_parent_mission_revision: request.expected_parent_mission_revision,
                    expected_parent_contract_digest: request.expected_parent_contract_digest,
                },
                now,
            )? {
                Vm11NextContractOrValidTerminalResult::Resolved {
                    next_dispatch: Some(dispatch),
                    ..
                } => DesktopMissionRuntimeOutcome::CheckpointRouted {
                    checkpoint_id: dispatch.checkpoint_id,
                    capability_id: dispatch.capability_id,
                    executor: dispatch.executor,
                    oracle_ids: dispatch.oracle_ids,
                    completion_policy: dispatch.completion_policy,
                    state: dispatch.state,
                },
                Vm11NextContractOrValidTerminalResult::Resolved {
                    mission,
                    next_dispatch: None,
                    ..
                } => DesktopMissionRuntimeOutcome::ApplicationCheckpointCompleted {
                    checkpoint_id: "next_contract_or_valid_terminal".into(),
                    evidence_digest: mission
                        .definition
                        .as_ref()
                        .and_then(|definition| {
                            definition.checkpoints.iter().find(|checkpoint| {
                                checkpoint.id == "next_contract_or_valid_terminal"
                            })
                        })
                        .and_then(|checkpoint| checkpoint.completion.as_ref())
                        .map(|completion| completion.evidence_digest.clone())
                        .ok_or(ApplicationError::MissionCheckpointDispatchUnavailable)?,
                },
                Vm11NextContractOrValidTerminalResult::WaitingUser { mission, .. } => {
                    let checkpoint = mission
                        .definition
                        .as_ref()
                        .and_then(|definition| {
                            definition.checkpoints.iter().find(|checkpoint| {
                                checkpoint.id == "next_contract_or_valid_terminal"
                            })
                        })
                        .ok_or(ApplicationError::MissionCheckpointDispatchUnavailable)?;
                    let route = checkpoint
                        .route
                        .as_ref()
                        .ok_or(ApplicationError::MissionCheckpointDispatchUnavailable)?;
                    DesktopMissionRuntimeOutcome::CheckpointRouted {
                        checkpoint_id: checkpoint.id.clone(),
                        capability_id: route.capability_id.clone(),
                        executor: route.executor,
                        oracle_ids: route.oracle_ids.clone(),
                        completion_policy: route
                            .completion_policy
                            .ok_or(ApplicationError::MissionCheckpointDispatchUnavailable)?,
                        state: MissionCheckpointDispatchState::WaitingUser,
                    }
                }
            };
        self.finish_mission_submission(
            &service,
            secret_store,
            runtime_reconciliation,
            mission_id,
            runtime_outcome,
            now,
        )
    }

    /// Continues one user-held Browser Workspace through Application
    /// `continue_browser_workspace` and a real BrowserControlHost. Missing or
    /// non-user-held workspaces fail closed; Host sync failure is reported as
    /// `BrowserHostReconciliationRequired` and is not treated as Verification.
    pub fn continue_browser_workspace_os(
        &self,
        request: DesktopContinueBrowserWorkspaceRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.continue_browser_workspace_with(&secret_store, request, now)
    }

    pub fn continue_browser_workspace_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopContinueBrowserWorkspaceRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.expected_revision == 0
            || request.expected_generation == 0
            || request.workspace_id.as_str().trim().is_empty()
        {
            return Err(DesktopDataError::InvalidBrowserWorkspaceContinue);
        }
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let live = service
            .load_live_browser_workspace_for_mission(&project_id, &request.mission_id)?
            .ok_or(DesktopDataError::BrowserWorkspaceUnavailable)?;
        if live.id != request.workspace_id
            || live.mission_id != request.mission_id
            || live.project_id != project_id
        {
            return Err(DesktopDataError::InvalidBrowserWorkspaceContinue);
        }
        if live.control_state != BrowserControlState::UserControlled {
            return Err(DesktopDataError::BrowserWorkspaceContinueNotHeld);
        }
        if live.revision != request.expected_revision
            || live.lease_generation != request.expected_generation
        {
            return Err(DesktopDataError::InvalidBrowserWorkspaceContinue);
        }
        let evidence_digest = continue_browser_workspace_evidence_digest(&live, now);
        let mut host = DesktopBrowserControlHost::attach(&live)?;
        service.continue_browser_workspace(
            &mut host,
            ContinueBrowserWorkspace {
                project_id,
                workspace_id: request.workspace_id,
                expected_revision: request.expected_revision,
                expected_generation: request.expected_generation,
                new_lease_id: BrowserControlLeaseId::new(),
                lease_expires_at: now + Duration::hours(1),
                evidence_digest,
            },
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    /// Reviews one exact uploaded Creator Deliverable through Application
    /// `review_creator_deliverable`. Stale revision, mismatched deliverable, or
    /// a missing submit fail closed. Review is not Verification and never
    /// executes an external Effect or prepares a Creator payout.
    pub fn review_creator_deliverable_os(
        &self,
        request: DesktopReviewCreatorDeliverableRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.review_creator_deliverable_with(&secret_store, request, now)
    }

    pub fn review_creator_deliverable_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopReviewCreatorDeliverableRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.expected_task_revision == 0
            || request.expected_deliverable_revision == 0
            || request.task_id.as_str().trim().is_empty()
            || request.deliverable_id.as_str().trim().is_empty()
            || request.acceptance_checks.is_empty()
            || !matches!(
                request.decision,
                ReviewDecision::Accept | ReviewDecision::RequestRevision
            )
        {
            return Err(DesktopDataError::InvalidCreatorDeliverableReview);
        }
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let live = service
            .load_creator_task(&project_id, &request.task_id)
            .map_err(|_| DesktopDataError::CreatorDeliverableReviewUnavailable)?;
        if live.project_id != project_id
            || live.mission_id != request.mission_id
            || live.id != request.task_id
        {
            return Err(DesktopDataError::InvalidCreatorDeliverableReview);
        }
        if live.state_revision != request.expected_task_revision {
            return Err(DesktopDataError::CreatorDeliverableReviewStale);
        }
        let Some(deliverable) = live
            .deliverables
            .iter()
            .find(|item| item.id == request.deliverable_id)
        else {
            return Err(DesktopDataError::CreatorDeliverableReviewUnavailable);
        };
        if deliverable.revision != request.expected_deliverable_revision
            || deliverable.status != hartevo_domain_kernel::DeliverableStatus::ReadyForReview
        {
            return Err(DesktopDataError::CreatorDeliverableReviewUnavailable);
        }
        let notes = match request.decision {
            ReviewDecision::Accept => {
                "window Accept of the exact uploaded Creator Deliverable".into()
            }
            ReviewDecision::RequestRevision => {
                "window request revision of the exact uploaded Creator Deliverable".into()
            }
            ReviewDecision::Reject | ReviewDecision::Dispute => {
                return Err(DesktopDataError::InvalidCreatorDeliverableReview);
            }
        };
        service.review_creator_deliverable(
            ReviewCreatorDeliverable {
                project_id,
                mission_id: request.mission_id,
                task_id: request.task_id,
                deliverable_id: request.deliverable_id,
                expected_task_revision: request.expected_task_revision,
                expected_deliverable_revision: request.expected_deliverable_revision,
                review_id: ReviewId::new(),
                reviewer_id: ActorId::from_stable(format!(
                    "desktop-local-operator:{}",
                    self.device_id
                )),
                decision: request.decision,
                acceptance_checks: request.acceptance_checks,
                notes,
            },
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    /// Opens one Mission-bound CRM Conversation through Application
    /// `open_conversation`. Missing Person/Connection identity fails closed.
    /// Open Conversation itself never mints Effect or Verification.
    pub fn open_conversation_os(
        &self,
        request: DesktopOpenConversationRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.open_conversation_with(&secret_store, request, now)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "window hops own the exact request fence; Continue/Review keep the same by-value Application boundary"
    )]
    pub fn open_conversation_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopOpenConversationRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.person_id.as_str().trim().is_empty()
            || request.connection_id.as_str().trim().is_empty()
            || request.account_id.as_str().trim().is_empty()
            || request.provider.trim().is_empty()
            || request.market.trim().is_empty()
            || !request.gateway.supports_provider(&request.provider)
        {
            return Err(DesktopDataError::InvalidConversationOpen);
        }
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let live = service
            .projection(
                &project_id,
                &request.mission_id,
                hartevo_application::WorkSurface::Orchestrator,
            )
            .map_err(|_| DesktopDataError::ConversationOpenUnavailable)?
            .relationship_conversation
            .ok_or(DesktopDataError::ConversationOpenUnavailable)?;
        if live.conversation_id.is_some() {
            return Err(DesktopDataError::ConversationAlreadyOpen);
        }
        if live.person_id != request.person_id
            || live.company_id != request.company_id
            || live.connection_id != request.connection_id
            || live.account_id != request.account_id
            || live.provider != request.provider
            || live.gateway != request.gateway
            || live.contact_channel != request.contact_channel
            || live.market != request.market
        {
            return Err(DesktopDataError::InvalidConversationOpen);
        }
        let person = service
            .load_person(&project_id, &request.person_id)
            .map_err(|_| DesktopDataError::ConversationOpenUnavailable)?;
        if person.project_id != project_id
            || person.id != request.person_id
            || person.company_id != request.company_id
        {
            return Err(DesktopDataError::InvalidConversationOpen);
        }
        let connection = service
            .load_connection(&project_id, &request.connection_id)
            .map_err(|_| DesktopDataError::ConversationOpenUnavailable)?;
        if connection.tenant_id() != &person.tenant_id
            || connection.project_id() != &project_id
            || connection.id() != &request.connection_id
            || connection.provider() != request.provider
            || connection.account_id() != &request.account_id
            || !connection.is_connected(now)
        {
            return Err(DesktopDataError::InvalidConversationOpen);
        }
        let route_digest = open_conversation_route_digest(&live, now);
        if !request.route_digest.is_empty() && request.route_digest != route_digest {
            return Err(DesktopDataError::InvalidConversationOpen);
        }
        let conversation = Conversation::open(
            ConversationId::new(),
            person.tenant_id.clone(),
            project_id.clone(),
            Some(request.mission_id.clone()),
            request.person_id.clone(),
            request.company_id.clone(),
            request.gateway.clone(),
            request.provider.clone(),
            request.connection_id.clone(),
            request.account_id.clone(),
            route_digest,
            request.contact_channel.clone(),
            request.market.clone(),
            now,
        )
        .map_err(ApplicationError::from)?;
        service.open_conversation(conversation, now)?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    /// Grants Domain Kernel Approval for one Proposed Effect without executing
    /// it. The frozen digest and Mission revision must match SQLCipher; a
    /// fixture SAMPLE digest is refused.
    pub fn grant_waiting_approval_os(
        &self,
        request: DesktopWaitingApprovalGrantRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.grant_waiting_approval_with(&secret_store, request, now)
    }

    pub fn grant_waiting_approval_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopWaitingApprovalGrantRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        if request.expected_mission_revision == 0
            || request.effect_id.as_str().trim().is_empty()
            || request.expected_scope_digest.len() != 64
            || !request
                .expected_scope_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DesktopDataError::InvalidWaitingApprovalGrant);
        }
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let broker = Self::waiting_approval_broker();
        service.approve_proposed_effect(
            &broker,
            ApproveProposedEffect {
                project_id,
                mission_id: request.mission_id,
                effect_id: request.effect_id,
                expected_scope_digest: request.expected_scope_digest,
                expected_mission_revision: request.expected_mission_revision,
            },
            ActorId::from_stable(format!("desktop-local-operator:{}", self.device_id)),
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    fn continue_mission_and_run_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopMissionContinuationRequest,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        self.continue_mission_and_run_with_cancellation(
            secret_store,
            request,
            DesktopMissionContinuationRuntimeAuthority::Legacy(None),
            runtime,
            availability,
            now,
        )
    }

    #[cfg(test)]
    fn continue_catalog_mission_and_run_with(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopMissionContinuationRequest,
        authority: DesktopCatalogRuntimeDispatchAuthority,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        self.continue_mission_and_run_with_cancellation(
            secret_store,
            request,
            DesktopMissionContinuationRuntimeAuthority::Catalog(Box::new(authority)),
            runtime,
            availability,
            now,
        )
    }

    fn continue_mission_and_run_with_cancellation(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopMissionContinuationRequest,
        authority: DesktopMissionContinuationRuntimeAuthority<'_>,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        if request.body.trim().is_empty() || request.idempotency_key.trim().is_empty() {
            return Err(DesktopDataError::InvalidMissionContinuation);
        }
        let (catalog_execution, legacy_cancellation) = match authority {
            DesktopMissionContinuationRuntimeAuthority::Legacy(cancellation) => {
                (None, cancellation)
            }
            DesktopMissionContinuationRuntimeAuthority::Catalog(authority) => {
                if !authority.is_exact_post_render_authority() {
                    return Err(ApplicationError::from(
                        RuntimeTextSubscriptionError::MissionHandleMismatch,
                    )
                    .into());
                }
                (Some((*authority).into_runtime_parts()), None)
            }
        };
        let catalog_handle = catalog_execution.as_ref().map(|(handle, _)| handle);
        self.require_exact_catalog_continuation_handle(secret_store, &request, catalog_handle)?;
        let project_id = request.project_id.clone();
        let mission_id = request.mission_id.clone();
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        validate_catalog_continuation_handle(&service, &request, catalog_handle)?;
        service.append_mission_conversation_message(
            AppendMissionConversationMessage {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                message_id: request.message_id,
                kind: request.kind,
                body: request.body,
                idempotency_key: request.idempotency_key,
                expected_conversation_revision: request.expected_conversation_revision,
            },
            now,
        )?;
        self.run_existing_mission_runtime_with_cancellation(
            &mut service,
            secret_store,
            runtime_reconciliation,
            &context_session,
            &project_id,
            mission_id,
            runtime,
            availability,
            catalog_execution
                .as_ref()
                .map(|(_, cancellation)| cancellation)
                .or(legacy_cancellation),
            now,
        )
    }

    fn resume_mission_runtime_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        self.resume_mission_runtime_with_cancellation(
            secret_store,
            project_id,
            mission_id,
            runtime,
            availability,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_mission_runtime_with_cancellation(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        cancellation: Option<&DesktopRuntimeCancellation>,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, project_id, now)?;
        let mission = service.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id
            || mission.stage.is_terminal()
            || (mission.definition.is_none() && mission.stage != MissionStage::Running)
        {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        self.run_existing_mission_runtime_with_cancellation(
            &mut service,
            secret_store,
            runtime_reconciliation,
            &context_session,
            project_id,
            mission.id,
            runtime,
            availability,
            cancellation,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_catalog_mission_runtime_with_cancellation(
        &self,
        secret_store: &impl SecretStore,
        authority: DesktopCatalogRuntimeDispatchAuthority,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        if !authority.is_exact_post_render_authority() {
            return Err(ApplicationError::from(
                RuntimeTextSubscriptionError::MissionHandleMismatch,
            )
            .into());
        }
        let (handle, cancellation) = authority.into_runtime_parts();
        let project_id = handle.project_id().clone();
        let mission_id = handle.mission_id().clone();
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let durable_handle = service.mission_execution_handle(&project_id, &mission_id)?;
        if durable_handle != handle {
            return Err(ApplicationError::from(
                RuntimeTextSubscriptionError::MissionHandleMismatch,
            )
            .into());
        }
        let mission = service.load_mission(&project_id, &mission_id)?;
        if mission.project_id != project_id
            || mission.id != mission_id
            || mission.stage.is_terminal()
            || mission.definition.is_none()
        {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        self.run_existing_mission_runtime_with_cancellation(
            &mut service,
            secret_store,
            runtime_reconciliation,
            &context_session,
            &project_id,
            mission.id,
            runtime,
            availability,
            Some(&cancellation),
            now,
        )
    }

    fn open_ready_runtime_project(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> Result<
        (
            ApplicationService,
            RuntimeTurnStartupReconciliation,
            ProjectContextMaterialSession,
        ),
        DesktopDataError,
    > {
        let secret = secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })?;
        let (service, runtime_reconciliation) = self.open_application_from_secret(&secret, now)?;
        let inventory = service.desktop_inventory()?;
        let project = inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
            .ok_or_else(|| DesktopDataError::ProjectNotFound(project_id.clone()))?;
        if !matches!(project.encryption, ProjectEncryptionReadiness::Ready { .. }) {
            return Err(DesktopDataError::ProjectEncryptionNotReady(
                project_id.clone(),
            ));
        }
        let context_session =
            self.project_context_material_session(&service, secret_store, project_id, now)?;
        Ok((service, runtime_reconciliation, context_session))
    }

    /// Public Project/Mission-id retry is retained only for legacy local
    /// Missions. Catalog Runtime requires a durable painted execution handle.
    fn require_id_only_runtime_resume(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<(), DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_secret = self.database_secret(secret_store)?;
        let service = self.open_read_application_from_secret(&database_secret)?;
        let mission = service.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id
            || mission.id != *mission_id
            || mission.definition.is_some()
        {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        Ok(())
    }

    /// Reject a missing, stale, substituted, or cross-scope Catalog handle
    /// before startup reconciliation, Conversation append, or Runtime dispatch.
    fn require_exact_catalog_continuation_handle(
        &self,
        secret_store: &impl SecretStore,
        request: &DesktopMissionContinuationRequest,
        catalog_handle: Option<&CatalogMissionExecutionHandle>,
    ) -> Result<(), DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_secret = self.database_secret(secret_store)?;
        let service = self.open_read_application_from_secret(&database_secret)?;
        validate_catalog_continuation_handle(&service, request, catalog_handle)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the Desktop Runtime Journey keeps encrypted Context preparation, restart-safe recovery selection, durable turn evidence, default local-action refusal, bounded cleanup, and draft adoption in one auditable coordinator"
    )]
    fn run_existing_mission_runtime_with(
        &self,
        service: &mut ApplicationService,
        secret_store: &impl SecretStore,
        runtime_reconciliation: RuntimeTurnStartupReconciliation,
        context_session: &ProjectContextMaterialSession,
        project_id: &ProjectId,
        mission_id: MissionId,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        self.run_existing_mission_runtime_with_cancellation(
            service,
            secret_store,
            runtime_reconciliation,
            context_session,
            project_id,
            mission_id,
            runtime,
            availability,
            None,
            now,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the cancellable Desktop Runtime Journey keeps the exact managed process and turn attempt inside one coordinator so a UI stop request becomes a fenced Runtime interrupt rather than a cosmetic task abort"
    )]
    fn run_existing_mission_runtime_with_cancellation(
        &self,
        service: &mut ApplicationService,
        secret_store: &impl SecretStore,
        runtime_reconciliation: RuntimeTurnStartupReconciliation,
        context_session: &ProjectContextMaterialSession,
        project_id: &ProjectId,
        mission_id: MissionId,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        cancellation: Option<&DesktopRuntimeCancellation>,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        if let Some(submission) = self.advance_application_checkpoint_before_runtime(
            service,
            secret_store,
            &runtime_reconciliation,
            project_id,
            &mission_id,
            now,
        )? {
            return Ok(submission);
        }
        let scope = runtime_authority_scope(service, project_id, &mission_id)?;
        let facts = live_domain_kernel_facts(service, project_id, &mission_id, now)?;
        map_runtime_dispatch_result(dispatch_live_runtime(
            &self.cordis,
            scope,
            &facts.consent,
            facts.record.as_ref(),
            facts.approval.as_ref(),
            now,
            |permit| {
                let current_scope = runtime_authority_scope(service, project_id, &mission_id)?;
                if &current_scope != permit.scope() {
                    return Err(CordisError::AuthorityScopeMismatch.into());
                }
                self.run_existing_mission_runtime_authorized(
                    service,
                    secret_store,
                    runtime_reconciliation,
                    context_session,
                    project_id,
                    mission_id,
                    runtime,
                    availability,
                    cancellation,
                    now,
                )
            },
        ))
    }

    /// Advance a deterministic Application-owned checkpoint before Cordis
    /// computes or issues any Runtime permit. A successful CAS therefore
    /// becomes part of the exact post-checkpoint Runtime scope rather than
    /// silently aging a previously issued permit.
    fn advance_application_checkpoint_before_runtime(
        &self,
        service: &mut ApplicationService,
        secret_store: &impl SecretStore,
        runtime_reconciliation: &RuntimeTurnStartupReconciliation,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<Option<DesktopMissionSubmission>, DesktopDataError> {
        let mission = service.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id || mission.id != *mission_id {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        if mission.definition.is_none() {
            return Ok(None);
        }

        let mut dispatch =
            service.dispatch_current_mission_checkpoint(project_id, mission_id, now)?;
        if dispatch.executor == MissionCheckpointExecutor::Application {
            if dispatch.checkpoint_id == "next_contract_or_valid_terminal" {
                return Err(ApplicationError::Vm11NextContractRouteSpecificCommandRequired.into());
            }
            match service.execute_application_mission_checkpoint(
                ExecuteApplicationMissionCheckpoint {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    checkpoint_id: dispatch.checkpoint_id.clone(),
                    expected_mission_revision: dispatch.mission_revision,
                    expected_checkpoint_revision: dispatch.checkpoint_revision,
                },
                now,
            )? {
                ApplicationMissionCheckpointExecution::Completed {
                    next_dispatch: Some(next_dispatch),
                    ..
                } => dispatch = next_dispatch,
                ApplicationMissionCheckpointExecution::Completed {
                    completed_checkpoint_id,
                    completion_evidence_digest,
                    next_dispatch: None,
                    ..
                } => {
                    return self
                        .finish_mission_submission(
                            service,
                            secret_store,
                            runtime_reconciliation.clone(),
                            mission_id.clone(),
                            DesktopMissionRuntimeOutcome::ApplicationCheckpointCompleted {
                                checkpoint_id: completed_checkpoint_id,
                                evidence_digest: completion_evidence_digest,
                            },
                            now,
                        )
                        .map(Some);
                }
                ApplicationMissionCheckpointExecution::Blocked { .. } => {
                    dispatch =
                        service.dispatch_current_mission_checkpoint(project_id, mission_id, now)?;
                }
                ApplicationMissionCheckpointExecution::NotImplemented { dispatch: current } => {
                    return self
                        .finish_mission_submission(
                            service,
                            secret_store,
                            runtime_reconciliation.clone(),
                            mission_id.clone(),
                            DesktopMissionRuntimeOutcome::ApplicationCheckpointNotImplemented {
                                checkpoint_id: current.checkpoint_id,
                                capability_id: current.capability_id,
                            },
                            now,
                        )
                        .map(Some);
                }
            }
        }
        if dispatch.executor == MissionCheckpointExecutor::Runtime
            && dispatch.state == MissionCheckpointDispatchState::Ready
        {
            return Ok(None);
        }
        self.finish_mission_submission(
            service,
            secret_store,
            runtime_reconciliation.clone(),
            mission_id.clone(),
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: dispatch.checkpoint_id,
                capability_id: dispatch.capability_id,
                executor: dispatch.executor,
                oracle_ids: dispatch.oracle_ids,
                completion_policy: dispatch.completion_policy,
                state: dispatch.state,
            },
            now,
        )
        .map(Some)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the authorized Desktop Runtime coordinator remains the single implementation behind Cordis dispatch; it preserves encrypted Context, recovery, bounded cancellation, and draft adoption"
    )]
    fn run_existing_mission_runtime_authorized(
        &self,
        service: &mut ApplicationService,
        secret_store: &impl SecretStore,
        runtime_reconciliation: RuntimeTurnStartupReconciliation,
        context_session: &ProjectContextMaterialSession,
        project_id: &ProjectId,
        mission_id: MissionId,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        cancellation: Option<&DesktopRuntimeCancellation>,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        if let Some(control) = cancellation {
            control.record_progress(DesktopRuntimeProgressPhase::Preparing);
        }
        let mission = service.load_mission(project_id, &mission_id)?;
        if mission.project_id != *project_id || mission.id != mission_id {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        if mission.definition.is_some() {
            let dispatch =
                service.dispatch_current_mission_checkpoint(project_id, &mission_id, now)?;
            if dispatch.executor != MissionCheckpointExecutor::Runtime
                || dispatch.state != MissionCheckpointDispatchState::Ready
            {
                return Err(CordisError::AuthorityScopeMismatch.into());
            }
        }
        if mission.stage != MissionStage::Running {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        let latest_recovery =
            service.latest_runtime_recovery_for_mission(project_id, &mission_id)?;
        let latest_turn = service.latest_runtime_turn_for_mission(project_id, &mission_id)?;
        let runtime_generation = runtime_entry_generation(
            service,
            &mission,
            project_id,
            &mission_id,
            latest_recovery.as_ref(),
            latest_turn.as_ref(),
        )?;
        let current_recovery = latest_recovery
            .as_ref()
            .filter(|recovery| recovery.worker_generation == runtime_generation);
        let current_turn = latest_turn.as_ref().filter(|turn| {
            turn.scope.worker_generation == runtime_generation
                && current_recovery.is_none_or(|recovery| {
                    turn.scope.recovery_id == recovery.id
                        && turn.scope.worker_generation == recovery.worker_generation
                        && turn.scope.workspace_id == recovery.workspace_id
                        && turn.scope.worker_id == recovery.worker_id
                })
        });
        if let Some(turn) = current_turn
            && turn.status.is_active()
        {
            return self.finish_mission_submission(
                service,
                secret_store,
                runtime_reconciliation,
                mission_id,
                DesktopMissionRuntimeOutcome::ReplaySuppressed {
                    turn_status: turn.status,
                },
                now,
            );
        }
        if let Some(turn) = current_turn
            && turn.status == RuntimeTurnStatus::Completed
            && mission.definition.is_some()
            && service
                .latest_runtime_turn_private_message(project_id, &turn.id)?
                .is_some()
        {
            let conversation = service.mission_conversation(project_id, &mission_id)?;
            let adoption = service.adopt_runtime_turn_draft(
                &AdoptRuntimeTurnDraft {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    runtime_turn_attempt_id: turn.id.clone(),
                    expected_conversation_revision: conversation.revision,
                },
                now,
            )?;
            return self.finish_mission_submission(
                service,
                secret_store,
                runtime_reconciliation,
                mission_id,
                DesktopMissionRuntimeOutcome::DraftReady {
                    work_product_id: adoption.work_product.id,
                },
                now,
            );
        }
        if let Some(turn) = current_turn
            && turn.status == RuntimeTurnStatus::Completed
            && mission.definition.is_none()
        {
            return self.finish_mission_submission(
                service,
                secret_store,
                runtime_reconciliation,
                mission_id,
                DesktopMissionRuntimeOutcome::ReplaySuppressed {
                    turn_status: turn.status,
                },
                now,
            );
        }
        let Some(runtime) = runtime else {
            return self.finish_mission_submission(
                service,
                secret_store,
                runtime_reconciliation,
                mission_id,
                DesktopMissionRuntimeOutcome::NotStarted { availability },
                now,
            );
        };
        let mut logical_millis = 1_i64;
        let resume_plan = match current_recovery.cloned() {
            None => LocalRuntimeResumePlan {
                generation: runtime_generation,
                strategy: RuntimeResumeStrategy::StartNew,
                resume_thread_id: None,
            },
            Some(recovery) if recovery.status == RuntimeRecoveryStatus::Failed => {
                let retired = service.ensure_failed_local_mission_runtime_generation_retired(
                    &EnsureFailedLocalMissionRuntimeGenerationRetired {
                        project_id: project_id.clone(),
                        mission_id: mission_id.clone(),
                        recovery_id: recovery.id,
                        expected_recovery_revision: recovery.revision,
                    },
                    now + Duration::milliseconds(logical_millis),
                )?;
                logical_millis += 1;
                LocalRuntimeResumePlan {
                    generation: retired.next_generation,
                    strategy: RuntimeResumeStrategy::StartNew,
                    resume_thread_id: None,
                }
            }
            Some(recovery) if recovery.status == RuntimeRecoveryStatus::Attached => {
                let resume_thread_id = recovery
                    .runtime_thread_id
                    .clone()
                    .or_else(|| {
                        latest_turn
                            .as_ref()
                            .filter(|turn| {
                                turn.scope.worker_generation == recovery.worker_generation
                                    && turn.scope.workspace_id == recovery.workspace_id
                                    && turn.scope.worker_id == recovery.worker_id
                            })
                            .map(|turn| turn.scope.runtime_thread_id.clone())
                    })
                    .ok_or(ApplicationError::RuntimeRecoveryResumeThreadMismatch)?;
                LocalRuntimeResumePlan {
                    generation: recovery.worker_generation,
                    strategy: RuntimeResumeStrategy::ResumeExisting,
                    resume_thread_id: Some(resume_thread_id),
                }
            }
            Some(recovery) => {
                let resume_thread_id = match recovery.initial_strategy {
                    RuntimeResumeStrategy::StartNew => None,
                    RuntimeResumeStrategy::ResumeExisting => recovery
                        .runtime_thread_id
                        .clone()
                        .or_else(|| {
                            latest_turn
                                .as_ref()
                                .filter(|turn| {
                                    turn.scope.worker_generation == recovery.worker_generation
                                        && turn.scope.workspace_id == recovery.workspace_id
                                        && turn.scope.worker_id == recovery.worker_id
                                })
                                .map(|turn| turn.scope.runtime_thread_id.clone())
                        })
                        .ok_or(ApplicationError::RuntimeRecoveryResumeThreadMismatch)
                        .map(Some)?,
                };
                LocalRuntimeResumePlan {
                    generation: recovery.worker_generation,
                    strategy: recovery.initial_strategy,
                    resume_thread_id,
                }
            }
        };
        let runtime_provider = runtime.provider().to_owned();
        let runtime_model = runtime.model().to_owned();
        let tokenizer = ConservativeByteBudgetTokenizer::new(
            runtime_provider,
            runtime_model.clone(),
            2_048,
            4 * 1024 * 1024,
        )
        .map_err(|error| DesktopDataError::Application(ApplicationError::from(error)))?;
        let prepared = service.prepare_local_mission_runtime_context(
            PrepareLocalMissionRuntimeContext {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                generation: resume_plan.generation,
            },
            context_session,
            &tokenizer,
            now + Duration::milliseconds(logical_millis),
        )?;
        logical_millis += 1;
        let Some(envelope) = prepared.assembly.envelope.clone() else {
            return self.finish_mission_submission(
                service,
                secret_store,
                runtime_reconciliation,
                mission_id,
                DesktopMissionRuntimeOutcome::ContextBlocked {
                    status: prepared.assembly.manifest.status,
                },
                now + Duration::milliseconds(logical_millis),
            );
        };
        let mission_scope_digest = format!("{:x}", Sha256::digest(mission_id.as_str().as_bytes()));
        let runtime_home =
            ensure_project_runtime_home(context_session.project_root(), &mission_scope_digest)?;
        let runtime_command =
            runtime.into_command(context_session.project_root(), &runtime_home)?;
        let active_recovery = service.active_context_runtime_recovery(
            project_id,
            &prepared.ids.workspace_id,
            &prepared.ids.worker_id,
        )?;
        let managed_result = if let Some(recovery) = active_recovery {
            service.retry_context_worker_runtime(
                RetryContextWorkerRuntime {
                    project_id: project_id.clone(),
                    recovery_id: recovery.id,
                    expected_attempt_revision: recovery.revision,
                    expected_handle_revision: prepared.handle.revision,
                    expected_mailbox_revision: prepared.mailbox.revision,
                    resume_thread_id: resume_plan.resume_thread_id.clone(),
                    model: Some(runtime_model.clone()),
                    health_timeout: StdDuration::from_secs(15),
                    thread_timeout: StdDuration::from_secs(15),
                },
                &runtime_command,
                now + Duration::milliseconds(logical_millis),
            )
        } else if prepared.handle.status == WorkerHandleStatus::Attached {
            service.recover_context_worker_runtime(
                RecoverContextWorkerRuntime {
                    id: hartevo_domain_kernel::RuntimeRecoveryAttemptId::new(),
                    project_id: project_id.clone(),
                    workspace_id: prepared.ids.workspace_id.clone(),
                    worker_id: prepared.ids.worker_id.clone(),
                    expected_handle_revision: prepared.handle.revision,
                    expected_mailbox_revision: prepared.mailbox.revision,
                    attachment_epoch: prepared.handle.attachment_epoch,
                    strategy: resume_plan.strategy,
                    resume_thread_id: resume_plan.resume_thread_id,
                    model: Some(runtime_model),
                    max_process_attempts: 3,
                    health_timeout: StdDuration::from_secs(15),
                    thread_timeout: StdDuration::from_secs(15),
                },
                &runtime_command,
                now + Duration::milliseconds(logical_millis),
            )
        } else {
            return Err(DesktopDataError::Application(
                ApplicationError::LocalRuntimeContextConflict,
            ));
        };
        let mut managed = match managed_result {
            Ok(managed) => managed,
            Err(ApplicationError::Runtime(_)) => {
                return self.finish_mission_submission(
                    service,
                    secret_store,
                    runtime_reconciliation,
                    mission_id,
                    DesktopMissionRuntimeOutcome::RuntimeStartFailed,
                    now + Duration::milliseconds(logical_millis + 1),
                );
            }
            Err(error) => return Err(error.into()),
        };
        logical_millis += 1;
        let turn_id = RuntimeTurnAttemptId::new();
        let expected_handle_revision = managed.handle.revision;
        let expected_recovery_revision = managed.recovery.revision;
        let attachment_epoch = managed.handle.attachment_epoch;
        let dispatch = service.dispatch_context_runtime_turn(
            &mut managed,
            DispatchContextRuntimeTurn {
                id: turn_id.clone(),
                project_id: project_id.clone(),
                workspace_id: prepared.ids.workspace_id,
                assembly_id: prepared.assembly.manifest.id,
                expected_assembly_revision: prepared.assembly.manifest.revision,
                expected_handle_revision,
                expected_recovery_revision,
                attachment_epoch,
                response_timeout: StdDuration::from_secs(15),
            },
            &envelope,
            now + Duration::milliseconds(logical_millis),
        )?;
        if dispatch.disposition != RuntimeTurnDispatchDisposition::Running {
            let outcome = if dispatch.disposition == RuntimeTurnDispatchDisposition::Failed {
                DesktopMissionRuntimeOutcome::DispatchFailed
            } else {
                DesktopMissionRuntimeOutcome::Uncertain
            };
            service.shutdown_managed_context_runtime(
                managed,
                now + Duration::milliseconds(logical_millis + 1),
            )?;
            return self.finish_mission_submission(
                service,
                secret_store,
                runtime_reconciliation,
                mission_id,
                outcome,
                now + Duration::milliseconds(logical_millis + 1),
            );
        }

        if let Some(control) = cancellation {
            control.record_progress(DesktopRuntimeProgressPhase::Dispatched);
        }

        let mut attempt = dispatch.attempt;
        let mut consecutive_timeouts = 0_u32;
        let mut cooperative_interrupt_sent = false;
        for _ in 0..128 {
            if !cooperative_interrupt_sent
                && cancellation.is_some_and(DesktopRuntimeCancellation::is_requested)
                && matches!(
                    attempt.status,
                    RuntimeTurnStatus::Running | RuntimeTurnStatus::WaitingLocalApproval
                )
            {
                logical_millis += 1;
                attempt = service.interrupt_context_runtime_turn(
                    &mut managed,
                    &InterruptContextRuntimeTurn {
                        project_id: project_id.clone(),
                        id: turn_id.clone(),
                        expected_revision: attempt.revision,
                        response_timeout: StdDuration::from_secs(5),
                    },
                    now + Duration::milliseconds(logical_millis),
                )?;
                cooperative_interrupt_sent = true;
                consecutive_timeouts = 0;
                if let Some(control) = cancellation {
                    control.record_progress(DesktopRuntimeProgressPhase::InterruptSent);
                }
                continue;
            }
            logical_millis += 1;
            let observation = service.observe_context_runtime_turn(
                &mut managed,
                &ObserveContextRuntimeTurn {
                    project_id: project_id.clone(),
                    id: turn_id.clone(),
                    expected_revision: attempt.revision,
                    event_timeout: StdDuration::from_secs(2),
                },
                now + Duration::milliseconds(logical_millis),
            )?;
            attempt = observation.attempt;
            if let Some(control) = cancellation {
                let phase = match &observation.kind {
                    hartevo_application::ContextRuntimeTurnObservationKind::Event(
                        MappedTurnEventKind::TurnStarted,
                    ) => Some(DesktopRuntimeProgressPhase::TurnStarted),
                    hartevo_application::ContextRuntimeTurnObservationKind::Event(
                        MappedTurnEventKind::ItemStarted,
                    ) => Some(DesktopRuntimeProgressPhase::ItemStarted),
                    hartevo_application::ContextRuntimeTurnObservationKind::Event(
                        MappedTurnEventKind::ItemCompleted,
                    ) => Some(DesktopRuntimeProgressPhase::ItemCompleted),
                    hartevo_application::ContextRuntimeTurnObservationKind::Uncertain => {
                        Some(DesktopRuntimeProgressPhase::Uncertain)
                    }
                    _ => None,
                };
                if let Some(phase) = phase {
                    control.record_progress(phase);
                }
            }
            if let Some(request) = observation.local_approval_request {
                let Some(control) = cancellation else {
                    return Err(DesktopDataError::RuntimeLocalApprovalUnavailable);
                };
                control.hold_local_approval(DesktopHeldLocalApproval {
                    project_id: project_id.clone(),
                    turn_id: turn_id.clone(),
                    expected_revision: attempt.revision,
                    request_digest: request.request_digest.clone(),
                    kind: request.kind,
                });
                let approved = loop {
                    if control.is_requested() {
                        control.clear_held_local_approval();
                        break None;
                    }
                    if let Some(decision) = control.take_local_approval_decision() {
                        break Some(decision);
                    }
                    std::thread::sleep(StdDuration::from_millis(50));
                };
                let Some(approved) = approved else {
                    consecutive_timeouts = 0;
                    continue;
                };
                if !approved {
                    control.clear_held_local_approval();
                    consecutive_timeouts = 0;
                    continue;
                }
                logical_millis += 1;
                attempt = service.respond_context_runtime_local_approval(
                    &mut managed,
                    &RespondContextRuntimeLocalApproval {
                        project_id: project_id.clone(),
                        id: turn_id.clone(),
                        expected_revision: attempt.revision,
                        request,
                        approved: true,
                    },
                    now + Duration::milliseconds(logical_millis),
                )?;
                control.clear_held_local_approval();
                control.record_progress(DesktopRuntimeProgressPhase::LocalActionApproved);
                consecutive_timeouts = 0;
                continue;
            }
            match observation.kind {
                hartevo_application::ContextRuntimeTurnObservationKind::NoEvent => {
                    consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                }
                hartevo_application::ContextRuntimeTurnObservationKind::Uncertain
                | hartevo_application::ContextRuntimeTurnObservationKind::Event(
                    MappedTurnEventKind::TurnCompleted(_),
                ) => break,
                hartevo_application::ContextRuntimeTurnObservationKind::Event(_) => {
                    consecutive_timeouts = 0;
                }
            }
            if attempt.status.is_terminal() || attempt.status == RuntimeTurnStatus::Uncertain {
                break;
            }
            if consecutive_timeouts >= 5 {
                if attempt.status == RuntimeTurnStatus::InterruptRequested {
                    break;
                }
                logical_millis += 1;
                attempt = service.interrupt_context_runtime_turn(
                    &mut managed,
                    &InterruptContextRuntimeTurn {
                        project_id: project_id.clone(),
                        id: turn_id.clone(),
                        expected_revision: attempt.revision,
                        response_timeout: StdDuration::from_secs(5),
                    },
                    now + Duration::milliseconds(logical_millis),
                )?;
                consecutive_timeouts = 0;
            }
        }
        logical_millis += 1;
        service.shutdown_managed_context_runtime(
            managed,
            now + Duration::milliseconds(logical_millis),
        )?;
        if attempt.status.is_active() && attempt.status != RuntimeTurnStatus::Uncertain {
            logical_millis += 1;
            attempt = service.fence_orphaned_context_runtime_turn(
                &FenceOrphanedContextRuntimeTurn {
                    project_id: project_id.clone(),
                    id: turn_id.clone(),
                    expected_revision: attempt.revision,
                },
                now + Duration::milliseconds(logical_millis),
            )?;
        }
        let outcome = match attempt.status {
            RuntimeTurnStatus::Completed => {
                if let Some(message) =
                    service.latest_runtime_turn_private_message(project_id, &turn_id)?
                {
                    if mission.definition.is_some() {
                        let conversation = service.mission_conversation(project_id, &mission_id)?;
                        let adoption = service.adopt_runtime_turn_draft(
                            &AdoptRuntimeTurnDraft {
                                project_id: project_id.clone(),
                                mission_id: mission_id.clone(),
                                runtime_turn_attempt_id: turn_id.clone(),
                                expected_conversation_revision: conversation.revision,
                            },
                            now + Duration::milliseconds(logical_millis + 1),
                        )?;
                        logical_millis += 1;
                        DesktopMissionRuntimeOutcome::DraftReady {
                            work_product_id: adoption.work_product.id,
                        }
                    } else {
                        let work_product_id = WorkProductId::from_stable(format!(
                            "runtime-draft:{}",
                            turn_id.as_str()
                        ));
                        let preview = message.body.chars().take(4_000).collect::<String>();
                        logical_millis += 1;
                        service.record_research(
                            project_id,
                            &mission_id,
                            ResearchPacket {
                                work_product_id: work_product_id.clone(),
                                title: "Runtime draft · requires human review".into(),
                                body: message.body,
                                work_product_type: "runtime_draft".into(),
                                fact_ids: BTreeSet::new(),
                                task_ids: BTreeSet::from([prepared.capsule.task_id]),
                                file_digest: None,
                                preview_media_type: "text/plain".into(),
                                preview,
                                editable_scopes: BTreeSet::from(["/body".into()]),
                                evidence: Vec::new(),
                            },
                            now + Duration::milliseconds(logical_millis),
                        )?;
                        DesktopMissionRuntimeOutcome::DraftReady { work_product_id }
                    }
                } else {
                    DesktopMissionRuntimeOutcome::CompletedWithoutArtifact
                }
            }
            RuntimeTurnStatus::Interrupted => DesktopMissionRuntimeOutcome::Interrupted,
            RuntimeTurnStatus::Failed => DesktopMissionRuntimeOutcome::Failed,
            RuntimeTurnStatus::Prepared
            | RuntimeTurnStatus::Dispatching
            | RuntimeTurnStatus::Running
            | RuntimeTurnStatus::WaitingLocalApproval
            | RuntimeTurnStatus::ApprovalResponding
            | RuntimeTurnStatus::InterruptRequested
            | RuntimeTurnStatus::Uncertain => DesktopMissionRuntimeOutcome::Uncertain,
        };
        if let Some(control) = cancellation {
            let phase = match attempt.status {
                RuntimeTurnStatus::Completed => DesktopRuntimeProgressPhase::Completed,
                RuntimeTurnStatus::Interrupted => DesktopRuntimeProgressPhase::Interrupted,
                RuntimeTurnStatus::Failed => DesktopRuntimeProgressPhase::Failed,
                RuntimeTurnStatus::Prepared
                | RuntimeTurnStatus::Dispatching
                | RuntimeTurnStatus::Running
                | RuntimeTurnStatus::WaitingLocalApproval
                | RuntimeTurnStatus::ApprovalResponding
                | RuntimeTurnStatus::InterruptRequested
                | RuntimeTurnStatus::Uncertain => DesktopRuntimeProgressPhase::Uncertain,
            };
            control.record_progress(phase);
        }
        self.finish_mission_submission(
            service,
            secret_store,
            runtime_reconciliation,
            mission_id,
            outcome,
            now + Duration::milliseconds(logical_millis + 1),
        )
    }

    pub fn create_personal_project_with(
        &self,
        secret_store: &impl SecretStore,
        name: &str,
        initial_goal: &str,
        exported_recovery_key: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(DesktopDataError::EmptyProjectName);
        }
        let initial_goal = initial_goal.trim();
        if initial_goal.is_empty() {
            return Err(DesktopDataError::EmptyMissionGoal);
        }
        let recovery_secret = decode_recovery_key(exported_recovery_key)?;
        let database_secret = secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })?;
        let (mut service, runtime_reconciliation) =
            self.open_application_from_secret(&database_secret, now)?;
        let project_id = ProjectId::new();
        let project_root = self.create_project_root(&project_id)?;
        service.create_project(
            CreateProject {
                tenant_id: TenantId::from("local-personal"),
                id: project_id.clone(),
                name: name.into(),
                description: initial_goal.into(),
                workspace_root: project_root,
                storage_mode: StorageMode::LocalNew,
            },
            now,
        )?;
        service.provision_project_encryption_with_user_recovery(
            secret_store,
            ProvisionProjectEncryption {
                project_id: project_id.clone(),
                mode: ProjectEncryptionMode::PersonalE2ee,
                primary_recipient: KeyRecipient::Device(self.device_id.clone()),
                recovery_recipient_id: Some(recovery_recipient_id(&project_id)),
            },
            &recovery_secret,
            now,
        )?;
        self.require_project_context_access(&service, secret_store, &project_id, now)?;
        service.start_mission(
            StartMission {
                id: MissionId::new(),
                research_task_id: TaskId::new(),
                project_id,
                title: None,
                prompt: initial_goal.into(),
            },
            now,
        )?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    pub fn create_personal_project_os(
        &self,
        name: &str,
        initial_goal: &str,
        exported_recovery_key: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.create_personal_project_with(
            &secret_store,
            name,
            initial_goal,
            exported_recovery_key,
            now,
        )
    }

    pub fn complete_personal_encryption_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        exported_recovery_key: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let recovery_secret = decode_recovery_key(exported_recovery_key)?;
        let database_secret = secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })?;
        let (mut service, runtime_reconciliation) =
            self.open_application_from_secret(&database_secret, now)?;
        let inventory = service.desktop_inventory()?;
        let project = inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
            .ok_or_else(|| DesktopDataError::ProjectNotFound(project_id.clone()))?;
        if project.encryption != ProjectEncryptionReadiness::NotProvisioned {
            return Err(DesktopDataError::ProjectEncryptionAlreadyProvisioned(
                project_id.clone(),
            ));
        }
        service.provision_project_encryption_with_user_recovery(
            secret_store,
            ProvisionProjectEncryption {
                project_id: project_id.clone(),
                mode: ProjectEncryptionMode::PersonalE2ee,
                primary_recipient: KeyRecipient::Device(self.device_id.clone()),
                recovery_recipient_id: Some(recovery_recipient_id(project_id)),
            },
            &recovery_secret,
            now,
        )?;
        self.require_project_context_access(&service, secret_store, project_id, now)?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    pub fn complete_personal_encryption_os(
        &self,
        project_id: &ProjectId,
        exported_recovery_key: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.complete_personal_encryption_with(
            &secret_store,
            project_id,
            exported_recovery_key,
            now,
        )
    }

    /// Uses the user-held Recovery Kit to attach a successor local Device
    /// identity to an already-provisioned personal project. The stable base
    /// Device envelope is never overwritten: each recovery generation gets a
    /// distinct recipient and SecretReference, so a missing old wrapping key
    /// cannot be mistaken for a successful rebind.
    pub fn recover_personal_project_device_with(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        exported_recovery_key: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let database_secret = secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })?;
        let (mut service, runtime_reconciliation) =
            self.open_application_from_secret(&database_secret, now)?;
        let inventory = service.desktop_inventory()?;
        let project = inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
            .ok_or_else(|| DesktopDataError::ProjectNotFound(project_id.clone()))?;
        let keyring_revision = match &project.encryption {
            ProjectEncryptionReadiness::Ready {
                mode: ProjectEncryptionMode::PersonalE2ee,
                keyring_revision,
                ..
            } => *keyring_revision,
            ProjectEncryptionReadiness::NotProvisioned
            | ProjectEncryptionReadiness::RotationRequired { .. } => {
                return Err(DesktopDataError::ProjectEncryptionNotReady(
                    project_id.clone(),
                ));
            }
            ProjectEncryptionReadiness::Ready { .. } => {
                return Err(DesktopDataError::ProjectRecoveryNotApplicable(
                    project_id.clone(),
                ));
            }
        };
        let keyring = service.load_project_keyring(project_id)?;
        let recovery_recipient_id = select_personal_recovery_recipient(&keyring, project_id, now)?;
        let successor_device_id = self.recovery_device_id(project_id, keyring_revision);
        let recovery_secret = decode_recovery_key(exported_recovery_key)?;
        let authorization = KeyAdministrationAuthorization {
            actor_id: ActorId::from("desktop-local-project-owner"),
            evidence_digest: desktop_recovery_authorization_digest(
                project_id,
                &successor_device_id,
                keyring_revision,
            ),
        };
        let recovered = service.recover_personal_project_device(
            secret_store,
            RecoverPersonalProjectDevice {
                project_id: project_id.clone(),
                expected_keyring_revision: keyring_revision,
                recovery_recipient_id,
                recovery_secret,
                device_id: successor_device_id.clone(),
                authorization,
                idempotency_key: format!(
                    "desktop-personal-recovery:{project_id}:{successor_device_id}:{keyring_revision}"
                ),
            },
            now,
        );
        match recovered {
            Ok(_) => {}
            Err(ApplicationError::SecretStore(
                SecretStoreError::AuthenticationFailed | SecretStoreError::InvalidSecret,
            )) => {
                return Err(DesktopDataError::InvalidRecoveryKey);
            }
            Err(error) => return Err(error.into()),
        }
        self.require_project_context_access(&service, secret_store, project_id, now)?;
        let product_evidence = load_product_evidence(now)?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )
    }

    pub fn recover_personal_project_device_os(
        &self,
        project_id: &ProjectId,
        exported_recovery_key: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.recover_personal_project_device_with(
            &secret_store,
            project_id,
            exported_recovery_key,
            now,
        )
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    fn waiting_approval_broker() -> EffectBroker {
        EffectBroker::new(
            EffectPolicy {
                version: "policy-v1".into(),
                allowed_capabilities: BTreeSet::from(["channel.preview".into()]),
                allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("CNY").expect("CNY"), 0)]),
                rate_limits: vec![EffectRateLimit {
                    rule_id: "desktop-preview-per-minute".into(),
                    provider: "fixture-provider".into(),
                    capability: "channel.preview".into(),
                    max_executions: 10,
                    window_seconds: 60,
                }],
            },
            "desktop-waiting-approval-worker",
        )
        .with_lease_for(Duration::days(36_500))
    }

    fn finish_mission_submission(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        runtime_reconciliation: RuntimeTurnStartupReconciliation,
        mission_id: MissionId,
        runtime_outcome: DesktopMissionRuntimeOutcome,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let product_evidence = load_product_evidence(now)?;
        let snapshot = self.build_snapshot(
            service,
            secret_store,
            runtime_reconciliation,
            product_evidence,
            now,
        )?;
        Ok(DesktopMissionSubmission {
            snapshot,
            mission_id,
            runtime_outcome,
        })
    }

    fn build_snapshot(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        runtime_reconciliation: RuntimeTurnStartupReconciliation,
        product_evidence: ProductEvidenceProjection,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let mut inventory = service.desktop_inventory()?;
        let context_access = inventory
            .projects
            .iter_mut()
            .map(|project| self.probe_project_context_access(service, secret_store, project, now))
            .collect();
        Ok(DesktopSnapshot {
            inventory,
            context_access,
            runtime_reconciliation,
            runtime: discover_runtime().projection,
            runtime_activity: service.desktop_runtime_activity()?,
            product_evidence,
        })
    }

    fn probe_project_context_access(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        project: &mut hartevo_application::DesktopProjectProjection,
        now: DateTime<Utc>,
    ) -> ProjectContextAccessProjection {
        let status = match &project.encryption {
            ProjectEncryptionReadiness::NotProvisioned => {
                ProjectContextAccessStatus::NotProvisioned
            }
            ProjectEncryptionReadiness::RotationRequired { .. } => {
                ProjectContextAccessStatus::RotationRequired
            }
            ProjectEncryptionReadiness::Ready { .. } => {
                match self.desktop_unlocked_project(service, secret_store, &project.project_id, now)
                {
                    Ok(unlocked) => {
                        project.missions = unlocked.missions;
                        if unlocked.unavailable_historical_key_versions.is_empty() {
                            ProjectContextAccessStatus::Ready {
                                keyring_revision: unlocked.keyring_revision,
                                active_key_version: unlocked.active_key_version,
                                readable_key_versions: unlocked.readable_key_versions,
                            }
                        } else {
                            ProjectContextAccessStatus::Degraded {
                                keyring_revision: unlocked.keyring_revision,
                                active_key_version: unlocked.active_key_version,
                                readable_key_versions: unlocked.readable_key_versions,
                                unavailable_historical_key_versions: unlocked
                                    .unavailable_historical_key_versions,
                            }
                        }
                    }
                    Err(error) => classify_context_access_error(&error),
                }
            }
        };
        ProjectContextAccessProjection {
            project_id: project.project_id.clone(),
            status,
        }
    }

    fn desktop_unlocked_project(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> Result<DesktopUnlockedProjectProjection, ApplicationError> {
        match service.desktop_unlocked_project(secret_store, project_id, &self.device_id, now) {
            Ok(project) => Ok(project),
            Err(error) if !context_device_is_unavailable(&error) => Err(error),
            Err(base_error) => {
                let keyring = service.load_project_keyring(project_id)?;
                let recovery_prefix = self.recovery_device_prefix(project_id);
                for envelope in keyring.envelopes.iter().rev().filter(|envelope| {
                    envelope.key_version == keyring.active_key_version
                        && envelope.is_available(now)
                        && matches!(
                            &envelope.recipient,
                            KeyRecipient::Device(device)
                                if device.as_str().starts_with(&recovery_prefix)
                        )
                }) {
                    let KeyRecipient::Device(device_id) = &envelope.recipient else {
                        continue;
                    };
                    match service.desktop_unlocked_project(secret_store, project_id, device_id, now)
                    {
                        Ok(project) => return Ok(project),
                        Err(error) if context_device_is_unavailable(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(base_error)
            }
        }
    }

    fn project_context_material_session(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> Result<ProjectContextMaterialSession, DesktopDataError> {
        match service.open_project_context_material_session(
            secret_store,
            project_id,
            &self.device_id,
            now,
        ) {
            Ok(session) => Ok(session),
            Err(error) if !context_device_is_unavailable(&error) => Err(error.into()),
            Err(base_error) => {
                let keyring = service.load_project_keyring(project_id)?;
                let recovery_prefix = self.recovery_device_prefix(project_id);
                for envelope in keyring.envelopes.iter().rev().filter(|envelope| {
                    envelope.key_version == keyring.active_key_version
                        && envelope.is_available(now)
                        && matches!(
                            &envelope.recipient,
                            KeyRecipient::Device(device)
                                if device.as_str().starts_with(&recovery_prefix)
                        )
                }) {
                    let KeyRecipient::Device(device_id) = &envelope.recipient else {
                        continue;
                    };
                    match service.open_project_context_material_session(
                        secret_store,
                        project_id,
                        device_id,
                        now,
                    ) {
                        Ok(session) => return Ok(session),
                        Err(error) if context_device_is_unavailable(&error) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(base_error.into())
            }
        }
    }

    fn recovery_device_prefix(&self, project_id: &ProjectId) -> String {
        format!("{}:recovery:{project_id}:", self.device_id)
    }

    fn recovery_device_id(&self, project_id: &ProjectId, keyring_revision: u64) -> DeviceId {
        DeviceId::from_stable(format!(
            "{}{keyring_revision}",
            self.recovery_device_prefix(project_id)
        ))
    }

    fn require_project_context_access(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> Result<(), DesktopDataError> {
        let mut inventory = service.desktop_inventory()?;
        let project = inventory
            .projects
            .iter_mut()
            .find(|project| &project.project_id == project_id)
            .ok_or_else(|| DesktopDataError::ProjectNotFound(project_id.clone()))?;
        let projection = self.probe_project_context_access(service, secret_store, project, now);
        match projection.status {
            ProjectContextAccessStatus::Ready { .. }
            | ProjectContextAccessStatus::Degraded { .. } => Ok(()),
            ProjectContextAccessStatus::NotProvisioned
            | ProjectContextAccessStatus::RotationRequired => Err(
                DesktopDataError::ProjectEncryptionNotReady(project_id.clone()),
            ),
            ProjectContextAccessStatus::RecoveryRequired => Err(
                DesktopDataError::ProjectContextRecoveryRequired(project_id.clone()),
            ),
            ProjectContextAccessStatus::BlockedEnvironment => Err(
                DesktopDataError::ProjectContextBlockedEnvironment(project_id.clone()),
            ),
            ProjectContextAccessStatus::IntegrityError => Err(
                DesktopDataError::ProjectContextIntegrityError(project_id.clone()),
            ),
        }
    }

    fn require_runtime_subscription_context_access(
        &self,
        service: &ApplicationService,
        secret_store: &impl SecretStore,
        handle: &CatalogMissionExecutionHandle,
        now: DateTime<Utc>,
    ) -> Result<(), DesktopDataError> {
        let inventory = service.desktop_inventory()?;
        let exact_project = inventory.projects.iter().find(|project| {
            project.project_id == *handle.project_id() && project.tenant_id == *handle.tenant_id()
        });
        if exact_project.is_none() {
            return Err(DesktopDataError::RuntimeSubscriptionContextMismatch);
        }
        self.require_project_context_access(service, secret_store, handle.project_id(), now)
    }

    fn database_secret(
        &self,
        secret_store: &impl SecretStore,
    ) -> Result<SecretBytes, DesktopDataError> {
        secret_store
            .get(&self.database_key_reference)
            .map_err(|error| {
                if matches!(error, SecretStoreError::SecretNotFound) {
                    DesktopDataError::MissingDatabaseKey
                } else {
                    error.into()
                }
            })
    }

    fn open_application_from_secret(
        &self,
        secret: &hartevo_storage::SecretBytes,
        now: DateTime<Utc>,
    ) -> Result<(ApplicationService, RuntimeTurnStartupReconciliation), DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_key = DatabaseKey::from_secret(secret)?;
        let store = ProjectStore::open(&self.database_path, &database_key)?;
        let mut service = ApplicationService::new(store);
        let reconciliation = service.reconcile_runtime_turns_on_startup(now)?;
        service.reconcile_mission_schedules_on_startup(now)?;
        Ok((service, reconciliation))
    }

    fn open_read_application_from_secret(
        &self,
        secret: &hartevo_storage::SecretBytes,
    ) -> Result<ApplicationService, DesktopDataError> {
        self.revalidate_database_entry()?;
        let database_key = DatabaseKey::from_secret(secret)?;
        let store = ProjectStore::open(&self.database_path, &database_key)?;
        Ok(ApplicationService::new(store))
    }

    #[cfg(test)]
    fn bind_live_domain_kernel_from_store(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<(), DesktopDataError> {
        self.revalidate_database_entry()?;
        match secret_store.get(&self.database_key_reference) {
            Ok(secret) => {
                let service = self.open_read_application_from_secret(&secret)?;
                self.bind_live_domain_kernel_from_service(&service, project_id, mission_id, now)
            }
            Err(SecretStoreError::SecretNotFound) => {
                // Uninitialized / missing key: host stays mounted and fail-closed.
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(test)]
    fn lock_cordis(&self) -> std::sync::MutexGuard<'_, CordisHost> {
        self.cordis
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    fn bind_live_domain_kernel_from_service(
        &self,
        service: &ApplicationService,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<(), DesktopDataError> {
        let mission = service.load_mission(project_id, mission_id)?;
        let scope = AuthorityScope::new(
            mission.tenant_id.as_str(),
            project_id.as_str(),
            mission_id.as_str(),
            mission.revision,
        )?;
        let facts = live_domain_kernel_facts(service, project_id, mission_id, now)?;
        self.bind_live_domain_kernel_scope(
            scope,
            &facts.consent,
            facts.record.as_ref(),
            facts.approval.as_ref(),
            now,
        )?;
        Ok(())
    }

    fn revalidate_database_entry(&self) -> Result<(), DesktopDataError> {
        reject_symlink(&self.data_root)?;
        if !self.data_root_identity.matches(&self.data_root)
            || self.database_path.parent() != Some(self.data_root.as_path())
            || !self.data_root_identity.matches(
                self.database_path
                    .parent()
                    .ok_or_else(|| DesktopDataError::InvalidDataRoot(self.database_path.clone()))?,
            )
        {
            return Err(DesktopDataError::InvalidDataRoot(self.data_root.clone()));
        }
        reject_symlink(&self.database_path)
    }

    fn create_project_root(&self, project_id: &ProjectId) -> Result<PathBuf, DesktopDataError> {
        self.revalidate_database_entry()?;
        let projects_directory = self.data_root.join("projects");
        reject_symlink(&projects_directory)?;
        fs::create_dir_all(&projects_directory)?;
        let workspace = projects_directory.join(project_id.as_str());
        reject_symlink(&workspace)?;
        fs::create_dir(&workspace)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        }
        Ok(workspace.canonicalize()?)
    }

    #[cfg(test)]
    fn database_key_reference(&self) -> &SecretReference {
        &self.database_key_reference
    }
}

fn runtime_authority_scope(
    service: &ApplicationService,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<AuthorityScope, DesktopDataError> {
    let mission = service.load_mission(project_id, mission_id)?;
    if mission.project_id != *project_id || mission.id != *mission_id {
        return Err(CordisError::AuthorityScopeMismatch.into());
    }
    let latest_recovery = service.latest_runtime_recovery_for_mission(project_id, mission_id)?;
    let latest_turn = service.latest_runtime_turn_for_mission(project_id, mission_id)?;
    let generation = runtime_entry_generation(
        service,
        &mission,
        project_id,
        mission_id,
        latest_recovery.as_ref(),
        latest_turn.as_ref(),
    )?;
    let mission_handle_digest = if mission.definition.is_some() {
        Some(
            service
                .mission_execution_handle(project_id, mission_id)?
                .handle_digest()
                .to_owned(),
        )
    } else {
        None
    };
    let runtime = RuntimeBinding::new(
        generation,
        latest_recovery
            .as_ref()
            .map(|recovery| RuntimeRecordBinding::new(recovery.id.as_str(), recovery.revision))
            .transpose()?,
        latest_turn
            .as_ref()
            .map(|turn| RuntimeRecordBinding::new(turn.id.as_str(), turn.revision))
            .transpose()?,
        runtime_authority_fence_digest(
            &mission,
            latest_recovery.as_ref(),
            latest_turn.as_ref(),
            mission_handle_digest.as_deref(),
        ),
    )?;
    Ok(AuthorityScope::new(
        mission.tenant_id.as_str(),
        project_id.as_str(),
        mission_id.as_str(),
        mission.revision,
    )?
    .with_runtime(runtime))
}

fn runtime_entry_generation(
    service: &ApplicationService,
    mission: &Mission,
    project_id: &ProjectId,
    mission_id: &MissionId,
    latest_recovery: Option<&RuntimeRecoveryAttempt>,
    latest_turn: Option<&RuntimeTurnAttempt>,
) -> Result<u64, DesktopDataError> {
    if mission.project_id != *project_id
        || mission.id != *mission_id
        || latest_recovery.is_some_and(|recovery| {
            recovery.tenant_id != mission.tenant_id
                || recovery.project_id != *project_id
                || recovery.mission_id != *mission_id
        })
        || latest_turn.is_some_and(|turn| {
            turn.scope.tenant_id != mission.tenant_id
                || turn.scope.project_id != *project_id
                || turn.scope.mission_id != *mission_id
        })
    {
        return Err(CordisError::AuthorityScopeMismatch.into());
    }

    let runtime_generation = match service.mission_conversation(project_id, mission_id) {
        Ok(conversation) => {
            if conversation.tenant_id != mission.tenant_id
                || conversation.project_id != *project_id
                || conversation.mission_id != *mission_id
            {
                return Err(CordisError::AuthorityScopeMismatch.into());
            }
            conversation
                .messages
                .iter()
                .rev()
                .find(|message| message.role == MissionConversationRole::User)
                .map(|message| message.sequence)
                .ok_or(ApplicationError::LocalRuntimeContextScopeMismatch)?
        }
        Err(ApplicationError::Storage(StorageError::ScopedRecordNotFound {
            kind: "mission conversation",
            ..
        })) if mission.definition.is_none() => latest_recovery
            .map(|recovery| recovery.worker_generation)
            .into_iter()
            .chain(latest_turn.map(|turn| turn.scope.worker_generation))
            .max()
            .unwrap_or(1),
        Err(error) => return Err(error.into()),
    };
    if runtime_generation == 0
        || (mission.definition.is_none()
            && latest_turn.is_some_and(|turn| {
                latest_recovery.is_none_or(|recovery| {
                    turn.scope.worker_generation > recovery.worker_generation
                })
            }))
        || latest_recovery.is_some_and(|recovery| recovery.worker_generation > runtime_generation)
        || latest_turn.is_some_and(|turn| turn.scope.worker_generation > runtime_generation)
    {
        return Err(ApplicationError::LocalRuntimeContextScopeMismatch.into());
    }
    Ok(runtime_generation)
}

fn runtime_authority_field(hasher: &mut Sha256, name: &str, value: &[u8]) {
    hasher.update((name.len() as u128).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update((value.len() as u128).to_be_bytes());
    hasher.update(value);
}

fn runtime_authority_optional_field(hasher: &mut Sha256, name: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            runtime_authority_field(hasher, name, b"some");
            runtime_authority_field(hasher, "value", value.as_bytes());
        }
        None => runtime_authority_field(hasher, name, b"none"),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the content-free authority digest explicitly frames every durable Mission, recovery, turn, workspace, attachment, assembly, and handle fence so omitted authority fields remain review-visible"
)]
fn runtime_authority_fence_digest(
    mission: &Mission,
    recovery: Option<&RuntimeRecoveryAttempt>,
    turn: Option<&RuntimeTurnAttempt>,
    mission_handle_digest: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    runtime_authority_field(
        &mut hasher,
        "domain",
        b"hartevo.cordis.runtime-authority/v1",
    );
    runtime_authority_field(&mut hasher, "tenant", mission.tenant_id.as_str().as_bytes());
    runtime_authority_field(
        &mut hasher,
        "project",
        mission.project_id.as_str().as_bytes(),
    );
    runtime_authority_field(&mut hasher, "mission", mission.id.as_str().as_bytes());
    runtime_authority_field(
        &mut hasher,
        "mission_revision",
        &mission.revision.to_be_bytes(),
    );
    runtime_authority_field(
        &mut hasher,
        "mission_stage",
        format!("{:?}", mission.stage).as_bytes(),
    );
    runtime_authority_optional_field(&mut hasher, "mission_handle_digest", mission_handle_digest);

    match recovery {
        None => runtime_authority_field(&mut hasher, "recovery", b"none"),
        Some(recovery) => {
            runtime_authority_field(&mut hasher, "recovery", b"some");
            runtime_authority_field(&mut hasher, "recovery_id", recovery.id.as_str().as_bytes());
            runtime_authority_field(
                &mut hasher,
                "recovery_tenant",
                recovery.tenant_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_project",
                recovery.project_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_mission",
                recovery.mission_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_workspace",
                recovery.workspace_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_worker",
                recovery.worker_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_generation",
                &recovery.worker_generation.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_source_attachment_epoch",
                &recovery.source_attachment_epoch.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_target_attachment_epoch",
                &recovery.target_attachment_epoch.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_source_mapping_digest",
                recovery.source_mapping_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_checkpoint_id",
                recovery.checkpoint_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_checkpoint_digest",
                recovery.checkpoint_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_runtime_config_digest",
                recovery.runtime_config_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_initial_strategy",
                format!("{:?}", recovery.initial_strategy).as_bytes(),
            );
            runtime_authority_optional_field(
                &mut hasher,
                "recovery_requested_thread_digest",
                recovery.requested_thread_id_digest.as_deref(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_max_process_attempts",
                &recovery.max_process_attempts.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_process_attempt",
                &recovery.process_attempt.to_be_bytes(),
            );
            runtime_authority_optional_field(
                &mut hasher,
                "recovery_health_digest",
                recovery.health_digest.as_deref(),
            );
            runtime_authority_optional_field(
                &mut hasher,
                "recovery_runtime_instance_digest",
                recovery.runtime_instance_digest.as_deref(),
            );
            runtime_authority_optional_field(
                &mut hasher,
                "recovery_runtime_thread_id",
                recovery.runtime_thread_id.as_deref(),
            );
            runtime_authority_optional_field(
                &mut hasher,
                "recovery_runtime_mapping_digest",
                recovery.runtime_mapping_digest.as_deref(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_status",
                format!("{:?}", recovery.status).as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_revision",
                &recovery.revision.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "recovery_updated_at",
                recovery.updated_at.to_rfc3339().as_bytes(),
            );
        }
    }

    match turn {
        None => runtime_authority_field(&mut hasher, "turn", b"none"),
        Some(turn) => {
            let scope = &turn.scope;
            runtime_authority_field(&mut hasher, "turn", b"some");
            runtime_authority_field(&mut hasher, "turn_id", turn.id.as_str().as_bytes());
            runtime_authority_field(
                &mut hasher,
                "turn_tenant",
                scope.tenant_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_project",
                scope.project_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_mission",
                scope.mission_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_workspace",
                scope.workspace_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_capsule_id",
                scope.capsule_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_capsule_revision",
                &scope.capsule_revision.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_capsule_authority_digest",
                scope.capsule_authority_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_branch_id",
                scope.branch_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_branch_revision",
                &scope.branch_revision.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_worker",
                scope.worker_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_generation",
                &scope.worker_generation.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_worker_lease_id",
                scope.worker_lease_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_worker_lease_revision",
                &scope.worker_lease_revision.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_attachment_epoch",
                &scope.attachment_epoch.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_assembly_id",
                scope.assembly_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_assembly_revision",
                &scope.assembly_revision.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_assembly_manifest_digest",
                scope.assembly_manifest_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_assembly_input_digest",
                scope.assembly_input_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_prompt_digest",
                scope.prompt_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_checkpoint_id",
                scope.checkpoint_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_checkpoint_digest",
                scope.checkpoint_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_recovery_id",
                scope.recovery_id.as_str().as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_recovery_revision",
                &scope.recovery_revision.to_be_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_runtime_instance_digest",
                scope.runtime_instance_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_runtime_mapping_digest",
                scope.runtime_mapping_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_runtime_thread_digest",
                scope.runtime_thread_id_digest.as_bytes(),
            );
            runtime_authority_field(
                &mut hasher,
                "turn_status",
                format!("{:?}", turn.status).as_bytes(),
            );
            runtime_authority_field(&mut hasher, "turn_revision", &turn.revision.to_be_bytes());
            runtime_authority_field(
                &mut hasher,
                "turn_updated_at",
                turn.updated_at.to_rfc3339().as_bytes(),
            );
        }
    }
    format!("{:x}", hasher.finalize())
}

struct LiveDomainKernelFacts {
    consent: ConsentState,
    record: Option<ConsentRecord>,
    approval: Option<Approval>,
}

fn live_domain_kernel_facts(
    service: &ApplicationService,
    project_id: &ProjectId,
    mission_id: &MissionId,
    now: DateTime<Utc>,
) -> Result<LiveDomainKernelFacts, DesktopDataError> {
    let mission = service.load_mission(project_id, mission_id)?;
    if mission.project_id != *project_id || mission.id != *mission_id {
        return Err(CordisError::AuthorityScopeMismatch.into());
    }
    let records = service.list_consent_records(project_id)?;
    let record = records
        .into_iter()
        .filter(|record| record.tenant_id == mission.tenant_id && record.project_id == *project_id)
        .max_by_key(|record| {
            (
                record.revision,
                record.granted_at.unwrap_or(DateTime::<Utc>::MIN_UTC),
                record.id.as_str().to_owned(),
            )
        });
    let consent = record
        .as_ref()
        .map_or(ConsentState::Missing, |record| match record.status {
            ConsentStatus::Granted
                if record.permits(
                    &record.person_id,
                    &record.purpose,
                    &record.channel,
                    &record.market,
                    now,
                ) =>
            {
                ConsentState::Confirmed
            }
            ConsentStatus::Withdrawn => ConsentState::Withdrawn,
            ConsentStatus::Granted | ConsentStatus::Denied | ConsentStatus::Expired => {
                ConsentState::Missing
            }
        });
    let approval = mission
        .effects
        .iter()
        .filter_map(|effect| effect.approval.as_ref())
        .filter(|candidate| {
            candidate.decision == ApprovalDecision::Approved && now < candidate.valid_until
        })
        .max_by_key(|candidate| (candidate.valid_until, candidate.decided_at))
        .cloned();
    Ok(LiveDomainKernelFacts {
        consent,
        record,
        approval,
    })
}

fn validate_catalog_continuation_handle(
    service: &ApplicationService,
    request: &DesktopMissionContinuationRequest,
    catalog_handle: Option<&CatalogMissionExecutionHandle>,
) -> Result<(), DesktopDataError> {
    let mission = service.load_mission(&request.project_id, &request.mission_id)?;
    if mission.project_id != request.project_id || mission.id != request.mission_id {
        return Err(CordisError::AuthorityScopeMismatch.into());
    }
    match (&mission.definition, catalog_handle) {
        (Some(_), Some(handle))
            if handle.project_id() == &request.project_id
                && handle.mission_id() == &request.mission_id
                && service
                    .mission_execution_handle(&request.project_id, &request.mission_id)?
                    == *handle =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        _ => {
            Err(ApplicationError::from(RuntimeTextSubscriptionError::MissionHandleMismatch).into())
        }
    }
}

fn no_runtime_turn_startup_reconciliation() -> RuntimeTurnStartupReconciliation {
    RuntimeTurnStartupReconciliation {
        scanned_attempts: 0,
        failed_before_dispatch: 0,
        frozen_uncertain: 0,
        already_safe: 0,
        event_sequences: Vec::new(),
        outbox_sequences: Vec::new(),
    }
}

/// Process-local BrowserControlHost for Desktop Continue.
///
/// Continue is a permissive transition: Application persists the new Agent
/// lease first, then this Host must adopt that successor. An unregistered or
/// non-successor Host fails as `BrowserHostReconciliationRequired`. This is
/// not a Fake Host test helper and does not execute Effects.
struct DesktopBrowserControlHost {
    workspace: BrowserWorkspace,
}

impl DesktopBrowserControlHost {
    fn attach(workspace: &BrowserWorkspace) -> Result<Self, DesktopDataError> {
        workspace
            .validate()
            .map_err(ApplicationError::from)
            .map_err(DesktopDataError::from)?;
        Ok(Self {
            workspace: workspace.clone(),
        })
    }
}

impl BrowserControlHost for DesktopBrowserControlHost {
    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        if *workspace == self.workspace {
            return Ok(());
        }
        if !workspace.is_valid_successor_of(&self.workspace)? {
            return Err(BrowserError::ScopeMismatch);
        }
        self.workspace = workspace.clone();
        Ok(())
    }
}

fn open_conversation_route_digest(
    live: &RelationshipConversationProjection,
    now: DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"desktop.conversation.open\0");
    hasher.update(live.person_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(live.connection_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(live.account_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(live.provider.as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("{:?}", live.gateway).as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("{:?}", live.contact_channel).as_bytes());
    hasher.update(b"\0");
    hasher.update(live.market.as_bytes());
    hasher.update(b"\0");
    hasher.update(now.to_rfc3339().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn continue_browser_workspace_evidence_digest(
    workspace: &BrowserWorkspace,
    now: DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"desktop.browser_workspace.continue\0");
    hasher.update(workspace.project_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(workspace.mission_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(workspace.id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(workspace.revision.to_le_bytes());
    hasher.update(workspace.lease_generation.to_le_bytes());
    hasher.update(b"\0");
    hasher.update(format!("{:?}", workspace.control_state).as_bytes());
    hasher.update(b"\0");
    hasher.update(now.to_rfc3339().as_bytes());
    format!("{:x}", hasher.finalize())
}

impl fmt::Debug for DesktopDataPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopDataPlane")
            .field(
                "data_root_digest",
                &format!(
                    "{:x}",
                    Sha256::digest(self.data_root.as_os_str().as_encoded_bytes())
                ),
            )
            .field(
                "database_key_credential_id",
                &self.database_key_reference.credential_id().ok(),
            )
            // The canonical database path is intentionally excluded from
            // diagnostics; the digest above is sufficient for correlation.
            .finish_non_exhaustive()
    }
}

fn load_product_evidence(
    observed_at: DateTime<Utc>,
) -> Result<ProductEvidenceProjection, DesktopDataError> {
    let catalog = Catalog::load()?;
    let snapshot = catalog.snapshot()?;
    let evidence = ReleaseEvidence::wave_zero_baseline(
        &snapshot,
        "WORKTREE_UNCOMMITTED_NOT_RELEASE_EVIDENCE",
        observed_at,
    );
    let missions = catalog
        .missions
        .missions
        .iter()
        .map(|manifest| {
            let record = evidence
                .mission_results
                .get(&manifest.id)
                .expect("validated Catalog and baseline share twelve Mission ids");
            MissionContractEvidenceProjection {
                mission_id: manifest.id.clone(),
                title: manifest.title.clone(),
                modes: manifest.modes.clone(),
                default_cadence: manifest.default_cadence.clone(),
                evidence_level: record.evidence_level,
                status: record.status,
                failure_count: record.failures.len(),
            }
        })
        .collect();
    Ok(ProductEvidenceProjection {
        catalog_digest: snapshot.digest,
        release_passed: evidence.passed,
        missions,
    })
}

fn reject_symlink(path: &Path) -> Result<(), DesktopDataError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(DesktopDataError::InvalidDataRoot(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataRootIdentity {
    canonical_path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DataRootIdentity {
    fn capture(path: &Path) -> Result<Self, DesktopDataError> {
        let canonical_path = path.canonicalize()?;
        let metadata = fs::metadata(&canonical_path)?;
        if !metadata.is_dir() {
            return Err(DesktopDataError::InvalidDataRoot(path.to_path_buf()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                canonical_path,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { canonical_path })
        }
    }

    fn matches(&self, path: &Path) -> bool {
        Self::capture(path).is_ok_and(|current| current == *self)
    }
}

fn decode_recovery_key(encoded: &str) -> Result<SecretBytes, DesktopDataError> {
    let encoded = encoded.trim();
    if encoded.len() != 64 {
        return Err(DesktopDataError::InvalidRecoveryKey);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(encoded, bytes.as_mut())
        .map_err(|_| DesktopDataError::InvalidRecoveryKey)?;
    SecretBytes::new(bytes.to_vec()).map_err(|_| DesktopDataError::InvalidRecoveryKey)
}

fn recovery_recipient_id(project_id: &ProjectId) -> String {
    format!("personal-recovery:{}", project_id.as_str())
}

fn select_personal_recovery_recipient(
    keyring: &ProjectKeyring,
    project_id: &ProjectId,
    now: DateTime<Utc>,
) -> Result<String, DesktopDataError> {
    let mut active = keyring
        .envelopes
        .iter()
        .filter(|envelope| {
            envelope.key_version == keyring.active_key_version && envelope.is_available(now)
        })
        .filter_map(|envelope| match &envelope.recipient {
            KeyRecipient::Recovery(id) => Some(id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    active.sort();
    active.dedup();
    let desktop_recipient = recovery_recipient_id(project_id);
    if active
        .iter()
        .any(|candidate| candidate == &desktop_recipient)
    {
        return Ok(desktop_recipient);
    }
    if let [only] = active.as_slice() {
        return Ok(only.clone());
    }
    Err(DesktopDataError::ProjectRecoveryNotApplicable(
        project_id.clone(),
    ))
}

fn desktop_recovery_authorization_digest(
    project_id: &ProjectId,
    device_id: &DeviceId,
    keyring_revision: u64,
) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!(
                "desktop-user-confirmed-personal-recovery-v1|{project_id}|{device_id}|{keyring_revision}"
            )
            .as_bytes()
        )
    )
}

fn context_device_is_unavailable(error: &ApplicationError) -> bool {
    matches!(
        error,
        ApplicationError::KeyManagement(KeyManagementError::RecipientNotFound)
            | ApplicationError::SecretStore(SecretStoreError::SecretNotFound)
            | ApplicationError::ContextMaterialKeyReferenceUnavailable { .. }
    )
}

fn classify_context_access_error(error: &ApplicationError) -> ProjectContextAccessStatus {
    match error {
        ApplicationError::KeyManagement(KeyManagementError::RecipientNotFound)
        | ApplicationError::SecretStore(SecretStoreError::SecretNotFound)
        | ApplicationError::ContextMaterialKeyReferenceUnavailable { .. } => {
            ProjectContextAccessStatus::RecoveryRequired
        }
        ApplicationError::ContextMaterialProjectRootUnavailable
        | ApplicationError::ContextMaterialStore(
            ContextMaterialStoreError::InvalidProjectRoot | ContextMaterialStoreError::Io(_),
        ) => ProjectContextAccessStatus::BlockedEnvironment,
        ApplicationError::KeyManagement(KeyManagementError::RotationRequired) => {
            ProjectContextAccessStatus::RotationRequired
        }
        _ => ProjectContextAccessStatus::IntegrityError,
    }
}

fn default_data_root() -> Result<PathBuf, DesktopDataError> {
    if let Some(path) = env::var_os(DATA_DIRECTORY_ENV) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Hartevo"));
    }
    #[cfg(target_os = "windows")]
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data)
            .join("Hartevo")
            .join("Desktop"));
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(data_home).join("hartevo"));
        }
        if let Some(home) = env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("hartevo"));
        }
    }
    Err(DesktopDataError::DataDirectoryUnavailable)
}

fn map_runtime_dispatch_result<T>(
    result: Result<T, AuthorityDispatchError<DesktopDataError>>,
) -> Result<T, DesktopDataError> {
    match result {
        Ok(output) => Ok(output),
        Err(AuthorityDispatchError::Cordis(error)) => Err((*error).into()),
        Err(AuthorityDispatchError::Authority(error)) => Err(error),
        Err(error @ AuthorityDispatchError::Combined(_)) => {
            Err(DesktopDataError::RuntimeDispatch(Box::new(error)))
        }
    }
}

#[derive(Debug, Error)]
pub enum DesktopDataError {
    #[error("Desktop data root must be an absolute non-symlink directory: {0}")]
    InvalidDataRoot(PathBuf),
    #[error("the platform data directory could not be resolved")]
    DataDirectoryUnavailable,
    #[error("the SQLCipher database exists but its OS-vault key is missing")]
    MissingDatabaseKey,
    #[error("Mission goal cannot be empty")]
    EmptyMissionGoal,
    #[error(
        "Catalog Mission requires an explicit valid route, mode, market, language, audience, timezone, nonnegative minor-unit budget, and ISO currency"
    )]
    InvalidCatalogMissionContract,
    #[error("Mission continuation requires a nonempty message and stable idempotency key")]
    InvalidMissionContinuation,
    #[error(
        "Human Checkpoint confirmation requires an exact Checkpoint, message, and idempotency key"
    )]
    InvalidHumanCheckpointConfirmation,
    #[error(
        "VM-11 outcome decision requires a typed action, private rationale, actor, and exact frozen review digests"
    )]
    InvalidVm11OutcomeDecision,
    #[error(
        "VM-11 next_contract_or_valid_terminal requires the frozen decision digest, parent contract digest, and exact Mission/Checkpoint revisions"
    )]
    InvalidVm11NextContractResolution,
    #[error(
        "WaitingApproval grant requires an exact Proposed Effect digest and Mission CAS revision"
    )]
    InvalidWaitingApprovalGrant,
    #[error(
        "Browser Workspace Continue requires the exact Mission-bound workspace id, revision, and generation from SQLCipher"
    )]
    InvalidBrowserWorkspaceContinue,
    #[error("no live Mission-bound Browser Workspace exists for Continue")]
    BrowserWorkspaceUnavailable,
    #[error(
        "Browser Workspace Continue requires a user-held lease; Take over remains NOT_IMPLEMENTED"
    )]
    BrowserWorkspaceContinueNotHeld,
    #[error(
        "Creator Deliverable Review requires the exact Project, Mission, task, deliverable, CAS revision, frozen checklist, and a typed ReviewDecision"
    )]
    InvalidCreatorDeliverableReview,
    #[error("no matching uploaded Creator Deliverable is ready for Review")]
    CreatorDeliverableReviewUnavailable,
    #[error(
        "Creator Deliverable Review must match the current task CAS revision; stale Review was not written"
    )]
    CreatorDeliverableReviewStale,
    #[error(
        "Open Conversation requires the exact live Project, Mission, Person, Connection, gateway, market, and route digest"
    )]
    InvalidConversationOpen,
    #[error("no live Mission-bound Person/Connection identity is ready for Open Conversation")]
    ConversationOpenUnavailable,
    #[error(
        "the Mission already has an opened CRM Conversation; Open Conversation does not mint another"
    )]
    ConversationAlreadyOpen,
    #[error("project name cannot be empty")]
    EmptyProjectName,
    #[error("recovery key must be exactly 32 bytes encoded as 64 hexadecimal characters")]
    InvalidRecoveryKey,
    #[error("project {0} is not present in the Application inventory")]
    ProjectNotFound(ProjectId),
    #[error("project {0} has no usable, non-rotating encryption keyring")]
    ProjectEncryptionNotReady(ProjectId),
    #[error("project {0} already has an encryption keyring")]
    ProjectEncryptionAlreadyProvisioned(ProjectId),
    #[error("project {0} cannot use a personal Recovery Kit device attachment")]
    ProjectRecoveryNotApplicable(ProjectId),
    #[error("project {0} requires device recovery before its encrypted Context can open")]
    ProjectContextRecoveryRequired(ProjectId),
    #[error("project {0} Context workspace is unavailable on this device")]
    ProjectContextBlockedEnvironment(ProjectId),
    #[error("project {0} Context key or storage integrity validation failed")]
    ProjectContextIntegrityError(ProjectId),
    #[error("Runtime text subscription context does not match the authorized Tenant and Project")]
    RuntimeSubscriptionContextMismatch,
    #[error("the selected WorkProduct revision no longer matches the current Mission projection")]
    WorkProductActionStale,
    #[error("no live Runtime local-write approval is held for this Desktop turn")]
    RuntimeLocalApprovalUnavailable,
    #[error("Runtime local-write approval must match the exact held digest and revision")]
    RuntimeLocalApprovalMismatch,
    #[error(transparent)]
    Cordis(#[from] CordisError),
    #[error("Cordis Runtime dispatch failed across phases: {0}")]
    RuntimeDispatch(#[source] Box<AuthorityDispatchError<DesktopDataError>>),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Application(#[from] ApplicationError),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::Duration;
    use hartevo_application::{
        AcceptCreatorTask, CreateBrowserWorkspace, CreateManagedBrowserProfile, CreateProject,
        EvidenceInput, ProposePreviewEffect, ProvisionProjectEncryption, PublishCreatorTask,
        ResearchPacket, RuntimeTextSubscriptionError, StartCreatorWorkMission, StartMission,
        StartRelationshipMission, SubmitCreatorDeliverable, TakeOverBrowserWorkspace,
    };
    use hartevo_browser_adapter::FakeBrowserHost;
    use hartevo_domain_kernel::{
        AccountId, ActorId, ApprovalDecision, BrowserControlLeaseId, BrowserProfileId,
        BrowserTabId, BrowserWorkspaceId, Company, CompanyId, Connection, ConnectionId,
        ConnectionProbe, ConsentPurpose, ConsentRecordId, ConsentRequirement, ConsentState,
        ContactChannel, ContextBranchStatus, ContextCapsuleStatus, ConversationState,
        CreatorApplicationId, CreatorDeliverableInput, CreatorEligibility, CreatorHiringAward,
        CreatorHiringId, CreatorId, CreatorMilestoneId, CreatorMilestoneSpec, CreatorTaskId,
        CreatorTaskSpec, DeliverableAssessment, DeliverableId, EffectId, EffectStatus, EvidenceId,
        ExternalIdentity, FundingReservation, IdentityLink, IdentityLinkId, IdentitySubject,
        KeyRecipient, KpiDirection, LegalBasis, MessagingGateway, MissionCheckpointExecutor,
        MissionScheduleStatus, MissionStage, OrderId, OutcomeDecision, OutcomeEvent,
        OutcomeEventId, OutcomeEventKind, OutcomeSourceVerification, OutcomeVerificationMethod,
        PartnerId, Person, PersonId, ProbeOutcome, ProjectEncryptionMode, RightsAttestation,
        StorageMode, TaskId, TaskStatus, UsageRights, WorkProductId, WorkerLeaseStatus,
    };
    use hartevo_effect_broker::EffectBroker;
    use hartevo_storage::MemorySecretStore;
    use rust_decimal::Decimal;

    use crate::runtime_subscription::{
        DesktopCatalogRuntimeDispatchAuthority, DesktopRuntimeDelivery,
        DesktopRuntimeExecutionPaintState, DesktopRuntimeReducerEffect,
        DesktopRuntimeSubscriptionEpoch, DesktopRuntimeSubscriptionReducer,
        DesktopRuntimeSubscriptionScope,
    };

    use super::*;

    fn observed_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-11T10:00:00Z")
            .expect("valid fixture time")
            .with_timezone(&Utc)
    }

    fn current_catalog_handle(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> CatalogMissionExecutionHandle {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        plane
            .open_read_application_from_secret(&database_secret)
            .expect("read Application")
            .mission_execution_handle(project_id, mission_id)
            .expect("exact Catalog execution handle")
    }

    fn catalog_runtime_authority(
        handle: CatalogMissionExecutionHandle,
    ) -> DesktopCatalogRuntimeDispatchAuthority {
        let mut paint = DesktopRuntimeExecutionPaintState::default();
        let commit = paint
            .commit_catalog_start(handle)
            .expect("prepare exact Catalog paint");
        let launch = paint
            .acknowledge_rendered_paint(&commit)
            .expect("acknowledge exact Catalog paint");
        let (_, _, authority) = launch.into_dispatch_parts();
        assert!(authority.is_exact_post_render_authority());
        authority
    }

    #[test]
    fn combined_runtime_dispatch_mapping_retains_every_typed_phase() {
        let started = CordisError::InvalidAuthorityScope { field: "started" };
        let combined = AuthorityDispatchError::from_phases(
            Some(started.clone()),
            Some(DesktopDataError::EmptyMissionGoal),
            None,
            None,
        )
        .expect("two failures form one combined dispatch error");

        let mapped = map_runtime_dispatch_result::<()>(Err(combined)).unwrap_err();

        let DesktopDataError::RuntimeDispatch(dispatch) = mapped else {
            panic!("combined dispatch must remain boxed as one Desktop error");
        };
        let AuthorityDispatchError::Combined(failures) = dispatch.as_ref() else {
            panic!("boxed dispatch must retain its combined structure");
        };
        assert_eq!(failures.started(), Some(&started));
        assert!(matches!(
            failures.authority(),
            Some(DesktopDataError::EmptyMissionGoal)
        ));
        assert!(failures.finish().is_none());
        assert!(failures.disposed().is_none());
    }

    #[test]
    fn persistent_installer_reuses_the_first_cordis_coordinator() {
        let directory = tempfile::tempdir().expect("directory");
        let first = DesktopDataPlane::at_data_root(directory.path().join("first")).unwrap();
        let second = DesktopDataPlane::at_data_root(directory.path().join("second")).unwrap();
        assert!(!first.shares_cordis_coordinator(&second));

        let cell = OnceLock::new();
        let installed = DesktopDataPlane::install_persistent(&cell, first);
        let raced = DesktopDataPlane::install_persistent(&cell, second);
        assert!(installed.shares_cordis_coordinator(&raced));
    }

    fn production_preview_broker() -> EffectBroker {
        DesktopDataPlane::waiting_approval_broker()
    }

    fn assert_host_fail_closed_on_consent(plane: &DesktopDataPlane) {
        use hartevo_cordis::{
            DomainSurface, OPENINTERPRETER, SurfaceOwner, host_is_cordis_loop, invariant_missing,
        };

        plane.with_cordis_host(|host| {
            host_is_cordis_loop(host).unwrap();
            let domain = host.context().domain::<DomainSurface>().unwrap();
            assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
            assert!(!domain.consent());
            assert!(!domain.approved());
            assert!(
                !host
                    .context()
                    .effect_broker::<hartevo_cordis::EffectBrokerSurface>()
                    .unwrap()
                    .receipt_is_verification()
            );
            assert_eq!(
                host.step(AgentStep::new("mission-unbound", "plan"))
                    .unwrap_err(),
                CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
            );
            assert_eq!(
                host.apply_effect().unwrap_err(),
                CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
            );
            assert!(
                host.context().get::<String>(OPENINTERPRETER).is_none()
                    || host.runtime_plugin() == Some(OPENINTERPRETER)
            );
        });
    }

    fn create_kernel_bind_project(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_root: &Path,
        suffix: &str,
        now: DateTime<Utc>,
    ) -> (ProjectId, TenantId) {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, now)
            .expect("application");
        let tenant_id = TenantId::from_stable(format!("desktop-kernel-tenant-{suffix}"));
        let project_id = ProjectId::from_stable(format!("desktop-kernel-project-{suffix}"));
        service
            .create_project(
                CreateProject {
                    tenant_id: tenant_id.clone(),
                    id: project_id.clone(),
                    name: format!("Kernel bind {suffix}"),
                    description: String::new(),
                    workspace_root: project_root.to_path_buf(),
                    storage_mode: StorageMode::LocalExisting,
                },
                now,
            )
            .expect("project");
        (project_id, tenant_id)
    }

    struct LiveConsentGrant<'a> {
        plane: &'a DesktopDataPlane,
        secrets: &'a MemorySecretStore,
        project_id: &'a ProjectId,
        tenant_id: &'a TenantId,
        suffix: &'a str,
        now: DateTime<Utc>,
        consent_until: Option<DateTime<Utc>>,
    }

    fn grant_live_consent(input: &LiveConsentGrant<'_>) -> (PersonId, ConsentRecordId, MissionId) {
        let database_secret = input
            .secrets
            .get(input.plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = input
            .plane
            .open_application_from_secret(&database_secret, input.now)
            .expect("application");
        let person_id = PersonId::from_stable(format!("desktop-kernel-person-{}", input.suffix));
        let consent_id =
            ConsentRecordId::from_stable(format!("desktop-kernel-consent-{}", input.suffix));
        let mission_id = MissionId::from_stable(format!("desktop-kernel-mission-{}", input.suffix));
        service
            .create_person(
                Person::create(
                    person_id.clone(),
                    input.tenant_id.clone(),
                    input.project_id.clone(),
                    "Kernel bind contact",
                    None,
                    vec![],
                )
                .expect("person"),
                input.now,
            )
            .expect("persist person");
        service
            .grant_consent(
                ConsentRecord::grant(
                    consent_id.clone(),
                    input.tenant_id.clone(),
                    input.project_id.clone(),
                    person_id.clone(),
                    ConsentPurpose::DirectOutreach,
                    ContactChannel::Email,
                    "US",
                    LegalBasis::ExplicitConsent,
                    "desktop-kernel-bind",
                    "e".repeat(64),
                    input.now,
                    input.consent_until,
                )
                .expect("granted consent"),
                input.now,
            )
            .expect("persist consent");
        service
            .start_mission(
                StartMission {
                    id: mission_id.clone(),
                    research_task_id: TaskId::from_stable(format!(
                        "desktop-kernel-task-{}",
                        input.suffix
                    )),
                    project_id: input.project_id.clone(),
                    title: Some("Kernel bind Mission".into()),
                    prompt: "研究当前增长约束；不得执行外部动作".into(),
                },
                input.now,
            )
            .expect("mission");
        (person_id, consent_id, mission_id)
    }

    struct LivePreviewApproval<'a> {
        plane: &'a DesktopDataPlane,
        secrets: &'a MemorySecretStore,
        project_id: &'a ProjectId,
        person_id: PersonId,
        consent_id: &'a ConsentRecordId,
        mission_id: &'a MissionId,
        suffix: &'a str,
        now: DateTime<Utc>,
    }

    fn approve_live_preview(input: &LivePreviewApproval<'_>) {
        let database_secret = input
            .secrets
            .get(input.plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = input
            .plane
            .open_application_from_secret(&database_secret, input.now)
            .expect("application");
        let effect_id = EffectId::from_stable(format!("desktop-kernel-effect-{}", input.suffix));
        service
            .propose_preview_effect(
                input.project_id,
                input.mission_id,
                ProposePreviewEffect {
                    effect_id: effect_id.clone(),
                    actor_id: ActorId::from("desktop-kernel-actor"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: None,
                    account_id: None,
                    required_scopes: BTreeSet::new(),
                    description: "Bind live Domain Kernel approval".into(),
                    target_resource: "preview://desktop-kernel".into(),
                    audience_digest: None,
                    payload_digest: "1".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: ConsentState::Confirmed,
                    consent_record_id: Some(input.consent_id.clone()),
                    consent_requirement: Some(ConsentRequirement {
                        person_id: input.person_id.clone(),
                        purpose: ConsentPurpose::DirectOutreach,
                        channel: ContactChannel::Email,
                        market: "US".into(),
                    }),
                    policy_version: "policy-v1".into(),
                    amount: Money::zero(CurrencyCode::parse("CNY").expect("CNY")),
                    idempotency_key: format!("desktop-kernel-{}", input.suffix),
                    expires_in: Duration::hours(1),
                },
                input.now + Duration::seconds(1),
            )
            .expect("effect");
        let broker = production_preview_broker();
        service
            .approve_effect(
                &broker,
                input.project_id,
                input.mission_id,
                &effect_id,
                ActorId::from("desktop-kernel-approver"),
                input.now + Duration::seconds(2),
            )
            .expect("approval");
    }

    fn catalog_count_kpis() -> BTreeMap<String, KpiContract> {
        BTreeMap::from([(
            "lead_qualified_count".into(),
            KpiContract {
                baseline: Some(Decimal::ZERO),
                target: Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            },
        )])
    }

    fn start_vm11_parent(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> MissionId {
        plane
            .start_catalog_mission_and_run_with(
                secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-07".into(),
                    mode: OperatingMode::OneOffDecision,
                    parent_mission_id: None,
                    title: Some("Outcome source mission".into()),
                    goal: "Decide a bounded market experiment and measure its verified lead".into(),
                    market: "US".into(),
                    language: "en-US".into(),
                    audience: "owner".into(),
                    timezone: "America/New_York".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "USD".into(),
                },
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                now,
            )
            .expect("VM-11 source Mission")
            .mission_id
    }

    fn ready_personal_fixture() -> (
        tempfile::TempDir,
        DesktopDataPlane,
        MemorySecretStore,
        ProjectId,
    ) {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");
        let recovery = RecoveryKitDraft::generate().expect("recovery kit");
        let created = plane
            .create_personal_project_with(
                &secrets,
                "Runtime journey fixture",
                "建立本地初始 Mission；不执行外部动作",
                recovery.expose_for_user_export(),
                observed_at() + Duration::minutes(1),
            )
            .expect("ready personal project");
        let project_id = created.inventory.projects[0].project_id.clone();
        (directory, plane, secrets, project_id)
    }

    fn catalog_runtime_request(project_id: &ProjectId) -> DesktopCatalogMissionRequest {
        DesktopCatalogMissionRequest {
            project_id: project_id.clone(),
            manifest_id: "VM-04".into(),
            mode: OperatingMode::Campaign,
            parent_mission_id: None,
            title: Some("Durable Runtime subscription".into()),
            goal: "Render authorized private Runtime text while execution remains bounded".into(),
            market: "DE".into(),
            language: "de-DE".into(),
            audience: "owner".into(),
            timezone: "Europe/Berlin".into(),
            kpis: catalog_count_kpis(),
            budget_minor: 0,
            currency: "EUR".into(),
        }
    }

    fn persisted_outbox_messages(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
    ) -> Vec<hartevo_storage::OutboxMessage> {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let database_key = DatabaseKey::from_secret(&database_secret).expect("database key");
        let store = ProjectStore::open(&plane.database_path, &database_key).expect("project store");
        let mut sequence = 1_i64;
        let mut messages = Vec::new();
        loop {
            match store.outbox_message(sequence) {
                Ok(message) => {
                    assert_eq!(message.sequence, sequence);
                    messages.push(message);
                }
                Err(StorageError::DomainDecode(message))
                    if message == format!("unknown outbox message {sequence}") =>
                {
                    return messages;
                }
                Err(error) => panic!("outbox inspection failed at {sequence}: {error}"),
            }
            sequence = sequence.checked_add(1).expect("bounded outbox fixture");
        }
    }

    #[derive(Clone, Eq, PartialEq)]
    struct DurableSnapshotDomainDigest {
        row_count: usize,
        digest: [u8; 32],
    }

    impl fmt::Debug for DurableSnapshotDomainDigest {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DurableSnapshotDomainDigest")
                .field("row_count", &self.row_count)
                .field("digest", &ShortSnapshotDigest(&self.digest))
                .finish()
        }
    }

    #[derive(Clone, Eq, PartialEq)]
    struct RuntimeSubscriptionDurableSnapshotDigest {
        project: DurableSnapshotDomainDigest,
        project_keyring: DurableSnapshotDomainDigest,
        missions: DurableSnapshotDomainDigest,
        conversations: DurableSnapshotDomainDigest,
        project_events: DurableSnapshotDomainDigest,
        outbox: DurableSnapshotDomainDigest,
        runtime_attempts: DurableSnapshotDomainDigest,
        private_messages: DurableSnapshotDomainDigest,
        private_text_deltas: DurableSnapshotDomainDigest,
        overall_digest: [u8; 32],
    }

    impl fmt::Debug for RuntimeSubscriptionDurableSnapshotDigest {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("RuntimeSubscriptionDurableSnapshotDigest")
                .field("project", &self.project)
                .field("project_keyring", &self.project_keyring)
                .field("missions", &self.missions)
                .field("conversations", &self.conversations)
                .field("project_events", &self.project_events)
                .field("outbox", &self.outbox)
                .field("runtime_attempts", &self.runtime_attempts)
                .field("private_messages", &self.private_messages)
                .field("private_text_deltas", &self.private_text_deltas)
                .field("overall_digest", &ShortSnapshotDigest(&self.overall_digest))
                .finish()
        }
    }

    struct ShortSnapshotDigest<'a>(&'a [u8; 32]);

    impl fmt::Debug for ShortSnapshotDigest<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "{:02x}{:02x}{:02x}{:02x}…",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }

    fn write_canonical_snapshot_json(value: &serde_json::Value, output: &mut Vec<u8>) {
        match value {
            serde_json::Value::Null => output.extend_from_slice(b"null"),
            serde_json::Value::Bool(value) => {
                output.extend_from_slice(if *value { b"true" } else { b"false" });
            }
            serde_json::Value::Number(value) => {
                output.extend_from_slice(value.to_string().as_bytes());
            }
            serde_json::Value::String(value) => {
                output.extend_from_slice(
                    serde_json::to_string(value)
                        .expect("snapshot string must serialize")
                        .as_bytes(),
                );
            }
            serde_json::Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write_canonical_snapshot_json(value, output);
                }
                output.push(b']');
            }
            serde_json::Value::Object(values) => {
                output.push(b'{');
                let mut fields = values.iter().collect::<Vec<_>>();
                fields.sort_unstable_by_key(|(name, _)| (*name).clone());
                for (index, (name, value)) in fields.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(
                        serde_json::to_string(name)
                            .expect("snapshot field name must serialize")
                            .as_bytes(),
                    );
                    output.push(b':');
                    write_canonical_snapshot_json(value, output);
                }
                output.push(b'}');
            }
        }
    }

    fn snapshot_frame(hasher: &mut Sha256, bytes: &[u8]) {
        let byte_count = u64::try_from(bytes.len()).expect("bounded snapshot material");
        hasher.update(byte_count.to_be_bytes());
        hasher.update(bytes);
    }

    fn durable_snapshot_json_domain_digest(
        domain: &str,
        rows: &[serde_json::Value],
    ) -> DurableSnapshotDomainDigest {
        let mut canonical_rows = rows
            .iter()
            .map(|row| {
                let mut encoded = Vec::new();
                write_canonical_snapshot_json(row, &mut encoded);
                encoded
            })
            .collect::<Vec<_>>();
        canonical_rows.sort_unstable();

        let mut hasher = Sha256::new();
        snapshot_frame(
            &mut hasher,
            b"hartevo-runtime-subscription-durable-domain-v1",
        );
        snapshot_frame(&mut hasher, domain.as_bytes());
        hasher.update(
            u64::try_from(canonical_rows.len())
                .expect("bounded snapshot row count")
                .to_be_bytes(),
        );
        for row in &canonical_rows {
            snapshot_frame(&mut hasher, row);
        }
        DurableSnapshotDomainDigest {
            row_count: canonical_rows.len(),
            digest: hasher.finalize().into(),
        }
    }

    macro_rules! durable_snapshot_domain_digest {
        ($domain:expr, $rows:expr) => {{
            let snapshot_rows = ($rows)
                .iter()
                .map(|row| serde_json::to_value(row).expect("snapshot row must serialize"))
                .collect::<Vec<_>>();
            durable_snapshot_json_domain_digest($domain, &snapshot_rows)
        }};
    }

    fn durable_snapshot_overall_digest(
        domains: &[(&str, &DurableSnapshotDomainDigest)],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        snapshot_frame(
            &mut hasher,
            b"hartevo-runtime-subscription-durable-snapshot-v1",
        );
        for (name, domain) in domains {
            snapshot_frame(&mut hasher, name.as_bytes());
            hasher.update(
                u64::try_from(domain.row_count)
                    .expect("bounded snapshot row count")
                    .to_be_bytes(),
            );
            hasher.update(domain.digest);
        }
        hasher.finalize().into()
    }

    fn contains_full_hex_digest(value: &str) -> bool {
        value
            .split(|character: char| !character.is_ascii_hexdigit())
            .any(|token| token.len() >= 64)
    }

    #[test]
    fn durable_snapshot_digest_is_canonical_private_and_mutation_sensitive() {
        let private_attempt_id = "runtime-attempt-private-raw-id";
        let private_text = "private Runtime text must never enter assertion output";
        let first = serde_json::json!({
            "runtimeAttemptId": private_attempt_id,
            "streamSequence": 1,
            "privateText": private_text,
        });
        let second = serde_json::json!({
            "runtimeAttemptId": private_attempt_id,
            "streamSequence": 2,
            "privateText": "second private increment",
        });
        let changed = serde_json::json!({
            "runtimeAttemptId": private_attempt_id,
            "streamSequence": 2,
            "privateText": "mutated private increment",
        });

        let ordered = durable_snapshot_json_domain_digest(
            "runtime-private-text-deltas",
            &[first.clone(), second.clone()],
        );
        let reordered = durable_snapshot_json_domain_digest(
            "runtime-private-text-deltas",
            &[second, first.clone()],
        );
        let mutated =
            durable_snapshot_json_domain_digest("runtime-private-text-deltas", &[first, changed]);
        assert_eq!(ordered, reordered);
        assert_ne!(ordered, mutated);
        assert_ne!(
            durable_snapshot_overall_digest(&[("runtime-private-text-deltas", &ordered)]),
            durable_snapshot_overall_digest(&[("runtime-private-text-deltas", &mutated)])
        );

        let debug = format!("{ordered:?}");
        assert!(!debug.contains(private_attempt_id));
        assert!(!debug.contains(private_text));
        assert!(!contains_full_hex_digest(&debug));
    }

    fn runtime_subscription_durable_snapshot(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
    ) -> RuntimeSubscriptionDurableSnapshotDigest {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let database_key = DatabaseKey::from_secret(&database_secret).expect("database key");
        let store = ProjectStore::open(&plane.database_path, &database_key).expect("project store");
        let project = store.load_project(project_id).expect("snapshot Project");
        let keyring = store
            .load_project_keyring(project_id)
            .expect("snapshot Project keyring");
        let missions = store.list_missions(project_id).expect("snapshot Missions");
        let project_events = store
            .events_for_project(project_id)
            .expect("snapshot all Project events");
        let mut conversations = Vec::new();
        for mission in &missions {
            match store.load_mission_conversation(project_id, &mission.id) {
                Ok(conversation) => conversations.push(conversation),
                Err(StorageError::ScopedRecordNotFound {
                    kind: "mission conversation",
                    ..
                }) => {}
                Err(error) => panic!("snapshot Conversation failed: {error}"),
            }
        }
        let outbox = persisted_outbox_messages(plane, secrets);
        let attempts = store
            .list_runtime_turn_attempts(project_id)
            .expect("snapshot all Runtime attempts");
        let mut private_messages = Vec::new();
        let mut private_text_deltas = Vec::new();
        for attempt in &attempts {
            private_messages.extend(
                store
                    .load_runtime_turn_private_messages(project_id, &attempt.id)
                    .unwrap_or_else(|_| panic!("snapshot Runtime private-message read failed")),
            );
            private_text_deltas.extend(
                store
                    .load_runtime_turn_private_text_deltas(project_id, &attempt.id)
                    .unwrap_or_else(|_| panic!("snapshot Runtime private-delta read failed")),
            );
        }

        let project = durable_snapshot_domain_digest!("project", std::slice::from_ref(&project));
        let project_keyring =
            durable_snapshot_domain_digest!("project-keyring", std::slice::from_ref(&keyring));
        let missions = durable_snapshot_domain_digest!("missions", &missions);
        let conversations = durable_snapshot_domain_digest!("conversations", &conversations);
        let project_events = durable_snapshot_domain_digest!("project-events", &project_events);
        let outbox = durable_snapshot_domain_digest!("outbox", &outbox);
        let runtime_attempts = durable_snapshot_domain_digest!("runtime-attempts", &attempts);
        let private_messages =
            durable_snapshot_domain_digest!("runtime-private-messages", &private_messages);
        let private_text_deltas =
            durable_snapshot_domain_digest!("runtime-private-text-deltas", &private_text_deltas);
        let overall_digest = durable_snapshot_overall_digest(&[
            ("project", &project),
            ("project-keyring", &project_keyring),
            ("missions", &missions),
            ("conversations", &conversations),
            ("project-events", &project_events),
            ("outbox", &outbox),
            ("runtime-attempts", &runtime_attempts),
            ("runtime-private-messages", &private_messages),
            ("runtime-private-text-deltas", &private_text_deltas),
        ]);
        RuntimeSubscriptionDurableSnapshotDigest {
            project,
            project_keyring,
            missions,
            conversations,
            project_events,
            outbox,
            runtime_attempts,
            private_messages,
            private_text_deltas,
            overall_digest,
        }
    }

    #[cfg(unix)]
    fn runtime_fixture_start_messages(project_root: &Path, runtime_home: &Path) -> [String; 4] {
        let thread_id = "desktop-fixture-thread";
        let turn_id = "desktop-fixture-turn";
        [
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"codexHome": runtime_home},
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "thread": {"id": thread_id},
                    "cwd": project_root,
                    "model": "fixture-model",
                    "modelProvider": "fixture-provider",
                    "approvalPolicy": "on-request",
                    "approvalsReviewer": "user",
                    "sandbox": "workspace-write",
                },
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "turn/started",
                "params": {
                    "threadId": thread_id,
                    "turn": {"id": turn_id, "status": "inProgress"},
                },
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {"turn": {"id": turn_id, "status": "inProgress"}},
            })
            .to_string(),
        ]
    }

    #[cfg(unix)]
    fn runtime_fixture_completion_messages() -> [String; 5] {
        let thread_id = "desktop-fixture-thread";
        let turn_id = "desktop-fixture-turn";
        [
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "item/started",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "item": {
                        "id": "desktop-fixture-item",
                        "type": "agentMessage",
                        "text": "",
                    },
                },
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "itemId": "desktop-fixture-item",
                    "delta": "Reviewable local runtime ",
                },
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "itemId": "desktop-fixture-item",
                    "delta": "draft; no external effect occurred.",
                },
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "item/completed",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "item": {
                        "id": "desktop-fixture-item",
                        "type": "agentMessage",
                        "text": "Reviewable local runtime draft; no external effect occurred.",
                    },
                },
            })
            .to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "turn/completed",
                "params": {
                    "threadId": thread_id,
                    "turn": {"id": turn_id, "status": "completed"},
                },
            })
            .to_string(),
        ]
    }

    #[cfg(unix)]
    fn completed_runtime_fixture_command(
        project_root: &Path,
        runtime_home: &Path,
    ) -> RuntimeCommand {
        let project_root = project_root
            .canonicalize()
            .expect("canonical fixture project root");
        let runtime_home = runtime_home
            .canonicalize()
            .expect("canonical fixture runtime home");
        let [
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
        ] = runtime_fixture_start_messages(&project_root, &runtime_home);
        let [
            item_started,
            first_delta,
            second_delta,
            item_completed,
            turn_completed,
        ] = runtime_fixture_completion_messages();
        let mut command = RuntimeCommand::new(PathBuf::from("/bin/sh"), &project_root);
        command.args = vec![
            "-c".into(),
            r#"IFS= read -r initialize
case "$initialize" in *'"method":"initialize"'*) ;; *) exit 31 ;; esac
printf '%s\n' "$1"
IFS= read -r thread
case "$thread" in *'"method":"thread/start"'*'"model":"fixture-model"'*) ;; *) exit 32 ;; esac
printf '%s\n' "$2"
IFS= read -r turn
case "$turn" in *'"method":"turn/start"'*'"clientUserMessageId"'*) ;; *) exit 33 ;; esac
printf '%s\n' "$3"
printf '%s\n' "$4"
printf '%s\n' "$5"
printf '%s\n' "$6"
printf '%s\n' "$7"
printf '%s\n' "$8"
printf '%s\n' "$9"
sleep 30"#
                .into(),
            "hartevo-desktop-runtime-fixture".into(),
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
            item_started,
            first_delta,
            second_delta,
            item_completed,
            turn_completed,
        ];
        command.environment.insert(
            "INTERPRETER_HOME".into(),
            runtime_home.to_string_lossy().into_owned(),
        );
        command.openinterpreter_home = Some(runtime_home);
        command.shutdown_grace = StdDuration::from_millis(50);
        command
    }

    #[cfg(unix)]
    fn completed_runtime_fixture_source() -> DesktopRuntimeSource {
        DesktopRuntimeSource::Fixture {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            command_builder: Box::new(completed_runtime_fixture_command),
        }
    }

    #[cfg(unix)]
    fn interruptible_runtime_fixture_command(
        project_root: &Path,
        runtime_home: &Path,
    ) -> RuntimeCommand {
        let project_root = project_root
            .canonicalize()
            .expect("canonical fixture project root");
        let runtime_home = runtime_home
            .canonicalize()
            .expect("canonical fixture runtime home");
        let [
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
        ] = runtime_fixture_start_messages(&project_root, &runtime_home);
        let turn_interrupted = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "turn/completed",
            "params": {
                "threadId": "desktop-fixture-thread",
                "turn": {"id": "desktop-fixture-turn", "status": "interrupted"},
            },
        })
        .to_string();
        let mut command = RuntimeCommand::new(PathBuf::from("/bin/sh"), &project_root);
        command.args = vec![
            "-c".into(),
            r#"IFS= read -r initialize
case "$initialize" in *'"method":"initialize"'*) ;; *) exit 51 ;; esac
printf '%s\n' "$1"
IFS= read -r thread
case "$thread" in *'"method":"thread/start"'*) ;; *) exit 52 ;; esac
printf '%s\n' "$2"
IFS= read -r turn
case "$turn" in *'"method":"turn/start"'*) ;; *) exit 53 ;; esac
printf '%s\n' "$3"
printf '%s\n' "$4"
IFS= read -r interrupt
case "$interrupt" in *'"method":"turn/interrupt"'*) ;; *) exit 54 ;; esac
interrupt_id="$(printf '%s\n' "$interrupt" | /usr/bin/sed -E 's/.*"id":([^,}]+).*/\1/')"
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$interrupt_id"
printf '%s\n' "$5"
sleep 30"#
                .into(),
            "hartevo-desktop-interrupt-runtime-fixture".into(),
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
            turn_interrupted,
        ];
        command.environment.insert(
            "INTERPRETER_HOME".into(),
            runtime_home.to_string_lossy().into_owned(),
        );
        command.openinterpreter_home = Some(runtime_home);
        command.shutdown_grace = StdDuration::from_millis(50);
        command
    }

    #[cfg(unix)]
    fn interruptible_runtime_fixture_source() -> DesktopRuntimeSource {
        DesktopRuntimeSource::Fixture {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            command_builder: Box::new(interruptible_runtime_fixture_command),
        }
    }

    #[cfg(unix)]
    fn local_write_approve_runtime_fixture_command(
        project_root: &Path,
        runtime_home: &Path,
    ) -> RuntimeCommand {
        let project_root = project_root
            .canonicalize()
            .expect("canonical fixture project root");
        let runtime_home = runtime_home
            .canonicalize()
            .expect("canonical fixture runtime home");
        let [
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
        ] = runtime_fixture_start_messages(&project_root, &runtime_home);
        let [
            item_started,
            first_delta,
            second_delta,
            item_completed,
            turn_completed,
        ] = runtime_fixture_completion_messages();
        let approval_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "desktop-fixture-local-approval",
            "method": "item/fileChange/requestApproval",
            "params": {
                "threadId": "desktop-fixture-thread",
                "turnId": "desktop-fixture-turn",
                "itemId": "desktop-fixture-item",
                "path": "must-not-be-written.txt",
            },
        })
        .to_string();
        let mut command = RuntimeCommand::new(PathBuf::from("/bin/sh"), &project_root);
        command.args = vec![
            "-c".into(),
            r#"IFS= read -r initialize
case "$initialize" in *'"method":"initialize"'*) ;; *) exit 61 ;; esac
printf '%s\n' "$1"
IFS= read -r thread
case "$thread" in *'"method":"thread/start"'*'"model":"fixture-model"'*) ;; *) exit 62 ;; esac
printf '%s\n' "$2"
IFS= read -r turn
case "$turn" in *'"method":"turn/start"'*'"clientUserMessageId"'*) ;; *) exit 63 ;; esac
printf '%s\n' "$3"
printf '%s\n' "$4"
printf '%s\n' "$5"
printf '%s\n' "$6"
printf '%s\n' "$7"
printf '%s\n' "$8"
IFS= read -r decision
case "$decision" in *'"id":"desktop-fixture-local-approval"'*'"decision":"accept"'*) ;; *) exit 64 ;; esac
printf '%s\n' "$9"
printf '%s\n' "${10}"
sleep 30"#
                .into(),
            "hartevo-desktop-local-write-approve-runtime-fixture".into(),
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
            item_started,
            first_delta,
            second_delta,
            approval_request,
            item_completed,
            turn_completed,
        ];
        command.environment.insert(
            "INTERPRETER_HOME".into(),
            runtime_home.to_string_lossy().into_owned(),
        );
        command.openinterpreter_home = Some(runtime_home);
        command.shutdown_grace = StdDuration::from_millis(50);
        command
    }

    #[cfg(unix)]
    fn local_write_approve_runtime_fixture_source() -> DesktopRuntimeSource {
        DesktopRuntimeSource::Fixture {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            command_builder: Box::new(local_write_approve_runtime_fixture_command),
        }
    }

    #[cfg(unix)]
    fn failing_runtime_fixture_command(project_root: &Path, runtime_home: &Path) -> RuntimeCommand {
        let project_root = project_root
            .canonicalize()
            .expect("canonical fixture project root");
        let runtime_home = runtime_home
            .canonicalize()
            .expect("canonical fixture runtime home");
        let mut command = RuntimeCommand::new(PathBuf::from("/usr/bin/false"), project_root);
        command.environment.insert(
            "INTERPRETER_HOME".into(),
            runtime_home.to_string_lossy().into_owned(),
        );
        command.openinterpreter_home = Some(runtime_home);
        command.shutdown_grace = StdDuration::from_millis(20);
        command
    }

    #[cfg(unix)]
    fn failing_runtime_fixture_source() -> DesktopRuntimeSource {
        DesktopRuntimeSource::Fixture {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            command_builder: Box::new(failing_runtime_fixture_command),
        }
    }

    #[cfg(unix)]
    fn terminal_runtime_fixture_command(
        project_root: &Path,
        runtime_home: &Path,
        thread_method: &str,
        terminal_status: &str,
        agent_message: &str,
    ) -> RuntimeCommand {
        let project_root = project_root
            .canonicalize()
            .expect("canonical fixture project root");
        let runtime_home = runtime_home
            .canonicalize()
            .expect("canonical fixture runtime home");
        let [
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
        ] = runtime_fixture_start_messages(&project_root, &runtime_home);
        let item_completed = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "item/completed",
            "params": {
                "threadId": "desktop-fixture-thread",
                "turnId": "desktop-fixture-turn",
                "item": {
                    "id": "desktop-terminal-fixture-item",
                    "type": "agentMessage",
                    "text": agent_message,
                },
            },
        })
        .to_string();
        let turn_completed = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "turn/completed",
            "params": {
                "threadId": "desktop-fixture-thread",
                "turn": {"id": "desktop-fixture-turn", "status": terminal_status},
            },
        })
        .to_string();
        let expected_thread_method = format!("\"method\":\"{thread_method}\"");
        let script = r#"IFS= read -r initialize
case "$initialize" in *'"method":"initialize"'*) ;; *) exit 41 ;; esac
printf '%s\n' "$1"
IFS= read -r thread
case "$thread" in *"$7"*) ;; *) exit 42 ;; esac
printf '%s\n' "$2"
IFS= read -r turn
case "$turn" in *'"method":"turn/start"'*'"clientUserMessageId"'*) ;; *) exit 43 ;; esac
printf '%s\n' "$3"
printf '%s\n' "$4"
printf '%s\n' "$5"
printf '%s\n' "$6"
sleep 30"#;
        let mut command = RuntimeCommand::new(PathBuf::from("/bin/sh"), &project_root);
        command.args = vec![
            "-c".into(),
            script.into(),
            "hartevo-desktop-terminal-runtime-fixture".into(),
            initialize_response,
            thread_response,
            turn_started,
            turn_response,
            item_completed,
            turn_completed,
            expected_thread_method,
        ];
        command.environment.insert(
            "INTERPRETER_HOME".into(),
            runtime_home.to_string_lossy().into_owned(),
        );
        command.openinterpreter_home = Some(runtime_home);
        command.shutdown_grace = StdDuration::from_millis(50);
        command
    }

    #[cfg(unix)]
    fn failed_turn_runtime_fixture_command(
        project_root: &Path,
        runtime_home: &Path,
    ) -> RuntimeCommand {
        terminal_runtime_fixture_command(
            project_root,
            runtime_home,
            "thread/start",
            "failed",
            "failed turn text must not become a Work Product",
        )
    }

    #[cfg(unix)]
    fn resumed_completed_runtime_fixture_command(
        project_root: &Path,
        runtime_home: &Path,
    ) -> RuntimeCommand {
        terminal_runtime_fixture_command(
            project_root,
            runtime_home,
            "thread/resume",
            "completed",
            "Reviewable draft recovered through the existing Runtime thread.",
        )
    }

    #[cfg(unix)]
    fn failed_turn_runtime_fixture_source() -> DesktopRuntimeSource {
        DesktopRuntimeSource::Fixture {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            command_builder: Box::new(failed_turn_runtime_fixture_command),
        }
    }

    #[cfg(unix)]
    fn resumed_completed_runtime_fixture_source() -> DesktopRuntimeSource {
        DesktopRuntimeSource::Fixture {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            command_builder: Box::new(resumed_completed_runtime_fixture_command),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop Journey verifies rejected routing, exact Catalog binding, private Contract persistence, and redacted evidence in one user flow"
    )]
    fn catalog_dispatch_persists_exact_vm_route_without_cross_executor_runtime() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let DesktopLoadState::Ready(before_invalid) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(1))
            .expect("ready fixture inventory")
        else {
            panic!("initialized Desktop remains ready");
        };
        let initial_mission_count = before_invalid.inventory.projects[0].missions.len();
        let invalid = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-07".into(),
                    mode: OperatingMode::BuildOnce,
                    parent_mission_id: None,
                    title: None,
                    goal: "invalid mode must not create state".into(),
                    market: "DE".into(),
                    language: "de".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "EUR".into(),
                },
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(2),
            )
            .expect_err("VM-07 does not allow build_once");
        assert!(matches!(
            invalid,
            DesktopDataError::Application(ApplicationError::CatalogMissionModeNotAllowed)
        ));
        let DesktopLoadState::Ready(after_invalid) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(3))
            .expect("reload after rejected route")
        else {
            panic!("initialized Desktop remains ready");
        };
        assert_eq!(
            after_invalid.inventory.projects[0].missions.len(),
            initial_mission_count
        );
        assert!(
            after_invalid.inventory.projects[0]
                .missions
                .iter()
                .all(|mission| mission.manifest_id.is_none())
        );

        let private_goal = "评估德国市场，但不要启动任何其他 Mission；内部 SKU=PRIVATE-441";
        let catalog = Catalog::load().expect("Catalog");
        let expected_digest = catalog.snapshot().expect("Catalog snapshot").digest;
        let manifest = catalog.mission("VM-07").expect("VM-07 Manifest");
        let submission = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-07".into(),
                    mode: OperatingMode::OneOffDecision,
                    parent_mission_id: None,
                    title: Some("德国市场决策".into()),
                    goal: private_goal.into(),
                    market: "DE".into(),
                    language: "de".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 12_500,
                    currency: "EUR".into(),
                },
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("Human Checkpoint must never construct a Runtime command")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(4),
            )
            .expect("Catalog-bound Desktop dispatch");
        assert_eq!(
            submission.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "product_market_budget_constraints".into(),
                capability_id: "decision.evaluate".into(),
                executor: MissionCheckpointExecutor::Human,
                oracle_ids: BTreeSet::from([
                    "decision".to_owned(),
                    "goal".to_owned(),
                    "operating_state".to_owned(),
                    "truth".to_owned(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::HumanConfirmation,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let projected = submission.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == submission.mission_id)
            .expect("Catalog Mission projection");
        assert_eq!(projected.manifest_id.as_deref(), Some("VM-07"));
        assert_eq!(projected.manifest_version, Some(manifest.version));
        assert_eq!(
            projected.catalog_digest.as_deref(),
            Some(expected_digest.as_str())
        );
        assert_eq!(
            projected.current_checkpoint_id.as_deref(),
            manifest.checkpoint_ids.first().map(String::as_str)
        );
        assert_eq!(
            projected.current_checkpoint_status,
            Some(hartevo_domain_kernel::MissionCheckpointStatus::Running)
        );
        let first_route = manifest
            .checkpoint_routes
            .first()
            .expect("first Checkpoint route");
        assert_eq!(
            projected.current_checkpoint_capability_id.as_deref(),
            Some(first_route.capability_id.as_str())
        );
        assert_eq!(
            projected.current_checkpoint_executor,
            Some(
                MissionCheckpointExecutor::try_from(first_route.executor.as_str())
                    .expect("validated executor")
            )
        );
        assert_eq!(projected.completed_checkpoint_count, 0);
        assert_eq!(projected.checkpoint_count, manifest.checkpoint_ids.len());
        assert_eq!(projected.stage, MissionStage::Running);
        assert_eq!(projected.work_product_count, 0);
        assert_eq!(projected.verified_effect_count, 0);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(5))
            .expect("reopen Application");
        let mission = service
            .load_mission(&project_id, &submission.mission_id)
            .expect("durable Catalog Mission");
        let definition = mission.definition.as_ref().expect("frozen definition");
        assert_eq!(definition.manifest_id, "VM-07");
        assert_eq!(definition.catalog_digest, expected_digest);
        assert_eq!(definition.operating_mode, OperatingMode::OneOffDecision);
        assert_eq!(mission.contract.goal, private_goal);
        assert_eq!(mission.contract.market, "DE");
        assert_eq!(mission.contract.language, "de");
        assert_eq!(mission.contract.audience, "owner");
        assert_eq!(mission.contract.timezone, "Europe/Berlin");
        assert_eq!(mission.contract.budget.amount_minor, 12_500);
        assert_eq!(mission.contract.budget.currency.as_str(), "EUR");
        assert_eq!(
            definition.capability_ids,
            mission.contract.enabled_capabilities
        );
        assert!(mission.effects.is_empty());
        let event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &submission.mission_id)
                .expect("content-free Mission events"),
        )
        .expect("event JSON");
        assert!(!event_json.contains(private_goal));
        assert!(event_json.contains("mission.catalog_bound"));
        assert!(event_json.contains("mission.checkpoint_started"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop data-plane Journey proves eight deterministic Application handlers, honest empty-ledger blocking, source-verified KPI/attribution/settlement/review recovery, atomic Human next-route handoff, typed next-contract resolution, and zero Runtime construction"
    )]
    fn vm11_application_handlers_recover_and_advance_without_constructing_runtime() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let parent_mission_id = start_vm11_parent(
            &plane,
            &secrets,
            &project_id,
            observed_at() + Duration::minutes(2),
        );
        let started = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-11".into(),
                    mode: OperatingMode::OneOffDecision,
                    parent_mission_id: Some(parent_mission_id.clone()),
                    title: Some("Verified outcome review".into()),
                    goal: "Use only verified outcome events for the next decision".into(),
                    market: "US".into(),
                    language: "en-US".into(),
                    audience: "owner".into(),
                    timezone: "America/New_York".into(),
                    kpis: BTreeMap::new(),
                    budget_minor: 0,
                    currency: "USD".into(),
                },
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("Application Checkpoint must never construct a Runtime command")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(3),
            )
            .expect("VM-11 Application dispatch");
        assert_eq!(
            started.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "event_ingest".into(),
                capability_id: "outcome.ingest".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "goal".into(),
                    "operating_state".into(),
                    "outcome".into(),
                    "truth".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Blocked,
            }
        );
        assert!(
            plane.with_cordis_host(|host| host.bound_scope().is_none()),
            "Application checkpoint CAS must complete or route before any Runtime scope is bound"
        );
        let blocked = started.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("blocked VM-11 projection");
        assert_eq!(blocked.stage, MissionStage::Blocked);
        assert_eq!(blocked.completed_checkpoint_count, 0);
        assert_eq!(
            blocked.current_checkpoint_status,
            Some(hartevo_domain_kernel::MissionCheckpointStatus::Blocked)
        );

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(4))
            .expect("reopen Application");
        let tenant_id = service
            .desktop_inventory()
            .expect("Desktop inventory")
            .projects
            .into_iter()
            .find(|project| project.project_id == project_id)
            .map(|project| project.tenant_id)
            .expect("project scope");
        let person_id = PersonId::from("desktop-vm11-person");
        service
            .create_person(
                Person::create(
                    person_id.clone(),
                    tenant_id.clone(),
                    project_id.clone(),
                    "Verified lead",
                    None,
                    vec![],
                )
                .expect("person"),
                observed_at() + Duration::minutes(4),
            )
            .expect("persist person");
        let identity_link_id = IdentityLinkId::from("desktop-vm11-identity");
        service
            .create_identity_link(
                IdentityLink::propose(
                    identity_link_id.clone(),
                    tenant_id.clone(),
                    project_id.clone(),
                    IdentitySubject::Person(person_id),
                    [ExternalIdentity {
                        provider: "user-review".into(),
                        account_id: AccountId::from("project-owner"),
                        external_subject_digest: "1".repeat(64),
                        encrypted_subject_ref: "ciphertext://desktop-vm11-lead".into(),
                        evidence_digest: "2".repeat(64),
                    }],
                    "1".parse().expect("identity confidence"),
                )
                .expect("identity link"),
                observed_at() + Duration::minutes(4),
            )
            .expect("persist identity link");
        service
            .confirm_identity_link(
                &project_id,
                &identity_link_id,
                ActorId::from("project-owner"),
                "2".repeat(64),
                observed_at() + Duration::minutes(4),
            )
            .expect("confirm identity link");
        let outcome_connection_id = ConnectionId::from("desktop-vm11-commerce-connection");
        service
            .register_connection(
                Connection::register(
                    outcome_connection_id.clone(),
                    tenant_id.clone(),
                    project_id.clone(),
                    "user-review",
                    AccountId::from("project-owner"),
                    "desktop-project-owner-external",
                    ["orders.read".into()],
                    observed_at() + Duration::minutes(4),
                )
                .expect("commerce connection"),
                observed_at() + Duration::minutes(4),
            )
            .expect("persist commerce connection");
        service
            .record_connection_probe(
                &project_id,
                &outcome_connection_id,
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "desktop-project-owner-external".into(),
                    granted_scopes: BTreeSet::from(["orders.read".into()]),
                    probed_at: observed_at() + Duration::minutes(4),
                    valid_until: observed_at() + Duration::days(30),
                    credential_expires_at: observed_at() + Duration::days(30),
                    evidence_digest: "6".repeat(64),
                },
                observed_at() + Duration::minutes(4),
            )
            .expect("probe commerce connection");
        service
            .start_outcome_ledger(&project_id, observed_at() + Duration::minutes(4))
            .expect("Outcome Ledger");
        service
            .ingest_outcome_event(
                OutcomeEvent {
                    id: OutcomeEventId::from("desktop-vm11-lead-event"),
                    tenant_id: tenant_id.clone(),
                    project_id: project_id.clone(),
                    mission_id: parent_mission_id.clone(),
                    kind: OutcomeEventKind::LeadQualified,
                    provider: "user-review".into(),
                    connection_id: None,
                    account_id: None,
                    source_event_id: "desktop-user-confirmation-1".into(),
                    identity_link_id: Some(identity_link_id.clone()),
                    opportunity_id: None,
                    campaign_id: None,
                    order_id: None,
                    refund_id: None,
                    commission_id: None,
                    payout_id: None,
                    partner_id: None,
                    amount: None,
                    occurred_at: observed_at() + Duration::minutes(4),
                    received_at: observed_at() + Duration::minutes(5),
                    evidence_digest: "3".repeat(64),
                    raw_payload_digest: "4".repeat(64),
                    source_verification: Some(OutcomeSourceVerification {
                        method: OutcomeVerificationMethod::UserConfirmed,
                        verifier: "project-owner".into(),
                        independent: false,
                        verified_at: observed_at() + Duration::minutes(5),
                        evidence_digest: "5".repeat(64),
                    }),
                },
                observed_at() + Duration::minutes(5),
            )
            .expect("verified OutcomeEvent");
        service
            .ingest_outcome_event(
                OutcomeEvent {
                    id: OutcomeEventId::from("desktop-vm11-order-event"),
                    tenant_id,
                    project_id: project_id.clone(),
                    mission_id: parent_mission_id.clone(),
                    kind: OutcomeEventKind::OrderPlaced,
                    provider: "user-review".into(),
                    connection_id: Some(outcome_connection_id),
                    account_id: Some(AccountId::from("project-owner")),
                    source_event_id: "desktop-signed-order-1".into(),
                    identity_link_id: Some(identity_link_id),
                    opportunity_id: None,
                    campaign_id: None,
                    order_id: Some(OrderId::from("desktop-vm11-order")),
                    refund_id: None,
                    commission_id: None,
                    payout_id: None,
                    partner_id: None,
                    amount: Some(Money::new(9_500, CurrencyCode::parse("USD").expect("USD"))),
                    occurred_at: observed_at() + Duration::minutes(4),
                    received_at: observed_at() + Duration::minutes(5),
                    evidence_digest: "7".repeat(64),
                    raw_payload_digest: "8".repeat(64),
                    source_verification: Some(OutcomeSourceVerification {
                        method: OutcomeVerificationMethod::SignedWebhook,
                        verifier: "commerce-webhook".into(),
                        independent: true,
                        verified_at: observed_at() + Duration::minutes(5),
                        evidence_digest: "9".repeat(64),
                    }),
                },
                observed_at() + Duration::minutes(5),
            )
            .expect("verified order OutcomeEvent");
        drop(service);

        let resumed = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("Application Checkpoint recovery must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(6),
            )
            .expect("recover VM-11 Application route");
        assert_eq!(
            resumed.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "normalize_dedupe_order".into(),
                capability_id: "outcome.ingest".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "operating_state".into(),
                    "outcome".into(),
                    "truth".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let projected = resumed.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("advanced VM-11 projection");
        assert_eq!(projected.completed_checkpoint_count, 1);
        assert_eq!(projected.stage, MissionStage::Running);
        assert_eq!(
            (
                projected.current_checkpoint_application_handler_status,
                projected
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented),
                Some("vm11.normalize-dedupe-order/v1"),
            )
        );
        assert!(resumed.snapshot.runtime_activity.iter().all(|activity| {
            activity.mission_id != started.mission_id
                || (activity.process_claim_status.is_none()
                    && activity.recovery_status.is_none()
                    && activity.turn_status.is_none())
        }));
        let normalized = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("normalization Application route must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(7),
            )
            .expect("normalize Outcome Ledger without Runtime");
        assert_eq!(
            normalized.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "identity_chain".into(),
                capability_id: "attribution.compute".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "decision".into(),
                    "operating_state".into(),
                    "outcome".into(),
                    "truth".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let normalized_projection = normalized.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("normalized VM-11 projection");
        assert_eq!(normalized_projection.completed_checkpoint_count, 2);
        assert_eq!(
            (
                normalized_projection.current_checkpoint_application_handler_status,
                normalized_projection
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented),
                Some("vm11.identity-chain/v1"),
            )
        );
        let identified = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("identity-chain Application route must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(8),
            )
            .expect("resolve identity chain without Runtime");
        assert_eq!(
            identified.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "mission_specific_kpi".into(),
                capability_id: "attribution.compute".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "decision".into(),
                    "operating_state".into(),
                    "outcome".into(),
                    "truth".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let identified_projection = identified.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("identity-resolved VM-11 projection");
        assert_eq!(identified_projection.completed_checkpoint_count, 3);
        assert_eq!(
            (
                identified_projection.current_checkpoint_application_handler_status,
                identified_projection
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented),
                Some("vm11.mission-specific-kpi/v1"),
            )
        );
        let measured = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("KPI Application route must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(9),
            )
            .expect("recompute parent Mission KPI without Runtime");
        assert_eq!(
            measured.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "attribution_and_unattributed".into(),
                capability_id: "attribution.compute".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "decision".into(),
                    "effect".into(),
                    "operating_state".into(),
                    "outcome".into(),
                    "truth".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let measured_projection = measured.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("KPI-measured VM-11 projection");
        assert_eq!(measured_projection.completed_checkpoint_count, 4);
        assert_eq!(
            (
                measured_projection.current_checkpoint_application_handler_status,
                measured_projection
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented),
                Some("vm11.attribution-and-unattributed/v1"),
            )
        );
        let attributed = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("attribution Application route must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(10),
            )
            .expect("compute attribution without Runtime");
        assert_eq!(
            attributed.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "refund_commission_payout_recalc".into(),
                capability_id: "settlement.compute".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "decision".into(),
                    "operating_state".into(),
                    "outcome".into(),
                    "truth".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let attributed_projection = attributed.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("attributed VM-11 projection");
        assert_eq!(attributed_projection.completed_checkpoint_count, 5);
        assert_eq!(
            (
                attributed_projection.current_checkpoint_application_handler_status,
                attributed_projection
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented),
                Some("vm11.refund-commission-payout-recalc/v1"),
            )
        );
        let settled = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("settlement Application route must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(11),
            )
            .expect("compute nonempty settlement view without Runtime");
        assert_eq!(
            settled.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "outcome_review".into(),
                capability_id: "decision.evaluate".into(),
                executor: MissionCheckpointExecutor::Application,
                oracle_ids: BTreeSet::from([
                    "decision".into(),
                    "operating_state".into(),
                    "outcome".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let settled_projection = settled.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("settled VM-11 projection");
        assert_eq!(settled_projection.completed_checkpoint_count, 6);
        assert_eq!(
            (
                settled_projection.current_checkpoint_application_handler_status,
                settled_projection
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented),
                Some("vm11.outcome-review/v1"),
            )
        );
        let reviewed = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("outcome review Application route must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(12),
            )
            .expect("freeze outcome review without Runtime");
        assert_eq!(
            reviewed.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "continue_stop_scale_test".into(),
                capability_id: "decision.evaluate".into(),
                executor: MissionCheckpointExecutor::Human,
                oracle_ids: BTreeSet::from([
                    "decision".into(),
                    "goal".into(),
                    "operating_state".into(),
                    "outcome".into(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::HumanConfirmation,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let reviewed_projection = reviewed.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("outcome-reviewed VM-11 projection");
        assert_eq!(reviewed_projection.completed_checkpoint_count, 7);
        assert_eq!(
            (
                reviewed_projection.current_checkpoint_executor,
                reviewed_projection.current_checkpoint_completion_policy,
                reviewed_projection.current_checkpoint_application_handler_status,
                reviewed_projection
                    .current_checkpoint_application_handler_id
                    .as_deref(),
            ),
            (
                Some(MissionCheckpointExecutor::Human),
                Some(MissionCheckpointCompletionPolicy::HumanConfirmation),
                None,
                None,
            )
        );
        let review_decision_projection = reviewed_projection
            .vm11_outcome_review
            .as_ref()
            .expect("frozen outcome review is projected for Human decision");
        assert_eq!(review_decision_projection.review.order_count, 1);
        assert_eq!(review_decision_projection.review.attributed_order_count, 0);
        assert_eq!(
            review_decision_projection.review.unattributed_order_count,
            1
        );
        assert_eq!(review_decision_projection.decision, None);
        assert_eq!(review_decision_projection.action_gates.len(), 4);
        assert_eq!(
            review_decision_projection
                .action_gates
                .iter()
                .find(|gate| gate.action == OutcomeDecision::Stop)
                .map(|gate| gate.status),
            Some(hartevo_domain_kernel::OutcomeReviewDecisionGateStatus::Available)
        );
        assert_eq!(
            review_decision_projection
                .action_gates
                .iter()
                .find(|gate| gate.action == OutcomeDecision::Scale)
                .map(|gate| gate.status),
            Some(hartevo_domain_kernel::OutcomeReviewDecisionGateStatus::BlockedLoopPolicy)
        );

        let generic_message_id = MissionConversationMessageId::new();
        assert!(matches!(
            plane.confirm_human_mission_checkpoint_with(
                &secrets,
                DesktopHumanCheckpointConfirmationRequest {
                    project_id: project_id.clone(),
                    mission_id: started.mission_id.clone(),
                    checkpoint_id: "continue_stop_scale_test".into(),
                    message_id: generic_message_id.clone(),
                    body: "stop".into(),
                    idempotency_key: format!(
                        "desktop-generic-vm11-decision:{}",
                        generic_message_id.as_str()
                    ),
                    work_product_ids: BTreeSet::new(),
                    expected_mission_revision: reviewed_projection.revision,
                    expected_checkpoint_revision: reviewed_projection
                        .current_checkpoint_revision
                        .expect("decision Checkpoint revision"),
                    expected_conversation_revision: reviewed_projection
                        .conversation_revision
                        .expect("decision Conversation revision"),
                },
                observed_at() + Duration::minutes(13),
            ),
            Err(DesktopDataError::Application(
                ApplicationError::StructuredOutcomeDecisionRequired
            ))
        ));

        let decision_message_id = MissionConversationMessageId::new();
        let decision_request = DesktopVm11OutcomeDecisionRequest {
            project_id: project_id.clone(),
            mission_id: started.mission_id.clone(),
            action: OutcomeDecision::Stop,
            message_id: decision_message_id.clone(),
            rationale: "Stop: the one-off parent contract forbids an implicit loop; retain the frozen outcome evidence".into(),
            idempotency_key: format!(
                "desktop-vm11-outcome-decision:{}",
                decision_message_id.as_str()
            ),
            expected_review_projection_digest: review_decision_projection
                .review_projection_digest
                .clone(),
            expected_review_completion_digest: review_decision_projection
                .review_completion_digest
                .clone(),
            expected_mission_revision: reviewed_projection.revision,
            expected_checkpoint_revision: reviewed_projection
                .current_checkpoint_revision
                .expect("decision Checkpoint revision"),
            expected_conversation_revision: reviewed_projection
                .conversation_revision
                .expect("decision Conversation revision"),
        };
        let decided = plane
            .decide_vm11_outcome_review_with(
                &secrets,
                decision_request.clone(),
                observed_at() + Duration::minutes(13),
            )
            .expect("structured Stop decision");
        let decided_projection = decided.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("decided VM-11 projection");
        assert_eq!(decided_projection.completed_checkpoint_count, 8);
        assert_eq!(
            decided_projection.current_checkpoint_id.as_deref(),
            Some("next_contract_or_valid_terminal")
        );
        assert_eq!(
            decided_projection.current_checkpoint_executor,
            Some(MissionCheckpointExecutor::Application)
        );
        assert_eq!(
            decided_projection.current_checkpoint_application_handler_status,
            Some(hartevo_application::ApplicationCheckpointHandlerStatus::Implemented)
        );
        let persisted_decision = decided_projection
            .vm11_outcome_review
            .as_ref()
            .and_then(|projection| projection.decision.as_ref())
            .expect("structured decision projection");
        assert_eq!(persisted_decision.action, OutcomeDecision::Stop);
        assert_eq!(persisted_decision.message_id, decision_message_id);
        assert!(
            persisted_decision
                .decided_by
                .as_str()
                .starts_with("desktop-local-operator:desktop-device:")
        );
        assert!(decided.runtime_activity.iter().all(|activity| {
            activity.mission_id != started.mission_id
                || (activity.process_claim_status.is_none()
                    && activity.recovery_status.is_none()
                    && activity.turn_status.is_none())
        }));
        let replayed = plane
            .decide_vm11_outcome_review_with(
                &secrets,
                decision_request,
                observed_at() + Duration::minutes(14),
            )
            .expect("exact structured decision replay");
        let replayed_projection = replayed.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("replayed VM-11 projection");
        assert_eq!(replayed_projection.revision, decided_projection.revision);
        assert_eq!(
            replayed_projection.conversation_revision,
            decided_projection.conversation_revision
        );
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(15))
            .expect("reopen completed Application route");
        let mission = service
            .load_mission(&project_id, &started.mission_id)
            .expect("durable VM-11 Mission");
        let next_contract_checkpoint = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "next_contract_or_valid_terminal")
            })
            .expect("durable pending next-contract Checkpoint");
        assert!(next_contract_checkpoint.completion.is_none());
        let completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "event_ingest")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable Application completion");
        assert_eq!(
            completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.event_ingest/v2")
        );
        let normalization_completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "normalize_dedupe_order")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable normalization completion");
        assert_eq!(
            normalization_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.normalize-dedupe-order/v1")
        );
        let identity_completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "identity_chain")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable identity-chain completion");
        assert_eq!(
            identity_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.identity-chain/v1")
        );
        let kpi_completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "mission_specific_kpi")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable mission-specific KPI completion");
        assert_eq!(
            kpi_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.mission-specific-kpi/v1")
        );
        let attribution_completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "attribution_and_unattributed")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable attribution completion");
        assert_eq!(
            attribution_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.attribution-and-unattributed/v1")
        );
        let settlement_completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "refund_commission_payout_recalc")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable settlement completion");
        assert_eq!(
            settlement_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.refund-commission-payout-recalc/v1")
        );
        let review_completion = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "outcome_review")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable outcome review completion");
        assert_eq!(
            review_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.outcome-review/v1")
        );
        assert_eq!(mission.effects.len(), 0);
        let decision = service
            .desktop_inventory()
            .expect("reopened Desktop inventory")
            .projects
            .into_iter()
            .find(|project| project.project_id == project_id)
            .and_then(|project| {
                project
                    .missions
                    .into_iter()
                    .find(|mission| mission.mission_id == started.mission_id)
            })
            .and_then(|mission| mission.vm11_outcome_review)
            .and_then(|projection| projection.decision)
            .expect("durable structured outcome decision");
        assert_eq!(decision.action, OutcomeDecision::Stop);
        let event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &started.mission_id)
                .expect("content-free VM-11 events"),
        )
        .expect("VM-11 event JSON");
        assert!(event_json.contains("mission.outcome_review_decided"));
        assert!(!event_json.contains("one-off parent contract"));

        assert!(matches!(
            plane.resume_mission_runtime_with(
                &secrets,
                &project_id,
                &started.mission_id,
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("eighth Application handler must not construct Runtime")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(16),
            ),
            Err(DesktopDataError::Application(
                ApplicationError::Vm11NextContractRouteSpecificCommandRequired
            ))
        ));
        let parent_projection = decided.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == parent_mission_id)
            .expect("parent Mission projection");
        let persisted_decision_digest = persisted_decision
            .digest()
            .expect("structured decision digest");
        let next_contract_request = DesktopVm11NextContractResolutionRequest {
            project_id: project_id.clone(),
            mission_id: started.mission_id.clone(),
            expected_mission_revision: decided_projection.revision,
            expected_checkpoint_revision: decided_projection
                .current_checkpoint_revision
                .expect("next-contract Checkpoint revision"),
            expected_decision_digest: persisted_decision_digest,
            expected_parent_mission_revision: parent_projection.revision,
            expected_parent_contract_digest: review_decision_projection
                .review
                .source_contract_digest
                .clone(),
        };
        let resolved = plane
            .resolve_vm11_next_contract_or_valid_terminal_with(
                &secrets,
                next_contract_request.clone(),
                observed_at() + Duration::minutes(17),
            )
            .expect("Desktop Stop typed terminal");
        assert!(matches!(
            resolved.runtime_outcome,
            DesktopMissionRuntimeOutcome::ApplicationCheckpointCompleted {
                checkpoint_id,
                ..
            } if checkpoint_id == "next_contract_or_valid_terminal"
        ));
        let resolved_projection = resolved.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("resolved VM-11 projection");
        assert_eq!(resolved_projection.stage, MissionStage::Completed);
        assert_eq!(resolved_projection.completed_checkpoint_count, 9);
        assert_eq!(resolved_projection.current_checkpoint_id, None);
        assert!(resolved.snapshot.runtime_activity.iter().all(|activity| {
            activity.mission_id != started.mission_id
                || (activity.process_claim_status.is_none()
                    && activity.recovery_status.is_none()
                    && activity.turn_status.is_none())
        }));
        let replayed_terminal = plane
            .resolve_vm11_next_contract_or_valid_terminal_with(
                &secrets,
                next_contract_request.clone(),
                observed_at() + Duration::minutes(18),
            )
            .expect("exact Desktop terminal replay");
        let replayed_terminal_projection = replayed_terminal.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("replayed terminal projection");
        assert_eq!(
            replayed_terminal_projection.revision,
            resolved_projection.revision
        );
        let mut drifted = next_contract_request;
        drifted.expected_parent_contract_digest = "f".repeat(64);
        assert!(matches!(
            plane.resolve_vm11_next_contract_or_valid_terminal_with(
                &secrets,
                drifted,
                observed_at() + Duration::minutes(19),
            ),
            Err(DesktopDataError::Application(
                ApplicationError::Vm11NextContractCommandMismatch
            ))
        ));
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(20))
            .expect("reopen typed terminal");
        let terminal_mission = service
            .load_mission(&project_id, &started.mission_id)
            .expect("durable typed terminal");
        assert_eq!(terminal_mission.stage, MissionStage::Completed);
        assert_eq!(terminal_mission.effects.len(), 0);
        let terminal_completion = terminal_mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "next_contract_or_valid_terminal")
            })
            .and_then(|checkpoint| checkpoint.completion.as_ref())
            .expect("durable eighth-handler completion");
        assert_eq!(
            terminal_completion
                .application_evidence
                .as_ref()
                .map(|evidence| evidence.handler_id.as_str()),
            Some("vm11.next-contract-or-valid-terminal/v1")
        );
        let candidate_learning = terminal_mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "candidate_learning")
            })
            .expect("durable skipped candidate_learning");
        assert_eq!(
            candidate_learning.status,
            hartevo_domain_kernel::MissionCheckpointStatus::Skipped
        );
        let terminal_event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &started.mission_id)
                .expect("content-free eighth-handler events"),
        )
        .expect("eighth-handler event JSON");
        assert!(terminal_event_json.contains("mission.next_contract_or_valid_terminal_resolved"));
        assert!(!terminal_event_json.contains("one-off parent contract"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop Journey proves exact Human confirmation, Conversation and Mission CAS, next-route dispatch, replay, and the absence of Runtime or Provider side effects"
    )]
    fn human_checkpoint_confirmation_atomically_enters_the_exact_next_route_without_runtime_or_effect()
     {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let started = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-07".into(),
                    mode: OperatingMode::OneOffDecision,
                    parent_mission_id: None,
                    title: Some("Germany evidence decision".into()),
                    goal: "Decide whether Germany merits a bounded evidence experiment".into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 25_000,
                    currency: "EUR".into(),
                },
                Some(DesktopRuntimeSource::Fixture {
                    provider: "must-not-run".into(),
                    model: "must-not-run".into(),
                    command_builder: Box::new(|_, _| {
                        panic!("Human Checkpoint dispatch must not construct a Runtime command")
                    }),
                }),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("VM-07 starts at its Human route");
        let started_runtime = started
            .snapshot
            .runtime_activity
            .iter()
            .find(|runtime| runtime.mission_id == started.mission_id)
            .expect("content-free Runtime projection exists for every Mission");
        assert_eq!(started_runtime.process_claim_status, None);
        assert_eq!(started_runtime.recovery_status, None);
        assert_eq!(started_runtime.turn_status, None);
        assert_eq!(started_runtime.turn_evidence_count, 0);
        assert!(!started_runtime.requires_reconciliation);
        let before = started.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("started Mission projection");
        let first_checkpoint_id = before
            .current_checkpoint_id
            .clone()
            .expect("current Checkpoint");
        let confirmation_body = "Germany only; budget EUR 250; no external write; stop if evidence remains insufficient";
        let message_id = MissionConversationMessageId::new();
        let request = DesktopHumanCheckpointConfirmationRequest {
            project_id: project_id.clone(),
            mission_id: started.mission_id.clone(),
            checkpoint_id: first_checkpoint_id.clone(),
            message_id: message_id.clone(),
            body: confirmation_body.into(),
            idempotency_key: format!("desktop-human-confirmation:{}", message_id.as_str()),
            work_product_ids: BTreeSet::new(),
            expected_mission_revision: before.revision,
            expected_checkpoint_revision: before
                .current_checkpoint_revision
                .expect("Checkpoint revision"),
            expected_conversation_revision: before
                .conversation_revision
                .expect("Conversation revision"),
        };

        let confirmed = plane
            .confirm_human_mission_checkpoint_with(
                &secrets,
                request.clone(),
                observed_at() + Duration::minutes(3),
            )
            .expect("exact Human confirmation");
        let confirmed_runtime = confirmed
            .runtime_activity
            .iter()
            .find(|runtime| runtime.mission_id == started.mission_id)
            .expect("content-free Runtime projection remains present");
        assert_eq!(confirmed_runtime.process_claim_status, None);
        assert_eq!(confirmed_runtime.recovery_status, None);
        assert_eq!(confirmed_runtime.turn_status, None);
        assert_eq!(confirmed_runtime.turn_evidence_count, 0);
        assert!(!confirmed_runtime.requires_reconciliation);
        let projected = confirmed.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("confirmed Mission projection");
        assert_eq!(projected.completed_checkpoint_count, 1);
        assert_eq!(
            projected.current_checkpoint_id.as_deref(),
            Some("evidence_plan")
        );
        assert_eq!(
            projected.current_checkpoint_executor,
            Some(MissionCheckpointExecutor::Runtime)
        );
        assert_eq!(
            projected.current_checkpoint_capability_id.as_deref(),
            Some("research.discover")
        );
        assert_eq!(
            projected.current_checkpoint_completion_policy,
            Some(MissionCheckpointCompletionPolicy::WorkProduct)
        );
        assert_eq!(projected.conversation_messages.len(), 2);
        let confirmation = projected
            .conversation_messages
            .last()
            .expect("confirmation message");
        assert_eq!(confirmation.message_id, message_id);
        assert_eq!(confirmation.role, MissionConversationRole::User);
        assert_eq!(
            confirmation.kind,
            MissionConversationMessageKind::CheckpointConfirmation
        );
        assert_eq!(confirmation.body, confirmation_body);
        assert_eq!(
            confirmation.checkpoint_id.as_deref(),
            Some(first_checkpoint_id.as_str())
        );

        let replayed = plane
            .confirm_human_mission_checkpoint_with(
                &secrets,
                request,
                observed_at() + Duration::minutes(3),
            )
            .expect("exact idempotent replay");
        let replayed_projection = replayed.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == started.mission_id)
            .expect("replayed Mission projection");
        assert_eq!(replayed_projection.revision, projected.revision);
        assert_eq!(replayed_projection.conversation_messages.len(), 2);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(4))
            .expect("reopen Application");
        let mission = service
            .load_mission(&project_id, &started.mission_id)
            .expect("durable confirmed Mission");
        assert!(mission.effects.is_empty());
        assert!(
            service
                .latest_runtime_turn_for_mission(&project_id, &started.mission_id)
                .expect("Runtime ledger query")
                .is_none()
        );
        let running_tasks = mission
            .tasks
            .iter()
            .filter(|task| task.status == TaskStatus::Running)
            .collect::<Vec<_>>();
        assert_eq!(running_tasks.len(), 1);
        assert_eq!(running_tasks[0].capability, "research.discover");
        let event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &started.mission_id)
                .expect("content-free Mission events"),
        )
        .expect("event JSON");
        assert!(event_json.contains("mission.human_checkpoint_confirmed"));
        assert!(event_json.contains("mission.checkpoint_started"));
        assert!(!event_json.contains(confirmation_body));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop Journey verifies same-Mission append, exact replay, payload-swap refusal, private projection, and event redaction"
    )]
    fn mission_continuation_appends_to_same_catalog_mission_idempotently_without_runtime() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let started = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-07".into(),
                    mode: OperatingMode::OneOffDecision,
                    parent_mission_id: None,
                    title: Some("Persistent decision".into()),
                    goal: "Compare the confirmed German market only".into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "EUR".into(),
                },
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(2),
            )
            .expect("Catalog Mission");
        let mission_count = started.snapshot.inventory.projects[0].missions.len();
        let execution_handle =
            current_catalog_handle(&plane, &secrets, &project_id, &started.mission_id);
        let private_steering = "只保留德国一方证据；内部修订 PRIVATE-STEER-882";
        let request = DesktopMissionContinuationRequest {
            project_id: project_id.clone(),
            mission_id: started.mission_id.clone(),
            message_id: MissionConversationMessageId::from("desktop-message-steer-1"),
            kind: MissionConversationMessageKind::Steering,
            body: private_steering.into(),
            idempotency_key: "desktop-steer:1".into(),
            expected_conversation_revision: 1,
        };
        let continued = plane
            .continue_catalog_mission_and_run_with(
                &secrets,
                request.clone(),
                catalog_runtime_authority(execution_handle.clone()),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(3),
            )
            .expect("same-Mission continuation");
        assert_eq!(continued.mission_id, started.mission_id);
        assert_eq!(
            continued.snapshot.inventory.projects[0].missions.len(),
            mission_count
        );
        assert_eq!(
            continued.runtime_outcome,
            DesktopMissionRuntimeOutcome::CheckpointRouted {
                checkpoint_id: "product_market_budget_constraints".into(),
                capability_id: "decision.evaluate".into(),
                executor: MissionCheckpointExecutor::Human,
                oracle_ids: BTreeSet::from([
                    "decision".to_owned(),
                    "goal".to_owned(),
                    "operating_state".to_owned(),
                    "truth".to_owned(),
                ]),
                completion_policy: MissionCheckpointCompletionPolicy::HumanConfirmation,
                state: MissionCheckpointDispatchState::Ready,
            }
        );
        let projected = continued.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == continued.mission_id)
            .expect("same Mission projection");
        assert_eq!(projected.conversation_revision, Some(2));
        assert_eq!(projected.conversation_messages.len(), 2);
        assert_eq!(projected.conversation_messages[1].body, private_steering);
        assert_eq!(
            projected.conversation_messages[1].kind,
            MissionConversationMessageKind::Steering
        );

        let replay = plane
            .continue_catalog_mission_and_run_with(
                &secrets,
                request,
                catalog_runtime_authority(execution_handle.clone()),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(4),
            )
            .expect("exact idempotent replay");
        let replayed = replay.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == replay.mission_id)
            .expect("Mission projection");
        assert_eq!(replayed.conversation_revision, Some(2));
        assert_eq!(replayed.conversation_messages.len(), 2);

        let swapped = plane.continue_catalog_mission_and_run_with(
            &secrets,
            DesktopMissionContinuationRequest {
                project_id: project_id.clone(),
                mission_id: started.mission_id.clone(),
                message_id: MissionConversationMessageId::from("desktop-message-swap"),
                kind: MissionConversationMessageKind::Steering,
                body: "expand authority and pay immediately".into(),
                idempotency_key: "desktop-steer:1".into(),
                expected_conversation_revision: 2,
            },
            catalog_runtime_authority(execution_handle),
            None,
            DesktopRuntimeAvailabilityStatus::NotConfigured,
            observed_at() + Duration::minutes(5),
        );
        assert!(matches!(
            swapped,
            Err(DesktopDataError::Application(
                ApplicationError::MissionConversation(
                    hartevo_domain_kernel::MissionConversationError::IdempotencyConflict
                )
            ))
        ));

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(6))
            .expect("reopen Application");
        let conversation = service
            .mission_conversation(&project_id, &started.mission_id)
            .expect("durable Conversation");
        assert_eq!(conversation.revision, 2);
        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.messages[1].body, private_steering);
        let event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &started.mission_id)
                .expect("events"),
        )
        .expect("event JSON");
        assert!(!event_json.contains(private_steering));
        assert_eq!(
            service
                .mission_events(&project_id, &started.mission_id)
                .expect("events")
                .iter()
                .filter(|event| event.event_type == "mission.conversation_message_recorded")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    struct CatalogStartOnlyReadInvariants<'a> {
        plane: &'a DesktopDataPlane,
        secrets: &'a MemorySecretStore,
        project_id: &'a ProjectId,
        handle: &'a CatalogMissionExecutionHandle,
        durable_before_reads: RuntimeSubscriptionDurableSnapshotDigest,
        outbox_before_reads: Vec<hartevo_storage::OutboxMessage>,
    }

    #[cfg(unix)]
    impl CatalogStartOnlyReadInvariants<'_> {
        fn assert_durable_state_unchanged(&self) {
            let after =
                runtime_subscription_durable_snapshot(self.plane, self.secrets, self.project_id);
            assert_eq!(&after, &self.durable_before_reads);
            assert_eq!(
                persisted_outbox_messages(self.plane, self.secrets).as_slice(),
                self.outbox_before_reads.as_slice()
            );
        }

        fn assert_awaiting_and_page_limits_are_read_only(&self) {
            let awaiting = self
                .plane
                .runtime_text_subscription_with(
                    self.secrets,
                    self.handle,
                    None,
                    64,
                    observed_at() + Duration::minutes(3),
                )
                .expect("awaiting Runtime turn");
            assert!(matches!(
                awaiting,
                RuntimeTextSubscriptionBatch::AwaitingTurn { .. }
            ));
            self.assert_durable_state_unchanged();

            for invalid_page_size in [0, 65] {
                assert!(matches!(
                    self.plane.runtime_text_subscription_with(
                        self.secrets,
                        self.handle,
                        None,
                        invalid_page_size,
                        observed_at() + Duration::minutes(3),
                    ),
                    Err(DesktopDataError::Application(
                        ApplicationError::RuntimeTextSubscription(
                            RuntimeTextSubscriptionError::InvalidPageSize
                        )
                    ))
                ));
                self.assert_durable_state_unchanged();
            }
        }

        fn assert_handle_tamper_is_read_only(&self) {
            let mut tampered_handle_json =
                serde_json::to_value(self.handle).expect("serialized execution handle");
            tampered_handle_json["contractDigest"] = serde_json::json!("0".repeat(64));
            let tampered_handle: CatalogMissionExecutionHandle =
                serde_json::from_value(tampered_handle_json).expect("tampered handle envelope");
            assert!(matches!(
                self.plane.runtime_text_subscription_with(
                    self.secrets,
                    &tampered_handle,
                    None,
                    64,
                    observed_at() + Duration::minutes(3),
                ),
                Err(DesktopDataError::Application(
                    ApplicationError::RuntimeTextSubscription(
                        RuntimeTextSubscriptionError::MissionHandleMismatch
                    )
                ))
            ));
            assert!(matches!(
                self.plane.resume_catalog_mission_runtime_with_cancellation(
                    self.secrets,
                    catalog_runtime_authority(tampered_handle),
                    None,
                    DesktopRuntimeAvailabilityStatus::NotConfigured,
                    observed_at() + Duration::minutes(3),
                ),
                Err(DesktopDataError::Application(
                    ApplicationError::RuntimeTextSubscription(
                        RuntimeTextSubscriptionError::MissionHandleMismatch
                    )
                ))
            ));
            self.assert_durable_state_unchanged();
        }

        fn assert_tenant_and_project_mismatch_are_read_only(&self) {
            for (field, value) in [
                ("tenantId", "tenant-outside-exact-context"),
                ("projectId", "project-outside-exact-context"),
            ] {
                let mut wrong_context_json =
                    serde_json::to_value(self.handle).expect("serialized execution handle");
                wrong_context_json[field] = serde_json::json!(value);
                let wrong_context_handle: CatalogMissionExecutionHandle =
                    serde_json::from_value(wrong_context_json)
                        .expect("tampered context handle envelope");
                assert!(matches!(
                    self.plane.runtime_text_subscription_with(
                        self.secrets,
                        &wrong_context_handle,
                        None,
                        64,
                        observed_at() + Duration::minutes(3),
                    ),
                    Err(DesktopDataError::RuntimeSubscriptionContextMismatch)
                ));
                self.assert_durable_state_unchanged();
            }
        }
    }

    #[cfg(unix)]
    fn assert_catalog_start_only_contract<'a>(
        plane: &'a DesktopDataPlane,
        secrets: &'a MemorySecretStore,
        project_id: &'a ProjectId,
        started: &'a DesktopCatalogMissionExecutionStart,
        private_goal: &str,
        baseline_outbox: &[hartevo_storage::OutboxMessage],
    ) -> CatalogStartOnlyReadInvariants<'a> {
        assert_eq!(started.handle.project_id(), project_id);
        assert_eq!(started.handle.manifest_id(), "VM-04");
        assert_eq!(
            started.snapshot.runtime_reconciliation,
            no_runtime_turn_startup_reconciliation()
        );
        let debug = format!("{started:?}");
        assert!(!debug.contains(private_goal));
        assert!(!debug.contains(started.handle.handle_digest()));
        assert!(debug.contains("runtime_dispatched: false"));

        let durable_before_reads =
            runtime_subscription_durable_snapshot(plane, secrets, project_id);
        let durable_debug = format!("{durable_before_reads:?}");
        assert!(!durable_debug.contains(private_goal));
        assert!(!durable_debug.contains(project_id.as_str()));
        assert!(!durable_debug.contains(started.handle.mission_id().as_str()));
        assert!(!contains_full_hex_digest(&durable_debug));

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let service = plane
            .open_read_application_from_secret(&database_secret)
            .expect("read-only Application");
        let mission = service
            .load_mission(project_id, started.handle.mission_id())
            .expect("started Mission");
        assert_eq!(
            service
                .mission_execution_handle(project_id, started.handle.mission_id())
                .expect("reopened durable execution handle"),
            started.handle
        );
        let events = service
            .mission_events(project_id, started.handle.mission_id())
            .expect("Mission events");
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|event| !event.event_type.contains("runtime"))
        );
        assert!(mission.effects.is_empty());
        assert!(
            service
                .latest_runtime_turn_for_mission(project_id, started.handle.mission_id())
                .expect("Runtime turn query")
                .is_none()
        );
        let outbox_before_reads = persisted_outbox_messages(plane, secrets);
        assert_eq!(
            outbox_before_reads.len(),
            baseline_outbox.len() + events.len()
        );
        assert_eq!(
            &outbox_before_reads[..baseline_outbox.len()],
            baseline_outbox
        );

        CatalogStartOnlyReadInvariants {
            plane,
            secrets,
            project_id,
            handle: &started.handle,
            durable_before_reads,
            outbox_before_reads,
        }
    }

    #[cfg(unix)]
    #[test]
    fn catalog_start_only_returns_handle_without_runtime_and_pull_is_read_only() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let baseline_outbox = persisted_outbox_messages(&plane, &secrets);
        let private_goal = catalog_runtime_request(&project_id).goal;
        let started = plane
            .start_catalog_mission_execution_with(
                &secrets,
                catalog_runtime_request(&project_id),
                observed_at() + Duration::minutes(2),
            )
            .expect("atomic Catalog Mission start");
        let invariants = assert_catalog_start_only_contract(
            &plane,
            &secrets,
            &project_id,
            &started,
            &private_goal,
            &baseline_outbox,
        );
        invariants.assert_durable_state_unchanged();
        invariants.assert_awaiting_and_page_limits_are_read_only();
        invariants.assert_handle_tamper_is_read_only();
        invariants.assert_tenant_and_project_mismatch_are_read_only();
    }

    #[cfg(unix)]
    #[test]
    fn catalog_retry_requires_repainted_exact_handle_and_preparation_is_read_only() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let started = plane
            .start_catalog_mission_execution_with(
                &secrets,
                catalog_runtime_request(&project_id),
                observed_at() + Duration::minutes(2),
            )
            .expect("atomic Catalog Mission start");
        let before = runtime_subscription_durable_snapshot(&plane, &secrets, &project_id);
        assert!(matches!(
            plane.require_id_only_runtime_resume(
                &secrets,
                &project_id,
                started.handle.mission_id(),
            ),
            Err(DesktopDataError::Application(
                ApplicationError::LocalRuntimeMissionNotSchedulable
            ))
        ));

        let prepared = plane
            .prepare_catalog_mission_runtime_resume_with(
                &secrets,
                &project_id,
                started.handle.mission_id(),
                observed_at() + Duration::minutes(3),
            )
            .expect("read-only retry preparation");
        assert_eq!(prepared.handle, started.handle);
        assert_eq!(
            prepared.snapshot.runtime_reconciliation,
            no_runtime_turn_startup_reconciliation()
        );
        assert_eq!(
            runtime_subscription_durable_snapshot(&plane, &secrets, &project_id),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn catalog_continuation_rejects_missing_or_tampered_handle_before_write_or_dispatch() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let started = plane
            .start_catalog_mission_execution_with(
                &secrets,
                catalog_runtime_request(&project_id),
                observed_at() + Duration::minutes(2),
            )
            .expect("atomic Catalog Mission start");
        let before = runtime_subscription_durable_snapshot(&plane, &secrets, &project_id);
        let base = DesktopMissionContinuationRequest {
            project_id: project_id.clone(),
            mission_id: started.handle.mission_id().clone(),
            message_id: MissionConversationMessageId::from("catalog-continuation-handle-gate"),
            kind: MissionConversationMessageKind::Steering,
            body: "private continuation that must stay unwritten".into(),
            idempotency_key: "catalog-continuation-handle-gate:1".into(),
            expected_conversation_revision: 1,
        };
        assert!(matches!(
            plane.continue_mission_and_run_with(
                &secrets,
                base.clone(),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(3),
            ),
            Err(DesktopDataError::Application(
                ApplicationError::RuntimeTextSubscription(
                    RuntimeTextSubscriptionError::MissionHandleMismatch
                )
            ))
        ));

        let mut tampered_json =
            serde_json::to_value(&started.handle).expect("serialized execution handle");
        tampered_json["contractDigest"] = serde_json::json!("0".repeat(64));
        let tampered = serde_json::from_value(tampered_json).expect("tampered handle envelope");
        assert!(matches!(
            plane.continue_catalog_mission_and_run_with(
                &secrets,
                base,
                catalog_runtime_authority(tampered),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(4),
            ),
            Err(DesktopDataError::Application(
                ApplicationError::RuntimeTextSubscription(
                    RuntimeTextSubscriptionError::MissionHandleMismatch
                )
            ))
        ));
        assert_eq!(
            runtime_subscription_durable_snapshot(&plane, &secrets, &project_id),
            before
        );
        plane.with_cordis_host(|host| {
            assert!(host.bound_scope().is_none());
            assert!(host.active_runtime_scope().is_none());
        });
    }

    #[cfg(unix)]
    struct RuntimeSubscriptionSqlcipherJourney<'a> {
        plane: &'a DesktopDataPlane,
        secrets: &'a MemorySecretStore,
        project_id: &'a ProjectId,
        handle: CatalogMissionExecutionHandle,
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        reducer: DesktopRuntimeSubscriptionReducer,
        durable_before_pulls: RuntimeSubscriptionDurableSnapshotDigest,
    }

    #[cfg(unix)]
    impl<'a> RuntimeSubscriptionSqlcipherJourney<'a> {
        fn prepare(
            plane: &'a DesktopDataPlane,
            secrets: &'a MemorySecretStore,
            project_id: &'a ProjectId,
            handle: CatalogMissionExecutionHandle,
        ) -> Self {
            let runtime_submission = plane
                .resume_mission_runtime_with(
                    secrets,
                    project_id,
                    handle.mission_id(),
                    Some(completed_runtime_fixture_source()),
                    DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                    observed_at() + Duration::minutes(3),
                )
                .expect("bounded Runtime completion fixture");
            assert_eq!(runtime_submission.mission_id, *handle.mission_id());
            let durable_before_pulls =
                runtime_subscription_durable_snapshot(plane, secrets, project_id);
            let scope = DesktopRuntimeSubscriptionScope::from_handle(&handle)
                .expect("Desktop subscription scope");
            let mut reducer = DesktopRuntimeSubscriptionReducer::default();
            let epoch = reducer
                .select_scope(Some(scope.clone()))
                .expect("select scope")
                .expect("selection")
                .epoch;
            RuntimeSubscriptionSqlcipherJourney {
                plane,
                secrets,
                project_id,
                handle,
                scope,
                epoch,
                reducer,
                durable_before_pulls,
            }
        }

        fn assert_durable_unchanged(&self) {
            assert_eq!(
                runtime_subscription_durable_snapshot(self.plane, self.secrets, self.project_id,),
                self.durable_before_pulls
            );
        }

        fn assert_snapshot_privacy_and_project_event_coverage(&self) {
            let database_secret = self
                .secrets
                .get(self.plane.database_key_reference())
                .expect("database secret");
            let service = self
                .plane
                .open_read_application_from_secret(&database_secret)
                .expect("read-only Application");
            let runtime = service
                .latest_runtime_turn_for_mission(self.project_id, self.handle.mission_id())
                .expect("Runtime before pulls")
                .expect("completed Runtime attempt");
            let deltas = service
                .runtime_turn_private_text_deltas(self.project_id, &runtime.id)
                .expect("private deltas before pulls");
            let debug = format!("{:?}", self.durable_before_pulls);
            assert!(!debug.contains("project.created"));
            assert!(!debug.contains("project_keyring.provisioned"));
            assert!(!debug.contains(runtime.id.as_str()));
            if let Some(runtime_turn_id) = &runtime.runtime_turn_id {
                assert!(!debug.contains(runtime_turn_id));
            }
            for delta in &deltas {
                assert!(!debug.contains(&delta.delta));
                assert!(!debug.contains(&delta.item_id_digest));
                assert!(!debug.contains(&delta.delta_digest));
                assert!(!debug.contains(&delta.chain_digest));
                assert!(!debug.contains(&delta.event_digest));
            }
            assert!(!contains_full_hex_digest(&debug));

            let database_key =
                DatabaseKey::from_secret(&database_secret).expect("database key for event proof");
            let events = ProjectStore::open(&self.plane.database_path, &database_key)
                .expect("project store for event proof")
                .events_for_project(self.project_id)
                .expect("all Project events for digest proof");
            assert!(events.iter().any(|event| {
                event.mission_id.is_none() && event.event_type == "project.created"
            }));
            assert!(events.iter().any(|event| {
                event.mission_id.is_none() && event.event_type == "project_keyring.provisioned"
            }));
            assert_eq!(
                durable_snapshot_domain_digest!("project-events", &events),
                self.durable_before_pulls.project_events
            );
            assert_eq!(
                self.durable_before_pulls.project_events.row_count,
                events.len()
            );

            let mut mutation = events
                .iter()
                .map(|event| serde_json::to_value(event).expect("Project event must serialize"))
                .collect::<Vec<_>>();
            let project_created = mutation
                .iter_mut()
                .find(|event| {
                    event.get("eventType").and_then(serde_json::Value::as_str)
                        == Some("project.created")
                })
                .expect("real project.created event");
            project_created["payload"] = serde_json::json!({"mutatedForDigestProof": true});
            assert_ne!(
                durable_snapshot_json_domain_digest("project-events", &mutation),
                self.durable_before_pulls.project_events
            );
        }

        fn pull_and_apply_reset(&mut self) -> RuntimeTextSubscriptionCursor {
            let batch = self
                .plane
                .runtime_text_subscription_with(
                    self.secrets,
                    &self.handle,
                    None,
                    1,
                    observed_at() + Duration::minutes(4),
                )
                .expect("first durable page");
            let cursor = match &batch {
                RuntimeTextSubscriptionBatch::Reset { page } => {
                    assert!(page.has_more());
                    page.next_cursor().clone()
                }
                other => panic!("expected Reset, got {other:?}"),
            };
            let delivery =
                DesktopRuntimeDelivery::from_application(self.scope.clone(), self.epoch, batch)
                    .expect("Desktop Reset");
            assert!(matches!(
                self.reducer.apply_delivery(&delivery).expect("apply Reset"),
                DesktopRuntimeReducerEffect::Reset { .. }
            ));
            assert_eq!(
                self.reducer
                    .viewport(&self.scope)
                    .expect("viewport")
                    .cursor()
                    .expect("exact cursor")
                    .producer(),
                &cursor
            );
            self.assert_durable_unchanged();
            cursor
        }

        fn pull_and_apply_append(
            &mut self,
            reset_cursor: &RuntimeTextSubscriptionCursor,
        ) -> RuntimeTextSubscriptionCursor {
            let batch = self
                .plane
                .runtime_text_subscription_with(
                    self.secrets,
                    &self.handle,
                    Some(reset_cursor),
                    1,
                    observed_at() + Duration::minutes(4),
                )
                .expect("second durable page");
            let cursor = match &batch {
                RuntimeTextSubscriptionBatch::Append { page } => {
                    assert!(!page.has_more());
                    page.next_cursor().clone()
                }
                other => panic!("expected Append, got {other:?}"),
            };
            let mut tampered = serde_json::to_value(&cursor).expect("serialized signed cursor");
            tampered["cursorDigest"] = serde_json::json!("0".repeat(64));
            let tampered =
                serde_json::from_value(tampered).expect("tampered signed cursor envelope");
            assert!(matches!(
                self.plane.runtime_text_subscription_with(
                    self.secrets,
                    &self.handle,
                    Some(&tampered),
                    1,
                    observed_at() + Duration::minutes(4),
                ),
                Err(DesktopDataError::Application(
                    ApplicationError::RuntimeTextSubscription(
                        RuntimeTextSubscriptionError::CursorMismatch
                    )
                ))
            ));
            self.assert_durable_unchanged();

            let delivery =
                DesktopRuntimeDelivery::from_application(self.scope.clone(), self.epoch, batch)
                    .expect("Desktop Append");
            self.reducer
                .apply_delivery(&delivery)
                .expect("apply Append");
            let viewport = self
                .reducer
                .viewport(&self.scope)
                .expect("appended viewport");
            assert_eq!(
                viewport.projection().expect("projection").items()[0].text(),
                "Reviewable local runtime draft; no external effect occurred."
            );
            assert_eq!(
                viewport.cursor().expect("append cursor").producer(),
                &cursor
            );
            self.assert_durable_unchanged();
            cursor
        }

        fn acknowledge_caught_up(&mut self, cursor: &RuntimeTextSubscriptionCursor) {
            let batch = self
                .plane
                .runtime_text_subscription_with(
                    self.secrets,
                    &self.handle,
                    Some(cursor),
                    1,
                    observed_at() + Duration::minutes(4),
                )
                .expect("caught-up acknowledgement");
            let delivery =
                DesktopRuntimeDelivery::from_application(self.scope.clone(), self.epoch, batch)
                    .expect("Desktop CaughtUp");
            assert_eq!(
                self.reducer
                    .apply_delivery(&delivery)
                    .expect("apply CaughtUp"),
                DesktopRuntimeReducerEffect::CaughtUp
            );
            let viewport = self
                .reducer
                .viewport(&self.scope)
                .expect("caught-up viewport");
            assert!(viewport.transport_caught_up());
            assert_eq!(
                viewport.projection().expect("projection").items()[0].text(),
                "Reviewable local runtime draft; no external effect occurred."
            );
            assert_eq!(
                viewport.cursor().expect("unchanged cursor").producer(),
                cursor
            );
            self.assert_durable_unchanged();
        }

        fn reselect_and_reopen(&mut self, cursor: &RuntimeTextSubscriptionCursor) {
            self.reducer.select_scope(None).expect("clear selection");
            let reselected = self
                .reducer
                .select_scope(Some(self.scope.clone()))
                .expect("reselect scope")
                .expect("reselection");
            assert_eq!(
                reselected
                    .cursor
                    .as_ref()
                    .expect("reselected cursor")
                    .producer(),
                cursor
            );
            let batch =
                self.plane
                    .runtime_text_subscription_with(
                        self.secrets,
                        &self.handle,
                        reselected.cursor.as_ref().map(
                            crate::runtime_subscription::DesktopRuntimeViewportCursor::producer,
                        ),
                        64,
                        observed_at() + Duration::minutes(5),
                    )
                    .expect("reselected durable read");
            self.reducer
                .apply_delivery(
                    &DesktopRuntimeDelivery::from_application(
                        self.scope.clone(),
                        reselected.epoch,
                        batch,
                    )
                    .expect("reselected delivery"),
                )
                .expect("apply reselected delivery");
            self.assert_durable_unchanged();

            let reopened = DesktopDataPlane::at_data_root(self.plane.data_root.clone())
                .expect("reopened Desktop data plane");
            let batch = reopened
                .runtime_text_subscription_with(
                    self.secrets,
                    &self.handle,
                    None,
                    64,
                    observed_at() + Duration::minutes(6),
                )
                .expect("restart hydration from SQLCipher");
            let mut restarted = DesktopRuntimeSubscriptionReducer::default();
            let selection = restarted
                .select_scope(Some(self.scope.clone()))
                .expect("restart select")
                .expect("restart selection");
            restarted
                .apply_delivery(
                    &DesktopRuntimeDelivery::from_application(
                        self.scope.clone(),
                        selection.epoch,
                        batch,
                    )
                    .expect("restart Reset"),
                )
                .expect("apply restart Reset");
            assert_eq!(
                restarted
                    .viewport(&self.scope)
                    .expect("restart viewport")
                    .projection()
                    .expect("restart projection")
                    .items()[0]
                    .text(),
                "Reviewable local runtime draft; no external effect occurred."
            );
            assert_eq!(
                runtime_subscription_durable_snapshot(&reopened, self.secrets, self.project_id,),
                self.durable_before_pulls
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn runtime_subscription_reducer_reuses_application_cursor_across_reselect_and_reopen() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let started = plane
            .start_catalog_mission_execution_with(
                &secrets,
                catalog_runtime_request(&project_id),
                observed_at() + Duration::minutes(2),
            )
            .expect("atomic Catalog Mission start");
        let mut journey = RuntimeSubscriptionSqlcipherJourney::prepare(
            &plane,
            &secrets,
            &project_id,
            started.handle,
        );
        journey.assert_snapshot_privacy_and_project_event_coverage();
        let reset_cursor = journey.pull_and_apply_reset();
        let append_cursor = journey.pull_and_apply_append(&reset_cursor);
        journey.acknowledge_caught_up(&append_cursor);
        journey.reselect_and_reopen(&append_cursor);
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop Journey proves Runtime output, Work Product, Conversation, and every Context authority aggregate finalize atomically and replay idempotently"
    )]
    fn catalog_runtime_draft_conversation_and_context_authority_finalize_atomically() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let private_goal = "Assess Germany with a reviewable private draft only";
        let submission = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-04".into(),
                    mode: OperatingMode::Campaign,
                    parent_mission_id: None,
                    title: Some("Germany social matrix draft".into()),
                    goal: private_goal.into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "EUR".into(),
                },
                Some(completed_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("completed Catalog Runtime draft");
        let work_product_id = match &submission.runtime_outcome {
            DesktopMissionRuntimeOutcome::DraftReady { work_product_id } => work_product_id.clone(),
            outcome => panic!("unexpected Runtime outcome: {outcome:?}"),
        };
        let projected = submission.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == submission.mission_id)
            .expect("Catalog Mission projection");
        assert_eq!(projected.manifest_id.as_deref(), Some("VM-04"));
        assert_eq!(projected.conversation_revision, Some(2));
        assert_eq!(projected.conversation_messages.len(), 2);
        assert_eq!(
            projected.conversation_messages[1].role,
            MissionConversationRole::Assistant
        );
        assert_eq!(
            projected.conversation_messages[1].kind,
            MissionConversationMessageKind::RuntimeDraft
        );
        assert_eq!(
            projected.conversation_messages[1].body,
            "Reviewable local runtime draft; no external effect occurred."
        );
        assert_eq!(
            projected.conversation_messages[1].work_product_id.as_ref(),
            Some(&work_product_id)
        );

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("reopen finalized Runtime state");
        let turn = service
            .latest_runtime_turn_for_mission(&project_id, &submission.mission_id)
            .expect("turn query")
            .expect("completed turn");
        assert_eq!(turn.status, RuntimeTurnStatus::Completed);
        let private_message = service
            .latest_runtime_turn_private_message(&project_id, &turn.id)
            .expect("private message query")
            .expect("durable private message");
        assert_eq!(
            private_message.body,
            "Reviewable local runtime draft; no external effect occurred."
        );
        let capsule = service
            .context_capsule(&project_id, &turn.scope.capsule_id)
            .expect("accepted capsule");
        let branch = service
            .context_branch(&project_id, &turn.scope.branch_id)
            .expect("completed branch");
        let handle = service
            .context_worker_handle(&project_id, &turn.scope.workspace_id, &turn.scope.worker_id)
            .expect("completed handle");
        let lease = service
            .context_worker_lease(&project_id, &turn.scope.worker_lease_id)
            .expect("released lease");
        assert_eq!(capsule.status, ContextCapsuleStatus::Accepted);
        assert_eq!(branch.status, ContextBranchStatus::Completed);
        assert_eq!(handle.status, WorkerHandleStatus::Completed);
        assert_eq!(lease.status, WorkerLeaseStatus::Released);
        let events_before_replay = service
            .mission_events(&project_id, &submission.mission_id)
            .expect("content-free events");
        let event_json = serde_json::to_string(&events_before_replay).expect("event JSON");
        for private in [
            private_goal,
            "Reviewable local runtime draft; no external effect occurred.",
            "transient streaming text must not be adopted",
        ] {
            assert!(!event_json.contains(private));
        }
        assert!(event_json.contains("context.capsule_result_accepted"));
        assert!(event_json.contains("context.worker_released"));

        let replay = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &submission.mission_id,
                Some(failing_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(4),
            )
            .expect("idempotent completed Catalog recovery");
        assert_eq!(
            replay.runtime_outcome,
            DesktopMissionRuntimeOutcome::DraftReady { work_product_id }
        );
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(5))
            .expect("reopen after replay");
        assert_eq!(
            service
                .mission_events(&project_id, &submission.mission_id)
                .expect("unchanged events"),
            events_before_replay
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the read-only Desktop boundary is proved end-to-end across exact scope, diagnostics, restart, and lost-device Context gating"
    )]
    fn runtime_text_stream_query_is_context_gated_redacted_and_restart_stable() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let submission = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-04".into(),
                    mode: OperatingMode::Campaign,
                    parent_mission_id: None,
                    title: Some("Persisted stream query".into()),
                    goal: "Render only the authorized private Runtime stream".into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "EUR".into(),
                },
                Some(completed_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("completed Runtime stream fixture");
        let expected_text = "Reviewable local runtime draft; no external effect occurred.";
        let projected = plane
            .runtime_text_stream_with(
                &secrets,
                &project_id,
                &submission.mission_id,
                observed_at() + Duration::minutes(3),
            )
            .expect("authorized stream query")
            .expect("latest Runtime turn");
        assert_eq!(projected.project_id, project_id);
        assert_eq!(projected.mission_id, submission.mission_id);
        assert_eq!(projected.turn_status, RuntimeTurnStatus::Completed);
        assert_eq!(projected.delta_count, 2);
        assert_eq!(projected.items.len(), 1);
        assert_eq!(projected.items[0].text, expected_text);
        assert_eq!(projected.items[0].delta_count, 2);
        assert_eq!(projected.items[0].last_stream_sequence, 2);
        assert_eq!(
            projected.items[0].cumulative_byte_count,
            u64::try_from(expected_text.len()).expect("fixture length")
        );
        assert!(projected.last_evidence_sequence.is_some());
        assert!(!format!("{projected:?}").contains(expected_text));
        assert!(!format!("{:?}", projected.items[0]).contains(expected_text));

        let replayed = plane
            .runtime_text_stream_with(
                &secrets,
                &project_id,
                &submission.mission_id,
                observed_at() + Duration::minutes(4),
            )
            .expect("restart-equivalent stream read")
            .expect("persisted stream");
        assert_eq!(replayed, projected);
        assert!(
            plane
                .runtime_text_stream_with(
                    &secrets,
                    &project_id,
                    &MissionId::from("mission-outside-exact-scope"),
                    observed_at() + Duration::minutes(4),
                )
                .expect("scoped empty query")
                .is_none()
        );

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at())
            .expect("application");
        let project = service
            .desktop_inventory()
            .expect("inventory")
            .projects
            .into_iter()
            .find(|project| project.project_id == project_id)
            .expect("project");
        let execution_handle = service
            .mission_execution_handle(&project_id, &submission.mission_id)
            .expect("durable execution handle");
        let keyring = service.load_project_keyring(&project_id).expect("keyring");
        let device_reference = keyring
            .envelopes
            .iter()
            .filter(|envelope| {
                envelope.key_version == keyring.active_key_version
                    && envelope.is_available(observed_at() + Duration::minutes(5))
            })
            .find_map(|envelope| {
                let KeyRecipient::Device(device_id) = &envelope.recipient else {
                    return None;
                };
                let recipient = KeyRecipient::Device(device_id.clone());
                let reference = SecretReference {
                    tenant_id: project.tenant_id.clone(),
                    project_id: project_id.clone(),
                    provider: "os-native".into(),
                    account_scope: recipient.stable_scope(),
                    purpose: format!("project_wrapping_key:{}", envelope.id),
                    version: envelope.key_version,
                };
                secrets.get(&reference).ok().map(|_| reference)
            })
            .expect("active local Device wrapping secret");
        let durable_before_context_failure =
            runtime_subscription_durable_snapshot(&plane, &secrets, &project_id);
        drop(service);
        secrets
            .delete(&device_reference)
            .expect("simulate a lost Device wrapping key");
        assert!(matches!(
            plane.runtime_text_stream_with(
                &secrets,
                &project_id,
                &submission.mission_id,
                observed_at() + Duration::minutes(5),
            ),
            Err(DesktopDataError::ProjectContextRecoveryRequired(id)) if id == project_id
        ));
        assert!(matches!(
            plane.runtime_text_subscription_with(
                &secrets,
                &execution_handle,
                None,
                64,
                observed_at() + Duration::minutes(5),
            ),
            Err(DesktopDataError::ProjectContextRecoveryRequired(id)) if id == project_id
        ));
        assert_eq!(
            runtime_subscription_durable_snapshot(&plane, &secrets, &project_id,),
            durable_before_context_failure
        );
    }

    #[cfg(unix)]
    #[test]
    fn cooperative_desktop_stop_becomes_exact_runtime_interrupt() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let cancellation = DesktopRuntimeCancellation::default();
        let observer = cancellation.clone();
        cancellation.request();
        assert!(observer.is_requested());

        let submission = plane
            .start_catalog_mission_and_run_with_cancellation(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-04".into(),
                    mode: OperatingMode::Campaign,
                    parent_mission_id: None,
                    title: Some("Interruptible social matrix turn".into()),
                    goal: "Prepare one reviewable draft and stop when requested".into(),
                    market: "US".into(),
                    language: "en-US".into(),
                    audience: "owner".into(),
                    timezone: "America/New_York".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "USD".into(),
                },
                Some(interruptible_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                Some(&cancellation),
                observed_at() + Duration::minutes(2),
            )
            .expect("cooperative stop finishes through the managed Runtime");
        assert_eq!(
            submission.runtime_outcome,
            DesktopMissionRuntimeOutcome::Interrupted
        );
        let progress = cancellation.progress_since(0);
        assert!(
            progress
                .windows(2)
                .all(|events| events[0].sequence < events[1].sequence)
        );
        let phases = progress.iter().map(|event| event.phase).collect::<Vec<_>>();
        assert_eq!(
            phases.first(),
            Some(&DesktopRuntimeProgressPhase::StopRequested)
        );
        assert_eq!(
            phases.last(),
            Some(&DesktopRuntimeProgressPhase::Interrupted)
        );
        for required in [
            DesktopRuntimeProgressPhase::Preparing,
            DesktopRuntimeProgressPhase::Dispatched,
            DesktopRuntimeProgressPhase::InterruptSent,
        ] {
            assert!(
                phases.contains(&required),
                "missing progress phase {required:?}"
            );
        }
        assert!(
            phases
                .iter()
                .position(|phase| *phase == DesktopRuntimeProgressPhase::InterruptSent)
                < phases
                    .iter()
                    .position(|phase| *phase == DesktopRuntimeProgressPhase::Interrupted)
        );
        assert_eq!(
            cancellation.progress_since(progress.last().expect("terminal progress event").sequence),
            Vec::<DesktopRuntimeProgressEvent>::new()
        );
        let projected = submission.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == submission.mission_id)
            .expect("interrupted Mission projection");
        assert_eq!(projected.work_product_count, 0);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("reopen interrupted Runtime state");
        let turn = service
            .latest_runtime_turn_for_mission(&project_id, &submission.mission_id)
            .expect("turn query")
            .expect("interrupted turn");
        assert_eq!(turn.status, RuntimeTurnStatus::Interrupted);
        assert!(
            service
                .latest_runtime_turn_private_message(&project_id, &turn.id)
                .expect("private message query")
                .is_none()
        );
    }

    #[test]
    fn held_local_write_approve_matches_exact_digest_and_rejects_stale() {
        let control = DesktopRuntimeCancellation::default();
        let project_id = ProjectId::from("project-local-approve");
        let turn_id = RuntimeTurnAttemptId::from("turn-local-approve");
        control.hold_local_approval(DesktopHeldLocalApproval {
            project_id: project_id.clone(),
            turn_id: turn_id.clone(),
            expected_revision: 4,
            request_digest: "digest-local-write".into(),
            kind: RuntimeLocalApprovalKind::FileChange,
        });
        assert_eq!(
            control
                .held_local_approval()
                .expect("held request")
                .request_digest,
            "digest-local-write"
        );
        assert!(matches!(
            control.approve_held_local_write(&project_id, &turn_id, 4, "stale-digest",),
            Err(DesktopDataError::RuntimeLocalApprovalMismatch)
        ));
        control
            .approve_held_local_write(&project_id, &turn_id, 4, "digest-local-write")
            .expect("exact digest approve");
        assert!(matches!(
            control.approve_held_local_write(&project_id, &turn_id, 4, "digest-local-write"),
            Err(DesktopDataError::RuntimeLocalApprovalUnavailable)
        ));
        assert_eq!(control.take_local_approval_decision(), Some(true));
        control.clear_held_local_approval();
        assert!(control.held_local_approval().is_none());
        assert!(matches!(
            control.approve_held_local_write(&project_id, &turn_id, 4, "digest-local-write"),
            Err(DesktopDataError::RuntimeLocalApprovalUnavailable)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn window_approve_issues_respond_context_runtime_local_approval() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let cancellation = DesktopRuntimeCancellation::default();
        let approver = {
            let control = cancellation.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    if let Some(held) = control.held_local_approval() {
                        control
                            .approve_held_local_write(
                                &held.project_id,
                                &held.turn_id,
                                held.expected_revision,
                                &held.request_digest,
                            )
                            .expect("window Approve of exact held digest");
                        return;
                    }
                    std::thread::sleep(StdDuration::from_millis(50));
                }
                panic!("window Approve never saw a held Runtime local-write request");
            })
        };
        let submission = plane
            .start_catalog_mission_and_run_with_cancellation(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-04".into(),
                    mode: OperatingMode::Campaign,
                    parent_mission_id: None,
                    title: Some("Window Approve local write".into()),
                    goal: "Hold one exact local write for window Approve".into(),
                    market: "US".into(),
                    language: "en-US".into(),
                    audience: "owner".into(),
                    timezone: "America/New_York".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "USD".into(),
                },
                Some(local_write_approve_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                Some(&cancellation),
                observed_at() + Duration::minutes(2),
            )
            .expect("window Approve completes the live Runtime turn");
        approver.join().expect("approver thread");
        assert!(matches!(
            submission.runtime_outcome,
            DesktopMissionRuntimeOutcome::DraftReady { .. }
        ));
        let phases = cancellation
            .progress_since(0)
            .into_iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>();
        assert!(
            phases.contains(&DesktopRuntimeProgressPhase::WaitingLocalApproval),
            "missing WaitingLocalApproval in {phases:?}"
        );
        assert!(
            phases.contains(&DesktopRuntimeProgressPhase::LocalActionApproved),
            "missing LocalActionApproved in {phases:?}"
        );
        assert!(!phases.contains(&DesktopRuntimeProgressPhase::LocalActionDeclined));
        assert!(cancellation.held_local_approval().is_none());
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop Journey proves a failed prior generation is fully fenced before private steering becomes durable"
    )]
    fn catalog_steering_retires_failed_prior_generation_before_append() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let failed = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-04".into(),
                    mode: OperatingMode::Campaign,
                    parent_mission_id: None,
                    title: Some("Failed social draft generation fencing".into()),
                    goal: "Produce one bounded market decision draft".into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "EUR".into(),
                },
                Some(failed_turn_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("definitively failed Catalog turn");
        assert_eq!(failed.runtime_outcome, DesktopMissionRuntimeOutcome::Failed);
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("reopen failed generation");
        let failed_turn = service
            .latest_runtime_turn_for_mission(&project_id, &failed.mission_id)
            .expect("turn query")
            .expect("failed turn");
        assert_eq!(failed_turn.status, RuntimeTurnStatus::Failed);
        assert_eq!(
            service
                .context_worker_handle(
                    &project_id,
                    &failed_turn.scope.workspace_id,
                    &failed_turn.scope.worker_id,
                )
                .expect("pre-steering handle")
                .status,
            WorkerHandleStatus::Attached
        );

        let private_steering = "Use only confirmed first-party evidence in the replacement turn";
        let execution_handle =
            current_catalog_handle(&plane, &secrets, &project_id, &failed.mission_id);
        let continued = plane
            .continue_catalog_mission_and_run_with(
                &secrets,
                DesktopMissionContinuationRequest {
                    project_id: project_id.clone(),
                    mission_id: failed.mission_id.clone(),
                    message_id: MissionConversationMessageId::from(
                        "message-retire-failed-generation",
                    ),
                    kind: MissionConversationMessageKind::Correction,
                    body: private_steering.into(),
                    idempotency_key: "retire-failed-generation:1".into(),
                    expected_conversation_revision: 1,
                },
                catalog_runtime_authority(execution_handle),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(4),
            )
            .expect("steering retires old authority then appends");
        assert_eq!(continued.mission_id, failed.mission_id);
        assert_eq!(
            continued.runtime_outcome,
            DesktopMissionRuntimeOutcome::NotStarted {
                availability: DesktopRuntimeAvailabilityStatus::NotConfigured,
            }
        );
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(5))
            .expect("reopen retired generation");
        assert_eq!(
            service
                .context_capsule(&project_id, &failed_turn.scope.capsule_id)
                .expect("cancelled capsule")
                .status,
            ContextCapsuleStatus::Cancelled
        );
        assert_eq!(
            service
                .context_branch(&project_id, &failed_turn.scope.branch_id)
                .expect("abandoned branch")
                .status,
            ContextBranchStatus::Abandoned
        );
        assert_eq!(
            service
                .context_worker_handle(
                    &project_id,
                    &failed_turn.scope.workspace_id,
                    &failed_turn.scope.worker_id,
                )
                .expect("cancelled handle")
                .status,
            WorkerHandleStatus::Cancelled
        );
        assert_eq!(
            service
                .context_worker_lease(&project_id, &failed_turn.scope.worker_lease_id)
                .expect("revoked lease")
                .status,
            WorkerLeaseStatus::Revoked
        );
        let conversation = service
            .mission_conversation(&project_id, &failed.mission_id)
            .expect("continued Conversation");
        assert_eq!(conversation.revision, 2);
        assert_eq!(conversation.messages[1].body, private_steering);
        let events = service
            .mission_events(&project_id, &failed.mission_id)
            .expect("retirement events");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "context.runtime_turn_authority_retired")
                .count(),
            1
        );
        let event_json = serde_json::to_string(&events).expect("event JSON");
        assert!(!event_json.contains(private_steering));
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Desktop Journey proves steering fences a prepared recovery before any Runtime turn exists and hides the obsolete generation"
    )]
    fn catalog_steering_retires_pre_turn_recovery_authority_before_append() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let failed_start = plane
            .start_catalog_mission_and_run_with(
                &secrets,
                DesktopCatalogMissionRequest {
                    project_id: project_id.clone(),
                    manifest_id: "VM-04".into(),
                    mode: OperatingMode::Campaign,
                    parent_mission_id: None,
                    title: Some("Pre-turn social draft recovery fencing".into()),
                    goal: "Prepare a bounded decision before steering changes".into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "owner".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: catalog_count_kpis(),
                    budget_minor: 0,
                    currency: "EUR".into(),
                },
                Some(failing_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("failed process startup remains a truthful Mission");
        assert_eq!(
            failed_start.runtime_outcome,
            DesktopMissionRuntimeOutcome::RuntimeStartFailed
        );
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("reopen pre-turn recovery");
        let recovery = service
            .latest_runtime_recovery_for_mission(&project_id, &failed_start.mission_id)
            .expect("recovery query")
            .expect("prepared recovery");
        assert_eq!(recovery.status, RuntimeRecoveryStatus::Prepared);
        assert!(
            service
                .latest_runtime_turn_for_mission(&project_id, &failed_start.mission_id)
                .expect("turn query")
                .is_none()
        );
        let pre_steering_handle = service
            .context_worker_handle(&project_id, &recovery.workspace_id, &recovery.worker_id)
            .expect("detached recovery handle");
        assert_eq!(pre_steering_handle.status, WorkerHandleStatus::Detached);

        let private_steering =
            "Supersede the startup generation before any model turn; keep this private";
        let execution_handle =
            current_catalog_handle(&plane, &secrets, &project_id, &failed_start.mission_id);
        let request = DesktopMissionContinuationRequest {
            project_id: project_id.clone(),
            mission_id: failed_start.mission_id.clone(),
            message_id: MissionConversationMessageId::from("message-retire-pre-turn-recovery"),
            kind: MissionConversationMessageKind::Correction,
            body: private_steering.into(),
            idempotency_key: "retire-pre-turn-recovery:1".into(),
            expected_conversation_revision: 1,
        };
        let continued = plane
            .continue_catalog_mission_and_run_with(
                &secrets,
                request.clone(),
                catalog_runtime_authority(execution_handle.clone()),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(4),
            )
            .expect("steering revokes pre-turn recovery authority");
        assert_eq!(continued.mission_id, failed_start.mission_id);
        assert_eq!(
            continued.runtime_outcome,
            DesktopMissionRuntimeOutcome::NotStarted {
                availability: DesktopRuntimeAvailabilityStatus::NotConfigured,
            }
        );

        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(5))
            .expect("reopen retired pre-turn generation");
        let handle = service
            .context_worker_handle(&project_id, &recovery.workspace_id, &recovery.worker_id)
            .expect("cancelled pre-turn handle");
        assert_eq!(handle.status, WorkerHandleStatus::Cancelled);
        assert_eq!(
            service
                .context_branch(&project_id, &handle.branch_id)
                .expect("abandoned pre-turn branch")
                .status,
            ContextBranchStatus::Abandoned
        );
        assert_eq!(
            service
                .context_worker_lease(&project_id, &handle.lease_id)
                .expect("revoked pre-turn lease")
                .status,
            WorkerLeaseStatus::Revoked
        );
        assert_eq!(
            service
                .context_capsule(&project_id, &handle.capsule_id)
                .expect("cancelled pre-turn capsule")
                .status,
            ContextCapsuleStatus::Cancelled
        );
        let conversation = service
            .mission_conversation(&project_id, &failed_start.mission_id)
            .expect("continued Conversation");
        assert_eq!(conversation.revision, 2);
        assert_eq!(conversation.messages[1].body, private_steering);
        let activity = service
            .desktop_runtime_activity()
            .expect("current-generation Runtime projection")
            .into_iter()
            .find(|activity| activity.mission_id == failed_start.mission_id)
            .expect("Mission Runtime projection");
        assert_eq!(activity.recovery_status, None);
        assert_eq!(activity.process_claim_status, None);
        assert_eq!(activity.process_cleanup_attempt_count, 0);
        assert_eq!(activity.turn_status, None);
        let events_before_replay = service
            .mission_events(&project_id, &failed_start.mission_id)
            .expect("retirement events");
        assert_eq!(
            events_before_replay
                .iter()
                .filter(|event| {
                    event.event_type == "context.runtime_generation_authority_retired"
                })
                .count(),
            1
        );
        let event_json = serde_json::to_string(&events_before_replay).expect("event JSON");
        assert!(event_json.contains("runtime_recovery_without_turn"));
        assert!(!event_json.contains(private_steering));

        plane
            .continue_catalog_mission_and_run_with(
                &secrets,
                request,
                catalog_runtime_authority(execution_handle),
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(6),
            )
            .expect("exact steering replay remains idempotent");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(7))
            .expect("reopen replayed steering");
        assert_eq!(
            service
                .mission_events(&project_id, &failed_start.mission_id)
                .expect("unchanged replay events"),
            events_before_replay
        );
    }

    #[test]
    fn unavailable_runtime_persists_mission_without_context_turn_or_fake_artifact() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let submission = plane
            .start_mission_and_run_with(
                &secrets,
                &project_id,
                "研究增长约束；禁止任何外部动作",
                None,
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                observed_at() + Duration::minutes(2),
            )
            .expect("honest unavailable Runtime submission");
        assert_eq!(
            submission.runtime_outcome,
            DesktopMissionRuntimeOutcome::NotStarted {
                availability: DesktopRuntimeAvailabilityStatus::NotConfigured,
            }
        );
        let projected = submission.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == submission.mission_id)
            .expect("persisted Mission projection");
        assert_eq!(
            projected.stage,
            hartevo_domain_kernel::MissionStage::Running
        );
        assert_eq!(projected.work_product_count, 0);
        assert_eq!(projected.pending_approval_count, 0);
        assert_eq!(projected.verified_effect_count, 0);
        let runtime = submission
            .snapshot
            .runtime_activity
            .iter()
            .find(|activity| activity.mission_id == submission.mission_id)
            .expect("content-free Runtime projection");
        assert_eq!(runtime.recovery_status, None);
        assert_eq!(runtime.turn_status, None);
        let bound_scope = plane
            .with_cordis_host(|host| host.bound_scope().cloned())
            .expect("Runtime coordinator must enter through exact Cordis scope");
        assert_eq!(bound_scope.project_id(), project_id.as_str());
        assert_eq!(bound_scope.mission_id(), submission.mission_id.as_str());
        plane.with_cordis_host(|host| {
            assert!(
                host.context()
                    .agents::<hartevo_cordis::AgentsSurface>()
                    .unwrap()
                    .list()
                    .is_empty(),
                "Cordis must dispose the exact scoped agent after Runtime returns"
            );
        });

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("reopen application");
        let mission = service
            .load_mission(&project_id, &submission.mission_id)
            .expect("durable Mission");
        assert!(mission.effects.is_empty());
        assert!(mission.work_products.is_empty());
        let events = service
            .mission_events(&project_id, &submission.mission_id)
            .expect("Mission events");
        assert!(events.iter().all(|event| {
            !event.event_type.starts_with("context.") && !event.event_type.starts_with("runtime.")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn desktop_runtime_journey_declines_local_write_and_adopts_only_completed_message() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let submission = plane
            .start_mission_and_run_with(
                &secrets,
                &project_id,
                "生成一个仅供审阅的本地研究草稿；禁止外部动作和本地文件写入",
                Some(completed_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("complete deterministic Desktop Runtime journey");
        let work_product_id = match &submission.runtime_outcome {
            DesktopMissionRuntimeOutcome::DraftReady { work_product_id } => work_product_id,
            outcome => panic!("unexpected Runtime outcome: {outcome:?}"),
        };
        let projected = submission.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == submission.mission_id)
            .expect("Mission projection");
        assert_eq!(
            projected.stage,
            hartevo_domain_kernel::MissionStage::Running
        );
        assert_eq!(projected.work_product_count, 1);
        assert_eq!(projected.work_products.len(), 1);
        assert_eq!(projected.work_products[0].work_product_id, *work_product_id);
        assert_eq!(
            projected.work_products[0].preview_text,
            "Reviewable local runtime draft; no external effect occurred."
        );
        assert_ne!(
            projected.work_products[0].preview_text,
            "transient streaming text must not be adopted"
        );
        assert_eq!(projected.pending_approval_count, 0);
        assert_eq!(projected.verified_effect_count, 0);

        let runtime = submission
            .snapshot
            .runtime_activity
            .iter()
            .find(|activity| activity.mission_id == submission.mission_id)
            .expect("durable Runtime activity");
        assert_eq!(
            runtime.recovery_status,
            Some(hartevo_domain_kernel::RuntimeRecoveryStatus::Attached)
        );
        assert_eq!(runtime.turn_status, Some(RuntimeTurnStatus::Completed));
        assert_eq!(runtime.recovery_failure_count, 0);
        assert_eq!(runtime.turn_failure_count, 0);
        assert_eq!(
            runtime.process_claim_status,
            Some(hartevo_domain_kernel::RuntimeProcessClaimStatus::Terminated)
        );
        assert_eq!(runtime.process_cleanup_attempt_count, 1);
        assert!(!runtime.requires_reconciliation);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("reopen Application");
        let mission = service
            .load_mission(&project_id, &submission.mission_id)
            .expect("durable Mission");
        assert_eq!(mission.stage, hartevo_domain_kernel::MissionStage::Running);
        assert!(mission.effects.is_empty());
        assert_eq!(mission.work_products.len(), 1);
        assert_eq!(
            mission.work_products[0].body,
            "Reviewable local runtime draft; no external effect occurred."
        );
        let event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &submission.mission_id)
                .expect("content-free durable events"),
        )
        .expect("event json");
        assert!(!event_json.contains("transient streaming text"));
        assert!(!event_json.contains("Reviewable local runtime draft"));
        let database_bytes = fs::read(&plane.database_path).expect("SQLCipher bytes");
        assert!(
            !database_bytes
                .windows("Reviewable local runtime draft".len())
                .any(|window| window == b"Reviewable local runtime draft")
        );
        assert!(
            !projected
                .work_products
                .iter()
                .any(|work_product| work_product.title.contains("complete"))
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart journey proves bounded same-generation retry, atomic authority retirement, generation replacement, replay suppression, and absence of fake Mission or Effect completion"
    )]
    fn desktop_runtime_retry_exhaustion_retires_generation_and_completes_same_mission() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let first = plane
            .start_mission_and_run_with(
                &secrets,
                &project_id,
                "在同一 Mission 内生成可审阅草稿；禁止外部动作",
                Some(failing_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("first durable Runtime failure");
        assert_eq!(
            first.runtime_outcome,
            DesktopMissionRuntimeOutcome::RuntimeStartFailed
        );
        let mission_id = first.mission_id.clone();
        let mission_count = first.snapshot.inventory.projects[0].missions.len();

        for minute in [3_i64, 4] {
            let retry = plane
                .resume_mission_runtime_with(
                    &secrets,
                    &project_id,
                    &mission_id,
                    Some(failing_runtime_fixture_source()),
                    DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                    observed_at() + Duration::minutes(minute),
                )
                .expect("bounded same-generation Runtime retry");
            assert_eq!(retry.mission_id, mission_id);
            assert_eq!(
                retry.runtime_outcome,
                DesktopMissionRuntimeOutcome::RuntimeStartFailed
            );
            assert_eq!(
                retry.snapshot.inventory.projects[0].missions.len(),
                mission_count
            );
        }

        let DesktopLoadState::Ready(exhausted_snapshot) = plane
            .load_with(
                &secrets,
                observed_at() + Duration::minutes(4) + Duration::seconds(1),
            )
            .expect("exhausted recovery projection")
        else {
            panic!("initialized Desktop remains ready");
        };
        let exhausted_activity = exhausted_snapshot
            .runtime_activity
            .iter()
            .find(|activity| activity.mission_id == mission_id)
            .expect("exhausted Runtime activity");
        assert_eq!(
            exhausted_activity.recovery_status,
            Some(RuntimeRecoveryStatus::Failed)
        );
        assert_eq!(exhausted_activity.recovery_process_attempt, Some(3));
        assert_eq!(exhausted_activity.recovery_failure_count, 3);
        assert_eq!(exhausted_activity.turn_status, None);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(
                &database_secret,
                observed_at() + Duration::minutes(4) + Duration::seconds(2),
            )
            .expect("reopen exhausted Runtime state");
        let failed_generation = service
            .latest_runtime_recovery_for_mission(&project_id, &mission_id)
            .expect("latest recovery")
            .expect("failed generation recovery");
        assert_eq!(failed_generation.worker_generation, 1);
        assert_eq!(failed_generation.status, RuntimeRecoveryStatus::Failed);

        let completed = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &mission_id,
                Some(completed_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(5),
            )
            .expect("replacement generation completes same Mission");
        assert_eq!(completed.mission_id, mission_id);
        assert!(matches!(
            completed.runtime_outcome,
            DesktopMissionRuntimeOutcome::DraftReady { .. }
        ));
        assert_eq!(
            completed.snapshot.inventory.projects[0].missions.len(),
            mission_count
        );
        let completed_mission = completed.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == mission_id)
            .expect("same Mission projection");
        assert_eq!(completed_mission.stage, MissionStage::Running);
        assert_eq!(completed_mission.work_product_count, 1);
        assert_eq!(completed_mission.pending_approval_count, 0);
        assert_eq!(completed_mission.verified_effect_count, 0);

        let (service, _) = plane
            .open_application_from_secret(
                &database_secret,
                observed_at() + Duration::minutes(5) + Duration::seconds(1),
            )
            .expect("reopen replacement generation");
        let replacement = service
            .latest_runtime_recovery_for_mission(&project_id, &mission_id)
            .expect("latest replacement recovery")
            .expect("replacement recovery");
        assert_eq!(replacement.worker_generation, 2);
        assert_eq!(replacement.status, RuntimeRecoveryStatus::Attached);
        let replacement_turn = service
            .latest_runtime_turn_for_mission(&project_id, &mission_id)
            .expect("latest replacement turn")
            .expect("completed replacement turn");
        assert_eq!(replacement_turn.scope.worker_generation, 2);
        assert_eq!(replacement_turn.status, RuntimeTurnStatus::Completed);
        let retired_handle = service
            .context_worker_handle(
                &project_id,
                &failed_generation.workspace_id,
                &failed_generation.worker_id,
            )
            .expect("retired generation handle");
        assert_eq!(retired_handle.status, WorkerHandleStatus::Cancelled);
        let mission = service
            .load_mission(&project_id, &mission_id)
            .expect("truthful Mission after replacement");
        assert_eq!(mission.stage, MissionStage::Running);
        assert_eq!(mission.work_products.len(), 1);
        assert!(mission.effects.is_empty());
        let events_before_replay = service
            .mission_events(&project_id, &mission_id)
            .expect("Mission Runtime events");
        assert_eq!(
            events_before_replay
                .iter()
                .filter(|event| event.event_type == "context.runtime_generation_retired")
                .count(),
            1
        );
        let event_json = serde_json::to_string(&events_before_replay).expect("event JSON");
        assert!(!event_json.contains("/usr/bin/false"));

        let replay = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &mission_id,
                Some(failing_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(6),
            )
            .expect("completed turn replay is suppressed");
        assert_eq!(
            replay.runtime_outcome,
            DesktopMissionRuntimeOutcome::ReplaySuppressed {
                turn_status: RuntimeTurnStatus::Completed,
            }
        );
        let (service, _) = plane
            .open_application_from_secret(
                &database_secret,
                observed_at() + Duration::minutes(6) + Duration::seconds(1),
            )
            .expect("reopen replay-suppressed state");
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("unchanged Mission events"),
            events_before_replay
        );
    }

    #[cfg(unix)]
    #[test]
    fn desktop_failed_turn_resumes_bound_thread_without_new_mission_or_generation() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let failed = plane
            .start_mission_and_run_with(
                &secrets,
                &project_id,
                "先失败再从同一 Runtime thread 恢复；禁止外部动作",
                Some(failed_turn_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(2),
            )
            .expect("durable failed turn");
        assert_eq!(failed.runtime_outcome, DesktopMissionRuntimeOutcome::Failed);
        let mission_id = failed.mission_id.clone();
        let mission_count = failed.snapshot.inventory.projects[0].missions.len();
        let failed_mission = failed.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == mission_id)
            .expect("failed Mission projection");
        assert_eq!(failed_mission.work_product_count, 0);
        let failed_activity = failed
            .snapshot
            .runtime_activity
            .iter()
            .find(|activity| activity.mission_id == mission_id)
            .expect("failed turn activity");
        assert_eq!(
            failed_activity.recovery_status,
            Some(RuntimeRecoveryStatus::Attached)
        );
        assert_eq!(failed_activity.turn_status, Some(RuntimeTurnStatus::Failed));

        let recovered = plane
            .resume_mission_runtime_with(
                &secrets,
                &project_id,
                &mission_id,
                Some(resumed_completed_runtime_fixture_source()),
                DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
                observed_at() + Duration::minutes(3),
            )
            .expect("resume exact bound Runtime thread");
        assert_eq!(recovered.mission_id, mission_id);
        assert!(matches!(
            recovered.runtime_outcome,
            DesktopMissionRuntimeOutcome::DraftReady { .. }
        ));
        assert_eq!(
            recovered.snapshot.inventory.projects[0].missions.len(),
            mission_count
        );
        let recovered_mission = recovered.snapshot.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == mission_id)
            .expect("recovered Mission projection");
        assert_eq!(recovered_mission.stage, MissionStage::Running);
        assert_eq!(recovered_mission.work_product_count, 1);
        assert_eq!(
            recovered_mission.work_products[0].preview_text,
            "Reviewable draft recovered through the existing Runtime thread."
        );
        assert_eq!(recovered_mission.pending_approval_count, 0);
        assert_eq!(recovered_mission.verified_effect_count, 0);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(4))
            .expect("reopen resumed Runtime state");
        let recovery = service
            .latest_runtime_recovery_for_mission(&project_id, &mission_id)
            .expect("latest recovery")
            .expect("resume recovery");
        assert_eq!(recovery.worker_generation, 1);
        assert_eq!(
            recovery.initial_strategy,
            RuntimeResumeStrategy::ResumeExisting
        );
        assert_eq!(recovery.status, RuntimeRecoveryStatus::Attached);
        assert_eq!(recovery.process_attempt, 1);
        let turn = service
            .latest_runtime_turn_for_mission(&project_id, &mission_id)
            .expect("latest turn")
            .expect("resumed completed turn");
        assert_eq!(turn.scope.worker_generation, 1);
        assert_eq!(turn.status, RuntimeTurnStatus::Completed);
        let mission = service
            .load_mission(&project_id, &mission_id)
            .expect("truthful resumed Mission");
        assert_eq!(mission.stage, MissionStage::Running);
        assert_eq!(mission.work_products.len(), 1);
        assert!(mission.effects.is_empty());
        let event_json = serde_json::to_string(
            &service
                .mission_events(&project_id, &mission_id)
                .expect("content-free Runtime events"),
        )
        .expect("event JSON");
        assert!(!event_json.contains("failed turn text"));
        assert!(!event_json.contains("Reviewable draft recovered"));
    }

    fn record_device_fenced_work_product(
        service: &mut ApplicationService,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> (&'static str, &'static str) {
        let mission = service
            .load_mission(project_id, mission_id)
            .expect("initial Mission");
        let task_id = mission.tasks[0].id.clone();
        let private_body = "private body must remain behind the exact device Context session";
        let preview = "Visible only after exact Device unlock";
        service
            .record_research(
                project_id,
                mission_id,
                ResearchPacket {
                    work_product_id: WorkProductId::from("device-fenced-work-product"),
                    title: "Device-fenced evidence pack".into(),
                    body: private_body.into(),
                    work_product_type: "document.device_fenced".into(),
                    fact_ids: BTreeSet::new(),
                    task_ids: BTreeSet::from([task_id]),
                    file_digest: None,
                    preview_media_type: "text/plain".into(),
                    preview: preview.into(),
                    editable_scopes: BTreeSet::from(["/body".into()]),
                    evidence: vec![EvidenceInput {
                        id: EvidenceId::from("device-fenced-evidence"),
                        title: "Device-fenced source".into(),
                        source_uri: "fixture://desktop/device-fenced".into(),
                        confidence: 1.0,
                        content: "private evidence source".into(),
                    }],
                },
                observed_at() + Duration::seconds(10),
            )
            .expect("manifested WorkProduct");
        (private_body, preview)
    }

    fn assert_device_fenced_projection(
        snapshot: &DesktopSnapshot,
        preview: &str,
        private_body: &str,
        unlocked: bool,
    ) {
        let mission = &snapshot.inventory.projects[0].missions[0];
        assert_eq!(mission.work_product_count, 1);
        assert_eq!(mission.work_products.len(), usize::from(unlocked));
        if unlocked {
            assert_eq!(mission.work_products[0].preview_text, preview);
        }
        let diagnostics = format!("{mission:?}");
        assert_eq!(diagnostics.contains(preview), unlocked);
        assert!(!diagnostics.contains(private_body));
    }

    fn recover_device_and_assert(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        recovery: &RecoveryKitDraft,
        preview: &str,
        private_body: &str,
    ) -> DesktopSnapshot {
        let wrong_key = "00".repeat(32);
        let wrong_recovery = plane.recover_personal_project_device_with(
            secrets,
            project_id,
            &wrong_key,
            observed_at() + Duration::minutes(4),
        );
        assert!(
            matches!(wrong_recovery, Err(DesktopDataError::InvalidRecoveryKey)),
            "unexpected wrong-kit result: {wrong_recovery:?}"
        );
        assert_eq!(secrets.entry_count().expect("database key only"), 1);
        let recovered = plane
            .recover_personal_project_device_with(
                secrets,
                project_id,
                recovery.expose_for_user_export(),
                observed_at() + Duration::minutes(5),
            )
            .expect("Recovery Kit attaches a successor local Device key");
        assert_eq!(secrets.entry_count().expect("database + successor key"), 2);
        assert!(matches!(
            recovered.context_access[0].status,
            ProjectContextAccessStatus::Ready {
                keyring_revision: 2,
                active_key_version: 1,
                ..
            }
        ));
        assert!(matches!(
            recovered.inventory.projects[0].encryption,
            ProjectEncryptionReadiness::Ready {
                keyring_revision: 2,
                ..
            }
        ));
        assert_device_fenced_projection(&recovered, preview, private_body, true);
        recovered
    }

    #[test]
    fn data_plane_mounts_cordis_host_with_hartevo_owned_surfaces() {
        use chrono::{Duration, TimeZone, Utc};
        use hartevo_cordis::{
            AgentStep, CordisError, DomainSurface, OPENINTERPRETER, SurfaceOwner,
            host_is_cordis_loop, invariant_missing,
        };
        use hartevo_domain_kernel::{
            ActorId, Approval, ApprovalDecision, ApprovalId, ConsentState,
        };

        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        plane.with_cordis_host(|host| {
            host_is_cordis_loop(host).unwrap();
            let domain = host.context().domain::<DomainSurface>().unwrap();
            assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
            assert!(!domain.consent());
            assert!(!domain.approved());
            assert_eq!(
                host.step(AgentStep::new("mission-plane", "plan"))
                    .unwrap_err(),
                CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
            );
            assert_eq!(
                host.apply_effect().unwrap_err(),
                CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
            );
            assert!(
                host.context().get::<String>(OPENINTERPRETER).is_none()
                    || host.runtime_plugin() == Some(OPENINTERPRETER)
            );
        });

        let now = Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap();
        plane
            .bind_live_domain_kernel(
                &ConsentState::Confirmed,
                None,
                Some(&Approval {
                    id: ApprovalId::from("approval-plane"),
                    decision: ApprovalDecision::Approved,
                    decided_by: ActorId::from("user-plane"),
                    decided_at: now,
                    valid_until: now + Duration::minutes(5),
                    scope_digest: "a".repeat(64),
                    permission_digest: "b".repeat(64),
                }),
                now,
            )
            .unwrap();
        let out = plane
            .with_cordis_host(|host| host.step(AgentStep::new("mission-plane", "plan")))
            .unwrap();
        assert_eq!(out.id, "mission-plane");
        plane.with_cordis_host(|host| host.apply_effect()).unwrap();
    }

    #[test]
    fn uninitialized_and_fresh_initialize_keep_host_mounted_and_fail_closed() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        let missing_project = ProjectId::from("missing-project");
        let missing_mission = MissionId::from("missing-mission");
        let DesktopLoadState::Uninitialized { .. } = plane
            .load_with(&secrets, observed_at())
            .expect("honest first-run state")
        else {
            panic!("first run must not create a database or key implicitly");
        };
        assert_host_fail_closed_on_consent(&plane);
        assert_eq!(
            plane
                .step(
                    &secrets,
                    &missing_project,
                    &missing_mission,
                    AgentStep::new("mission-uninitialized", "plan"),
                    observed_at(),
                )
                .unwrap_err()
                .to_string(),
            DesktopDataError::Cordis(CordisError::MissingDependencies(vec![
                hartevo_cordis::invariant_missing::CONSENT.to_string()
            ]))
            .to_string()
        );
        assert_eq!(
            plane
                .apply_effect(&secrets, &missing_project, &missing_mission, observed_at(),)
                .unwrap_err()
                .to_string(),
            DesktopDataError::Cordis(CordisError::MissingDependencies(vec![
                hartevo_cordis::invariant_missing::CONSENT.to_string()
            ]))
            .to_string()
        );

        plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");
        assert_host_fail_closed_on_consent(&plane);
        for error in [
            plane
                .step(
                    &secrets,
                    &missing_project,
                    &missing_mission,
                    AgentStep::new("mission-initialized", "plan"),
                    observed_at(),
                )
                .unwrap_err(),
            plane
                .apply_effect(&secrets, &missing_project, &missing_mission, observed_at())
                .unwrap_err(),
        ] {
            assert!(
                matches!(
                    &error,
                    DesktopDataError::Application(ApplicationError::Storage(
                        StorageError::MissionNotFound { .. }
                    ))
                ),
                "unexpected exact-scope error: {error:?}"
            );
        }
        assert!(
            plane
                .with_cordis_host(|host| host.bound_scope().cloned())
                .is_none(),
            "a missing Mission must not bind fallback authority"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the scoped Domain fact test covers an approved exact Mission plus a consent-only planning/effect gate fixture"
    )]
    fn exact_mission_step_binds_live_grant_and_in_window_approval() {
        use hartevo_cordis::{DomainSurface, host_is_cordis_loop, invariant_missing};

        let directory = tempfile::tempdir().expect("directory");
        let data_root = directory.path().join("desktop-data");
        let project_root = directory.path().join("project");
        fs::create_dir(&project_root).expect("project root");
        let plane = DesktopDataPlane::at_data_root(&data_root).expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("initialize");
        let (project_id, tenant_id) = create_kernel_bind_project(
            &plane,
            &secrets,
            &project_root,
            "live",
            observed_at() + Duration::minutes(1),
        );
        let (person_id, consent_id, mission_id) = grant_live_consent(&LiveConsentGrant {
            plane: &plane,
            secrets: &secrets,
            project_id: &project_id,
            tenant_id: &tenant_id,
            suffix: "live",
            now: observed_at() + Duration::minutes(2),
            consent_until: Some(observed_at() + Duration::days(30)),
        });
        approve_live_preview(&LivePreviewApproval {
            plane: &plane,
            secrets: &secrets,
            project_id: &project_id,
            person_id,
            consent_id: &consent_id,
            mission_id: &mission_id,
            suffix: "live",
            now: observed_at() + Duration::minutes(2),
        });

        let DesktopLoadState::Ready(_) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(3))
            .expect("reload binds live kernel facts")
        else {
            panic!("initialized database must reopen");
        };
        plane.with_cordis_host(|host| {
            host_is_cordis_loop(host).unwrap();
            let domain = host.context().domain::<DomainSurface>().unwrap();
            assert!(!domain.consent());
            assert!(!domain.approved());
        });
        let out = plane
            .step(
                &secrets,
                &project_id,
                &mission_id,
                AgentStep::new("mission-live", "plan"),
                observed_at() + Duration::minutes(3),
            )
            .expect("production step after live bind");
        assert_eq!(out.id, "mission-live");
        plane
            .apply_effect(
                &secrets,
                &project_id,
                &mission_id,
                observed_at() + Duration::minutes(3),
            )
            .expect("production apply_effect after live bind");

        let consent_only = DesktopDataPlane::at_data_root(directory.path().join("consent-only"))
            .expect("consent-only plane");
        let consent_secrets = MemorySecretStore::default();
        consent_only
            .initialize_with(&consent_secrets, observed_at())
            .expect("initialize");
        let consent_root = directory.path().join("consent-only-project");
        fs::create_dir(&consent_root).expect("consent-only project root");
        let (consent_project, consent_tenant) = create_kernel_bind_project(
            &consent_only,
            &consent_secrets,
            &consent_root,
            "consent-only",
            observed_at() + Duration::minutes(1),
        );
        let (_, _, consent_mission) = grant_live_consent(&LiveConsentGrant {
            plane: &consent_only,
            secrets: &consent_secrets,
            project_id: &consent_project,
            tenant_id: &consent_tenant,
            suffix: "consent-only",
            now: observed_at() + Duration::minutes(2),
            consent_until: Some(observed_at() + Duration::days(30)),
        });
        consent_only
            .load_with(&consent_secrets, observed_at() + Duration::minutes(3))
            .expect("reload consent-only");
        assert!(matches!(
            consent_only.step(
                &consent_secrets,
                &consent_project,
                &consent_mission,
                AgentStep::new("mission-consent-only", "plan"),
                observed_at() + Duration::minutes(3),
            ),
            Err(DesktopDataError::Cordis(CordisError::MissingDependencies(missing)))
                if missing == [invariant_missing::APPROVAL]
        ));
    }

    #[test]
    fn approval_from_another_mission_cannot_bind_runtime_authority() {
        use hartevo_cordis::{DomainSurface, invariant_missing};

        let directory = tempfile::tempdir().expect("directory");
        let project_root = directory.path().join("project");
        fs::create_dir(&project_root).expect("project root");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data")).unwrap();
        let secrets = MemorySecretStore::default();
        plane.initialize_with(&secrets, observed_at()).unwrap();
        let (project_id, tenant_id) = create_kernel_bind_project(
            &plane,
            &secrets,
            &project_root,
            "cross-mission",
            observed_at() + Duration::minutes(1),
        );
        let (person_id, consent_id, approved_mission) = grant_live_consent(&LiveConsentGrant {
            plane: &plane,
            secrets: &secrets,
            project_id: &project_id,
            tenant_id: &tenant_id,
            suffix: "cross-mission",
            now: observed_at() + Duration::minutes(2),
            consent_until: Some(observed_at() + Duration::days(30)),
        });
        approve_live_preview(&LivePreviewApproval {
            plane: &plane,
            secrets: &secrets,
            project_id: &project_id,
            person_id,
            consent_id: &consent_id,
            mission_id: &approved_mission,
            suffix: "cross-mission",
            now: observed_at() + Duration::minutes(2),
        });

        let other_mission = MissionId::from("desktop-kernel-mission-without-approval");
        let database_secret = secrets.get(plane.database_key_reference()).unwrap();
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .unwrap();
        service
            .start_mission(
                StartMission {
                    id: other_mission.clone(),
                    research_task_id: TaskId::from("desktop-kernel-task-without-approval"),
                    project_id: project_id.clone(),
                    title: Some("Unapproved Mission".into()),
                    prompt: "plan only; do not execute an external effect".into(),
                },
                observed_at() + Duration::minutes(3),
            )
            .unwrap();
        drop(service);

        assert!(matches!(
            plane.step(
                &secrets,
                &project_id,
                &other_mission,
                AgentStep::new("cross-mission-attack", "plan"),
                observed_at() + Duration::minutes(4),
            ),
            Err(DesktopDataError::Cordis(CordisError::MissingDependencies(missing)))
                if missing == [invariant_missing::APPROVAL]
        ));
        plane.with_cordis_host(|host| {
            let bound = host.bound_scope().expect("exact Mission scope");
            assert_eq!(bound.mission_id(), other_mission.as_str());
            assert!(!host.context().domain::<DomainSurface>().unwrap().approved());
        });
    }

    #[test]
    fn withdrawn_kernel_facts_stay_fail_closed() {
        use hartevo_cordis::invariant_missing;

        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("initialize");
        let project_root = directory.path().join("project");
        fs::create_dir(&project_root).expect("project root");
        let (project_id, tenant_id) = create_kernel_bind_project(
            &plane,
            &secrets,
            &project_root,
            "withdrawn",
            observed_at() + Duration::minutes(1),
        );
        let (person_id, consent_id, mission_id) = grant_live_consent(&LiveConsentGrant {
            plane: &plane,
            secrets: &secrets,
            project_id: &project_id,
            tenant_id: &tenant_id,
            suffix: "withdrawn",
            now: observed_at() + Duration::minutes(2),
            consent_until: Some(observed_at() + Duration::days(30)),
        });
        approve_live_preview(&LivePreviewApproval {
            plane: &plane,
            secrets: &secrets,
            project_id: &project_id,
            person_id,
            consent_id: &consent_id,
            mission_id: &mission_id,
            suffix: "withdrawn",
            now: observed_at() + Duration::minutes(2),
        });
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at() + Duration::minutes(3))
            .expect("application");
        service
            .withdraw_consent(
                &project_id,
                &consent_id,
                observed_at() + Duration::minutes(4),
            )
            .expect("withdraw");
        drop(service);
        plane
            .load_with(&secrets, observed_at() + Duration::minutes(5))
            .expect("reload withdrawn");
        assert!(matches!(
            plane.step(
                &secrets,
                &project_id,
                &mission_id,
                AgentStep::new("mission-withdrawn", "plan"),
                observed_at() + Duration::minutes(5),
            ),
            Err(DesktopDataError::Cordis(CordisError::MissingDependencies(missing)))
                if missing == [invariant_missing::CONSENT]
        ));
    }

    #[test]
    fn expired_kernel_facts_stay_fail_closed() {
        use hartevo_cordis::invariant_missing;

        let directory = tempfile::tempdir().expect("directory");
        let expired = DesktopDataPlane::at_data_root(directory.path().join("expired"))
            .expect("expired plane");
        let expired_secrets = MemorySecretStore::default();
        expired
            .initialize_with(&expired_secrets, observed_at())
            .expect("initialize");
        let expired_root = directory.path().join("expired-project");
        fs::create_dir(&expired_root).expect("expired project root");
        let (expired_project, expired_tenant) = create_kernel_bind_project(
            &expired,
            &expired_secrets,
            &expired_root,
            "expired",
            observed_at() + Duration::minutes(1),
        );
        let (person_id, consent_id, mission_id) = grant_live_consent(&LiveConsentGrant {
            plane: &expired,
            secrets: &expired_secrets,
            project_id: &expired_project,
            tenant_id: &expired_tenant,
            suffix: "expired",
            now: observed_at() + Duration::minutes(2),
            consent_until: Some(observed_at() + Duration::minutes(3)),
        });
        approve_live_preview(&LivePreviewApproval {
            plane: &expired,
            secrets: &expired_secrets,
            project_id: &expired_project,
            person_id,
            consent_id: &consent_id,
            mission_id: &mission_id,
            suffix: "expired",
            now: observed_at() + Duration::minutes(2),
        });
        expired
            .load_with(&expired_secrets, observed_at() + Duration::minutes(4))
            .expect("reload expired");
        assert!(matches!(
            expired.step(
                &expired_secrets,
                &expired_project,
                &mission_id,
                AgentStep::new("mission-expired", "plan"),
                observed_at() + Duration::minutes(4),
            ),
            Err(DesktopDataError::Cordis(CordisError::MissingDependencies(missing)))
                if missing == [invariant_missing::CONSENT]
                    || missing == [invariant_missing::APPROVAL]
        ));
    }

    #[test]
    fn explicit_initialization_and_application_inventory_survive_restart() {
        let directory = tempfile::tempdir().expect("directory");
        let data_root = directory.path().join("desktop-data");
        let project_root = directory.path().join("project");
        fs::create_dir(&project_root).expect("project root");
        let plane = DesktopDataPlane::at_data_root(&data_root).expect("data plane");
        let secrets = MemorySecretStore::default();

        let DesktopLoadState::Uninitialized { product_evidence } = plane
            .load_with(&secrets, observed_at())
            .expect("honest first-run state")
        else {
            panic!("first run must not create a database or key implicitly");
        };
        assert!(!product_evidence.release_passed);
        assert_eq!(product_evidence.missions.len(), 12);
        assert!(product_evidence.missions.iter().all(|mission| {
            mission.evidence_level == EvidenceLevel::E1
                && mission.status == MissionEvidenceStatus::NotImplemented
        }));

        let initialized = plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");
        assert!(initialized.inventory.projects.is_empty());
        assert!(initialized.context_access.is_empty());
        assert_eq!(secrets.entry_count().expect("entry count"), 1);
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at())
            .expect("application");
        let project_id = ProjectId::from("desktop-restart-project");
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("desktop-restart-tenant"),
                    id: project_id.clone(),
                    name: "Restart-safe project".into(),
                    description: "Application-owned inventory".into(),
                    workspace_root: project_root,
                    storage_mode: StorageMode::LocalExisting,
                },
                observed_at(),
            )
            .expect("project");
        service
            .provision_project_encryption(
                &secrets,
                ProvisionProjectEncryption {
                    project_id: project_id.clone(),
                    mode: ProjectEncryptionMode::TeamEnvelope,
                    primary_recipient: KeyRecipient::Device(plane.device_id.clone()),
                    recovery_recipient_id: None,
                },
                observed_at(),
            )
            .expect("encryption");
        drop(service);

        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "研究当前增长约束；不得执行外部动作",
                observed_at() + Duration::minutes(1),
            )
            .expect("persisted mission");
        assert_eq!(started.inventory.projects[0].missions.len(), 1);
        assert!(matches!(
            started.context_access[0].status,
            ProjectContextAccessStatus::Ready {
                active_key_version: 1,
                ..
            }
        ));
        assert_eq!(started.inventory.projects[0].missions[0].revision, 2);
        assert_eq!(
            started.inventory.projects[0].missions[0].stage,
            hartevo_domain_kernel::MissionStage::Running
        );

        let DesktopLoadState::Ready(restarted) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(2))
            .expect("restart")
        else {
            panic!("initialized database must reopen");
        };
        assert_eq!(restarted.inventory, started.inventory);
        assert_eq!(restarted.context_access, started.context_access);
        assert_eq!(restarted.inventory.projects[0].project_id, project_id);
        assert_eq!(restarted.runtime_reconciliation.scanned_attempts, 0);
        assert!(!format!("{plane:?}").contains(data_root.to_string_lossy().as_ref()));
    }

    #[test]
    fn desktop_reopen_reconciles_expired_mission_schedule_once_before_projection() {
        let directory = tempfile::tempdir().expect("directory");
        let data_root = directory.path().join("desktop-data");
        let project_root = directory.path().join("project");
        fs::create_dir(&project_root).expect("project root");
        let plane = DesktopDataPlane::at_data_root(&data_root).expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("initialize");
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at())
            .expect("application");
        let project_id = ProjectId::from("desktop-scheduler-expiry-project");
        let mission_id = MissionId::from("desktop-scheduler-expiry-mission");
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("desktop-scheduler-expiry-tenant"),
                    id: project_id.clone(),
                    name: "Desktop scheduler expiry".into(),
                    description: String::new(),
                    workspace_root: project_root,
                    storage_mode: StorageMode::LocalExisting,
                },
                observed_at(),
            )
            .expect("project");
        service
            .start_relationship_mission(
                StartRelationshipMission {
                    id: mission_id.clone(),
                    project_id: project_id.clone(),
                    task_id: TaskId::from("desktop-scheduler-cycle-1"),
                    title: "Bounded inbox operator".into(),
                    goal: "Reconcile contract expiry before Desktop renders".into(),
                },
                observed_at(),
            )
            .expect("mission");
        let contract_valid_until = service
            .load_mission(&project_id, &mission_id)
            .expect("mission")
            .contract
            .valid_until;
        service
            .record_outcome(
                &project_id,
                &mission_id,
                "Initial cycle reviewed",
                OutcomeDecision::Continue,
                BTreeMap::new(),
                observed_at() + Duration::seconds(1),
            )
            .expect("schedule cycle two");
        drop(service);

        let DesktopLoadState::Ready(first_reopen) = plane
            .load_with(&secrets, contract_valid_until)
            .expect("reopen at contract boundary")
        else {
            panic!("Desktop must reopen");
        };
        let first_projection = &first_reopen.inventory.projects[0].missions[0];
        assert_eq!(first_projection.stage, MissionStage::Completed);
        assert_eq!(
            first_projection
                .schedule
                .as_ref()
                .map(|schedule| schedule.status),
            Some(MissionScheduleStatus::Expired)
        );
        let terminal_revision = first_projection.revision;

        let DesktopLoadState::Ready(second_reopen) = plane
            .load_with(&secrets, contract_valid_until + Duration::seconds(1))
            .expect("idempotent reopen")
        else {
            panic!("Desktop must reopen twice");
        };
        let second_projection = &second_reopen.inventory.projects[0].missions[0];
        assert_eq!(second_projection.revision, terminal_revision);
        assert_eq!(second_projection.stage, MissionStage::Completed);
        assert_eq!(
            second_projection
                .schedule
                .as_ref()
                .map(|schedule| schedule.status),
            Some(MissionScheduleStatus::Expired)
        );
    }

    #[test]
    fn existing_database_without_its_os_vault_key_fails_closed() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("initialize");
        secrets
            .delete(plane.database_key_reference())
            .expect("delete database key");

        assert!(matches!(
            plane.load_with(&secrets, observed_at()),
            Err(DesktopDataError::MissingDatabaseKey)
        ));
        assert!(plane.database_path.exists());
        assert_eq!(secrets.entry_count().expect("entry count"), 0);
    }

    #[test]
    fn substituted_database_key_is_rejected_without_rewriting_ciphertext() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("initialize");
        let before = fs::read(&plane.database_path).expect("database ciphertext");
        let replacement = KeyMaterial::generate()
            .expect("replacement key")
            .to_secret();
        secrets
            .put(plane.database_key_reference(), &replacement)
            .expect("substitute key");

        assert!(matches!(
            plane.load_with(&secrets, observed_at()),
            Err(DesktopDataError::Storage(_))
        ));
        assert_eq!(
            fs::read(&plane.database_path).expect("unchanged database ciphertext"),
            before
        );
    }

    #[test]
    fn exported_recovery_kit_creates_ready_personal_project_without_escrow_and_restarts() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");
        let recovery = RecoveryKitDraft::generate().expect("recovery kit");
        let exported = Zeroizing::new(recovery.expose_for_user_export().to_owned());
        assert_eq!(exported.len(), 64);
        assert!(exported.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let redacted_debug = format!("{recovery:?}");
        assert!(redacted_debug.contains("[REDACTED]"));
        assert!(!redacted_debug.contains(exported.as_str()));

        let created = plane
            .create_personal_project_with(
                &secrets,
                "Local-first launch",
                "建立当前经营基线，不执行外部动作",
                exported.as_str(),
                observed_at() + Duration::minutes(1),
            )
            .expect("personal project");
        assert_eq!(created.inventory.projects.len(), 1);
        let project = &created.inventory.projects[0];
        assert_eq!(project.storage_mode, StorageMode::LocalNew);
        assert!(matches!(
            project.encryption,
            ProjectEncryptionReadiness::Ready {
                mode: ProjectEncryptionMode::PersonalE2ee,
                active_key_version: 1,
                ..
            }
        ));
        assert_eq!(project.missions.len(), 1);
        assert_eq!(
            project.missions[0].stage,
            hartevo_domain_kernel::MissionStage::Running
        );
        assert_eq!(secrets.entry_count().expect("database + device key"), 2);
        assert!(matches!(
            created.context_access[0].status,
            ProjectContextAccessStatus::Ready {
                active_key_version: 1,
                ..
            }
        ));

        let DesktopLoadState::Ready(restarted) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(2))
            .expect("restart")
        else {
            panic!("personal project must reopen from SQLCipher and OS Secret Store");
        };
        assert_eq!(restarted.inventory, created.inventory);
        assert_eq!(restarted.context_access, created.context_access);
        assert_eq!(secrets.entry_count().expect("no recovery escrow"), 2);
    }

    #[test]
    fn invalid_recovery_kit_fails_before_project_or_workspace_creation() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");

        assert!(matches!(
            plane.create_personal_project_with(
                &secrets,
                "Must not exist",
                "Must not start",
                "not-a-recovery-key",
                observed_at(),
            ),
            Err(DesktopDataError::InvalidRecoveryKey)
        ));
        assert!(!plane.data_root().join("projects").exists());
        let DesktopLoadState::Ready(reloaded) =
            plane.load_with(&secrets, observed_at()).expect("reload")
        else {
            panic!("initialized Desktop remains ready");
        };
        assert!(reloaded.inventory.projects.is_empty());
        assert_eq!(secrets.entry_count().expect("installation key only"), 1);
    }

    #[test]
    fn interrupted_unprovisioned_project_can_resume_once_with_saved_recovery_kit() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at())
            .expect("application");
        let project_id = ProjectId::from("interrupted-personal-project");
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("local-personal"),
                    id: project_id.clone(),
                    name: "Interrupted setup".into(),
                    description: "Resume without replacing state".into(),
                    workspace_root: plane
                        .create_project_root(&project_id)
                        .expect("private project root"),
                    storage_mode: StorageMode::LocalNew,
                },
                observed_at(),
            )
            .expect("partial project");
        drop(service);
        let recovery = RecoveryKitDraft::generate().expect("saved recovery kit");

        let completed = plane
            .complete_personal_encryption_with(
                &secrets,
                &project_id,
                recovery.expose_for_user_export(),
                observed_at() + Duration::minutes(1),
            )
            .expect("resume encryption");
        assert!(matches!(
            completed.inventory.projects[0].encryption,
            ProjectEncryptionReadiness::Ready {
                mode: ProjectEncryptionMode::PersonalE2ee,
                ..
            }
        ));
        assert_eq!(secrets.entry_count().expect("database + device key"), 2);
        assert!(matches!(
            plane.complete_personal_encryption_with(
                &secrets,
                &project_id,
                recovery.expose_for_user_export(),
                observed_at() + Duration::minutes(2),
            ),
            Err(DesktopDataError::ProjectEncryptionAlreadyProvisioned(id)) if id == project_id
        ));
        assert_eq!(secrets.entry_count().expect("no duplicate device key"), 2);

        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "继续中断前的安全本地设置",
                observed_at() + Duration::minutes(3),
            )
            .expect("ready project accepts mission");
        assert_eq!(started.inventory.projects[0].missions.len(), 1);
    }

    #[test]
    fn missing_or_foreign_device_key_blocks_new_missions_without_hiding_inventory() {
        let directory = tempfile::tempdir().expect("directory");
        let plane = DesktopDataPlane::at_data_root(directory.path().join("desktop-data"))
            .expect("data plane");
        let secrets = MemorySecretStore::default();
        plane
            .initialize_with(&secrets, observed_at())
            .expect("explicit initialization");
        let recovery = RecoveryKitDraft::generate().expect("recovery kit");
        let created = plane
            .create_personal_project_with(
                &secrets,
                "Device-fenced project",
                "Persist one initial Mission",
                recovery.expose_for_user_export(),
                observed_at(),
            )
            .expect("personal project");
        let project = &created.inventory.projects[0];
        let project_id = project.project_id.clone();
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, observed_at())
            .expect("application");
        let mission_id = project.missions[0].mission_id.clone();
        let (private_body, preview) =
            record_device_fenced_work_product(&mut service, &project_id, &mission_id);
        let keyring = service.load_project_keyring(&project_id).expect("keyring");
        let recipient = KeyRecipient::Device(plane.device_id.clone());
        let envelope = keyring
            .active_envelope_for(&recipient, observed_at())
            .expect("device envelope");
        let device_reference = SecretReference {
            tenant_id: project.tenant_id.clone(),
            project_id: project_id.clone(),
            provider: "os-native".into(),
            account_scope: recipient.stable_scope(),
            purpose: format!("project_wrapping_key:{}", envelope.id),
            version: envelope.key_version,
        };
        drop(service);

        let DesktopLoadState::Ready(unlocked) = plane
            .load_with(&secrets, observed_at() + Duration::seconds(20))
            .expect("exact device session loads preview")
        else {
            panic!("installation database remains available");
        };
        assert_device_fenced_projection(&unlocked, preview, private_body, true);

        secrets
            .delete(&device_reference)
            .expect("simulate lost device wrapping key");

        let DesktopLoadState::Ready(reloaded) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(1))
            .expect("inventory remains visible")
        else {
            panic!("installation database remains available");
        };
        assert_eq!(reloaded.inventory.projects[0].missions.len(), 1);
        assert_device_fenced_projection(&reloaded, preview, private_body, false);
        assert_eq!(
            reloaded.context_access[0].status,
            ProjectContextAccessStatus::RecoveryRequired
        );
        assert!(matches!(
            plane.start_mission_with(
                &secrets,
                &project_id,
                "Must not persist without a device key",
                observed_at() + Duration::minutes(2),
            ),
            Err(DesktopDataError::ProjectContextRecoveryRequired(id)) if id == project_id
        ));
        let DesktopLoadState::Ready(after_denial) = plane
            .load_with(&secrets, observed_at() + Duration::minutes(3))
            .expect("reload after denial")
        else {
            panic!("installation database remains available");
        };
        assert_eq!(after_denial.inventory.projects[0].missions.len(), 1);

        recover_device_and_assert(
            &plane,
            &secrets,
            &project_id,
            &recovery,
            preview,
            private_body,
        );
        let after_recovery = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "Recovery restores exact local Mission writes",
                observed_at() + Duration::minutes(6),
            )
            .expect("successor Device session can create a Mission");
        assert_eq!(after_recovery.inventory.projects[0].missions.len(), 2);
        assert_device_fenced_projection(&after_recovery, preview, private_body, true);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_data_root_is_rejected_before_key_or_database_access() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("directory");
        let real_root = directory.path().join("real");
        let link_root = directory.path().join("linked");
        fs::create_dir(&real_root).expect("real root");
        symlink(&real_root, &link_root).expect("symlink");
        assert!(matches!(
            DesktopDataPlane::at_data_root(&link_root),
            Err(DesktopDataError::InvalidDataRoot(path)) if path == link_root
        ));
    }

    #[cfg(unix)]
    #[test]
    fn renamed_and_recreated_regular_data_root_fails_installed_identity_before_access() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let installed_root = plane.data_root().to_path_buf();
        let displaced_root = installed_root.with_extension("displaced");
        fs::rename(&installed_root, &displaced_root).expect("displace installed root");
        fs::create_dir(&installed_root).expect("recreate regular lexical root");

        assert!(matches!(
            plane.load_with(&secrets, observed_at() + Duration::minutes(2)),
            Err(DesktopDataError::InvalidDataRoot(path)) if path == installed_root
        ));
        assert!(matches!(
            plane.start_mission_with(
                &secrets,
                &project_id,
                "must not write through a replaced root",
                observed_at() + Duration::minutes(3),
            ),
            Err(DesktopDataError::InvalidDataRoot(path)) if path == installed_root
        ));
        assert!(
            fs::read_dir(&installed_root)
                .expect("replacement root")
                .next()
                .is_none(),
            "replacement root must remain untouched"
        );
        assert!(displaced_root.join(DATABASE_FILE_NAME).is_file());
    }

    fn propose_waiting_approval_preview(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        suffix: &str,
        now: DateTime<Utc>,
    ) -> (MissionId, EffectId, String, u64) {
        let started = plane
            .start_mission_with(
                secrets,
                project_id,
                "准备受控预览；等待精确 digest 审批，禁止执行外部动作",
                now,
            )
            .expect("WaitingApproval Mission");
        let mission_id = started.inventory.projects[0].missions[0].mission_id.clone();
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(1))
            .expect("application");
        let effect_id = EffectId::from_stable(format!("desktop-waiting-approval-{suffix}"));
        service
            .propose_preview_effect(
                project_id,
                &mission_id,
                ProposePreviewEffect {
                    effect_id: effect_id.clone(),
                    actor_id: ActorId::from("desktop-waiting-approval-actor"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: None,
                    account_id: None,
                    required_scopes: BTreeSet::new(),
                    description: "Publish exact preview after window grant".into(),
                    target_resource: "preview://desktop-waiting-approval".into(),
                    audience_digest: None,
                    payload_digest: "1".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: ConsentState::NotRequired,
                    consent_record_id: None,
                    consent_requirement: None,
                    policy_version: "policy-v1".into(),
                    amount: Money::zero(CurrencyCode::parse("CNY").expect("CNY")),
                    idempotency_key: format!("desktop-waiting-approval-{suffix}"),
                    expires_in: Duration::hours(1),
                },
                now + Duration::seconds(2),
            )
            .expect("proposed Effect");
        let mission = service
            .load_mission(project_id, &mission_id)
            .expect("WaitingApproval Mission after propose");
        let effect = mission.effect(&effect_id).expect("proposed Effect");
        assert_eq!(mission.stage, MissionStage::WaitingApproval);
        assert_eq!(effect.status, EffectStatus::Proposed);
        (
            mission_id,
            effect_id,
            effect.approval_digest(),
            mission.revision,
        )
    }

    #[test]
    fn waiting_approval_window_grant_records_approval_without_executing_effect() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(2);
        let (mission_id, effect_id, scope_digest, revision) =
            propose_waiting_approval_preview(&plane, &secrets, &project_id, "grant", now);
        let request = DesktopWaitingApprovalGrantRequest {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            effect_id: effect_id.clone(),
            expected_scope_digest: scope_digest.clone(),
            expected_mission_revision: revision,
        };
        let granted = plane
            .grant_waiting_approval_with(&secrets, request.clone(), now + Duration::seconds(3))
            .expect("production WaitingApproval grant");
        let projected = granted.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == mission_id)
            .expect("granted Mission projection");
        assert_eq!(projected.stage, MissionStage::Running);
        assert_eq!(projected.pending_approval_count, 0);
        assert!(projected.pending_effects.is_empty());
        assert_eq!(projected.verified_effect_count, 0);

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(4))
            .expect("reopen after grant");
        let mission = service
            .load_mission(&project_id, &mission_id)
            .expect("durable granted Mission");
        let effect = mission.effect(&effect_id).expect("granted Effect");
        let approval = effect.approval.as_ref().expect("Domain Kernel Approval");
        assert_eq!(effect.status, EffectStatus::Approved);
        assert_eq!(approval.decision, ApprovalDecision::Approved);
        assert_eq!(approval.scope_digest, scope_digest);
        assert!(approval.valid_until > now + Duration::seconds(3));
        assert!(effect.receipt.is_none());
        assert!(effect.verification.is_none());
        let events_before_replay = service
            .mission_events(&project_id, &mission_id)
            .expect("grant events");
        assert_eq!(
            events_before_replay
                .iter()
                .filter(|event| event.event_type == "approval.decided")
                .count(),
            1
        );
        let event_json = serde_json::to_string(&events_before_replay).expect("event JSON");
        assert!(!event_json.contains("Receipt"));
        assert!(!event_json.contains("Verification"));

        let replay_request = DesktopWaitingApprovalGrantRequest {
            expected_mission_revision: projected.revision,
            ..request
        };
        let replayed = plane
            .grant_waiting_approval_with(&secrets, replay_request, now + Duration::seconds(5))
            .expect("exact grant replay");
        let replayed_projection = replayed.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == mission_id)
            .expect("replayed Mission projection");
        assert_eq!(replayed_projection.revision, projected.revision);
        assert_eq!(replayed_projection.pending_approval_count, 0);
        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(6))
            .expect("reopen after replay");
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("unchanged replay events"),
            events_before_replay
        );
        let replayed_effect = service
            .load_mission(&project_id, &mission_id)
            .expect("replayed Mission")
            .effect(&effect_id)
            .expect("replayed Effect")
            .clone();
        assert_eq!(replayed_effect.status, EffectStatus::Approved);
        assert!(replayed_effect.receipt.is_none());
        assert!(replayed_effect.verification.is_none());
    }

    #[test]
    fn waiting_approval_grant_cas_mismatches_refuse_without_mutating_mission() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(3);
        let (mission_id, effect_id, scope_digest, revision) =
            propose_waiting_approval_preview(&plane, &secrets, &project_id, "cas", now);
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(3))
            .expect("baseline before CAS refusals");
        let before = service
            .load_mission(&project_id, &mission_id)
            .expect("unmutated Mission");
        let events_before = service
            .mission_events(&project_id, &mission_id)
            .expect("baseline events");

        let swapped = plane.grant_waiting_approval_with(
            &secrets,
            DesktopWaitingApprovalGrantRequest {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                effect_id: effect_id.clone(),
                expected_scope_digest: "a".repeat(64),
                expected_mission_revision: revision,
            },
            now + Duration::seconds(4),
        );
        assert!(matches!(
            swapped,
            Err(DesktopDataError::Application(
                ApplicationError::ProposedEffectApprovalDigestMismatch
            ))
        ));

        let stale_revision = plane.grant_waiting_approval_with(
            &secrets,
            DesktopWaitingApprovalGrantRequest {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                effect_id: effect_id.clone(),
                expected_scope_digest: scope_digest.clone(),
                expected_mission_revision: revision.saturating_add(1),
            },
            now + Duration::seconds(5),
        );
        assert!(matches!(
            stale_revision,
            Err(DesktopDataError::Application(
                ApplicationError::MissionRevisionMismatch { expected, actual }
            )) if expected == revision.saturating_add(1) && actual == revision
        ));

        let sample_digest = plane.grant_waiting_approval_with(
            &secrets,
            DesktopWaitingApprovalGrantRequest {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                effect_id: effect_id.clone(),
                expected_scope_digest: "SAMPLE-r1-not-an-effect-digest".into(),
                expected_mission_revision: revision,
            },
            now + Duration::seconds(6),
        );
        assert!(matches!(
            sample_digest,
            Err(DesktopDataError::InvalidWaitingApprovalGrant)
        ));

        let expired = plane.grant_waiting_approval_with(
            &secrets,
            DesktopWaitingApprovalGrantRequest {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                effect_id: effect_id.clone(),
                expected_scope_digest: scope_digest,
                expected_mission_revision: revision,
            },
            now + Duration::hours(2),
        );
        assert!(expired.is_err());

        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(7))
            .expect("reopen after CAS refusals");
        let after = service
            .load_mission(&project_id, &mission_id)
            .expect("Mission after refusals");
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.stage, MissionStage::WaitingApproval);
        let effect = after.effect(&effect_id).expect("still Proposed");
        assert_eq!(effect.status, EffectStatus::Proposed);
        assert!(effect.approval.is_none());
        assert!(effect.receipt.is_none());
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("unchanged events"),
            events_before
        );
    }

    fn persist_user_held_browser_workspace(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> (BrowserWorkspaceId, u64, u64) {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, now)
            .expect("application");
        let profile = service
            .create_managed_browser_profile(
                CreateManagedBrowserProfile {
                    id: BrowserProfileId::from("profile-desktop-continue"),
                    project_id: project_id.clone(),
                    credential_reference: "keychain://desktop-continue/profile".into(),
                    provider: "fixture-provider".into(),
                    account_id: AccountId::from("account-desktop-continue"),
                    identity_digest: "1".repeat(64),
                    probe_digest: "2".repeat(64),
                },
                now,
            )
            .expect("profile");
        let workspace = service
            .create_browser_workspace(
                CreateBrowserWorkspace {
                    id: BrowserWorkspaceId::from("workspace-desktop-continue"),
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    profile_id: profile.id.clone(),
                    initial_tab_id: BrowserTabId::from("tab-desktop-continue"),
                    lease_id: BrowserControlLeaseId::from("lease-desktop-continue-1"),
                    lease_expires_at: now + Duration::hours(1),
                    evidence_digest: "3".repeat(64),
                },
                now,
            )
            .expect("workspace");
        let mut host = FakeBrowserHost::new();
        host.register_workspace(
            profile,
            workspace.clone(),
            vec![hartevo_browser_adapter::FakeBrowserPage {
                tab_id: BrowserTabId::from("tab-desktop-continue"),
                identity_digest: "1".repeat(64),
                url_digest: "4".repeat(64),
                origin_digest: "5".repeat(64),
                content_digest: "6".repeat(64),
                redaction_digest: "7".repeat(64),
                document_generation: 1,
                prompt_risk: hartevo_browser_adapter::BrowserPromptRisk::None,
                element_refs: Vec::new(),
            }],
        )
        .expect("register host");
        let taken = service
            .take_over_browser_workspace(
                &mut host,
                TakeOverBrowserWorkspace {
                    project_id: project_id.clone(),
                    workspace_id: workspace.id.clone(),
                    expected_revision: workspace.revision,
                    expected_generation: workspace.lease_generation,
                    new_lease_id: BrowserControlLeaseId::from("lease-desktop-continue-2"),
                    evidence_digest: "b".repeat(64),
                },
                now + Duration::seconds(1),
            )
            .expect("user-held lease");
        assert_eq!(taken.control_state, BrowserControlState::UserControlled);
        (taken.id, taken.revision, taken.lease_generation)
    }

    #[test]
    fn continue_without_mission_workspace_stays_empty() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(2);
        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "没有 Browser Workspace 时 Continue 必须失败关闭",
                now,
            )
            .expect("mission");
        let mission = &started.inventory.projects[0].missions[0];
        assert!(mission.browser_workspace.is_none());
        let refused = plane.continue_browser_workspace_with(
            &secrets,
            DesktopContinueBrowserWorkspaceRequest {
                project_id: project_id.clone(),
                mission_id: mission.mission_id.clone(),
                workspace_id: BrowserWorkspaceId::from("workspace-does-not-exist"),
                expected_revision: 1,
                expected_generation: 1,
            },
            now + Duration::seconds(1),
        );
        assert!(matches!(
            refused,
            Err(DesktopDataError::BrowserWorkspaceUnavailable)
        ));
    }

    #[test]
    fn continue_on_agent_held_workspace_stays_disabled() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(3);
        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "Agent-held Continue 在 Take over 前保持 NOT_IMPLEMENTED",
                now,
            )
            .expect("mission");
        let mission_id = started.inventory.projects[0].missions[0].mission_id.clone();
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(1))
            .expect("application");
        let profile = service
            .create_managed_browser_profile(
                CreateManagedBrowserProfile {
                    id: BrowserProfileId::from("profile-desktop-agent-held"),
                    project_id: project_id.clone(),
                    credential_reference: "keychain://desktop-continue/agent-held".into(),
                    provider: "fixture-provider".into(),
                    account_id: AccountId::from("account-desktop-agent-held"),
                    identity_digest: "1".repeat(64),
                    probe_digest: "2".repeat(64),
                },
                now + Duration::seconds(1),
            )
            .expect("profile");
        let workspace = service
            .create_browser_workspace(
                CreateBrowserWorkspace {
                    id: BrowserWorkspaceId::from("workspace-desktop-agent-held"),
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    profile_id: profile.id.clone(),
                    initial_tab_id: BrowserTabId::from("tab-desktop-agent-held"),
                    lease_id: BrowserControlLeaseId::from("lease-desktop-agent-held-1"),
                    lease_expires_at: now + Duration::hours(1),
                    evidence_digest: "3".repeat(64),
                },
                now + Duration::seconds(1),
            )
            .expect("agent-held workspace");
        assert_eq!(
            workspace.control_state,
            BrowserControlState::AgentControlled
        );
        let refused = plane.continue_browser_workspace_with(
            &secrets,
            DesktopContinueBrowserWorkspaceRequest {
                project_id: project_id.clone(),
                mission_id,
                workspace_id: workspace.id,
                expected_revision: workspace.revision,
                expected_generation: workspace.lease_generation,
            },
            now + Duration::seconds(2),
        );
        assert!(matches!(
            refused,
            Err(DesktopDataError::BrowserWorkspaceContinueNotHeld)
        ));
    }

    #[test]
    fn continue_user_held_workspace_issues_continue_browser_workspace() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(4);
        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "用户持有 lease 后 Continue 走 Application continue_browser_workspace",
                now,
            )
            .expect("mission");
        let mission_id = started.inventory.projects[0].missions[0].mission_id.clone();
        let (workspace_id, revision, generation) = persist_user_held_browser_workspace(
            &plane,
            &secrets,
            &project_id,
            &mission_id,
            now + Duration::seconds(1),
        );
        let continued = plane
            .continue_browser_workspace_with(
                &secrets,
                DesktopContinueBrowserWorkspaceRequest {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    workspace_id: workspace_id.clone(),
                    expected_revision: revision,
                    expected_generation: generation,
                },
                now + Duration::seconds(3),
            )
            .expect("Continue through Application");
        let projected = continued.inventory.projects[0]
            .missions
            .iter()
            .find(|mission| mission.mission_id == mission_id)
            .expect("continued Mission")
            .browser_workspace
            .as_ref()
            .expect("continued workspace");
        assert_eq!(projected.workspace_id, workspace_id);
        assert_eq!(
            projected.control_state,
            BrowserControlState::AgentControlled
        );
        assert_eq!(projected.revision, revision.saturating_add(1));
        assert_eq!(projected.lease_generation, generation.saturating_add(1));
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::seconds(4))
            .expect("reopen");
        let durable = service
            .load_browser_workspace(&project_id, &workspace_id)
            .expect("durable continued workspace");
        assert_eq!(durable.control_state, BrowserControlState::AgentControlled);
        assert_eq!(durable.lease_generation, generation.saturating_add(1));
        assert!(
            durable
                .agent_lease_proof(now + Duration::seconds(4))
                .is_ok()
        );
    }

    struct WindowCreatorReviewFixture {
        mission_id: MissionId,
        task_id: CreatorTaskId,
        deliverable_id: DeliverableId,
        expected_task_revision: u64,
        expected_deliverable_revision: u32,
        content_digest: String,
        acceptance_checks: Vec<AcceptanceCheck>,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "tests plant Offer through Submit via Application before this unit's Review path"
    )]
    fn persist_submitted_creator_deliverable(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> WindowCreatorReviewFixture {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, now)
            .expect("application");
        let inventory = service.desktop_inventory().expect("inventory");
        let project = inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
            .expect("ready project");
        let tenant_id = project.tenant_id.clone();
        let mission_id = MissionId::from("mission-desktop-creator-review");
        let task_id = CreatorTaskId::from("task-desktop-creator-review");
        let milestone_id = CreatorMilestoneId::from("milestone-desktop-creator-review");
        let deliverable_id = DeliverableId::from("deliverable-desktop-creator-review");
        let creator_id = CreatorId::from("creator-desktop-review");
        let connection_id = ConnectionId::from("connection-desktop-creator-review");
        let usd = CurrencyCode::parse("USD").expect("USD");
        let bounty = Money::new(5_000, usd.clone());
        service
            .start_creator_work_mission(
                StartCreatorWorkMission {
                    id: mission_id.clone(),
                    project_id: project_id.clone(),
                    task_id: TaskId::from("mission-task-desktop-creator-review"),
                    title: "Window Review Creator Deliverable".into(),
                    goal: "Accept one exact uploaded Creator Deliverable without payout".into(),
                    mode: OperatingMode::Campaign,
                },
                now,
            )
            .expect("creator work Mission");
        service
            .register_connection(
                Connection::register(
                    connection_id.clone(),
                    tenant_id.clone(),
                    project_id.clone(),
                    "stripe-connect",
                    AccountId::from("acct-desktop-creator-review"),
                    "acct-desktop-creator-review",
                    ["payout.write".into()],
                    now,
                )
                .expect("creator review connection"),
                now,
            )
            .expect("persist creator review connection");
        service
            .record_connection_probe(
                project_id,
                &connection_id,
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "acct-desktop-creator-review".into(),
                    granted_scopes: BTreeSet::from(["payout.write".into()]),
                    probed_at: now,
                    valid_until: now + Duration::days(30),
                    credential_expires_at: now + Duration::days(30),
                    evidence_digest: "3".repeat(64),
                },
                now,
            )
            .expect("creator review connection probe");
        let task = hartevo_domain_kernel::CreatorTask::create(
            CreatorTaskSpec {
                id: task_id.clone(),
                tenant_id: tenant_id.clone(),
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                creator_id: creator_id.clone(),
                hiring_award: CreatorHiringAward {
                    hiring_id: CreatorHiringId::from("hiring-desktop-creator-review"),
                    tenant_id: tenant_id.clone(),
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    creator_id: creator_id.clone(),
                    partner_id: PartnerId::from("partner-desktop-creator-review"),
                    application_id: CreatorApplicationId::from(
                        "application-desktop-creator-review",
                    ),
                    offer_digest: "1".repeat(64),
                    bounty: bounty.clone(),
                    selected_by: ActorId::from("desktop-creator-review-selector"),
                    selection_evidence_digest: "2".repeat(64),
                    selected_at: now,
                },
                title: "Exact uploaded deliverable".into(),
                brief: "Produce one reviewable Creator Deliverable".into(),
                acceptance_criteria: vec!["Matches the approved scope".into()],
                deliverable_requirements: vec!["Includes the source manifest".into()],
                bounty: bounty.clone(),
                milestones: vec![CreatorMilestoneSpec {
                    id: milestone_id.clone(),
                    title: "Reviewed delivery".into(),
                    amount: bounty.clone(),
                    due_at: now + Duration::days(7),
                }],
                revision_limit: 1,
                usage_rights: UsageRights {
                    license: "campaign review use".into(),
                    territories: vec!["US".into()],
                    channels: vec!["owned".into()],
                    exclusivity: "none".into(),
                    disclosure_required: true,
                    source_manifest_required: true,
                },
                due_at: now + Duration::days(10),
            },
            now,
        )
        .expect("creator review task");
        service
            .persist_created_creator_task(task.clone(), now)
            .expect("persist creator review task");
        service
            .publish_creator_task(
                PublishCreatorTask {
                    project_id: project_id.clone(),
                    task_id: task_id.clone(),
                    reservation: FundingReservation {
                        provider: "stripe-connect".into(),
                        external_id: "funding-desktop-creator-review".into(),
                        connection_id: connection_id.clone(),
                        payer_account_id: AccountId::from("acct-desktop-payer"),
                        amount: bounty,
                        contract_revision: task.contract_revision,
                        contract_digest: task.contract_digest(),
                        reserved_at: now + Duration::minutes(1),
                        expires_at: now + Duration::days(30),
                        request_digest: "4".repeat(64),
                        provider_receipt_digest: "5".repeat(64),
                        verification_evidence_digest: "6".repeat(64),
                    },
                },
                now + Duration::minutes(1),
            )
            .expect("publish creator review task");
        let published = service
            .load_creator_task(project_id, &task_id)
            .expect("published creator review task");
        service
            .accept_creator_task(
                &AcceptCreatorTask {
                    project_id: project_id.clone(),
                    task_id: task_id.clone(),
                    eligibility: CreatorEligibility {
                        creator_id,
                        connected_account_id: AccountId::from("acct-desktop-creator-review"),
                        connection_id,
                        kyc_verified: true,
                        payouts_enabled: true,
                        region_supported: true,
                        verified_at: now,
                        expires_at: now + Duration::days(30),
                        verification_evidence_digest: "9".repeat(64),
                    },
                    contract_digest: published.contract_digest(),
                },
                now + Duration::minutes(2),
            )
            .expect("accept creator review task");
        service
            .start_creator_work(project_id, &task_id, now + Duration::minutes(3))
            .expect("start creator review work");
        service
            .submit_creator_deliverable(
                SubmitCreatorDeliverable {
                    project_id: project_id.clone(),
                    task_id: task_id.clone(),
                    deliverable: CreatorDeliverableInput {
                        id: deliverable_id.clone(),
                        milestone_id,
                        artifact_uri: "cas://creator/desktop-review".into(),
                        media_type: "application/zip".into(),
                        size_bytes: 1_024,
                        content_digest: "7".repeat(64),
                        uploaded_at: now + Duration::minutes(4),
                        assessment: DeliverableAssessment {
                            scanner: "desktop-review-scanner".into(),
                            clean: true,
                            assessed_at: now + Duration::minutes(4),
                            evidence_digest: "8".repeat(64),
                        },
                        rights: RightsAttestation {
                            ownership_or_license: "creator original".into(),
                            source_manifest_digest: "9".repeat(64),
                            permitted_use: "campaign review use".into(),
                            verified: true,
                        },
                    },
                },
                now + Duration::minutes(4),
            )
            .expect("submit creator review deliverable");
        let submitted = service
            .load_creator_task(project_id, &task_id)
            .expect("submitted creator review task");
        WindowCreatorReviewFixture {
            mission_id,
            task_id,
            deliverable_id,
            expected_task_revision: submitted.state_revision,
            expected_deliverable_revision: 1,
            content_digest: "7".repeat(64),
            acceptance_checks: vec![
                AcceptanceCheck {
                    requirement: "Matches the approved scope".into(),
                    satisfied: true,
                    evidence: "window-scope-check".into(),
                },
                AcceptanceCheck {
                    requirement: "Includes the source manifest".into(),
                    satisfied: true,
                    evidence: "window-manifest-check".into(),
                },
            ],
        }
    }

    #[test]
    fn review_without_uploaded_deliverable_stays_empty() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(2);
        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "没有 uploaded Creator Deliverable 时 Review 必须失败关闭",
                now,
            )
            .expect("mission");
        let mission = &started.inventory.projects[0].missions[0];
        assert!(mission.creator_work.is_none());
        let refused = plane.review_creator_deliverable_with(
            &secrets,
            DesktopReviewCreatorDeliverableRequest {
                project_id: project_id.clone(),
                mission_id: mission.mission_id.clone(),
                task_id: CreatorTaskId::from("task-does-not-exist"),
                deliverable_id: DeliverableId::from("deliverable-does-not-exist"),
                expected_task_revision: 1,
                expected_deliverable_revision: 1,
                decision: ReviewDecision::Accept,
                acceptance_checks: vec![AcceptanceCheck {
                    requirement: "Matches the approved scope".into(),
                    satisfied: true,
                    evidence: "missing".into(),
                }],
            },
            now + Duration::seconds(1),
        );
        assert!(matches!(
            refused,
            Err(DesktopDataError::CreatorDeliverableReviewUnavailable)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the window Review journey asserts stale, mismatch, typed-decision, Accept, and no-payout fences together"
    )]
    fn window_review_accepts_exact_uploaded_deliverable_without_payout_or_effect() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(5);
        let fixture = persist_submitted_creator_deliverable(&plane, &secrets, &project_id, now);
        let snapshot = plane
            .load_with(&secrets, now + Duration::minutes(5))
            .expect("reload after submit");
        let DesktopLoadState::Ready(ready) = snapshot else {
            panic!("ready after submit");
        };
        let projected = ready
            .inventory
            .projects
            .iter()
            .find(|project| project.project_id == project_id)
            .expect("project")
            .missions
            .iter()
            .find(|mission| mission.mission_id == fixture.mission_id)
            .expect("creator Mission")
            .creator_work
            .as_ref()
            .expect("creator work projection");
        let reviewable = projected
            .reviewable
            .as_ref()
            .expect("reviewable deliverable");
        assert_eq!(projected.task_id, fixture.task_id);
        assert_eq!(
            projected.expected_task_revision,
            fixture.expected_task_revision
        );
        assert_eq!(reviewable.deliverable_id, fixture.deliverable_id);
        assert_eq!(reviewable.content_digest, fixture.content_digest);
        assert!(!projected.payout_verified);

        let stale = plane.review_creator_deliverable_with(
            &secrets,
            DesktopReviewCreatorDeliverableRequest {
                project_id: project_id.clone(),
                mission_id: fixture.mission_id.clone(),
                task_id: fixture.task_id.clone(),
                deliverable_id: fixture.deliverable_id.clone(),
                expected_task_revision: fixture.expected_task_revision.saturating_sub(1),
                expected_deliverable_revision: fixture.expected_deliverable_revision,
                decision: ReviewDecision::Accept,
                acceptance_checks: fixture.acceptance_checks.clone(),
            },
            now + Duration::minutes(6),
        );
        assert!(matches!(
            stale,
            Err(DesktopDataError::CreatorDeliverableReviewStale)
        ));
        let mismatched = plane.review_creator_deliverable_with(
            &secrets,
            DesktopReviewCreatorDeliverableRequest {
                project_id: project_id.clone(),
                mission_id: fixture.mission_id.clone(),
                task_id: fixture.task_id.clone(),
                deliverable_id: DeliverableId::from("deliverable-other"),
                expected_task_revision: fixture.expected_task_revision,
                expected_deliverable_revision: fixture.expected_deliverable_revision,
                decision: ReviewDecision::Accept,
                acceptance_checks: fixture.acceptance_checks.clone(),
            },
            now + Duration::minutes(6),
        );
        assert!(matches!(
            mismatched,
            Err(DesktopDataError::CreatorDeliverableReviewUnavailable)
        ));
        let reject = plane.review_creator_deliverable_with(
            &secrets,
            DesktopReviewCreatorDeliverableRequest {
                project_id: project_id.clone(),
                mission_id: fixture.mission_id.clone(),
                task_id: fixture.task_id.clone(),
                deliverable_id: fixture.deliverable_id.clone(),
                expected_task_revision: fixture.expected_task_revision,
                expected_deliverable_revision: fixture.expected_deliverable_revision,
                decision: ReviewDecision::Reject,
                acceptance_checks: fixture.acceptance_checks.clone(),
            },
            now + Duration::minutes(6),
        );
        assert!(matches!(
            reject,
            Err(DesktopDataError::InvalidCreatorDeliverableReview)
        ));

        let accepted = plane
            .review_creator_deliverable_with(
                &secrets,
                DesktopReviewCreatorDeliverableRequest {
                    project_id: project_id.clone(),
                    mission_id: fixture.mission_id.clone(),
                    task_id: fixture.task_id.clone(),
                    deliverable_id: fixture.deliverable_id.clone(),
                    expected_task_revision: fixture.expected_task_revision,
                    expected_deliverable_revision: fixture.expected_deliverable_revision,
                    decision: ReviewDecision::Accept,
                    acceptance_checks: fixture.acceptance_checks.clone(),
                },
                now + Duration::minutes(6),
            )
            .expect("window Accept through Application");
        let accepted_work = accepted
            .inventory
            .projects
            .iter()
            .find(|project| project.project_id == project_id)
            .expect("project")
            .missions
            .iter()
            .find(|mission| mission.mission_id == fixture.mission_id)
            .expect("accepted Mission")
            .creator_work
            .as_ref()
            .expect("accepted creator work");
        assert!(accepted_work.reviewable.is_none());
        assert_eq!(accepted_work.accepted_deliverable_count, 1);
        assert!(!accepted_work.payout_verified);
        assert_eq!(
            accepted_work.status,
            hartevo_domain_kernel::CreatorTaskStatus::SettlementPending
        );

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::minutes(7))
            .expect("reopen after Accept");
        let durable = service
            .load_creator_task(&project_id, &fixture.task_id)
            .expect("durable reviewed task");
        assert_eq!(
            durable
                .deliverable_entitlement(&fixture.deliverable_id)
                .expect("reviewed entitlement"),
            hartevo_domain_kernel::DeliverableEntitlementStatus::AcceptedAwaitingVerifiedPayout
        );
        assert!(durable.payouts.is_empty());
        assert!(durable.payout_authorizations.is_empty());
        let mission = service
            .load_mission(&project_id, &fixture.mission_id)
            .expect("durable Mission");
        assert!(mission.effects.is_empty());
    }

    struct WindowOpenConversationFixture {
        mission_id: MissionId,
        person_id: PersonId,
        company_id: CompanyId,
        connection_id: ConnectionId,
        account_id: AccountId,
        provider: String,
        market: String,
    }

    fn persist_openable_conversation_identity(
        plane: &DesktopDataPlane,
        secrets: &MemorySecretStore,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> WindowOpenConversationFixture {
        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (mut service, _) = plane
            .open_application_from_secret(&database_secret, now)
            .expect("application");
        let inventory = service.desktop_inventory().expect("inventory");
        let project = inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
            .expect("ready project");
        let tenant_id = project.tenant_id.clone();
        let mission_id = MissionId::from("mission-desktop-open-conversation");
        let person_id = PersonId::from("person-desktop-open-conversation");
        let company_id = CompanyId::from("company-desktop-open-conversation");
        let connection_id = ConnectionId::from("connection-desktop-open-conversation");
        let account_id = AccountId::from("gmail-account-desktop-open");
        service
            .start_relationship_mission(
                StartRelationshipMission {
                    id: mission_id.clone(),
                    project_id: project_id.clone(),
                    task_id: TaskId::from("task-desktop-open-conversation"),
                    title: "Window Open Conversation".into(),
                    goal: "Open one live CRM Conversation without Effect".into(),
                },
                now,
            )
            .expect("relationship Mission");
        service
            .create_company(
                Company::create(
                    company_id.clone(),
                    tenant_id.clone(),
                    project_id.clone(),
                    "Desktop Open Studio",
                    "DE",
                )
                .expect("company"),
                now,
            )
            .expect("persist company");
        service
            .create_person(
                Person::create(
                    person_id.clone(),
                    tenant_id.clone(),
                    project_id.clone(),
                    "Opted-in contact",
                    Some(company_id.clone()),
                    vec![],
                )
                .expect("person"),
                now,
            )
            .expect("persist person");
        service
            .register_connection(
                Connection::register(
                    connection_id.clone(),
                    tenant_id,
                    project_id.clone(),
                    "gmail",
                    account_id.clone(),
                    "opted-in@example.invalid",
                    ["messages.send".into()],
                    now,
                )
                .expect("connection"),
                now,
            )
            .expect("persist connection");
        service
            .record_connection_probe(
                project_id,
                &connection_id,
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "opted-in@example.invalid".into(),
                    granted_scopes: BTreeSet::from(["messages.send".into()]),
                    probed_at: now,
                    valid_until: now + Duration::days(30),
                    credential_expires_at: now + Duration::days(30),
                    evidence_digest: "2".repeat(64),
                },
                now,
            )
            .expect("probe connection");
        WindowOpenConversationFixture {
            mission_id,
            person_id,
            company_id,
            connection_id,
            account_id,
            provider: "gmail".into(),
            market: "DE".into(),
        }
    }

    #[test]
    fn open_conversation_without_live_identity_stays_empty() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(2);
        let started = plane
            .start_mission_with(
                &secrets,
                &project_id,
                "没有 live Person / Connection 时 Open Conversation 必须失败关闭",
                now,
            )
            .expect("mission");
        let mission = &started.inventory.projects[0].missions[0];
        assert!(mission.relationship_conversation.is_none());
        let refused = plane.open_conversation_with(
            &secrets,
            DesktopOpenConversationRequest {
                project_id: project_id.clone(),
                mission_id: mission.mission_id.clone(),
                person_id: PersonId::from("person-does-not-exist"),
                company_id: None,
                connection_id: ConnectionId::from("connection-does-not-exist"),
                account_id: AccountId::from("account-does-not-exist"),
                provider: "gmail".into(),
                gateway: MessagingGateway::Gmail,
                contact_channel: ContactChannel::Email,
                market: "DE".into(),
                route_digest: String::new(),
            },
            now + Duration::seconds(1),
        );
        assert!(matches!(
            refused,
            Err(DesktopDataError::ConversationOpenUnavailable)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the window Open Conversation journey asserts missing identity, mismatch, open, replay, and no-effect fences together"
    )]
    fn window_open_conversation_issues_application_open_conversation_without_effect() {
        let (_directory, plane, secrets, project_id) = ready_personal_fixture();
        let now = observed_at() + Duration::minutes(5);
        let fixture = persist_openable_conversation_identity(&plane, &secrets, &project_id, now);
        let snapshot = plane
            .load_with(&secrets, now + Duration::minutes(5))
            .expect("reload after identity");
        let DesktopLoadState::Ready(ready) = snapshot else {
            panic!("ready after identity");
        };
        let projected = ready
            .inventory
            .projects
            .iter()
            .find(|project| project.project_id == project_id)
            .expect("project")
            .missions
            .iter()
            .find(|mission| mission.mission_id == fixture.mission_id)
            .expect("relationship Mission")
            .relationship_conversation
            .as_ref()
            .expect("openable identity");
        assert!(projected.conversation_id.is_none());
        assert_eq!(projected.person_id, fixture.person_id);
        assert_eq!(projected.company_id.as_ref(), Some(&fixture.company_id));
        assert_eq!(projected.connection_id, fixture.connection_id);
        assert_eq!(projected.account_id, fixture.account_id);
        assert_eq!(projected.provider, fixture.provider);
        assert_eq!(projected.market, fixture.market);

        let mismatched = plane.open_conversation_with(
            &secrets,
            DesktopOpenConversationRequest {
                project_id: project_id.clone(),
                mission_id: fixture.mission_id.clone(),
                person_id: PersonId::from("person-other"),
                company_id: Some(fixture.company_id.clone()),
                connection_id: fixture.connection_id.clone(),
                account_id: fixture.account_id.clone(),
                provider: fixture.provider.clone(),
                gateway: MessagingGateway::Gmail,
                contact_channel: ContactChannel::Email,
                market: fixture.market.clone(),
                route_digest: String::new(),
            },
            now + Duration::minutes(6),
        );
        assert!(matches!(
            mismatched,
            Err(DesktopDataError::InvalidConversationOpen)
        ));

        let opened = plane
            .open_conversation_with(
                &secrets,
                DesktopOpenConversationRequest {
                    project_id: project_id.clone(),
                    mission_id: fixture.mission_id.clone(),
                    person_id: fixture.person_id.clone(),
                    company_id: Some(fixture.company_id.clone()),
                    connection_id: fixture.connection_id.clone(),
                    account_id: fixture.account_id.clone(),
                    provider: fixture.provider.clone(),
                    gateway: MessagingGateway::Gmail,
                    contact_channel: ContactChannel::Email,
                    market: fixture.market.clone(),
                    route_digest: String::new(),
                },
                now + Duration::minutes(6),
            )
            .expect("window Open Conversation through Application");
        let opened_identity = opened
            .inventory
            .projects
            .iter()
            .find(|project| project.project_id == project_id)
            .expect("project")
            .missions
            .iter()
            .find(|mission| mission.mission_id == fixture.mission_id)
            .expect("opened Mission")
            .relationship_conversation
            .as_ref()
            .expect("opened conversation");
        let conversation_id = opened_identity
            .conversation_id
            .clone()
            .expect("durable conversation id");
        assert_eq!(opened_identity.state, Some(ConversationState::Open));
        assert_eq!(opened_identity.revision, Some(1));
        assert_eq!(opened_identity.person_id, fixture.person_id);
        assert_eq!(opened_identity.connection_id, fixture.connection_id);

        let replay = plane.open_conversation_with(
            &secrets,
            DesktopOpenConversationRequest {
                project_id: project_id.clone(),
                mission_id: fixture.mission_id.clone(),
                person_id: fixture.person_id.clone(),
                company_id: Some(fixture.company_id.clone()),
                connection_id: fixture.connection_id.clone(),
                account_id: fixture.account_id.clone(),
                provider: fixture.provider.clone(),
                gateway: MessagingGateway::Gmail,
                contact_channel: ContactChannel::Email,
                market: fixture.market.clone(),
                route_digest: String::new(),
            },
            now + Duration::minutes(7),
        );
        assert!(matches!(
            replay,
            Err(DesktopDataError::ConversationAlreadyOpen)
        ));

        let database_secret = secrets
            .get(plane.database_key_reference())
            .expect("database secret");
        let (service, _) = plane
            .open_application_from_secret(&database_secret, now + Duration::minutes(8))
            .expect("reopen after Open Conversation");
        let durable = service
            .load_conversation(&project_id, &conversation_id)
            .expect("durable conversation");
        assert_eq!(durable.state, ConversationState::Open);
        assert_eq!(durable.revision, 1);
        assert!(durable.messages.is_empty());
        let mission = service
            .load_mission(&project_id, &fixture.mission_id)
            .expect("durable Mission");
        assert!(mission.effects.is_empty());
    }
}

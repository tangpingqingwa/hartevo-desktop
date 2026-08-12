use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use hartevo_application::{
    AdoptRuntimeTurnDraft, AppendMissionConversationMessage, ApplicationError,
    ApplicationMissionCheckpointExecution, ApplicationService, ConfirmHumanMissionCheckpoint,
    CreateProject, DecideVm11OutcomeReview, DesktopInventoryProjection,
    DesktopUnlockedProjectProjection, DispatchContextRuntimeTurn,
    EnsureFailedLocalMissionRuntimeGenerationRetired, ExecuteApplicationMissionCheckpoint,
    FenceOrphanedContextRuntimeTurn, InterruptContextRuntimeTurn, KeyAdministrationAuthorization,
    MissionCheckpointDispatchState, MissionRuntimeProjection, ObserveContextRuntimeTurn,
    PrepareLocalMissionRuntimeContext, ProjectContextMaterialSession, ProjectEncryptionReadiness,
    ProvisionProjectEncryption, RecoverContextWorkerRuntime, RecoverPersonalProjectDevice,
    ResearchPacket, RespondContextRuntimeLocalApproval, RetryContextWorkerRuntime,
    RuntimeTurnDispatchDisposition, StartCatalogMission, StartMission,
};
use hartevo_catalog::{
    Catalog, CatalogError, EvidenceLevel, MissionEvidenceStatus, ReleaseEvidence,
};
use hartevo_context_fabric::{ConservativeByteBudgetTokenizer, ContextAssemblyStatus};
use hartevo_domain_kernel::{
    ActorId, CurrencyCode, DeviceId, KeyManagementError, KeyRecipient, KpiContract,
    MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionConversationMessageId,
    MissionConversationMessageKind, MissionConversationRole, MissionId, MissionStage, Money,
    OperatingMode, OutcomeDecision, ProjectEncryptionMode, ProjectId, ProjectKeyring,
    RuntimeRecoveryStatus, RuntimeResumeStrategy, RuntimeTurnAttemptId, RuntimeTurnStatus,
    StorageMode, TaskId, TenantId, WorkProductId, WorkerHandleStatus,
};
use hartevo_runtime_adapter::{MappedTurnEventKind, RuntimeCommand};
use hartevo_storage::{
    ContextMaterialStoreError, DatabaseKey, KeyMaterial, OsSecretStore, ProjectStore,
    RuntimeTurnStartupReconciliation, SecretBytes, SecretReference, SecretStore, SecretStoreError,
    StorageError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::runtime_plane::{
    DesktopRuntimeAvailabilityStatus, DesktopRuntimeConfiguration, DesktopRuntimeProjection,
    discover_runtime, ensure_project_runtime_home,
};

const DATA_DIRECTORY_ENV: &str = "HARTEVO_DESKTOP_DATA_DIR";
const DATABASE_FILE_NAME: &str = "hartevo.sqlite3";
const OS_SECRET_SERVICE: &str = "com.hartevo.desktop";

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

#[cfg(test)]
type DesktopRuntimeCommandBuilder = Box<dyn FnOnce(&Path, &Path) -> RuntimeCommand>;

enum DesktopRuntimeSource {
    Pinned(Box<DesktopRuntimeConfiguration>),
    #[cfg(test)]
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
            #[cfg(test)]
            Self::Fixture { provider, .. } => provider,
        }
    }

    fn model(&self) -> &str {
        match self {
            Self::Pinned(configuration) => &configuration.model,
            #[cfg(test)]
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
            #[cfg(test)]
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
    database_path: PathBuf,
    database_key_reference: SecretReference,
    device_id: DeviceId,
}

impl DesktopDataPlane {
    pub fn discover() -> Result<Self, DesktopDataError> {
        Self::at_data_root(default_data_root()?)
    }

    pub fn at_data_root(root: impl AsRef<Path>) -> Result<Self, DesktopDataError> {
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
        Ok(Self {
            data_root,
            database_path,
            database_key_reference,
            device_id,
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

    /// Starts an explicitly confirmed VM-00..VM-11 Mission from the machine
    /// Catalog and then runs at most one bounded local Runtime turn. The
    /// Catalog binding and first Checkpoint are committed before Runtime
    /// discovery can fail; Runtime output still cannot complete the Mission.
    pub fn start_catalog_mission_and_run_os(
        &self,
        request: DesktopCatalogMissionRequest,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.start_catalog_mission_and_run_with(
            &secret_store,
            request,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            now,
        )
    }

    pub fn start_catalog_mission_and_run_cancellable_os(
        &self,
        request: DesktopCatalogMissionRequest,
        cancellation: &DesktopRuntimeCancellation,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        let secret_store = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let runtime = discover_runtime();
        self.start_catalog_mission_and_run_with_cancellation(
            &secret_store,
            request,
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            Some(cancellation),
            now,
        )
    }

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

    fn start_catalog_mission_and_run_with_cancellation(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopCatalogMissionRequest,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        cancellation: Option<&DesktopRuntimeCancellation>,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
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
        let project_id = request.project_id.clone();
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
        let (mode, parent_mission_id, market, language, audience, timezone, kpis, budget) = if vm11
        {
            let parent_mission_id = request
                .parent_mission_id
                .clone()
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
        let mission = service.start_catalog_mission(
            StartCatalogMission {
                id: MissionId::new(),
                first_task_id: TaskId::new(),
                project_id: project_id.clone(),
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
            },
            now,
        )?;
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
        self.resume_mission_runtime_with(
            &secret_store,
            project_id,
            mission_id,
            None,
            DesktopRuntimeAvailabilityStatus::NotConfigured,
            now,
        )
    }

    /// Appends one user message to the existing Catalog Mission Conversation
    /// and runs a new bounded generation for that same Mission. The message is
    /// durable before Runtime discovery or dispatch; no second Mission is
    /// created, and the Conversation command cannot change Capability authority.
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
            runtime
                .configuration
                .map(|configuration| DesktopRuntimeSource::Pinned(Box::new(configuration))),
            runtime.projection.status,
            Some(cancellation),
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
            runtime,
            availability,
            None,
            now,
        )
    }

    fn continue_mission_and_run_with_cancellation(
        &self,
        secret_store: &impl SecretStore,
        request: DesktopMissionContinuationRequest,
        runtime: Option<DesktopRuntimeSource>,
        availability: DesktopRuntimeAvailabilityStatus,
        cancellation: Option<&DesktopRuntimeCancellation>,
        now: DateTime<Utc>,
    ) -> Result<DesktopMissionSubmission, DesktopDataError> {
        if request.body.trim().is_empty() || request.idempotency_key.trim().is_empty() {
            return Err(DesktopDataError::InvalidMissionContinuation);
        }
        let project_id = request.project_id.clone();
        let mission_id = request.mission_id.clone();
        let (mut service, runtime_reconciliation, context_session) =
            self.open_ready_runtime_project(secret_store, &project_id, now)?;
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
            cancellation,
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
        if let Some(control) = cancellation {
            control.record_progress(DesktopRuntimeProgressPhase::Preparing);
        }
        let mut mission = service.load_mission(project_id, &mission_id)?;
        if mission.project_id != *project_id {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        if mission.definition.is_some() {
            let mut dispatch =
                service.dispatch_current_mission_checkpoint(project_id, &mission_id, now)?;
            if dispatch.executor == MissionCheckpointExecutor::Application {
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
                        return self.finish_mission_submission(
                            service,
                            secret_store,
                            runtime_reconciliation,
                            mission_id,
                            DesktopMissionRuntimeOutcome::ApplicationCheckpointCompleted {
                                checkpoint_id: completed_checkpoint_id,
                                evidence_digest: completion_evidence_digest,
                            },
                            now,
                        );
                    }
                    ApplicationMissionCheckpointExecution::Blocked { .. } => {
                        dispatch = service.dispatch_current_mission_checkpoint(
                            project_id,
                            &mission_id,
                            now,
                        )?;
                    }
                    ApplicationMissionCheckpointExecution::NotImplemented { dispatch: current } => {
                        return self.finish_mission_submission(
                            service,
                            secret_store,
                            runtime_reconciliation,
                            mission_id,
                            DesktopMissionRuntimeOutcome::ApplicationCheckpointNotImplemented {
                                checkpoint_id: current.checkpoint_id,
                                capability_id: current.capability_id,
                            },
                            now,
                        );
                    }
                }
            }
            if dispatch.executor != MissionCheckpointExecutor::Runtime
                || dispatch.state != MissionCheckpointDispatchState::Ready
            {
                return self.finish_mission_submission(
                    service,
                    secret_store,
                    runtime_reconciliation,
                    mission_id,
                    DesktopMissionRuntimeOutcome::CheckpointRouted {
                        checkpoint_id: dispatch.checkpoint_id,
                        capability_id: dispatch.capability_id,
                        executor: dispatch.executor,
                        oracle_ids: dispatch.oracle_ids,
                        completion_policy: dispatch.completion_policy,
                        state: dispatch.state,
                    },
                    now,
                );
            }
            mission = service.load_mission(project_id, &mission_id)?;
        }
        if mission.stage != MissionStage::Running {
            return Err(ApplicationError::LocalRuntimeMissionNotSchedulable.into());
        }
        let latest_recovery =
            service.latest_runtime_recovery_for_mission(project_id, &mission_id)?;
        let latest_turn = service.latest_runtime_turn_for_mission(project_id, &mission_id)?;
        let runtime_generation = match service.mission_conversation(project_id, &mission_id) {
            Ok(conversation) => conversation
                .messages
                .iter()
                .rev()
                .find(|message| message.role == MissionConversationRole::User)
                .map(|message| message.sequence)
                .ok_or(ApplicationError::LocalRuntimeContextScopeMismatch)?,
            Err(ApplicationError::Storage(StorageError::ScopedRecordNotFound {
                kind: "mission conversation",
                ..
            })) if mission.definition.is_none() => latest_recovery
                .as_ref()
                .map(|recovery| recovery.worker_generation)
                .into_iter()
                .chain(
                    latest_turn
                        .as_ref()
                        .map(|turn| turn.scope.worker_generation),
                )
                .max()
                .unwrap_or(1),
            Err(error) => return Err(error.into()),
        };
        if mission.definition.is_none()
            && latest_turn.as_ref().is_some_and(|turn| {
                latest_recovery.as_ref().is_none_or(|recovery| {
                    turn.scope.worker_generation > recovery.worker_generation
                })
            })
        {
            return Err(ApplicationError::LocalRuntimeContextScopeMismatch.into());
        }
        if latest_recovery
            .as_ref()
            .is_some_and(|recovery| recovery.worker_generation > runtime_generation)
            || latest_turn
                .as_ref()
                .is_some_and(|turn| turn.scope.worker_generation > runtime_generation)
        {
            return Err(ApplicationError::LocalRuntimeContextScopeMismatch.into());
        }
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
                if let Some(control) = cancellation {
                    control.record_progress(DesktopRuntimeProgressPhase::LocalActionDeclined);
                }
                logical_millis += 1;
                attempt = service.respond_context_runtime_local_approval(
                    &mut managed,
                    &RespondContextRuntimeLocalApproval {
                        project_id: project_id.clone(),
                        id: turn_id.clone(),
                        expected_revision: attempt.revision,
                        request,
                        approved: false,
                    },
                    now + Duration::milliseconds(logical_millis),
                )?;
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

    fn open_application_from_secret(
        &self,
        secret: &hartevo_storage::SecretBytes,
        now: DateTime<Utc>,
    ) -> Result<(ApplicationService, RuntimeTurnStartupReconciliation), DesktopDataError> {
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
        let database_key = DatabaseKey::from_secret(secret)?;
        let store = ProjectStore::open(&self.database_path, &database_key)?;
        Ok(ApplicationService::new(store))
    }

    fn revalidate_database_entry(&self) -> Result<(), DesktopDataError> {
        reject_symlink(&self.data_root)?;
        reject_symlink(&self.database_path)
    }

    fn create_project_root(&self, project_id: &ProjectId) -> Result<PathBuf, DesktopDataError> {
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
        CreateProject, EvidenceInput, ProvisionProjectEncryption, ResearchPacket,
        StartRelationshipMission,
    };
    use hartevo_domain_kernel::{
        AccountId, ActorId, Connection, ConnectionId, ConnectionProbe, ContextBranchStatus,
        ContextCapsuleStatus, EvidenceId, ExternalIdentity, IdentityLink, IdentityLinkId,
        IdentitySubject, KeyRecipient, KpiDirection, MissionCheckpointExecutor,
        MissionScheduleStatus, MissionStage, OrderId, OutcomeDecision, OutcomeEvent,
        OutcomeEventId, OutcomeEventKind, OutcomeSourceVerification, OutcomeVerificationMethod,
        Person, PersonId, ProbeOutcome, ProjectEncryptionMode, StorageMode, TaskId, TaskStatus,
        WorkProductId, WorkerLeaseStatus,
    };
    use hartevo_storage::MemorySecretStore;
    use rust_decimal::Decimal;

    use super::*;

    fn observed_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-11T10:00:00Z")
            .expect("valid fixture time")
            .with_timezone(&Utc)
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
    fn runtime_fixture_completion_messages() -> [String; 6] {
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
                "id": "desktop-fixture-local-approval",
                "method": "item/fileChange/requestApproval",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "itemId": "desktop-fixture-item",
                    "path": "must-not-be-written.txt",
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
            approval_request,
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
IFS= read -r decision
case "$decision" in *'"id":"desktop-fixture-local-approval"'*'"decision":"decline"'*) ;; *) exit 34 ;; esac
printf '%s\n' "$9"
printf '%s\n' "${10}"
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
        reason = "the Desktop data-plane Journey proves seven deterministic Application handlers, honest empty-ledger blocking, source-verified KPI/attribution/settlement/review recovery, atomic Human next-route handoff, and zero Runtime construction"
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
                    mission_id: parent_mission_id,
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
            Some(hartevo_application::ApplicationCheckpointHandlerStatus::NotImplemented)
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
            .continue_mission_and_run_with(
                &secrets,
                request.clone(),
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
            .continue_mission_and_run_with(
                &secrets,
                request,
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

        let swapped = plane.continue_mission_and_run_with(
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
        let continued = plane
            .continue_mission_and_run_with(
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
            .continue_mission_and_run_with(
                &secrets,
                request.clone(),
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
            .continue_mission_and_run_with(
                &secrets,
                request,
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
}

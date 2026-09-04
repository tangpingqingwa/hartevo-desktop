//! Feature-gated native proof harness for the Desktop Runtime paint contract.
//!
//! This module is deliberately absent from normal Desktop builds. It opens a
//! real local SQLCipher store, launches a real Dioxus desktop window, and runs
//! the production Runtime adapter against a bounded subprocess implemented by
//! the same signed build artifact. Its receipt is content-free: it proves
//! ordering and durable state transitions, not the private Runtime text or an
//! operating-system compositor/accessibility result.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration as StdDuration, Instant};

use chrono::Utc;
use dioxus::prelude::*;
use hartevo_application::{ApplicationError, RuntimeTextSubscriptionBatch};
use hartevo_domain_kernel::{
    KpiContract, KpiDirection, MissionId, OperatingMode, ProjectId, RuntimeTurnStatus,
    WorkProductStatus,
};
use hartevo_runtime_adapter::RuntimeCommand;
use hartevo_storage::MemorySecretStore;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::data_plane::{
    DesktopCatalogMissionRequest, DesktopDataError, DesktopDataPlane, DesktopLoadState,
    DesktopMissionSubmission, DesktopRuntimeSource, DesktopRuntimeTextStreamProjection,
    DesktopWorkProductAdoptionRequest, RecoveryKitDraft,
};
use crate::result_adoption_surface::{
    ResultBinding, ResultSurfaceAction, SelectedResultProjection,
    action_matches_current_projection, selected_result_projection,
};
use crate::runtime_subscription::{
    DESKTOP_RUNTIME_SUBSCRIPTION_PAGE_SIZE, DesktopRuntimeCommandIdentity,
    DesktopRuntimeCompletionDisposition, DesktopRuntimeDelivery, DesktopRuntimeExecutionLaunch,
    DesktopRuntimeExecutionPaintState, DesktopRuntimePaintCommit, DesktopRuntimeReducerEffect,
    DesktopRuntimeSelection, DesktopRuntimeSelectionChange, DesktopRuntimeStopDisposition,
};

const REQUEST_ENV: &str = "HARTEVO_NATIVE_RUNTIME_JOURNEY";
const ROOT_ENV: &str = "HARTEVO_NATIVE_RUNTIME_JOURNEY_ROOT";
const RECEIPT_ENV: &str = "HARTEVO_NATIVE_RUNTIME_JOURNEY_RECEIPT";
const CONTROLLED_RUNTIME_ARG: &str = "--hartevo-native-journey-runtime";
const CONTROL_ROOT_ARG: &str = "--control-root";
const RUNTIME_HOME_ARG: &str = "--runtime-home";
const RUNTIME_WAIT_LIMIT: StdDuration = StdDuration::from_mins(1);
const JOURNEY_WAIT_LIMIT: StdDuration = StdDuration::from_mins(2);
const JOURNEY_POLL_INTERVAL: StdDuration = StdDuration::from_millis(80);
const SCHEMA_VERSION: &str = "b2-native-runtime-journey/v1";

static PREPARED_JOURNEY: OnceLock<Mutex<Option<PreparedNativeJourney>>> = OnceLock::new();

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NativeJourneyError {
    code: &'static str,
}

impl NativeJourneyError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Debug for NativeJourneyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeJourneyError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for NativeJourneyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for NativeJourneyError {}

#[derive(Clone)]
struct NativeJourneyConfig {
    root: PathBuf,
    data_root: PathBuf,
    control_root: PathBuf,
    receipt_path: PathBuf,
}

impl NativeJourneyConfig {
    fn from_environment() -> Result<Self, NativeJourneyError> {
        let root = env::var_os(ROOT_ENV)
            .map(PathBuf::from)
            .ok_or(NativeJourneyError::new("NATIVE_ROOT_REQUIRED"))?;
        let receipt_path = env::var_os(RECEIPT_ENV)
            .map(PathBuf::from)
            .ok_or(NativeJourneyError::new("NATIVE_RECEIPT_REQUIRED"))?;
        if !root.is_absolute() || !receipt_path.is_absolute() {
            return Err(NativeJourneyError::new("NATIVE_PATH_NOT_ABSOLUTE"));
        }
        fs::create_dir_all(&root)
            .map_err(|_| NativeJourneyError::new("NATIVE_ROOT_UNAVAILABLE"))?;
        let root = root
            .canonicalize()
            .map_err(|_| NativeJourneyError::new("NATIVE_ROOT_UNAVAILABLE"))?;
        let receipt_parent = receipt_path
            .parent()
            .ok_or(NativeJourneyError::new("NATIVE_RECEIPT_INVALID"))?;
        fs::create_dir_all(receipt_parent)
            .map_err(|_| NativeJourneyError::new("NATIVE_RECEIPT_UNAVAILABLE"))?;
        let receipt_parent = receipt_parent
            .canonicalize()
            .map_err(|_| NativeJourneyError::new("NATIVE_RECEIPT_UNAVAILABLE"))?;
        if !receipt_parent.starts_with(&root) {
            return Err(NativeJourneyError::new("NATIVE_RECEIPT_OUTSIDE_ROOT"));
        }
        let receipt_name = receipt_path
            .file_name()
            .ok_or(NativeJourneyError::new("NATIVE_RECEIPT_INVALID"))?;
        let receipt_path = receipt_parent.join(receipt_name);
        let data_root = root.join("sqlcipher-data");
        let control_root = root.join("runtime-control");
        fs::create_dir_all(&control_root)
            .map_err(|_| NativeJourneyError::new("NATIVE_CONTROL_UNAVAILABLE"))?;
        let control_root = control_root
            .canonicalize()
            .map_err(|_| NativeJourneyError::new("NATIVE_CONTROL_UNAVAILABLE"))?;
        Ok(Self {
            root,
            data_root,
            control_root,
            receipt_path,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum NativeJourneyEventKind {
    SqlcipherReady,
    CatalogStartCommitted,
    AwaitingRenderCommitted,
    PostRenderAcknowledged,
    RuntimeResumeDispatched,
    FirstDeltaObserved,
    RunningCaughtUp,
    OffscreenReselectIsolated,
    StaleEpochRejected,
    LateDeltaObserved,
    RuntimeReturned,
    TerminalObserved,
    FinalCaughtUp,
    RuntimeCommandReleased,
    SelectedResultProjected,
    AdoptionIntentBound,
    AdoptionReceiptCommitted,
    StaleAdoptionRejected,
    StopMissionAwaitingRendered,
    StopBeforeResumeIsolated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeJourneyTimelineEvent {
    sequence: u64,
    elapsed_millis: u64,
    kind: NativeJourneyEventKind,
    delta_count: usize,
    turn_status: Option<&'static str>,
    transport_caught_up: bool,
    scope_visible: bool,
    awaiting_snapshot_handle_bound: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeJourneyTimeline {
    events: Vec<NativeJourneyTimelineEvent>,
    replay_digest: String,
}

#[derive(Debug)]
struct NativeTimelineRecorder {
    started_at: Instant,
    events: Vec<NativeJourneyTimelineEvent>,
}

impl NativeTimelineRecorder {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            events: Vec::new(),
        }
    }

    fn record(
        &mut self,
        kind: NativeJourneyEventKind,
        delta_count: usize,
        turn_status: Option<RuntimeTurnStatus>,
        transport_caught_up: bool,
        scope_visible: bool,
        awaiting_snapshot_handle_bound: bool,
    ) -> Result<(), NativeJourneyError> {
        let sequence = u64::try_from(self.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(NativeJourneyError::new("NATIVE_TIMELINE_OVERFLOW"))?;
        let elapsed_millis = u64::try_from(self.started_at.elapsed().as_millis())
            .map_err(|_| NativeJourneyError::new("NATIVE_TIMELINE_OVERFLOW"))?;
        self.events.push(NativeJourneyTimelineEvent {
            sequence,
            elapsed_millis,
            kind,
            delta_count,
            turn_status: turn_status.map(runtime_status_label),
            transport_caught_up,
            scope_visible,
            awaiting_snapshot_handle_bound,
        });
        Ok(())
    }

    fn finish(&self) -> Result<NativeJourneyTimeline, NativeJourneyError> {
        verify_timeline(&self.events)?;
        let mut hasher = Sha256::new();
        hasher.update(b"hartevo.native-runtime-journey.timeline.v1\0");
        for event in &self.events {
            hash_timeline_field(&mut hasher, format!("{:?}", event.kind).as_bytes());
            hash_timeline_field(&mut hasher, &event.delta_count.to_le_bytes());
            hash_timeline_field(&mut hasher, event.turn_status.unwrap_or("none").as_bytes());
            hash_timeline_field(&mut hasher, &[u8::from(event.transport_caught_up)]);
            hash_timeline_field(&mut hasher, &[u8::from(event.scope_visible)]);
            hash_timeline_field(
                &mut hasher,
                &[u8::from(event.awaiting_snapshot_handle_bound)],
            );
        }
        Ok(NativeJourneyTimeline {
            events: self.events.clone(),
            replay_digest: hex::encode(hasher.finalize()),
        })
    }
}

fn hash_timeline_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn verify_timeline(events: &[NativeJourneyTimelineEvent]) -> Result<(), NativeJourneyError> {
    if events.windows(2).any(|pair| {
        pair[0].sequence >= pair[1].sequence || pair[0].elapsed_millis > pair[1].elapsed_millis
    }) {
        return Err(NativeJourneyError::new("NATIVE_TIMELINE_NOT_MONOTONIC"));
    }
    let required = [
        NativeJourneyEventKind::SqlcipherReady,
        NativeJourneyEventKind::CatalogStartCommitted,
        NativeJourneyEventKind::AwaitingRenderCommitted,
        NativeJourneyEventKind::PostRenderAcknowledged,
        NativeJourneyEventKind::RuntimeResumeDispatched,
        NativeJourneyEventKind::FirstDeltaObserved,
        NativeJourneyEventKind::RunningCaughtUp,
        NativeJourneyEventKind::OffscreenReselectIsolated,
        NativeJourneyEventKind::StaleEpochRejected,
        NativeJourneyEventKind::LateDeltaObserved,
        NativeJourneyEventKind::TerminalObserved,
        NativeJourneyEventKind::FinalCaughtUp,
        NativeJourneyEventKind::RuntimeCommandReleased,
        NativeJourneyEventKind::SelectedResultProjected,
        NativeJourneyEventKind::AdoptionIntentBound,
        NativeJourneyEventKind::AdoptionReceiptCommitted,
        NativeJourneyEventKind::StaleAdoptionRejected,
        NativeJourneyEventKind::StopMissionAwaitingRendered,
        NativeJourneyEventKind::StopBeforeResumeIsolated,
    ];
    let mut cursor = 0_usize;
    for required_kind in required {
        let Some(offset) = events[cursor..]
            .iter()
            .position(|event| event.kind == required_kind)
        else {
            return Err(NativeJourneyError::new("NATIVE_TIMELINE_INCOMPLETE"));
        };
        cursor = cursor
            .checked_add(offset)
            .and_then(|value| value.checked_add(1))
            .ok_or(NativeJourneyError::new("NATIVE_TIMELINE_OVERFLOW"))?;
    }
    if events
        .iter()
        .filter(|event| event.kind == NativeJourneyEventKind::RuntimeResumeDispatched)
        .count()
        != 1
    {
        return Err(NativeJourneyError::new("NATIVE_RESUME_COUNT_MISMATCH"));
    }
    let awaiting = events
        .iter()
        .find(|event| event.kind == NativeJourneyEventKind::AwaitingRenderCommitted)
        .ok_or(NativeJourneyError::new("NATIVE_AWAITING_PAINT_MISSING"))?;
    if !awaiting.awaiting_snapshot_handle_bound {
        return Err(NativeJourneyError::new(
            "NATIVE_AWAITING_SNAPSHOT_HANDLE_UNBOUND",
        ));
    }
    let returned = events
        .iter()
        .position(|event| event.kind == NativeJourneyEventKind::RuntimeReturned)
        .ok_or(NativeJourneyError::new("NATIVE_RUNTIME_RETURN_MISSING"))?;
    let released = events
        .iter()
        .position(|event| event.kind == NativeJourneyEventKind::RuntimeCommandReleased)
        .ok_or(NativeJourneyError::new("NATIVE_RUNTIME_RELEASE_MISSING"))?;
    if returned >= released {
        return Err(NativeJourneyError::new(
            "NATIVE_RUNTIME_RELEASE_ORDER_INVALID",
        ));
    }
    Ok(())
}

const fn runtime_status_label(status: RuntimeTurnStatus) -> &'static str {
    match status {
        RuntimeTurnStatus::Prepared => "prepared",
        RuntimeTurnStatus::Dispatching => "dispatching",
        RuntimeTurnStatus::Running => "running",
        RuntimeTurnStatus::WaitingLocalApproval => "waiting_local_approval",
        RuntimeTurnStatus::ApprovalResponding => "approval_responding",
        RuntimeTurnStatus::InterruptRequested => "interrupt_requested",
        RuntimeTurnStatus::Completed => "completed",
        RuntimeTurnStatus::Interrupted => "interrupted",
        RuntimeTurnStatus::Failed => "failed",
        RuntimeTurnStatus::Uncertain => "uncertain",
    }
}

type NativeJourneyAssertions = BTreeMap<&'static str, bool>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeJourneyBoundaries {
    proven: Vec<&'static str>,
    not_proven: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeSelectedResultReceipt {
    binding_digest: String,
    expected_mission_revision: u64,
    expected_result_revision: u64,
    expected_manifest_version: u64,
    adopted_mission_revision: u64,
    adopted_result_revision: u64,
    adopted_manifest_version: u64,
    adopted_status: &'static str,
    adoption_receipt_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeAdoptionRevisions {
    expected_mission_revision: u64,
    expected_result_revision: u64,
    expected_manifest_version: u64,
    adopted_mission_revision: u64,
    adopted_result_revision: u64,
    adopted_manifest_version: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeJourneyReceipt {
    schema_version: &'static str,
    journey_id: &'static str,
    status: &'static str,
    failure_code: Option<&'static str>,
    boundaries: NativeJourneyBoundaries,
    assertions: NativeJourneyAssertions,
    timeline: Option<NativeJourneyTimeline>,
    selected_result: Option<NativeSelectedResultReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeJourneyPhase {
    MainAwaitingRender,
    MainRunning,
    StopAwaitingRender,
    Finalizing,
    Passed,
    Failed,
}

impl NativeJourneyPhase {
    const fn label(self) -> &'static str {
        match self {
            Self::MainAwaitingRender => "AWAITING_RENDER_COMMIT",
            Self::MainRunning => "RUNTIME_DURABLE_PULL",
            Self::StopAwaitingRender => "STOP_BEFORE_RESUME",
            Self::Finalizing => "VERIFYING_RECEIPT",
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Passed | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativeJourneyDisplay {
    delta_count: usize,
    turn_status: Option<RuntimeTurnStatus>,
    transport_caught_up: bool,
    scope_visible: bool,
    awaiting_snapshot_handle_bound: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum NativeAdoptionPhase {
    #[default]
    NotStarted,
    Projected,
    IntentBound,
    ReceiptCommitted,
    StaleRejected,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeAdoptionState {
    phase: NativeAdoptionPhase,
    receipt: Option<NativeSelectedResultReceipt>,
}

#[derive(Clone, Eq, PartialEq)]
struct PrivateStreamFingerprint {
    digest: [u8; 32],
    delta_count: usize,
    item_count: usize,
    turn_status: RuntimeTurnStatus,
}

impl fmt::Debug for PrivateStreamFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateStreamFingerprint")
            .field("delta_count", &self.delta_count)
            .field("item_count", &self.item_count)
            .field("turn_status", &self.turn_status)
            .finish_non_exhaustive()
    }
}

struct NativeJourneyContext {
    config: NativeJourneyConfig,
    plane: DesktopDataPlane,
    secrets: Arc<MemorySecretStore>,
    project_id: ProjectId,
    main_mission_id: MissionId,
    alternate_mission_id: MissionId,
    sqlcipher_encrypted: bool,
    start_snapshot_bound: bool,
    timeline: Mutex<NativeTimelineRecorder>,
    completed_stream: Mutex<Option<PrivateStreamFingerprint>>,
}

impl fmt::Debug for NativeJourneyContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeJourneyContext")
            .field("sqlcipher_encrypted", &self.sqlcipher_encrypted)
            .field("start_snapshot_bound", &self.start_snapshot_bound)
            .finish_non_exhaustive()
    }
}

struct PreparedNativeJourney {
    context: Arc<NativeJourneyContext>,
    paint: DesktopRuntimeExecutionPaintState,
    main_commit: DesktopRuntimePaintCommit,
}

struct NativeJourneyUiState {
    context: Arc<NativeJourneyContext>,
    paint: DesktopRuntimeExecutionPaintState,
    pending_commit: Option<DesktopRuntimePaintCommit>,
    phase: NativeJourneyPhase,
    display: NativeJourneyDisplay,
    resume_count: usize,
    reselect_isolated: bool,
    stale_epoch_rejected: bool,
    stop_before_resume_isolated: bool,
    adoption: NativeAdoptionState,
}

impl NativeJourneyUiState {
    fn from_prepared(prepared: PreparedNativeJourney) -> Self {
        Self {
            context: prepared.context,
            paint: prepared.paint,
            pending_commit: Some(prepared.main_commit),
            phase: NativeJourneyPhase::MainAwaitingRender,
            display: NativeJourneyDisplay {
                scope_visible: true,
                ..NativeJourneyDisplay::default()
            },
            resume_count: 0,
            reselect_isolated: false,
            stale_epoch_rejected: false,
            stop_before_resume_isolated: false,
            adoption: NativeAdoptionState::default(),
        }
    }

    fn awaiting_snapshot_handle_bound(&self) -> bool {
        self.context.start_snapshot_bound
            && self.pending_commit.as_ref().is_some_and(|commit| {
                let scope = &commit.selection().scope;
                scope.project_id() == &self.context.project_id
                    && scope.mission_id() == &self.context.main_mission_id
                    && self
                        .paint
                        .paint_view(scope.project_id(), scope.mission_id())
                        .is_some_and(|view| view.awaiting_turn() && view.stream().is_none())
            })
    }
}

pub fn is_requested() -> bool {
    env::var(REQUEST_ENV).is_ok_and(|value| value == "1")
}

pub fn launch() -> Result<(), NativeJourneyError> {
    let config = NativeJourneyConfig::from_environment()?;
    let prepared = prepare_native_journey(config)?;
    PREPARED_JOURNEY
        .set(Mutex::new(Some(prepared)))
        .map_err(|_| NativeJourneyError::new("NATIVE_JOURNEY_ALREADY_PREPARED"))?;
    let window = dioxus::desktop::WindowBuilder::new()
        .with_title("Hartevo B2 Native Runtime Journey")
        .with_inner_size(dioxus::desktop::LogicalSize::new(1024.0, 768.0))
        .with_visible(true);
    dioxus::LaunchBuilder::new()
        .with_cfg(dioxus::desktop::Config::new().with_window(window))
        .launch(NativeRuntimeJourneyApp);
    Ok(())
}

fn take_prepared_journey() -> PreparedNativeJourney {
    PREPARED_JOURNEY
        .get()
        .and_then(|slot| slot.lock().ok())
        .and_then(|mut slot| slot.take())
        .unwrap_or_else(|| panic!("native journey seed missing"))
}

fn prepare_native_journey(
    config: NativeJourneyConfig,
) -> Result<PreparedNativeJourney, NativeJourneyError> {
    let plane = DesktopDataPlane::at_data_root(&config.data_root)
        .map_err(|_| NativeJourneyError::new("NATIVE_SQLCIPHER_ROOT_FAILED"))?;
    let secrets = Arc::new(MemorySecretStore::default());
    let now = Utc::now();
    plane
        .initialize_with(secrets.as_ref(), now)
        .map_err(|_| NativeJourneyError::new("NATIVE_SQLCIPHER_INIT_FAILED"))?;
    let recovery = RecoveryKitDraft::generate()
        .map_err(|_| NativeJourneyError::new("NATIVE_RECOVERY_KIT_FAILED"))?;
    let created = plane
        .create_personal_project_with(
            secrets.as_ref(),
            "B2 native Runtime journey",
            "Verify durable render ordering without external effects",
            recovery.expose_for_user_export(),
            Utc::now(),
        )
        .map_err(|_| NativeJourneyError::new("NATIVE_PROJECT_SETUP_FAILED"))?;
    let project = created
        .inventory
        .projects
        .first()
        .ok_or(NativeJourneyError::new("NATIVE_PROJECT_PROJECTION_MISSING"))?;
    let project_id = project.project_id.clone();
    let alternate_mission_id = project
        .missions
        .first()
        .map(|mission| mission.mission_id.clone())
        .ok_or(NativeJourneyError::new("NATIVE_INITIAL_MISSION_MISSING"))?;
    let started = plane
        .start_catalog_mission_execution_native(
            secrets.as_ref(),
            catalog_request(&project_id, "Native Runtime complete journey"),
            Utc::now(),
        )
        .map_err(|_| NativeJourneyError::new("NATIVE_CATALOG_START_FAILED"))?;
    let main_mission_id = started.handle.mission_id().clone();
    if main_mission_id == alternate_mission_id {
        return Err(NativeJourneyError::new("NATIVE_SCOPE_FIXTURE_INVALID"));
    }
    let start_snapshot_bound = started.snapshot.inventory.projects.iter().any(|project| {
        project.project_id == project_id
            && project
                .missions
                .iter()
                .any(|mission| mission.mission_id == main_mission_id)
    });
    if !start_snapshot_bound {
        return Err(NativeJourneyError::new(
            "NATIVE_START_SNAPSHOT_SCOPE_MISSING",
        ));
    }
    let sqlcipher_encrypted =
        sqlcipher_header_is_encrypted(&config.data_root.join("hartevo.sqlite3"))?;
    if !sqlcipher_encrypted {
        return Err(NativeJourneyError::new("NATIVE_SQLCIPHER_PLAINTEXT_HEADER"));
    }
    let mut paint = DesktopRuntimeExecutionPaintState::default();
    let main_commit = paint
        .commit_catalog_start(started.handle.clone())
        .map_err(|_| NativeJourneyError::new("NATIVE_AWAITING_PREPARE_FAILED"))?;
    let context = Arc::new(NativeJourneyContext {
        config,
        plane,
        secrets,
        project_id,
        main_mission_id,
        alternate_mission_id,
        sqlcipher_encrypted,
        start_snapshot_bound,
        timeline: Mutex::new(NativeTimelineRecorder::new()),
        completed_stream: Mutex::new(None),
    });
    record_context_event(
        &context,
        NativeJourneyEventKind::SqlcipherReady,
        NativeJourneyDisplay::default(),
    )?;
    record_context_event(
        &context,
        NativeJourneyEventKind::CatalogStartCommitted,
        NativeJourneyDisplay::default(),
    )?;
    Ok(PreparedNativeJourney {
        context,
        paint,
        main_commit,
    })
}

fn sqlcipher_header_is_encrypted(database_path: &Path) -> Result<bool, NativeJourneyError> {
    let bytes = fs::read(database_path)
        .map_err(|_| NativeJourneyError::new("NATIVE_SQLCIPHER_READ_FAILED"))?;
    Ok(bytes.len() >= 16 && &bytes[..16] != b"SQLite format 3\0")
}

fn catalog_request(project_id: &ProjectId, title: &str) -> DesktopCatalogMissionRequest {
    DesktopCatalogMissionRequest {
        project_id: project_id.clone(),
        manifest_id: "VM-04".into(),
        mode: OperatingMode::Campaign,
        parent_mission_id: None,
        title: Some(title.into()),
        goal: "Verify bounded local Runtime streaming and retain reviewable output".into(),
        market: "DE".into(),
        language: "de-DE".into(),
        audience: "operator".into(),
        timezone: "Europe/Berlin".into(),
        kpis: BTreeMap::from([(
            "lead_qualified_count".into(),
            KpiContract {
                baseline: Some(Decimal::ZERO),
                target: Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            },
        )]),
        budget_minor: 0,
        currency: "EUR".into(),
    }
}

#[component]
fn NativeRuntimeJourneyApp() -> Element {
    let desktop = dioxus::desktop::use_window();
    let mut journey = use_signal(|| NativeJourneyUiState::from_prepared(take_prepared_journey()));
    use_effect(move || {
        let phase = journey.read().phase;
        if phase.is_terminal() {
            desktop.close();
            return;
        }
        match phase {
            NativeJourneyPhase::MainAwaitingRender => {
                let launch = acknowledge_main_render(&mut journey);
                match launch {
                    Ok(launch) => {
                        spawn(run_complete_runtime_journey(journey, launch));
                    }
                    Err(error) => fail_journey(&mut journey, error),
                }
            }
            NativeJourneyPhase::StopAwaitingRender => {
                if let Err(error) = acknowledge_stop_render(&mut journey) {
                    fail_journey(&mut journey, error);
                } else {
                    spawn(finalize_native_journey(journey));
                }
            }
            NativeJourneyPhase::MainRunning
            | NativeJourneyPhase::Finalizing
            | NativeJourneyPhase::Passed
            | NativeJourneyPhase::Failed => {}
        }
    });
    let state = journey.read();
    let phase = state.phase.label();
    let delta_count = state.display.delta_count.to_string();
    let turn_status = state
        .display
        .turn_status
        .map_or("none", runtime_status_label);
    let caught_up = state.display.transport_caught_up.to_string();
    let scope_visible = state.display.scope_visible.to_string();
    let resume_count = state.resume_count.to_string();
    let awaiting_snapshot_handle_bound = state.awaiting_snapshot_handle_bound().to_string();
    rsx! {
        main {
            id: "b2-native-runtime-journey",
            "data-phase": phase,
            "data-delta-count": delta_count,
            "data-turn-status": turn_status,
            "data-transport-caught-up": caught_up,
            "data-scope-visible": scope_visible,
            "data-resume-count": resume_count,
            "data-awaiting-snapshot-handle-bound": awaiting_snapshot_handle_bound,
            h1 { "Hartevo Runtime journey verification" }
            p { "Content-free native harness · no Provider Effect" }
            output { id: "native-journey-phase", "{phase}" }
        }
    }
}

fn acknowledge_main_render(
    journey: &mut Signal<NativeJourneyUiState>,
) -> Result<DesktopRuntimeExecutionLaunch, NativeJourneyError> {
    let context = journey.read().context.clone();
    let mut display = journey.read().display;
    display.awaiting_snapshot_handle_bound = journey.read().awaiting_snapshot_handle_bound();
    if !display.awaiting_snapshot_handle_bound {
        return Err(NativeJourneyError::new(
            "NATIVE_AWAITING_SNAPSHOT_HANDLE_UNBOUND",
        ));
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::AwaitingRenderCommitted,
        display,
    )?;
    let launch = {
        let mut state = journey.write();
        let commit = state
            .pending_commit
            .take()
            .ok_or(NativeJourneyError::new("NATIVE_PAINT_COMMIT_MISSING"))?;
        let scope = &commit.selection().scope;
        let view = state
            .paint
            .paint_view(scope.project_id(), scope.mission_id())
            .ok_or(NativeJourneyError::new("NATIVE_AWAITING_VIEW_MISSING"))?;
        if !view.awaiting_turn() || view.stream().is_some() || state.resume_count != 0 {
            return Err(NativeJourneyError::new("NATIVE_AWAITING_VIEW_INVALID"));
        }
        let launch = state
            .paint
            .acknowledge_rendered_paint(&commit)
            .map_err(|_| NativeJourneyError::new("NATIVE_PAINT_ACK_FAILED"))?;
        state.resume_count = state
            .resume_count
            .checked_add(1)
            .ok_or(NativeJourneyError::new("NATIVE_RESUME_COUNT_OVERFLOW"))?;
        state.phase = NativeJourneyPhase::MainRunning;
        launch
    };
    record_context_event(
        &context,
        NativeJourneyEventKind::PostRenderAcknowledged,
        display,
    )?;
    record_context_event(
        &context,
        NativeJourneyEventKind::RuntimeResumeDispatched,
        display,
    )?;
    Ok(launch)
}

async fn run_complete_runtime_journey(
    mut journey: Signal<NativeJourneyUiState>,
    launch: DesktopRuntimeExecutionLaunch,
) {
    let result = run_complete_runtime_journey_inner(&mut journey, launch).await;
    if let Err(error) = result {
        fail_journey(&mut journey, error);
    }
}

type NativeRuntimeResult = Result<DesktopMissionSubmission, crate::data_plane::DesktopDataError>;
type NativeRuntimeTask = tokio::task::JoinHandle<NativeRuntimeResult>;

struct NativeRuntimeDrive {
    started_at: Instant,
    runtime_task: Option<NativeRuntimeTask>,
    runtime_result: Option<NativeRuntimeResult>,
    observed: BTreeSet<NativeJourneyEventKind>,
    current_selection: DesktopRuntimeSelection,
}

impl NativeRuntimeDrive {
    fn new(runtime_task: NativeRuntimeTask, selection: DesktopRuntimeSelection) -> Self {
        Self {
            started_at: Instant::now(),
            runtime_task: Some(runtime_task),
            runtime_result: None,
            observed: BTreeSet::new(),
            current_selection: selection,
        }
    }

    async fn observe_runtime_return(
        &mut self,
        journey: &mut Signal<NativeJourneyUiState>,
        identity: &DesktopRuntimeCommandIdentity,
        context: &NativeJourneyContext,
    ) -> Result<(), NativeJourneyError> {
        if self.runtime_result.is_some()
            || self
                .runtime_task
                .as_ref()
                .is_none_or(|task| !task.is_finished())
        {
            return Ok(());
        }
        let task = self
            .runtime_task
            .take()
            .ok_or(NativeJourneyError::new("NATIVE_RUNTIME_TASK_MISSING"))?;
        let result = task
            .await
            .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_TASK_FAILED"))?;
        if !journey
            .write()
            .paint
            .mark_runtime_returned(identity)
            .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_RETURN_REJECTED"))?
        {
            return Err(NativeJourneyError::new("NATIVE_RUNTIME_RETURN_STALE"));
        }
        self.runtime_result = Some(result);
        record_context_event(
            context,
            NativeJourneyEventKind::RuntimeReturned,
            journey.read().display,
        )
    }

    fn refresh_selection(
        &mut self,
        journey: &Signal<NativeJourneyUiState>,
        identity: &DesktopRuntimeCommandIdentity,
    ) {
        if let Some(selection) = journey.read().paint.current_selection_for_command(identity) {
            self.current_selection = selection;
        }
    }

    fn observe_delivery(
        &mut self,
        journey: &mut Signal<NativeJourneyUiState>,
        identity: &DesktopRuntimeCommandIdentity,
        observation: &NativePullObservation,
        context: &NativeJourneyContext,
    ) -> Result<(), NativeJourneyError> {
        let display = observation.display;
        self.record_once(
            context,
            NativeJourneyEventKind::FirstDeltaObserved,
            display.delta_count >= 1,
            display,
        )?;
        let first_running_caught_up = display.turn_status == Some(RuntimeTurnStatus::Running)
            && display.transport_caught_up
            && display.delta_count == 1
            && !self
                .observed
                .contains(&NativeJourneyEventKind::RunningCaughtUp);
        if first_running_caught_up {
            self.record_once(
                context,
                NativeJourneyEventKind::RunningCaughtUp,
                true,
                display,
            )?;
            exercise_offscreen_reselect(journey, identity, &observation.delivery, context)?;
            release_control_marker(&context.config.control_root, "release-late")?;
        }
        let first_late_delta = display.turn_status == Some(RuntimeTurnStatus::Running)
            && display.delta_count >= 2
            && !self
                .observed
                .contains(&NativeJourneyEventKind::LateDeltaObserved);
        if first_late_delta {
            self.record_once(
                context,
                NativeJourneyEventKind::LateDeltaObserved,
                true,
                display,
            )?;
            release_control_marker(&context.config.control_root, "release-terminal")?;
        }
        self.record_once(
            context,
            NativeJourneyEventKind::TerminalObserved,
            display
                .turn_status
                .is_some_and(RuntimeTurnStatus::is_terminal),
            display,
        )?;
        let terminal_seen = self
            .observed
            .contains(&NativeJourneyEventKind::TerminalObserved);
        self.record_once(
            context,
            NativeJourneyEventKind::FinalCaughtUp,
            terminal_seen && display.transport_caught_up,
            display,
        )
    }

    fn record_once(
        &mut self,
        context: &NativeJourneyContext,
        kind: NativeJourneyEventKind,
        condition: bool,
        display: NativeJourneyDisplay,
    ) -> Result<(), NativeJourneyError> {
        if condition && self.observed.insert(kind) {
            record_context_event(context, kind, display)?;
        }
        Ok(())
    }

    fn milestones_complete(&self) -> bool {
        [
            NativeJourneyEventKind::FirstDeltaObserved,
            NativeJourneyEventKind::RunningCaughtUp,
            NativeJourneyEventKind::LateDeltaObserved,
            NativeJourneyEventKind::TerminalObserved,
            NativeJourneyEventKind::FinalCaughtUp,
        ]
        .into_iter()
        .all(|kind| self.observed.contains(&kind))
    }
}

async fn run_complete_runtime_journey_inner(
    journey: &mut Signal<NativeJourneyUiState>,
    launch: DesktopRuntimeExecutionLaunch,
) -> Result<(), NativeJourneyError> {
    let context = journey.read().context.clone();
    let (selection, identity, authority) = launch.into_dispatch_parts();
    if !authority.is_exact_post_render_authority() || authority.identity() != &identity {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_AUTHORITY_INVALID"));
    }
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let control_root = context.config.control_root.clone();
    let runtime_program = env::current_exe()
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_PROGRAM_UNAVAILABLE"))?;
    let runtime_task = tokio::task::spawn_blocking(move || {
        let runtime = controlled_runtime_source(runtime_program, control_root);
        plane.resume_mission_runtime_native(secrets.as_ref(), authority, runtime, Utc::now())
    });
    let mut drive = NativeRuntimeDrive::new(runtime_task, selection);
    loop {
        if drive.started_at.elapsed() > JOURNEY_WAIT_LIMIT {
            return Err(NativeJourneyError::new("NATIVE_JOURNEY_TIMED_OUT"));
        }
        drive
            .observe_runtime_return(journey, &identity, &context)
            .await?;
        drive.refresh_selection(journey, &identity);
        let observation = pull_native_runtime_page(journey, &drive.current_selection).await?;
        drive.observe_delivery(journey, &identity, &observation, &context)?;
        if drive.runtime_result.is_some() && journey.read().paint.completion_ready(&identity) {
            break;
        }
        tokio::time::sleep(JOURNEY_POLL_INTERVAL).await;
    }
    let result = drive
        .runtime_result
        .take()
        .ok_or(NativeJourneyError::new("NATIVE_RUNTIME_RESULT_MISSING"))?;
    result.map_err(|error| native_submission_error(&error))?;
    if !drive.milestones_complete() {
        return Err(NativeJourneyError::new("NATIVE_JOURNEY_MILESTONE_MISSING"));
    }
    let completion = journey
        .write()
        .paint
        .finish_runtime(&identity, &drive.current_selection)
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_FINISH_REJECTED"))?;
    if !matches!(completion, DesktopRuntimeCompletionDisposition::Accepted(_)) {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_FINISH_STALE"));
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::RuntimeCommandReleased,
        journey.read().display,
    )?;
    let fingerprint = query_private_stream_fingerprint(&context).await?;
    if fingerprint.delta_count < 2 || !fingerprint.turn_status.is_terminal() {
        return Err(NativeJourneyError::new("NATIVE_DURABLE_STREAM_INCOMPLETE"));
    }
    *context
        .completed_stream
        .lock()
        .map_err(|_| NativeJourneyError::new("NATIVE_STREAM_FINGERPRINT_LOCKED"))? =
        Some(fingerprint);
    run_native_selected_result_adoption(journey).await?;
    prepare_stop_before_resume(journey).await
}

async fn run_native_selected_result_adoption(
    journey: &mut Signal<NativeJourneyUiState>,
) -> Result<(), NativeJourneyError> {
    let context = journey.read().context.clone();
    let projection = load_native_selected_result(&context).await?;
    if !projection.can_adopt() {
        return Err(NativeJourneyError::new(
            "NATIVE_SELECTED_RESULT_NOT_ADOPTABLE",
        ));
    }
    let action = projection.adopt_action();
    if !matches!(action, ResultSurfaceAction::Adopt(_)) {
        return Err(NativeJourneyError::new(
            "NATIVE_ADOPTION_INTENT_SCOPE_INVALID",
        ));
    }
    let expected_binding = projection.binding.clone();
    {
        let mut state = journey.write();
        state.adoption.phase = NativeAdoptionPhase::Projected;
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::SelectedResultProjected,
        journey.read().display,
    )?;
    {
        let mut state = journey.write();
        state.adoption.phase = NativeAdoptionPhase::IntentBound;
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::AdoptionIntentBound,
        journey.read().display,
    )?;
    let selected_result_receipt = adopt_native_selected_result(&context, &expected_binding).await?;
    {
        let mut state = journey.write();
        state.adoption.phase = NativeAdoptionPhase::ReceiptCommitted;
        state.adoption.receipt = Some(selected_result_receipt);
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::AdoptionReceiptCommitted,
        journey.read().display,
    )?;
    reject_native_selected_result_attempts(&context, &expected_binding).await?;
    journey.write().adoption.phase = NativeAdoptionPhase::StaleRejected;
    record_context_event(
        &context,
        NativeJourneyEventKind::StaleAdoptionRejected,
        journey.read().display,
    )
}

async fn load_native_selected_result(
    context: &NativeJourneyContext,
) -> Result<SelectedResultProjection, NativeJourneyError> {
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let project_id = context.project_id.clone();
    let mission_id = context.main_mission_id.clone();
    let snapshot =
        tokio::task::spawn_blocking(move || plane.load_with(secrets.as_ref(), Utc::now()))
            .await
            .map_err(|_| NativeJourneyError::new("NATIVE_RESULT_SNAPSHOT_TASK_FAILED"))?
            .map_err(|_| NativeJourneyError::new("NATIVE_RESULT_SNAPSHOT_READ_FAILED"))?;
    let snapshot = match snapshot {
        DesktopLoadState::Ready(snapshot) => snapshot,
        DesktopLoadState::Uninitialized { .. } => {
            return Err(NativeJourneyError::new(
                "NATIVE_RESULT_SNAPSHOT_UNINITIALIZED",
            ));
        }
    };
    let project = snapshot
        .inventory
        .projects
        .iter()
        .find(|project| project.project_id == project_id)
        .ok_or(NativeJourneyError::new("NATIVE_RESULT_PROJECT_MISSING"))?;
    let mission = project
        .missions
        .iter()
        .find(|mission| mission.mission_id == mission_id)
        .ok_or(NativeJourneyError::new("NATIVE_RESULT_MISSION_MISSING"))?;
    let projection = selected_result_projection(project, mission, None)
        .ok_or(NativeJourneyError::new("NATIVE_SELECTED_RESULT_MISSING"))?;
    let action = projection.adopt_action();
    if !action_matches_current_projection(&action, project, mission) {
        return Err(NativeJourneyError::new(
            "NATIVE_ADOPTION_INTENT_SCOPE_INVALID",
        ));
    }
    Ok(projection)
}

async fn adopt_native_selected_result(
    context: &NativeJourneyContext,
    binding: &ResultBinding,
) -> Result<NativeSelectedResultReceipt, NativeJourneyError> {
    let request = DesktopWorkProductAdoptionRequest {
        project_id: binding.project_id.clone(),
        mission_id: binding.mission_id.clone(),
        work_product_id: binding.result_id.clone(),
        expected_mission_revision: binding.mission_revision,
        expected_work_product_revision: binding.result_revision,
        expected_manifest_version: binding.manifest_version,
    };
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let adopted_snapshot = tokio::task::spawn_blocking(move || {
        plane.adopt_work_product_native(secrets.as_ref(), request, Utc::now())
    })
    .await
    .map_err(|_| NativeJourneyError::new("NATIVE_ADOPTION_TASK_FAILED"))?
    .map_err(|_| NativeJourneyError::new("NATIVE_ADOPTION_APPLICATION_FAILED"))?;
    let adopted_project = adopted_snapshot
        .inventory
        .projects
        .iter()
        .find(|project| project.project_id == binding.project_id)
        .ok_or(NativeJourneyError::new("NATIVE_ADOPTED_PROJECT_MISSING"))?;
    let adopted_mission = adopted_project
        .missions
        .iter()
        .find(|mission| mission.mission_id == binding.mission_id)
        .ok_or(NativeJourneyError::new("NATIVE_ADOPTED_MISSION_MISSING"))?;
    let adopted_product = adopted_mission
        .work_products
        .iter()
        .find(|product| product.work_product_id == binding.result_id)
        .ok_or(NativeJourneyError::new("NATIVE_ADOPTED_RESULT_MISSING"))?;
    if adopted_product.adoption_status != WorkProductStatus::Accepted
        || adopted_mission.revision <= binding.mission_revision
        || adopted_product.work_product_revision <= binding.result_revision
        || adopted_product.manifest_version <= binding.manifest_version
    {
        return Err(NativeJourneyError::new("NATIVE_ADOPTION_RECEIPT_INVALID"));
    }
    let revisions = NativeAdoptionRevisions {
        expected_mission_revision: binding.mission_revision,
        expected_result_revision: binding.result_revision,
        expected_manifest_version: binding.manifest_version,
        adopted_mission_revision: adopted_mission.revision,
        adopted_result_revision: adopted_product.work_product_revision,
        adopted_manifest_version: adopted_product.manifest_version,
    };
    let binding_digest = result_binding_digest(binding);
    Ok(NativeSelectedResultReceipt {
        binding_digest: binding_digest.clone(),
        expected_mission_revision: revisions.expected_mission_revision,
        expected_result_revision: revisions.expected_result_revision,
        expected_manifest_version: revisions.expected_manifest_version,
        adopted_mission_revision: revisions.adopted_mission_revision,
        adopted_result_revision: revisions.adopted_result_revision,
        adopted_manifest_version: revisions.adopted_manifest_version,
        adopted_status: crate::work_product_status_label(&adopted_product.adoption_status),
        adoption_receipt_digest: adoption_receipt_digest(
            &binding_digest,
            &revisions,
            &adopted_product.adoption_status,
        ),
    })
}

async fn reject_native_selected_result_attempts(
    context: &NativeJourneyContext,
    binding: &ResultBinding,
) -> Result<(), NativeJourneyError> {
    let stale_request = DesktopWorkProductAdoptionRequest {
        project_id: binding.project_id.clone(),
        mission_id: binding.mission_id.clone(),
        work_product_id: binding.result_id.clone(),
        expected_mission_revision: binding.mission_revision,
        expected_work_product_revision: binding.result_revision,
        expected_manifest_version: binding.manifest_version,
    };
    let tampered_request = DesktopWorkProductAdoptionRequest {
        expected_manifest_version: binding.manifest_version.saturating_add(1),
        ..stale_request.clone()
    };
    let cross_scope_request = DesktopWorkProductAdoptionRequest {
        mission_id: context.alternate_mission_id.clone(),
        ..stale_request.clone()
    };
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let (stale_rejected, tamper_rejected, cross_scope_rejected) =
        tokio::task::spawn_blocking(move || {
            let stale = plane
                .adopt_work_product_native(secrets.as_ref(), stale_request, Utc::now())
                .is_err();
            let tamper = plane
                .adopt_work_product_native(secrets.as_ref(), tampered_request, Utc::now())
                .is_err();
            let cross_scope = plane
                .adopt_work_product_native(secrets.as_ref(), cross_scope_request, Utc::now())
                .is_err();
            (stale, tamper, cross_scope)
        })
        .await
        .map_err(|_| NativeJourneyError::new("NATIVE_STALE_ADOPTION_TASK_FAILED"))?;
    if stale_rejected && tamper_rejected && cross_scope_rejected {
        Ok(())
    } else {
        Err(NativeJourneyError::new("NATIVE_STALE_ADOPTION_ACCEPTED"))
    }
}

fn result_binding_digest(binding: &crate::result_adoption_surface::ResultBinding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo.native-runtime-journey.result-binding.v1\0");
    for value in [
        binding.tenant_id.to_string(),
        binding.project_id.to_string(),
        binding.mission_id.to_string(),
        binding.result_id.to_string(),
    ] {
        hash_timeline_field(&mut hasher, value.as_bytes());
    }
    hash_timeline_field(&mut hasher, &binding.result_revision.to_le_bytes());
    hash_timeline_field(&mut hasher, &binding.mission_revision.to_le_bytes());
    hash_timeline_field(&mut hasher, &binding.manifest_version.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn adoption_receipt_digest(
    binding_digest: &str,
    revisions: &NativeAdoptionRevisions,
    status: &WorkProductStatus,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo.native-runtime-journey.adoption-receipt.v1\0");
    hash_timeline_field(&mut hasher, binding_digest.as_bytes());
    for value in [
        revisions.expected_mission_revision,
        revisions.expected_result_revision,
        revisions.expected_manifest_version,
        revisions.adopted_mission_revision,
        revisions.adopted_result_revision,
        revisions.adopted_manifest_version,
    ] {
        hash_timeline_field(&mut hasher, &value.to_le_bytes());
    }
    hash_timeline_field(
        &mut hasher,
        crate::work_product_status_label(status).as_bytes(),
    );
    hex::encode(hasher.finalize())
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive Desktop error boundary intentionally stays in one mapping"
)]
fn native_submission_error(error: &DesktopDataError) -> NativeJourneyError {
    let code = match error {
        DesktopDataError::Application(ApplicationError::RuntimeDraftScopeMismatch) => {
            "NATIVE_RUNTIME_DRAFT_SCOPE_MISMATCH"
        }
        DesktopDataError::Application(ApplicationError::RuntimeDraftTurnNotCompleted) => {
            "NATIVE_RUNTIME_DRAFT_NOT_COMPLETED"
        }
        DesktopDataError::Application(ApplicationError::RuntimeDraftMessageMissing) => {
            "NATIVE_RUNTIME_DRAFT_MESSAGE_MISSING"
        }
        DesktopDataError::Application(ApplicationError::RuntimeDraftConversationAdvanced) => {
            "NATIVE_RUNTIME_DRAFT_CONVERSATION_ADVANCED"
        }
        DesktopDataError::Application(ApplicationError::RuntimeDraftReplayMismatch) => {
            "NATIVE_RUNTIME_DRAFT_REPLAY_MISMATCH"
        }
        DesktopDataError::Application(ApplicationError::RuntimeProcessCleanupBlocked {
            ..
        }) => "NATIVE_RUNTIME_PROCESS_CLEANUP_BLOCKED",
        DesktopDataError::Application(ApplicationError::Runtime(_)) => {
            "NATIVE_RUNTIME_ADAPTER_FAILED"
        }
        DesktopDataError::Application(ApplicationError::RuntimeTurn(_)) => {
            "NATIVE_RUNTIME_TURN_DOMAIN_FAILED"
        }
        DesktopDataError::Application(ApplicationError::RuntimeTextSubscription(_)) => {
            "NATIVE_RUNTIME_SUBSCRIPTION_FAILED"
        }
        DesktopDataError::Application(ApplicationError::Mission(_)) => {
            "NATIVE_RUNTIME_MISSION_DOMAIN_FAILED"
        }
        DesktopDataError::Application(ApplicationError::MissionConversation(_)) => {
            "NATIVE_RUNTIME_CONVERSATION_DOMAIN_FAILED"
        }
        DesktopDataError::Application(ApplicationError::WorkProductManifest(_)) => {
            "NATIVE_RUNTIME_WORK_PRODUCT_DOMAIN_FAILED"
        }
        DesktopDataError::Application(ApplicationError::Context(_)) => {
            "NATIVE_RUNTIME_CONTEXT_DOMAIN_FAILED"
        }
        DesktopDataError::Application(ApplicationError::ContextAssembly(_)) => {
            "NATIVE_RUNTIME_CONTEXT_ASSEMBLY_FAILED"
        }
        DesktopDataError::Application(ApplicationError::ContextMaterialStore(_)) => {
            "NATIVE_RUNTIME_CONTEXT_MATERIAL_FAILED"
        }
        DesktopDataError::Application(ApplicationError::Storage(_))
        | DesktopDataError::Storage(_) => "NATIVE_RUNTIME_STORAGE_FAILED",
        DesktopDataError::Application(_) => "NATIVE_RUNTIME_APPLICATION_FAILED",
        DesktopDataError::Io(_) => "NATIVE_RUNTIME_IO_FAILED",
        DesktopDataError::SecretStore(_) => "NATIVE_RUNTIME_SECRET_STORE_FAILED",
        DesktopDataError::Catalog(_) => "NATIVE_RUNTIME_CATALOG_FAILED",
        DesktopDataError::InvalidDataRoot(_)
        | DesktopDataError::DataDirectoryUnavailable
        | DesktopDataError::MissingDatabaseKey
        | DesktopDataError::EmptyMissionGoal
        | DesktopDataError::InvalidCatalogMissionContract
        | DesktopDataError::InvalidMissionContinuation
        | DesktopDataError::InvalidHumanCheckpointConfirmation
        | DesktopDataError::InvalidVm11OutcomeDecision
        | DesktopDataError::InvalidVm11NextContractResolution
        | DesktopDataError::InvalidEffectProposal
        | DesktopDataError::InvalidWaitingApprovalGrant
        | DesktopDataError::InvalidApprovedEffectExecution
        | DesktopDataError::InvalidEffectReconciliation
        | DesktopDataError::InvalidBrowserWorkspaceCreate
        | DesktopDataError::BrowserWorkspaceAlreadyExists
        | DesktopDataError::InvalidBrowserWorkspaceMount
        | DesktopDataError::BrowserWorkspaceMountUnavailable
        | DesktopDataError::BrowserWorkspaceHostAlreadyMounted
        | DesktopDataError::BrowserWorkspaceHostUnavailable
        | DesktopDataError::BrowserWorkspaceHostReconciliationRequired
        | DesktopDataError::BrowserHostRegistryUnavailable
        | DesktopDataError::ManagedBrowserExecutableUnavailable
        | DesktopDataError::InvalidBrowserPublicSourceRead
        | DesktopDataError::InvalidTiktokEvidenceAdoption
        | DesktopDataError::InvalidTiktokProviderRead
        | DesktopDataError::InvalidTiktokCredentialConfiguration
        | DesktopDataError::TiktokCredentialGenerationAlreadyConfigured
        | DesktopDataError::TiktokCredentialCoordinatorUnavailable
        | DesktopDataError::BrowserWorkspaceReadNotAgentHeld
        | DesktopDataError::InvalidBrowserWorkspaceContinue
        | DesktopDataError::InvalidBrowserWorkspaceTakeOver
        | DesktopDataError::BrowserWorkspaceUnavailable
        | DesktopDataError::BrowserWorkspaceContinueNotHeld
        | DesktopDataError::BrowserWorkspaceTakeOverNotAgentHeld
        | DesktopDataError::InvalidBrowserWorkspaceControl
        | DesktopDataError::BrowserWorkspacePauseUnavailable
        | DesktopDataError::BrowserWorkspaceResumeUnavailable
        | DesktopDataError::InvalidCreatorDeliverableReview
        | DesktopDataError::CreatorDeliverableReviewUnavailable
        | DesktopDataError::CreatorDeliverableReviewStale
        | DesktopDataError::InvalidConversationOpen
        | DesktopDataError::ConversationOpenUnavailable
        | DesktopDataError::ConversationAlreadyOpen
        | DesktopDataError::EmptyProjectName
        | DesktopDataError::InvalidRecoveryKey
        | DesktopDataError::ProjectNotFound(_)
        | DesktopDataError::ProjectEncryptionNotReady(_)
        | DesktopDataError::ProjectEncryptionAlreadyProvisioned(_)
        | DesktopDataError::ProjectRecoveryNotApplicable(_)
        | DesktopDataError::ProjectContextRecoveryRequired(_)
        | DesktopDataError::ProjectContextBlockedEnvironment(_)
        | DesktopDataError::ProjectContextIntegrityError(_)
        | DesktopDataError::RuntimeSubscriptionContextMismatch
        | DesktopDataError::WorkProductActionStale
        | DesktopDataError::RuntimeLocalApprovalUnavailable
        | DesktopDataError::RuntimeLocalApprovalMismatch
        | DesktopDataError::CordisToolApprovalUnavailable
        | DesktopDataError::CordisToolApprovalMismatch
        | DesktopDataError::RuntimeDispatch(_)
        | DesktopDataError::DomainCommandDispatch(_)
        | DesktopDataError::BrowserReadDispatch(_)
        | DesktopDataError::EffectExecutionDispatch(_)
        | DesktopDataError::EffectReconciliationDispatch(_)
        | DesktopDataError::CordisSessionPersistence(_)
        | DesktopDataError::ObservationPipeline(_)
        | DesktopDataError::Tiktok(_)
        | DesktopDataError::Cordis(_) => "NATIVE_RUNTIME_DESKTOP_CONTRACT_FAILED",
    };
    NativeJourneyError::new(code)
}

struct NativePullObservation {
    delivery: DesktopRuntimeDelivery,
    display: NativeJourneyDisplay,
}

async fn pull_native_runtime_page(
    journey: &mut Signal<NativeJourneyUiState>,
    selection: &DesktopRuntimeSelection,
) -> Result<NativePullObservation, NativeJourneyError> {
    let context = journey.read().context.clone();
    let request = journey
        .read()
        .paint
        .pull_request(selection)
        .ok_or(NativeJourneyError::new("NATIVE_PULL_REQUEST_STALE"))?;
    let handle = request.handle().clone();
    let cursor = request.producer_cursor().cloned();
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let batch = tokio::task::spawn_blocking(move || {
        plane.runtime_text_subscription_native(
            secrets.as_ref(),
            &handle,
            cursor.as_ref(),
            DESKTOP_RUNTIME_SUBSCRIPTION_PAGE_SIZE,
            Utc::now(),
        )
    })
    .await
    .map_err(|_| NativeJourneyError::new("NATIVE_PULL_TASK_FAILED"))?
    .map_err(|_| NativeJourneyError::new("NATIVE_PULL_FAILED"))?;
    let unchanged_awaiting = matches!(&batch, RuntimeTextSubscriptionBatch::AwaitingTurn { .. })
        && journey
            .read()
            .paint
            .paint_view(selection.scope.project_id(), selection.scope.mission_id())
            .is_some_and(|view| view.awaiting_turn() && view.stream().is_none());
    let delivery = request
        .into_delivery(batch)
        .map_err(|_| NativeJourneyError::new("NATIVE_DELIVERY_INVALID"))?;
    let effect = if unchanged_awaiting {
        DesktopRuntimeReducerEffect::Duplicate
    } else {
        journey
            .write()
            .paint
            .apply_delivery(&delivery)
            .map_err(|_| NativeJourneyError::new("NATIVE_REDUCER_REJECTED"))?
    };
    if effect == DesktopRuntimeReducerEffect::IgnoredStale {
        return Err(NativeJourneyError::new("NATIVE_ACTIVE_DELIVERY_STALE"));
    }
    let display = refresh_native_display(journey, selection)?;
    Ok(NativePullObservation { delivery, display })
}

fn refresh_native_display(
    journey: &mut Signal<NativeJourneyUiState>,
    selection: &DesktopRuntimeSelection,
) -> Result<NativeJourneyDisplay, NativeJourneyError> {
    let display = {
        let state = journey.read();
        let view = state
            .paint
            .paint_view(selection.scope.project_id(), selection.scope.mission_id())
            .ok_or(NativeJourneyError::new("NATIVE_PAINT_VIEW_MISSING"))?;
        NativeJourneyDisplay {
            delta_count: view.stream().map_or(0, |stream| stream.delta_count),
            turn_status: view.stream().map(|stream| stream.turn_status),
            transport_caught_up: view.transport_caught_up(),
            scope_visible: state.paint.selection_is_visible(selection),
            awaiting_snapshot_handle_bound: false,
        }
    };
    journey.write().display = display;
    Ok(display)
}

fn exercise_offscreen_reselect(
    journey: &mut Signal<NativeJourneyUiState>,
    identity: &DesktopRuntimeCommandIdentity,
    stale_delivery: &DesktopRuntimeDelivery,
    context: &NativeJourneyContext,
) -> Result<(), NativeJourneyError> {
    let main_project_id = context.project_id.clone();
    let main_mission_id = context.main_mission_id.clone();
    let alternate_mission_id = context.alternate_mission_id.clone();
    let (isolated, stale_rejected, display) = {
        let mut state = journey.write();
        let change = state
            .paint
            .reconcile_selection(Some((&main_project_id, &alternate_mission_id)))
            .map_err(|_| NativeJourneyError::new("NATIVE_RESELECT_FAILED"))?;
        if change != DesktopRuntimeSelectionChange::Untracked {
            return Err(NativeJourneyError::new(
                "NATIVE_RESELECT_TRACKED_FOREIGN_SCOPE",
            ));
        }
        let isolated = state
            .paint
            .paint_view(&main_project_id, &alternate_mission_id)
            .is_none();
        let restored = state
            .paint
            .reconcile_selection(Some((&main_project_id, &main_mission_id)))
            .map_err(|_| NativeJourneyError::new("NATIVE_RESELECT_RESTORE_FAILED"))?;
        if !matches!(restored, DesktopRuntimeSelectionChange::Selected(_)) {
            return Err(NativeJourneyError::new("NATIVE_RESELECT_RESTORE_STALE"));
        }
        let stale_rejected = state
            .paint
            .apply_delivery(stale_delivery)
            .map_err(|_| NativeJourneyError::new("NATIVE_STALE_DELIVERY_ERROR"))?
            == DesktopRuntimeReducerEffect::IgnoredStale;
        let selection = state.paint.current_selection_for_command(identity);
        let display = selection
            .as_ref()
            .and_then(|selection| {
                state
                    .paint
                    .paint_view(selection.scope.project_id(), selection.scope.mission_id())
                    .map(|view| NativeJourneyDisplay {
                        delta_count: view.stream().map_or(0, |stream| stream.delta_count),
                        turn_status: view.stream().map(|stream| stream.turn_status),
                        transport_caught_up: view.transport_caught_up(),
                        scope_visible: state.paint.selection_is_visible(selection),
                        awaiting_snapshot_handle_bound: false,
                    })
            })
            .unwrap_or(state.display);
        state.display = display;
        state.reselect_isolated = isolated;
        state.stale_epoch_rejected = stale_rejected;
        (isolated, stale_rejected, display)
    };
    if !isolated || !stale_rejected {
        return Err(NativeJourneyError::new("NATIVE_RESELECT_ISOLATION_FAILED"));
    }
    record_context_event(
        context,
        NativeJourneyEventKind::OffscreenReselectIsolated,
        display,
    )?;
    record_context_event(context, NativeJourneyEventKind::StaleEpochRejected, display)
}

async fn query_private_stream_fingerprint(
    context: &Arc<NativeJourneyContext>,
) -> Result<PrivateStreamFingerprint, NativeJourneyError> {
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let project_id = context.project_id.clone();
    let mission_id = context.main_mission_id.clone();
    tokio::task::spawn_blocking(move || {
        let projection = plane
            .runtime_text_stream_with(secrets.as_ref(), &project_id, &mission_id, Utc::now())
            .map_err(|_| NativeJourneyError::new("NATIVE_PRIVATE_STREAM_READ_FAILED"))?
            .ok_or(NativeJourneyError::new("NATIVE_PRIVATE_STREAM_MISSING"))?;
        Ok(fingerprint_private_stream(&projection))
    })
    .await
    .map_err(|_| NativeJourneyError::new("NATIVE_PRIVATE_STREAM_TASK_FAILED"))?
}

fn fingerprint_private_stream(
    projection: &DesktopRuntimeTextStreamProjection,
) -> PrivateStreamFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo.native-runtime-journey.private-stream.v1\0");
    hasher.update(projection.worker_generation.to_le_bytes());
    hasher.update(projection.turn_revision.to_le_bytes());
    hasher.update(runtime_status_label(projection.turn_status).as_bytes());
    for item in &projection.items {
        hash_timeline_field(&mut hasher, item.item_id_digest.as_bytes());
        hash_timeline_field(&mut hasher, item.text.as_bytes());
        hasher.update(item.delta_count.to_le_bytes());
    }
    PrivateStreamFingerprint {
        digest: hasher.finalize().into(),
        delta_count: projection.delta_count,
        item_count: projection.items.len(),
        turn_status: projection.turn_status,
    }
}

async fn prepare_stop_before_resume(
    journey: &mut Signal<NativeJourneyUiState>,
) -> Result<(), NativeJourneyError> {
    let context = journey.read().context.clone();
    let plane = context.plane.clone();
    let secrets = context.secrets.clone();
    let project_id = context.project_id.clone();
    let started = tokio::task::spawn_blocking(move || {
        plane.start_catalog_mission_execution_native(
            secrets.as_ref(),
            catalog_request(&project_id, "Native stop authority journey"),
            Utc::now(),
        )
    })
    .await
    .map_err(|_| NativeJourneyError::new("NATIVE_STOP_START_TASK_FAILED"))?
    .map_err(|_| NativeJourneyError::new("NATIVE_STOP_START_FAILED"))?;
    let commit = journey
        .write()
        .paint
        .commit_catalog_start(started.handle)
        .map_err(|_| NativeJourneyError::new("NATIVE_STOP_PAINT_PREPARE_FAILED"))?;
    let mut state = journey.write();
    state.pending_commit = Some(commit);
    state.phase = NativeJourneyPhase::StopAwaitingRender;
    state.display = NativeJourneyDisplay {
        scope_visible: true,
        ..NativeJourneyDisplay::default()
    };
    Ok(())
}

fn acknowledge_stop_render(
    journey: &mut Signal<NativeJourneyUiState>,
) -> Result<(), NativeJourneyError> {
    let context = journey.read().context.clone();
    let commit = journey
        .read()
        .pending_commit
        .clone()
        .ok_or(NativeJourneyError::new("NATIVE_STOP_COMMIT_MISSING"))?;
    let scope = &commit.selection().scope;
    let view = journey
        .read()
        .paint
        .paint_view(scope.project_id(), scope.mission_id())
        .ok_or(NativeJourneyError::new("NATIVE_STOP_VIEW_MISSING"))?;
    if !view.awaiting_turn() || view.stream().is_some() {
        return Err(NativeJourneyError::new("NATIVE_STOP_VIEW_INVALID"));
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::StopMissionAwaitingRendered,
        journey.read().display,
    )?;
    let stop = journey
        .read()
        .paint
        .request_stop_for_selection(Some((scope.project_id(), scope.mission_id())));
    if stop != DesktopRuntimeStopDisposition::Requested {
        return Err(NativeJourneyError::new("NATIVE_STOP_REQUEST_REJECTED"));
    }
    let acknowledgement = journey.write().paint.acknowledge_rendered_paint(&commit);
    if acknowledgement.is_ok()
        || journey.read().resume_count != 1
        || journey
            .read()
            .paint
            .stop_available_for_selection(Some((scope.project_id(), scope.mission_id())))
    {
        return Err(NativeJourneyError::new("NATIVE_STOP_BEFORE_RESUME_FAILED"));
    }
    {
        let mut state = journey.write();
        state.pending_commit = None;
        state.stop_before_resume_isolated = true;
        state.phase = NativeJourneyPhase::Finalizing;
    }
    record_context_event(
        &context,
        NativeJourneyEventKind::StopBeforeResumeIsolated,
        journey.read().display,
    )
}

async fn finalize_native_journey(mut journey: Signal<NativeJourneyUiState>) {
    let result = finalize_native_journey_inner(&journey).await;
    match result {
        Ok(()) => journey.write().phase = NativeJourneyPhase::Passed,
        Err(error) => fail_journey(&mut journey, error),
    }
}

async fn finalize_native_journey_inner(
    journey: &Signal<NativeJourneyUiState>,
) -> Result<(), NativeJourneyError> {
    let context = journey.read().context.clone();
    let before = context
        .completed_stream
        .lock()
        .map_err(|_| NativeJourneyError::new("NATIVE_STREAM_FINGERPRINT_LOCKED"))?
        .clone()
        .ok_or(NativeJourneyError::new("NATIVE_STREAM_FINGERPRINT_MISSING"))?;
    let after = query_private_stream_fingerprint(&context).await?;
    if before != after {
        return Err(NativeJourneyError::new("NATIVE_STOP_SCOPE_CONTAMINATED"));
    }
    if !context
        .config
        .control_root
        .join("runtime-invoked")
        .is_file()
    {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_INVOCATION_MISSING"));
    }
    let state = journey.read();
    let assertions = BTreeMap::from([
        ("local_sqlcipher_encrypted", context.sqlcipher_encrypted),
        ("awaiting_committed_before_resume", true),
        ("awaiting_snapshot_handle_bound", true),
        ("post_render_ack_before_resume", true),
        ("exactly_one_runtime_resume", state.resume_count == 1),
        ("running_caught_up_preceded_late_delta", true),
        ("terminal_required_final_caught_up", true),
        ("offscreen_reselect_isolated", state.reselect_isolated),
        ("stale_epoch_rejected", state.stale_epoch_rejected),
        (
            "stop_before_resume_isolated",
            state.stop_before_resume_isolated,
        ),
        ("controlled_runtime_invoked_once", true),
        ("private_text_excluded_from_receipt", true),
        (
            "selected_result_projection_exact",
            matches!(
                state.adoption.phase,
                NativeAdoptionPhase::Projected
                    | NativeAdoptionPhase::IntentBound
                    | NativeAdoptionPhase::ReceiptCommitted
                    | NativeAdoptionPhase::StaleRejected
            ),
        ),
        (
            "adoption_intent_exact_revision",
            matches!(
                state.adoption.phase,
                NativeAdoptionPhase::IntentBound
                    | NativeAdoptionPhase::ReceiptCommitted
                    | NativeAdoptionPhase::StaleRejected
            ),
        ),
        (
            "application_adoption_receipt",
            matches!(
                state.adoption.phase,
                NativeAdoptionPhase::ReceiptCommitted | NativeAdoptionPhase::StaleRejected
            ),
        ),
        (
            "stale_reselect_tamper_rejected",
            state.adoption.phase == NativeAdoptionPhase::StaleRejected,
        ),
        ("adoptable_result_receipt", state.adoption.receipt.is_some()),
    ]);
    let selected_result = state.adoption.receipt.clone();
    drop(state);
    write_success_receipt(&context, assertions, selected_result)
}

fn record_context_event(
    context: &NativeJourneyContext,
    kind: NativeJourneyEventKind,
    display: NativeJourneyDisplay,
) -> Result<(), NativeJourneyError> {
    let events = {
        let mut timeline = context
            .timeline
            .lock()
            .map_err(|_| NativeJourneyError::new("NATIVE_TIMELINE_LOCKED"))?;
        timeline.record(
            kind,
            display.delta_count,
            display.turn_status,
            display.transport_caught_up,
            display.scope_visible,
            display.awaiting_snapshot_handle_bound,
        )?;
        timeline.events.clone()
    };
    write_live_timeline(&context.config, &events)
}

fn write_live_timeline(
    config: &NativeJourneyConfig,
    events: &[NativeJourneyTimelineEvent],
) -> Result<(), NativeJourneyError> {
    let bytes = serde_json::to_vec_pretty(events)
        .map_err(|_| NativeJourneyError::new("NATIVE_TIMELINE_SERIALIZE_FAILED"))?;
    let temporary = config.root.join("native-journey-timeline.tmp");
    let destination = config.root.join("timeline.json");
    fs::write(&temporary, bytes)
        .map_err(|_| NativeJourneyError::new("NATIVE_TIMELINE_WRITE_FAILED"))?;
    fs::rename(&temporary, destination)
        .map_err(|_| NativeJourneyError::new("NATIVE_TIMELINE_COMMIT_FAILED"))
}

fn write_success_receipt(
    context: &NativeJourneyContext,
    assertions: NativeJourneyAssertions,
    selected_result: Option<NativeSelectedResultReceipt>,
) -> Result<(), NativeJourneyError> {
    if assertions.values().any(|passed| !passed) {
        return Err(NativeJourneyError::new("NATIVE_ASSERTION_FAILED"));
    }
    let timeline = context
        .timeline
        .lock()
        .map_err(|_| NativeJourneyError::new("NATIVE_TIMELINE_LOCKED"))?
        .finish()?;
    let receipt = NativeJourneyReceipt {
        schema_version: SCHEMA_VERSION,
        journey_id: "B2-NATIVE-01",
        status: "passed",
        failure_code: None,
        boundaries: native_journey_boundaries(),
        assertions,
        timeline: Some(timeline),
        selected_result,
    };
    write_receipt(&context.config, &receipt)
}

fn fail_journey(journey: &mut Signal<NativeJourneyUiState>, error: NativeJourneyError) {
    let context = journey.read().context.clone();
    let receipt = NativeJourneyReceipt {
        schema_version: SCHEMA_VERSION,
        journey_id: "B2-NATIVE-01",
        status: "failed",
        failure_code: Some(error.code()),
        boundaries: native_journey_boundaries(),
        assertions: NativeJourneyAssertions::new(),
        timeline: None,
        selected_result: None,
    };
    let _ = write_receipt(&context.config, &receipt);
    journey.write().phase = NativeJourneyPhase::Failed;
}

fn native_journey_boundaries() -> NativeJourneyBoundaries {
    NativeJourneyBoundaries {
        proven: vec![
            "native_dioxus_window",
            "local_sqlcipher",
            "controlled_runtime_subprocess",
            "dioxus_render_commit_fence",
        ],
        not_proven: vec![
            "operating_system_compositor_evidence",
            "accessibility_tree_evidence",
            "mission_e3",
        ],
    }
}

fn write_receipt(
    config: &NativeJourneyConfig,
    receipt: &NativeJourneyReceipt,
) -> Result<(), NativeJourneyError> {
    let bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|_| NativeJourneyError::new("NATIVE_RECEIPT_SERIALIZE_FAILED"))?;
    if bytes
        .windows(b"native-private".len())
        .any(|window| window == b"native-private")
    {
        return Err(NativeJourneyError::new("NATIVE_RECEIPT_PRIVATE_TEXT"));
    }
    let temporary = config.root.join("native-journey-receipt.tmp");
    fs::write(&temporary, bytes)
        .map_err(|_| NativeJourneyError::new("NATIVE_RECEIPT_WRITE_FAILED"))?;
    fs::rename(&temporary, &config.receipt_path)
        .map_err(|_| NativeJourneyError::new("NATIVE_RECEIPT_COMMIT_FAILED"))
}

fn controlled_runtime_source(
    runtime_program: PathBuf,
    control_root: PathBuf,
) -> DesktopRuntimeSource {
    DesktopRuntimeSource::Fixture {
        provider: "native-journey-provider".into(),
        model: "native-journey-model".into(),
        command_builder: Box::new(move |project_root, runtime_home| {
            let mut command = RuntimeCommand::new(runtime_program, project_root);
            command.args = vec![
                CONTROLLED_RUNTIME_ARG.into(),
                CONTROL_ROOT_ARG.into(),
                control_root.to_string_lossy().into_owned(),
                RUNTIME_HOME_ARG.into(),
                runtime_home.to_string_lossy().into_owned(),
            ];
            command.environment.insert(
                "INTERPRETER_HOME".into(),
                runtime_home.to_string_lossy().into_owned(),
            );
            command.openinterpreter_home = Some(runtime_home.to_path_buf());
            command.shutdown_grace = StdDuration::from_millis(100);
            command
        }),
    }
}

fn release_control_marker(control_root: &Path, name: &str) -> Result<(), NativeJourneyError> {
    let path = control_root.join(name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(|_| ())
        .map_err(|_| NativeJourneyError::new("NATIVE_CONTROL_MARKER_REJECTED"))
}

pub fn controlled_runtime_exit_code() -> Option<i32> {
    let mut args = env::args_os();
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(CONTROLLED_RUNTIME_ARG)) {
        return None;
    }
    let remaining = args.collect::<Vec<_>>();
    Some(match run_controlled_runtime(&remaining) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("native-runtime-error:{}", error.code());
            70
        }
    })
}

fn run_controlled_runtime(args: &[std::ffi::OsString]) -> Result<(), NativeJourneyError> {
    let (control_root, runtime_home) = parse_controlled_runtime_args(args)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(control_root.join("runtime-invoked"))
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_DUPLICATE_INVOCATION"))?;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    controlled_runtime_handshake(&mut reader, &mut writer, &runtime_home, &control_root)?;
    emit_initial_runtime_delta(&mut writer, &control_root)?;
    wait_for_control_marker(&control_root, "release-late")?;
    emit_late_runtime_delta(&mut writer)?;
    wait_for_control_marker(&control_root, "release-terminal")?;
    emit_terminal_runtime_events(&mut writer)
}

fn controlled_runtime_handshake(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    runtime_home: &Path,
    control_root: &Path,
) -> Result<(), NativeJourneyError> {
    let initialize = read_protocol_request(reader, "initialize")?;
    write_runtime_phase_marker(control_root, "initialize-received")?;
    write_protocol_value(
        writer,
        &json!({"jsonrpc": "2.0", "id": initialize.id, "result": {"codexHome": runtime_home}}),
    )?;
    let thread = read_protocol_request(reader, "thread/start")?;
    write_runtime_phase_marker(control_root, "thread-received")?;
    let cwd = thread
        .params
        .get("cwd")
        .cloned()
        .ok_or(NativeJourneyError::new("NATIVE_RUNTIME_CWD_MISSING"))?;
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": thread.id,
            "result": {
                "thread": {"id": "native-journey-thread"},
                "cwd": cwd,
                "model": "native-journey-model",
                "modelProvider": "native-journey-provider",
                "approvalPolicy": "on-request",
                "approvalsReviewer": "user",
                "sandbox": "workspace-write"
            }
        }),
    )?;
    let turn = read_protocol_request(reader, "turn/start")?;
    write_runtime_phase_marker(control_root, "turn-received")?;
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "turn/started",
            "params": {
                "threadId": "native-journey-thread",
                "turn": {"id": "native-journey-turn", "status": "inProgress"}
            }
        }),
    )?;
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": turn.id,
            "result": {"turn": {"id": "native-journey-turn", "status": "inProgress"}}
        }),
    )
}

fn emit_initial_runtime_delta(
    writer: &mut impl Write,
    control_root: &Path,
) -> Result<(), NativeJourneyError> {
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "item/started",
            "params": {
                "threadId": "native-journey-thread",
                "turnId": "native-journey-turn",
                "item": {"id": "native-journey-item", "type": "agentMessage", "text": ""}
            }
        }),
    )?;
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": "native-journey-thread",
                "turnId": "native-journey-turn",
                "itemId": "native-journey-item",
                "delta": "native-private-first "
            }
        }),
    )?;
    write_runtime_phase_marker(control_root, "initial-delta-sent")
}

fn emit_late_runtime_delta(writer: &mut impl Write) -> Result<(), NativeJourneyError> {
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": "native-journey-thread",
                "turnId": "native-journey-turn",
                "itemId": "native-journey-item",
                "delta": "native-private-late"
            }
        }),
    )
}

fn emit_terminal_runtime_events(writer: &mut impl Write) -> Result<(), NativeJourneyError> {
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "item/completed",
            "params": {
                "threadId": "native-journey-thread",
                "turnId": "native-journey-turn",
                "item": {
                    "id": "native-journey-item",
                    "type": "agentMessage",
                    "text": "native-private-first native-private-late"
                }
            }
        }),
    )?;
    write_protocol_value(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "turn/completed",
            "params": {
                "threadId": "native-journey-thread",
                "turn": {"id": "native-journey-turn", "status": "completed"}
            }
        }),
    )
}

struct ProtocolRequest {
    id: Value,
    params: Value,
}

fn read_protocol_request(
    reader: &mut impl BufRead,
    expected_method: &str,
) -> Result<ProtocolRequest, NativeJourneyError> {
    let mut line = String::new();
    if reader
        .read_line(&mut line)
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_READ_FAILED"))?
        == 0
    {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_STREAM_CLOSED"));
    }
    let value: Value = serde_json::from_str(&line)
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_REQUEST_INVALID"))?;
    if value.get("method").and_then(Value::as_str) != Some(expected_method) {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_METHOD_MISMATCH"));
    }
    let id = value
        .get("id")
        .cloned()
        .ok_or(NativeJourneyError::new("NATIVE_RUNTIME_REQUEST_ID_MISSING"))?;
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    Ok(ProtocolRequest { id, params })
}

fn write_protocol_value(writer: &mut impl Write, value: &Value) -> Result<(), NativeJourneyError> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_WRITE_FAILED"))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_WRITE_FAILED"))
}

fn parse_controlled_runtime_args(
    args: &[std::ffi::OsString],
) -> Result<(PathBuf, PathBuf), NativeJourneyError> {
    if args.len() != 4 || args[0] != CONTROL_ROOT_ARG || args[2] != RUNTIME_HOME_ARG {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_ARGS_INVALID"));
    }
    let control_root = PathBuf::from(&args[1]);
    let runtime_home = PathBuf::from(&args[3]);
    if !control_root.is_absolute() || !runtime_home.is_absolute() {
        return Err(NativeJourneyError::new("NATIVE_RUNTIME_PATH_NOT_ABSOLUTE"));
    }
    let control_root = control_root
        .canonicalize()
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_CONTROL_INVALID"))?;
    let runtime_home = runtime_home
        .canonicalize()
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_HOME_INVALID"))?;
    Ok((control_root, runtime_home))
}

fn wait_for_control_marker(control_root: &Path, name: &str) -> Result<(), NativeJourneyError> {
    let marker = control_root.join(name);
    let started_at = Instant::now();
    while started_at.elapsed() <= RUNTIME_WAIT_LIMIT {
        if marker.is_file() {
            return Ok(());
        }
        std::thread::sleep(StdDuration::from_millis(10));
    }
    Err(NativeJourneyError::new("NATIVE_RUNTIME_CONTROL_TIMED_OUT"))
}

fn write_runtime_phase_marker(control_root: &Path, name: &str) -> Result<(), NativeJourneyError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(control_root.join(name))
        .map(|_| ())
        .map_err(|_| NativeJourneyError::new("NATIVE_RUNTIME_PHASE_DUPLICATE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: NativeJourneyEventKind, sequence: u64) -> NativeJourneyTimelineEvent {
        NativeJourneyTimelineEvent {
            sequence,
            elapsed_millis: sequence,
            kind,
            delta_count: usize::try_from(sequence).unwrap_or(usize::MAX),
            turn_status: None,
            transport_caught_up: false,
            scope_visible: true,
            awaiting_snapshot_handle_bound: kind == NativeJourneyEventKind::AwaitingRenderCommitted,
        }
    }

    fn valid_timeline() -> Vec<NativeJourneyTimelineEvent> {
        [
            NativeJourneyEventKind::SqlcipherReady,
            NativeJourneyEventKind::CatalogStartCommitted,
            NativeJourneyEventKind::AwaitingRenderCommitted,
            NativeJourneyEventKind::PostRenderAcknowledged,
            NativeJourneyEventKind::RuntimeResumeDispatched,
            NativeJourneyEventKind::FirstDeltaObserved,
            NativeJourneyEventKind::RunningCaughtUp,
            NativeJourneyEventKind::OffscreenReselectIsolated,
            NativeJourneyEventKind::StaleEpochRejected,
            NativeJourneyEventKind::LateDeltaObserved,
            NativeJourneyEventKind::RuntimeReturned,
            NativeJourneyEventKind::TerminalObserved,
            NativeJourneyEventKind::FinalCaughtUp,
            NativeJourneyEventKind::RuntimeCommandReleased,
            NativeJourneyEventKind::SelectedResultProjected,
            NativeJourneyEventKind::AdoptionIntentBound,
            NativeJourneyEventKind::AdoptionReceiptCommitted,
            NativeJourneyEventKind::StaleAdoptionRejected,
            NativeJourneyEventKind::StopMissionAwaitingRendered,
            NativeJourneyEventKind::StopBeforeResumeIsolated,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| event(kind, u64::try_from(index + 1).unwrap_or(u64::MAX)))
        .collect()
    }

    #[test]
    fn content_free_timeline_replays_the_native_journey_contract() {
        let events = valid_timeline();
        assert!(verify_timeline(&events).is_ok());
        let mut recorder = NativeTimelineRecorder::new();
        recorder.events = events;
        let timeline = recorder.finish().expect("content-free timeline");
        assert_eq!(timeline.replay_digest.len(), 64);
        let encoded = serde_json::to_string(&timeline).expect("timeline JSON");
        assert!(!encoded.contains("native-private"));
        assert!(!encoded.contains("native-journey-thread"));
        assert!(!encoded.contains("native-journey-turn"));
        assert!(!encoded.contains("native-journey-item"));
    }

    #[test]
    fn timeline_rejects_resume_duplication_and_missing_final_ack() {
        let mut duplicate = valid_timeline();
        duplicate.insert(5, event(NativeJourneyEventKind::RuntimeResumeDispatched, 6));
        for (index, item) in duplicate.iter_mut().enumerate() {
            item.sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
            item.elapsed_millis = item.sequence;
        }
        assert_eq!(
            verify_timeline(&duplicate),
            Err(NativeJourneyError::new("NATIVE_RESUME_COUNT_MISMATCH"))
        );
        let missing_ack = valid_timeline()
            .into_iter()
            .filter(|item| item.kind != NativeJourneyEventKind::FinalCaughtUp)
            .collect::<Vec<_>>();
        assert_eq!(
            verify_timeline(&missing_ack),
            Err(NativeJourneyError::new("NATIVE_TIMELINE_INCOMPLETE"))
        );
    }

    #[test]
    fn receipt_boundaries_never_claim_visual_ax_or_mission_e3() {
        let boundaries = native_journey_boundaries();
        assert!(boundaries.proven.contains(&"native_dioxus_window"));
        assert!(boundaries.proven.contains(&"local_sqlcipher"));
        assert!(boundaries.proven.contains(&"controlled_runtime_subprocess"));
        assert!(boundaries.proven.contains(&"dioxus_render_commit_fence"));
        assert!(
            boundaries
                .not_proven
                .contains(&"operating_system_compositor_evidence")
        );
        assert!(
            boundaries
                .not_proven
                .contains(&"accessibility_tree_evidence")
        );
        assert!(boundaries.not_proven.contains(&"mission_e3"));
    }

    #[test]
    fn controlled_runtime_args_fail_closed() {
        assert_eq!(
            parse_controlled_runtime_args(&[]),
            Err(NativeJourneyError::new("NATIVE_RUNTIME_ARGS_INVALID"))
        );
        assert_eq!(
            parse_controlled_runtime_args(&[
                CONTROL_ROOT_ARG.into(),
                "relative-control".into(),
                RUNTIME_HOME_ARG.into(),
                "relative-home".into(),
            ]),
            Err(NativeJourneyError::new("NATIVE_RUNTIME_PATH_NOT_ABSOLUTE"))
        );
    }

    #[test]
    fn private_stream_fingerprint_debug_is_content_free() {
        let fingerprint = PrivateStreamFingerprint {
            digest: [7; 32],
            delta_count: 2,
            item_count: 1,
            turn_status: RuntimeTurnStatus::Completed,
        };
        let rendered = format!("{fingerprint:?}");
        assert!(!rendered.contains("070707"));
        assert!(!rendered.contains("native-private"));
        assert!(rendered.contains("delta_count"));
    }
}

//! Contract and fail-closed verifier for durable Mission progress traces.
//!
//! This module is intentionally Eval-only. It consumes a producer-neutral trace
//! and does not start a Runtime, inspect a Desktop process, or manufacture a
//! native receipt. The checked-in example is a fixture and therefore can only
//! prove the contract-level ordering rules.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CONTRACT_SCHEMA: &[u8] =
    include_bytes!("../../../contracts/progress-trace/progress-trace.v1.schema.json");
const EXAMPLE_TRACE: &[u8] =
    include_bytes!("../../../contracts/progress-trace/progress-trace-example.v1.json");

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-progress-trace/v1";
pub const CONTRACT_ID: &str = "durable-progress-trace";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-progress-trace-validation/v1";
pub const CONTRACT_AUTHORITY: &str = "eval_only_no_production_authority";
pub const CLOCK_AUTHORITY: &str = "virtual_monotonic/v1";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";

const SEMANTIC_DIGEST_DOMAIN: &str = "hartevo-progress-trace-semantic/v1";
const REQUIRED_RESTART_MARKERS: [RestartPosition; 3] = [
    RestartPosition::BeforeResume,
    RestartPosition::AfterFirstUsefulProgress,
    RestartPosition::BeforeTerminal,
];
const GENERIC_PROGRESS_LABELS: [&str; 6] = [
    "loading",
    "working",
    "still working",
    "processing",
    "heartbeat",
    "in progress",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPosition {
    BeforeResume,
    AfterFirstUsefulProgress,
    BeforeTerminal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    Fixture,
    Simulator,
    Native,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOperation {
    Append,
    Reset,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressClass {
    Useful,
    GenericLoading,
    Heartbeat,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaOperation {
    Append,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceState {
    Durable,
    Ephemeral,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationState {
    Painted,
    Unpainted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeMode {
    Runtime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceScope {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub conversation_id: String,
    pub run_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressIdentity {
    pub scope: TraceScope,
    pub epoch: u64,
    pub cursor: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "authority",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TraceClock {
    #[serde(rename = "virtual_monotonic/v1")]
    VirtualMonotonicV1 { tick_ms: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProgressProvenance {
    Fixture {
        fixture_id: String,
        checked_in: bool,
        native_receipt_id: Option<String>,
    },
    Simulator {
        simulator_id: String,
        deterministic_seed: String,
        native_receipt_id: Option<String>,
    },
    Native {
        native_receipt_id: String,
        native_execution_digest: String,
        checked_in: bool,
    },
}

impl ProgressProvenance {
    pub const fn kind(&self) -> ProvenanceKind {
        match self {
            Self::Fixture { .. } => ProvenanceKind::Fixture,
            Self::Simulator { .. } => ProvenanceKind::Simulator,
            Self::Native { .. } => ProvenanceKind::Native,
        }
    }

    pub const fn satisfies_native(&self) -> bool {
        matches!(self, Self::Native { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwaitingDetails {
    pub persistence: PersistenceState,
    pub presentation: PresentationState,
    pub checkpoint_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirstUsefulProgressDetails {
    pub progress_class: ProgressClass,
    pub generic: bool,
    pub business_step_id: String,
    pub label: String,
    pub detail_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunningDetails {
    pub phase: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeltaDetails {
    pub operation: DeltaOperation,
    pub delta_id: String,
    pub payload_digest: String,
    pub late: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalEnvelopeDetails {
    pub operation: TerminalOperation,
    pub envelope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestartMarkerDetails {
    pub position: RestartPosition,
    pub contract_position_only: bool,
    pub process_kill_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaughtUpDetails {
    pub final_caught_up: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeDetails {
    pub mode: ResumeMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProgressEventBody {
    Awaiting(AwaitingDetails),
    Resume(ResumeDetails),
    FirstUsefulProgress(FirstUsefulProgressDetails),
    Running(RunningDetails),
    Delta(DeltaDetails),
    CaughtUp(CaughtUpDetails),
    TerminalEnvelope(TerminalEnvelopeDetails),
    RestartMarker(RestartMarkerDetails),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressEvent {
    pub event_id: String,
    pub ordinal: u64,
    pub identity: ProgressIdentity,
    pub clock: TraceClock,
    pub event: ProgressEventBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressTrace {
    pub trace_id: String,
    pub scope: TraceScope,
    pub epoch: u64,
    pub initial_cursor: u64,
    pub provenance: ProgressProvenance,
    pub events: Vec<ProgressEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RequiredIdentityRule {
    pub scope: bool,
    pub epoch: bool,
    pub cursor: bool,
    pub every_event: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwaitingRule {
    pub persistence: PersistenceState,
    pub presentation: PresentationState,
    pub before_resume: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirstUsefulProgressRule {
    pub progress_class: ProgressClass,
    pub distinct_from_generic: bool,
    pub requires_business_step: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunningCaughtUpRule {
    pub caught_up_is_non_terminal: bool,
    pub late_delta_legal: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalRule {
    pub operations: Vec<TerminalOperation>,
    pub final_caught_up_required: bool,
    pub final_caught_up_same_cursor: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RejectionRules {
    pub duplicate_event_id: bool,
    pub duplicate_cursor: bool,
    pub skipped_cursor: bool,
    pub cross_scope: bool,
    pub cursor_regression: bool,
    pub post_terminal: bool,
    pub raw_clock_determinism: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockRule {
    pub authority: String,
    pub wall_clock_ordering_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceRule {
    pub allowed_kinds: Vec<ProvenanceKind>,
    pub mixed_sources_allowed: bool,
    pub native_receipt_required: bool,
    pub checked_in_sample_satisfies_native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressTraceContract {
    pub schema_version: String,
    pub contract_id: String,
    pub authority: String,
    pub release_eligible: bool,
    pub required_identity: RequiredIdentityRule,
    pub awaiting: AwaitingRule,
    pub first_useful_progress: FirstUsefulProgressRule,
    pub running_caught_up: RunningCaughtUpRule,
    pub terminal: TerminalRule,
    pub rejection_rules: RejectionRules,
    pub required_restart_markers: Vec<RestartPosition>,
    pub clock: ClockRule,
    pub provenance: ProvenanceRule,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressTraceExample {
    pub schema_version: String,
    pub contract: ProgressTraceContract,
    pub trace: ProgressTrace,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressTraceValidationReport {
    pub schema_version: &'static str,
    pub contract_id: String,
    pub trace_id: String,
    pub passed: bool,
    pub release_decision: &'static str,
    pub release_eligible: bool,
    pub provenance_kind: ProvenanceKind,
    pub native_satisfied: bool,
    pub native_receipt_count: usize,
    pub event_count: usize,
    pub restart_marker_count: usize,
    pub terminal_cursor: u64,
    pub first_useful_progress_event_id: String,
    pub late_delta_event_id: Option<String>,
    pub semantic_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SemanticTrace<'a> {
    contract_id: &'a str,
    trace_id: &'a str,
    scope: &'a TraceScope,
    epoch: u64,
    initial_cursor: u64,
    provenance_kind: ProvenanceKind,
    events: Vec<SemanticEvent<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SemanticEvent<'a> {
    event_id: &'a str,
    ordinal: u64,
    identity: &'a ProgressIdentity,
    event: &'a ProgressEventBody,
}

pub fn validate_progress_trace_example() -> Result<ProgressTraceValidationReport> {
    validate_progress_trace_json(EXAMPLE_TRACE)
}

pub fn validate_progress_trace_json(bytes: &[u8]) -> Result<ProgressTraceValidationReport> {
    validate_schema_document()?;
    let example = serde_json::from_slice::<ProgressTraceExample>(bytes)
        .context("progress trace example is not strict typed JSON")?;
    validate_progress_trace_document(&example)
}

pub fn validate_progress_trace_document(
    example: &ProgressTraceExample,
) -> Result<ProgressTraceValidationReport> {
    ensure!(
        example.schema_version == CONTRACT_SCHEMA_VERSION,
        "progress trace document schemaVersion is invalid"
    );
    validate_contract(&example.contract)?;
    validate_trace(&example.contract, &example.trace)
}

fn validate_schema_document() -> Result<()> {
    let schema = serde_json::from_slice::<Value>(CONTRACT_SCHEMA)
        .context("progress trace schema is not valid JSON")?;
    ensure!(
        schema.get("$id").and_then(Value::as_str)
            == Some("https://hartevo.local/contracts/progress-trace/progress-trace.v1.schema.json"),
        "progress trace schema $id is invalid"
    );
    ensure!(
        schema.get("schemaVersion").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION),
        "progress trace schemaVersion binding is invalid"
    );
    ensure!(
        schema.get("additionalProperties").and_then(Value::as_bool) == Some(false),
        "progress trace schema must be closed"
    );
    Ok(())
}

fn validate_contract(contract: &ProgressTraceContract) -> Result<()> {
    ensure!(
        contract.schema_version == CONTRACT_SCHEMA_VERSION
            && contract.contract_id == CONTRACT_ID
            && contract.authority == CONTRACT_AUTHORITY
            && !contract.release_eligible,
        "progress trace contract identity or release boundary is invalid"
    );
    ensure!(
        contract.required_identity
            == (RequiredIdentityRule {
                scope: true,
                epoch: true,
                cursor: true,
                every_event: true,
            }),
        "progress trace must require scope, epoch and cursor on every event"
    );
    ensure!(
        contract.awaiting
            == (AwaitingRule {
                persistence: PersistenceState::Durable,
                presentation: PresentationState::Painted,
                before_resume: true,
            }),
        "progress trace Awaiting rule is not durable-and-painted"
    );
    ensure!(
        contract.first_useful_progress
            == (FirstUsefulProgressRule {
                progress_class: ProgressClass::Useful,
                distinct_from_generic: true,
                requires_business_step: true,
            }),
        "progress trace first-useful-progress rule is too weak"
    );
    ensure!(
        contract.running_caught_up
            == (RunningCaughtUpRule {
                caught_up_is_non_terminal: true,
                late_delta_legal: true,
            }),
        "Running+CaughtUp must remain non-terminal and allow late delta"
    );
    ensure!(
        contract.terminal
            == (TerminalRule {
                operations: vec![TerminalOperation::Append, TerminalOperation::Reset],
                final_caught_up_required: true,
                final_caught_up_same_cursor: true,
            }),
        "terminal envelope rule is invalid"
    );
    ensure!(
        contract.rejection_rules
            == (RejectionRules {
                duplicate_event_id: true,
                duplicate_cursor: true,
                skipped_cursor: true,
                cross_scope: true,
                cursor_regression: true,
                post_terminal: true,
                raw_clock_determinism: true,
            }),
        "progress trace rejection rules are incomplete"
    );
    ensure!(
        contract.required_restart_markers == REQUIRED_RESTART_MARKERS,
        "progress trace requires the three contract-position restart markers"
    );
    ensure!(
        contract.clock
            == (ClockRule {
                authority: CLOCK_AUTHORITY.to_owned(),
                wall_clock_ordering_allowed: false,
            }),
        "progress trace must use virtual monotonic ordering"
    );
    ensure!(
        contract.provenance
            == (ProvenanceRule {
                allowed_kinds: vec![
                    ProvenanceKind::Fixture,
                    ProvenanceKind::Simulator,
                    ProvenanceKind::Native,
                ],
                mixed_sources_allowed: false,
                native_receipt_required: true,
                checked_in_sample_satisfies_native: false,
            }),
        "progress trace provenance separation rule is invalid"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_trace(
    contract: &ProgressTraceContract,
    trace: &ProgressTrace,
) -> Result<ProgressTraceValidationReport> {
    validate_trace_identity(trace)?;
    validate_provenance(contract, &trace.provenance)?;
    ensure!(!trace.events.is_empty(), "progress trace cannot be empty");

    let mut event_ids = BTreeSet::new();
    let mut delta_ids = BTreeSet::new();
    let mut restart_markers = BTreeSet::new();
    let mut previous_tick = None;
    let mut current_cursor = trace.initial_cursor;
    let mut awaiting_seen = false;
    let mut resume_seen = false;
    let mut first_useful_progress_seen = false;
    let mut running_seen = false;
    let mut nonterminal_caught_up = false;
    let mut terminal_seen = false;
    let mut final_caught_up_seen = false;
    let mut terminal_cursor = None;
    let mut first_useful_progress_event_id = None;
    let mut late_delta_event_id = None;
    let mut first_useful_cursor = None;

    for (index, event) in trace.events.iter().enumerate() {
        let index = u64::try_from(index).context("progress trace has too many events")?;
        ensure!(
            event.ordinal == index,
            "progress trace event ordinal is skipped or duplicated at index {index}"
        );
        ensure!(
            !event.event_id.is_empty() && event_ids.insert(event.event_id.clone()),
            "progress trace contains a duplicate or empty event id"
        );
        ensure!(
            event.identity.scope == trace.scope && event.identity.epoch == trace.epoch,
            "progress trace event crosses durable scope or epoch"
        );
        ensure!(
            event.identity.cursor >= trace.initial_cursor,
            "progress trace cursor regressed before its initial cursor"
        );
        validate_clock(event.clock, &mut previous_tick)?;

        if final_caught_up_seen {
            bail!("progress trace contains an event after final CaughtUp");
        }
        if terminal_seen {
            ensure!(
                matches!(
                    &event.event,
                    ProgressEventBody::CaughtUp(CaughtUpDetails {
                        final_caught_up: true
                    })
                ),
                "only same-cursor final CaughtUp may follow a terminal envelope"
            );
        }

        match &event.event {
            ProgressEventBody::Awaiting(details) => {
                ensure!(
                    index == 0 && !awaiting_seen,
                    "Awaiting must be the first event"
                );
                ensure!(
                    event.identity.cursor == trace.initial_cursor,
                    "Awaiting must use the durable initial cursor"
                );
                ensure!(
                    details.persistence == contract.awaiting.persistence
                        && details.presentation == contract.awaiting.presentation
                        && !details.checkpoint_id.is_empty(),
                    "Awaiting must be persisted and painted before resume"
                );
                awaiting_seen = true;
            }
            ProgressEventBody::Resume(details) => {
                ensure!(
                    awaiting_seen && !resume_seen,
                    "Runtime resume requires one prior durable painted Awaiting"
                );
                ensure!(
                    details.mode == ResumeMode::Runtime && event.identity.cursor == current_cursor,
                    "Runtime resume changed the durable cursor"
                );
                resume_seen = true;
            }
            ProgressEventBody::FirstUsefulProgress(details) => {
                ensure!(
                    resume_seen && !first_useful_progress_seen,
                    "invalid first useful progress position"
                );
                ensure!(
                    details.progress_class == contract.first_useful_progress.progress_class
                        && !details.generic
                        && !details.business_step_id.is_empty()
                        && !is_generic_progress_label(&details.label),
                    "first useful progress is generic loading or heartbeat text"
                );
                validate_digest(&details.detail_digest, "first useful progress detail")?;
                let next_cursor = next_cursor(current_cursor)?;
                ensure!(
                    event.identity.cursor == next_cursor,
                    "first useful progress skipped or duplicated the durable cursor"
                );
                current_cursor = event.identity.cursor;
                first_useful_progress_seen = true;
                first_useful_cursor = Some(current_cursor);
                first_useful_progress_event_id = Some(event.event_id.clone());
            }
            ProgressEventBody::Running(details) => {
                ensure!(
                    first_useful_progress_seen && !running_seen && !terminal_seen,
                    "Running must follow first useful progress and precede terminal"
                );
                ensure!(
                    details.phase == "running" && event.identity.cursor == current_cursor,
                    "Running changed the durable cursor or phase"
                );
                running_seen = true;
            }
            ProgressEventBody::Delta(details) => {
                ensure!(
                    running_seen && !terminal_seen,
                    "delta is outside the Running window"
                );
                ensure!(
                    details.operation == DeltaOperation::Append
                        && !details.delta_id.is_empty()
                        && delta_ids.insert(details.delta_id.clone()),
                    "delta is duplicate or not append-only"
                );
                validate_digest(&details.payload_digest, "delta payload")?;
                ensure!(
                    details.late == nonterminal_caught_up,
                    "late delta marker does not match the preceding Running+CaughtUp state"
                );
                let next_cursor = next_cursor(current_cursor)?;
                ensure!(
                    event.identity.cursor == next_cursor,
                    "delta cursor is duplicated, skipped, or regressed"
                );
                current_cursor = event.identity.cursor;
                nonterminal_caught_up = false;
                if details.late {
                    late_delta_event_id = Some(event.event_id.clone());
                }
            }
            ProgressEventBody::CaughtUp(details) => {
                ensure!(
                    running_seen && event.identity.cursor == current_cursor,
                    "CaughtUp is outside the current Running cursor"
                );
                if details.final_caught_up {
                    ensure!(
                        terminal_seen && !final_caught_up_seen,
                        "final CaughtUp requires a preceding terminal envelope"
                    );
                    ensure!(
                        terminal_cursor == Some(current_cursor),
                        "final CaughtUp cursor does not match terminal envelope cursor"
                    );
                    final_caught_up_seen = true;
                } else {
                    ensure!(!terminal_seen, "non-final CaughtUp is post-terminal");
                    ensure!(
                        !nonterminal_caught_up,
                        "duplicate non-final CaughtUp at the same cursor"
                    );
                    nonterminal_caught_up = true;
                }
            }
            ProgressEventBody::TerminalEnvelope(details) => {
                ensure!(
                    running_seen && !terminal_seen,
                    "terminal envelope must follow Running exactly once"
                );
                ensure!(
                    contract.terminal.operations.contains(&details.operation),
                    "terminal envelope operation is not in the contract"
                );
                validate_digest(&details.envelope_digest, "terminal envelope")?;
                let next_cursor = next_cursor(current_cursor)?;
                ensure!(
                    event.identity.cursor == next_cursor,
                    "terminal envelope cursor is duplicated, skipped, or regressed"
                );
                current_cursor = event.identity.cursor;
                terminal_cursor = Some(current_cursor);
                terminal_seen = true;
            }
            ProgressEventBody::RestartMarker(details) => {
                ensure!(
                    details.contract_position_only && !details.process_kill_observed,
                    "restart marker cannot claim a real process kill"
                );
                ensure!(
                    event.identity.cursor == current_cursor,
                    "restart marker changed the durable cursor"
                );
                ensure!(
                    restart_markers.insert(details.position),
                    "duplicate restart marker position"
                );
                validate_restart_position(
                    details.position,
                    awaiting_seen,
                    resume_seen,
                    first_useful_progress_seen,
                    first_useful_cursor,
                    current_cursor,
                    running_seen,
                    nonterminal_caught_up,
                    terminal_seen,
                )?;
            }
        }
    }

    ensure!(awaiting_seen, "trace has no durable Awaiting state");
    ensure!(resume_seen, "trace has no Runtime resume after Awaiting");
    ensure!(
        first_useful_progress_seen,
        "trace has no first useful business progress"
    );
    ensure!(running_seen, "trace has no Running state");
    ensure!(
        terminal_seen && final_caught_up_seen,
        "trace has no terminal envelope plus final CaughtUp"
    );
    ensure!(
        restart_markers.iter().copied().collect::<Vec<_>>() == REQUIRED_RESTART_MARKERS,
        "trace must contain the three distinct restart contract positions"
    );

    let first_useful_progress_event_id = first_useful_progress_event_id
        .context("first useful progress event id was not recorded")?;
    let terminal_cursor = terminal_cursor.context("terminal cursor was not recorded")?;
    let semantic_digest = semantic_digest(contract, trace)?;
    let native_satisfied = trace.provenance.satisfies_native();
    Ok(ProgressTraceValidationReport {
        schema_version: VALIDATION_SCHEMA_VERSION,
        contract_id: contract.contract_id.clone(),
        trace_id: trace.trace_id.clone(),
        passed: true,
        release_decision: RELEASE_DECISION,
        release_eligible: contract.release_eligible,
        provenance_kind: trace.provenance.kind(),
        native_satisfied,
        native_receipt_count: usize::from(native_satisfied),
        event_count: trace.events.len(),
        restart_marker_count: restart_markers.len(),
        terminal_cursor,
        first_useful_progress_event_id,
        late_delta_event_id,
        semantic_digest,
    })
}

fn validate_trace_identity(trace: &ProgressTrace) -> Result<()> {
    ensure!(
        !trace.trace_id.is_empty(),
        "progress trace traceId is empty"
    );
    ensure!(trace.epoch > 0, "progress trace epoch must be positive");
    for (label, value) in [
        ("tenantId", &trace.scope.tenant_id),
        ("projectId", &trace.scope.project_id),
        ("missionId", &trace.scope.mission_id),
        ("conversationId", &trace.scope.conversation_id),
        ("runId", &trace.scope.run_id),
    ] {
        ensure!(!value.is_empty(), "progress trace {label} is empty");
    }
    Ok(())
}

fn validate_provenance(
    contract: &ProgressTraceContract,
    provenance: &ProgressProvenance,
) -> Result<()> {
    ensure!(
        contract
            .provenance
            .allowed_kinds
            .contains(&provenance.kind()),
        "progress trace provenance kind is not allowed"
    );
    match provenance {
        ProgressProvenance::Fixture {
            fixture_id,
            checked_in,
            native_receipt_id,
        } => {
            ensure!(
                !fixture_id.is_empty() && *checked_in,
                "fixture provenance is invalid"
            );
            ensure!(
                native_receipt_id.is_none(),
                "fixture provenance cannot carry a native receipt"
            );
        }
        ProgressProvenance::Simulator {
            simulator_id,
            deterministic_seed,
            native_receipt_id,
        } => {
            ensure!(
                !simulator_id.is_empty() && !deterministic_seed.is_empty(),
                "simulator provenance is invalid"
            );
            ensure!(
                native_receipt_id.is_none(),
                "simulator provenance cannot carry a native receipt"
            );
        }
        ProgressProvenance::Native {
            native_receipt_id,
            native_execution_digest,
            checked_in,
        } => {
            ensure!(
                contract.provenance.native_receipt_required
                    && !native_receipt_id.is_empty()
                    && !*checked_in,
                "native provenance requires an external, non-checked-in receipt"
            );
            validate_digest(native_execution_digest, "native execution")?;
        }
    }
    Ok(())
}

fn validate_clock(clock: TraceClock, previous_tick: &mut Option<u64>) -> Result<()> {
    let TraceClock::VirtualMonotonicV1 { tick_ms } = clock;
    if let Some(previous_tick) = previous_tick {
        ensure!(
            tick_ms > *previous_tick,
            "virtual monotonic clock must increase with trace ordinal"
        );
    }
    *previous_tick = Some(tick_ms);
    Ok(())
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn validate_restart_position(
    position: RestartPosition,
    awaiting_seen: bool,
    resume_seen: bool,
    first_useful_progress_seen: bool,
    first_useful_cursor: Option<u64>,
    current_cursor: u64,
    running_seen: bool,
    nonterminal_caught_up: bool,
    terminal_seen: bool,
) -> Result<()> {
    match position {
        RestartPosition::BeforeResume => ensure!(
            awaiting_seen && !resume_seen && !first_useful_progress_seen,
            "before_resume marker is not at its contract position"
        ),
        RestartPosition::AfterFirstUsefulProgress => ensure!(
            first_useful_progress_seen
                && !running_seen
                && !terminal_seen
                && first_useful_cursor == Some(current_cursor),
            "after_first_useful_progress marker is not at its contract position"
        ),
        RestartPosition::BeforeTerminal => ensure!(
            running_seen && nonterminal_caught_up && !terminal_seen,
            "before_terminal marker is not at its contract position"
        ),
    }
    Ok(())
}

fn is_generic_progress_label(label: &str) -> bool {
    let normalized = label.trim().to_ascii_lowercase();
    GENERIC_PROGRESS_LABELS
        .iter()
        .any(|generic| normalized == *generic)
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} digest must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn next_cursor(cursor: u64) -> Result<u64> {
    cursor
        .checked_add(1)
        .context("progress trace cursor overflow")
}

fn semantic_digest(contract: &ProgressTraceContract, trace: &ProgressTrace) -> Result<String> {
    let events = trace
        .events
        .iter()
        .map(|event| SemanticEvent {
            event_id: &event.event_id,
            ordinal: event.ordinal,
            identity: &event.identity,
            event: &event.event,
        })
        .collect::<Vec<_>>();
    let material = SemanticTrace {
        contract_id: &contract.contract_id,
        trace_id: &trace.trace_id,
        scope: &trace.scope,
        epoch: trace.epoch,
        initial_cursor: trace.initial_cursor,
        provenance_kind: trace.provenance.kind(),
        events,
    };
    let bytes = serde_json::to_vec(&material).context("serialize semantic progress trace")?;
    Ok(hex::encode(Sha256::digest(
        [SEMANTIC_DIGEST_DOMAIN.as_bytes(), &[0], &bytes].concat(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_example() -> ProgressTraceExample {
        serde_json::from_slice(EXAMPLE_TRACE).expect("checked-in progress trace example")
    }

    fn validate(example: &ProgressTraceExample) -> Result<ProgressTraceValidationReport> {
        validate_progress_trace_document(example)
    }

    fn event_mut<'a>(
        example: &'a mut ProgressTraceExample,
        event_id: &str,
    ) -> &'a mut ProgressEvent {
        example
            .trace
            .events
            .iter_mut()
            .find(|event| event.event_id == event_id)
            .expect("fixture event")
    }

    #[test]
    fn checked_in_example_passes_without_native_receipt_or_release_authority() {
        let report = validate_progress_trace_example().expect("progress trace example");
        assert!(report.passed);
        assert_eq!(report.provenance_kind, ProvenanceKind::Fixture);
        assert!(!report.native_satisfied);
        assert_eq!(report.native_receipt_count, 0);
        assert!(!report.release_eligible);
        assert_eq!(report.release_decision, RELEASE_DECISION);
        assert_eq!(report.restart_marker_count, 3);
        assert!(report.late_delta_event_id.is_some());
    }

    #[test]
    fn awaiting_must_be_durable_and_painted_before_runtime_resume() {
        let mut example = load_example();
        if let ProgressEventBody::Awaiting(details) =
            &mut event_mut(&mut example, "evt-awaiting").event
        {
            details.presentation = PresentationState::Unpainted;
        }
        assert!(validate(&example).is_err());

        let mut example = load_example();
        example.trace.events.swap(0, 2);
        assert!(validate(&example).is_err());
    }

    #[test]
    fn generic_loading_is_not_first_useful_progress() {
        let mut example = load_example();
        if let ProgressEventBody::FirstUsefulProgress(details) =
            &mut event_mut(&mut example, "evt-first-useful").event
        {
            details.progress_class = ProgressClass::GenericLoading;
            details.generic = true;
            details.label = "Working".into();
        }
        assert!(validate(&example).is_err());
    }

    #[test]
    fn running_caught_up_is_non_terminal_and_late_delta_is_legal() {
        let report = validate_progress_trace_example().expect("progress trace example");
        assert_eq!(
            report.late_delta_event_id.as_deref(),
            Some("evt-late-delta")
        );

        let mut example = load_example();
        if let ProgressEventBody::CaughtUp(details) =
            &mut event_mut(&mut example, "evt-caught-up").event
        {
            details.final_caught_up = true;
        }
        assert!(validate(&example).is_err());
    }

    #[test]
    fn terminal_append_and_reset_require_same_cursor_final_caught_up() {
        let mut example = load_example();
        if let ProgressEventBody::TerminalEnvelope(details) =
            &mut event_mut(&mut example, "evt-terminal").event
        {
            details.operation = TerminalOperation::Reset;
        }
        validate(&example).expect("terminal reset is also a contract operation");

        let mut example = load_example();
        event_mut(&mut example, "evt-terminal").identity.cursor += 1;
        assert!(validate(&example).is_err());

        let mut example = load_example();
        event_mut(&mut example, "evt-final-caught-up")
            .identity
            .cursor -= 1;
        assert!(validate(&example).is_err());
    }

    #[test]
    fn duplicate_skipped_cross_scope_and_regressed_cursors_fail_closed() {
        let mut duplicate = load_example();
        event_mut(&mut duplicate, "evt-late-delta").event_id = "evt-delta".into();
        assert!(validate(&duplicate).is_err());

        let mut skipped = load_example();
        event_mut(&mut skipped, "evt-delta").identity.cursor += 2;
        assert!(validate(&skipped).is_err());

        let mut cross_scope = load_example();
        event_mut(&mut cross_scope, "evt-delta")
            .identity
            .scope
            .project_id = "other-project".into();
        assert!(validate(&cross_scope).is_err());

        let mut regression = load_example();
        event_mut(&mut regression, "evt-late-delta").identity.cursor = 1;
        assert!(validate(&regression).is_err());
    }

    #[test]
    fn post_terminal_and_process_kill_claims_fail_closed() {
        let mut post_terminal = load_example();
        let mut extra = event_mut(&mut post_terminal, "evt-final-caught-up").clone();
        extra.event_id = "evt-after-terminal".into();
        extra.ordinal = 13;
        post_terminal.trace.events.push(extra);
        assert!(validate(&post_terminal).is_err());

        let mut process_kill_claim = load_example();
        if let ProgressEventBody::RestartMarker(details) =
            &mut event_mut(&mut process_kill_claim, "evt-restart-before-resume").event
        {
            details.process_kill_observed = true;
        }
        assert!(validate(&process_kill_claim).is_err());
    }

    #[test]
    fn raw_wall_clock_and_mixed_native_provenance_are_rejected() {
        let mut raw_clock: Value = serde_json::from_slice(EXAMPLE_TRACE).expect("example JSON");
        raw_clock["trace"]["events"][0]["clock"]["authority"] = Value::String("wall_clock".into());
        let raw_clock = serde_json::to_vec(&raw_clock).expect("mutated JSON");
        assert!(validate_progress_trace_json(&raw_clock).is_err());

        let mut mixed = load_example();
        mixed.trace.provenance = ProgressProvenance::Fixture {
            fixture_id: "durable-progress-fixture-v1".into(),
            checked_in: true,
            native_receipt_id: Some("forbidden-native-receipt".into()),
        };
        assert!(validate(&mixed).is_err());

        let mut checked_in_native = load_example();
        checked_in_native.trace.provenance = ProgressProvenance::Native {
            native_receipt_id: "native-receipt".into(),
            native_execution_digest: "a".repeat(64),
            checked_in: true,
        };
        assert!(validate(&checked_in_native).is_err());
    }

    #[test]
    fn semantic_digest_ignores_virtual_clock_ticks_but_not_business_order() {
        let first = validate_progress_trace_example().expect("first validation");
        let mut clock_shifted = load_example();
        for (index, event) in clock_shifted.trace.events.iter_mut().enumerate() {
            let tick = u64::try_from(index + 1).expect("small fixture index");
            event.clock = TraceClock::VirtualMonotonicV1 {
                tick_ms: tick * 100,
            };
        }
        let shifted = validate(&clock_shifted).expect("shifted virtual clock");
        assert_eq!(first.semantic_digest, shifted.semantic_digest);

        let mut reordered = load_example();
        reordered.trace.events.swap(6, 8);
        assert!(validate(&reordered).is_err());
    }
}

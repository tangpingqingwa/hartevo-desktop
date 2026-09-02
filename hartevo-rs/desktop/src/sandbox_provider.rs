use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use command_group::{CommandGroup, GroupChild};
#[cfg(test)]
use hartevo_cordis::Context;
use hartevo_cordis::{
    ConfinedArgv, ConfinedSandboxMode, ConfinedSandboxPolicy, CordisError, CordisHost,
    LifecycleCancellation, SandboxEnforcement, SandboxError, SandboxExecutionEnvironment,
    SandboxExecutionPlan, SandboxMode, SandboxPolicyRequest, SandboxProcessClassification,
    SandboxProvider, SandboxProviderUnavailable, SandboxRunnerFailureRule, SessionContentBlock,
    SessionToolSchema, ToolDefinition, ToolRunContext, classify_sandbox_process,
    consume_sandbox_escalation_approval, plan_sandbox_escalation_approval,
    register_sandbox_provider, register_tool_definition, validate_sandbox_escalation_args,
};
use thiserror::Error;

const SEATBELT_EXEC: &str = "/usr/bin/sandbox-exec";
const SEATBELT_READ_ONLY_PROFILE: &str =
    "(version 1) (allow default) (deny file-write*) (allow file-write* (literal \"/dev/null\"))";
const SANDBOX_PROCESS_TIMEOUT_MS: f64 = 120_000.0;
const SANDBOX_PROCESS_MAX_TIMEOUT_MS: f64 = 600_000.0;
const SANDBOX_PROCESS_OUTPUT_BYTES: usize = 64_000;
const SANDBOX_PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const BASH_ENVIRONMENT_OVERRIDES: [(&str, &str); 4] = [
    ("NO_COLOR", "1"),
    ("TERM", "dumb"),
    ("PAGER", "cat"),
    ("GIT_PAGER", "cat"),
];
const SENSITIVE_ENVIRONMENT_FRAGMENTS: [&str; 4] = ["KEY", "PASSWORD", "SECRET", "TOKEN"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SandboxProcessTermination {
    Completed,
    TimedOut,
    Cancelled,
}

pub(crate) struct SandboxProcessOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) byte_count: u64,
    pub(crate) truncated: bool,
}

impl std::fmt::Debug for SandboxProcessOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxProcessOutput")
            .field("byte_count", &self.byte_count)
            .field("retained_byte_count", &self.bytes.len())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

pub(crate) struct SandboxedProcessOutcome {
    pub(crate) exit_code: Option<i32>,
    pub(crate) termination: SandboxProcessTermination,
    pub(crate) timeout_ms: f64,
    pub(crate) mode: SandboxMode,
    pub(crate) enforcement: Option<SandboxEnforcement>,
    pub(crate) classification: Option<SandboxProcessClassification>,
    pub(crate) stdout: SandboxProcessOutput,
    pub(crate) stderr: SandboxProcessOutput,
}

impl std::fmt::Debug for SandboxedProcessOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxedProcessOutcome")
            .field("exit_code", &self.exit_code)
            .field("termination", &self.termination)
            .field("timeout_ms", &self.timeout_ms)
            .field("mode", &self.mode)
            .field("enforcement", &self.enforcement)
            .field("classification", &self.classification)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish()
    }
}

#[derive(Debug, Error)]
pub(crate) enum SandboxProcessError {
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error("sandbox process was cancelled before spawn")]
    CancelledBeforeSpawn,
    #[error("sandbox process workspace is unusable: {detail}")]
    UnusableWorkspace { detail: String },
    #[error("sandbox process working directory is unusable: {detail}")]
    UnusableWorkingDirectory { detail: String },
    #[error("sandbox process failed to spawn: {source}")]
    Spawn {
        #[source]
        source: io::Error,
    },
    #[error("sandbox process lifecycle failed: {source}")]
    Lifecycle {
        #[source]
        source: io::Error,
    },
    #[error("sandbox process output collection failed: {source}")]
    Output {
        #[source]
        source: io::Error,
    },
    #[error("sandbox process output collector stopped unexpectedly")]
    OutputCollectorStopped,
}

impl SandboxProcessError {
    #[must_use]
    pub(crate) const fn code(&self) -> Option<&'static str> {
        match self {
            Self::Sandbox(error) => error.code(),
            Self::CancelledBeforeSpawn
            | Self::UnusableWorkspace { .. }
            | Self::UnusableWorkingDirectory { .. }
            | Self::Spawn { .. }
            | Self::Lifecycle { .. }
            | Self::Output { .. }
            | Self::OutputCollectorStopped => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ResolvedBashTimeout {
    duration: Duration,
    milliseconds: f64,
}

impl Default for ResolvedBashTimeout {
    fn default() -> Self {
        Self {
            duration: Duration::from_mins(2),
            milliseconds: SANDBOX_PROCESS_TIMEOUT_MS,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SandboxProcessLimits {
    timeout: Duration,
    timeout_ms: f64,
    output_bytes: usize,
    poll_interval: Duration,
}

impl SandboxProcessLimits {
    fn with_timeout(timeout: ResolvedBashTimeout) -> Self {
        Self {
            timeout: timeout.duration,
            timeout_ms: timeout.milliseconds,
            ..Self::default()
        }
    }
}

impl Default for SandboxProcessLimits {
    fn default() -> Self {
        Self {
            timeout: ResolvedBashTimeout::default().duration,
            timeout_ms: SANDBOX_PROCESS_TIMEOUT_MS,
            output_bytes: SANDBOX_PROCESS_OUTPUT_BYTES,
            poll_interval: SANDBOX_PROCESS_POLL_INTERVAL,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct MacosSeatbeltSandboxProvider;

impl SandboxProvider for MacosSeatbeltSandboxProvider {
    fn confine(
        &self,
        argv: &[OsString],
        policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        let profile = seatbelt_profile(policy)?;
        let mut wrapped = Vec::with_capacity(argv.len() + 4);
        wrapped.extend([
            OsString::from(SEATBELT_EXEC),
            OsString::from("-p"),
            OsString::from(profile),
            OsString::from("--"),
        ]);
        wrapped.extend_from_slice(argv);
        Ok(ConfinedArgv::new(
            wrapped,
            SandboxEnforcement::Full,
            vec!["operation not permitted".to_string()],
            vec![SandboxRunnerFailureRule::new(["sandbox-exec: "])],
        ))
    }
}

pub(crate) fn mount_macos_sandbox_provider(host: &mut CordisHost) -> Result<(), CordisError> {
    register_sandbox_provider(host.context_mut(), MacosSeatbeltSandboxProvider).map(|_| ())
}

pub(crate) fn mount_macos_sandboxed_bash_tool(host: &mut CordisHost) -> Result<(), CordisError> {
    let environment = SandboxExecutionEnvironment::capture(host.context()).map_err(|error| {
        CordisError::SandboxPolicyInitialization {
            detail: error.to_string(),
        }
    })?;
    register_tool_definition(host.context_mut(), sandboxed_bash_definition(environment)).map(|_| ())
}

/// Run one exact argv through the currently resolved Cordis sandbox policy.
///
/// This is the shared Desktop process boundary for the next concrete Cordis
/// tool adapter. It deliberately owns only foreground process mechanics; the
/// existing Cordis tool pipeline remains the sole tool system.
#[cfg(test)]
pub(crate) fn run_sandboxed_process(
    ctx: &Context,
    argv: Vec<OsString>,
    policy_request: SandboxPolicyRequest,
    cancellation: &LifecycleCancellation,
) -> Result<SandboxedProcessOutcome, SandboxProcessError> {
    let environment = SandboxExecutionEnvironment::capture(ctx)?;
    run_sandboxed_process_in_environment(&environment, argv, policy_request, None, cancellation)
}

#[cfg(test)]
fn run_sandboxed_process_in_environment(
    environment: &SandboxExecutionEnvironment,
    argv: Vec<OsString>,
    policy_request: SandboxPolicyRequest,
    working_directory: Option<&Path>,
    cancellation: &LifecycleCancellation,
) -> Result<SandboxedProcessOutcome, SandboxProcessError> {
    run_sandboxed_process_in_environment_with_limits(
        environment,
        argv,
        policy_request,
        working_directory,
        &[],
        cancellation,
        SandboxProcessLimits::default(),
    )
}

#[cfg(test)]
fn run_sandboxed_process_with_limits(
    ctx: &Context,
    argv: Vec<OsString>,
    policy_request: SandboxPolicyRequest,
    cancellation: &LifecycleCancellation,
    limits: SandboxProcessLimits,
) -> Result<SandboxedProcessOutcome, SandboxProcessError> {
    let environment = SandboxExecutionEnvironment::capture(ctx)?;
    run_sandboxed_process_in_environment_with_limits(
        &environment,
        argv,
        policy_request,
        None,
        &[],
        cancellation,
        limits,
    )
}

fn run_sandboxed_process_in_environment_with_limits(
    environment: &SandboxExecutionEnvironment,
    argv: Vec<OsString>,
    policy_request: SandboxPolicyRequest,
    working_directory: Option<&Path>,
    managed_environment: &[(&str, &str)],
    cancellation: &LifecycleCancellation,
    limits: SandboxProcessLimits,
) -> Result<SandboxedProcessOutcome, SandboxProcessError> {
    if cancellation.is_cancelled() {
        return Err(SandboxProcessError::CancelledBeforeSpawn);
    }
    let policy = environment.resolve(policy_request)?;
    let plan = environment.prepare(argv, policy)?;
    let workspace = usable_workspace(plan.workspace_root())?;
    let working_directory = working_directory
        .map(usable_working_directory)
        .transpose()?
        .unwrap_or(workspace);
    if cancellation.is_cancelled() {
        return Err(SandboxProcessError::CancelledBeforeSpawn);
    }

    let (program, arguments) = plan
        .argv()
        .split_first()
        .expect("Cordis validates every prepared process argv");
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(&working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_bash_environment(&mut command, std::env::vars_os(), managed_environment);
    let mut child = command
        .group_spawn()
        .map_err(|source| spawn_error(&plan, &working_directory, source))?;
    let stdout = child.inner().stdout.take().ok_or_else(|| {
        terminate_group_best_effort(&mut child);
        SandboxProcessError::Output {
            source: io::Error::other("sandbox process stdout pipe is unavailable"),
        }
    })?;
    let stderr = child.inner().stderr.take().ok_or_else(|| {
        terminate_group_best_effort(&mut child);
        SandboxProcessError::Output {
            source: io::Error::other("sandbox process stderr pipe is unavailable"),
        }
    })?;

    let stdout_reader =
        spawn_output_collector("hartevo-sandbox-stdout", stdout, limits.output_bytes).map_err(
            |source| {
                terminate_group_best_effort(&mut child);
                SandboxProcessError::Output { source }
            },
        )?;
    let stderr_reader =
        match spawn_output_collector("hartevo-sandbox-stderr", stderr, limits.output_bytes) {
            Ok(reader) => reader,
            Err(source) => {
                terminate_group_best_effort(&mut child);
                let _ = stdout_reader.join();
                return Err(SandboxProcessError::Output { source });
            }
        };

    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .unwrap_or_else(Instant::now);
    let wait = wait_for_process(&mut child, cancellation, deadline, limits.poll_interval);
    let stdout = join_output_collector(stdout_reader);
    let stderr = join_output_collector(stderr_reader);
    let (status, termination) = wait?;
    let stdout = stdout?;
    let stderr = stderr?;
    settle_sandboxed_process(
        &plan,
        status,
        termination,
        limits.timeout_ms,
        stdout,
        stderr,
    )
}

fn configure_bash_environment(
    command: &mut Command,
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    managed: &[(&str, &str)],
) {
    command.env_clear();
    command.envs(scrubbed_parent_environment(parent));
    command.envs(BASH_ENVIRONMENT_OVERRIDES);
    command.envs(managed.iter().copied());
}

fn scrubbed_parent_environment(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    parent
        .into_iter()
        .filter(|(key, _)| !environment_key_is_sensitive_or_managed(key))
        .collect()
}

fn environment_key_is_sensitive_or_managed(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return true;
    };
    let key = key.to_ascii_uppercase();
    key.starts_with("DSH_")
        || SENSITIVE_ENVIRONMENT_FRAGMENTS
            .iter()
            .any(|fragment| key.contains(fragment))
}

fn sandboxed_bash_definition(environment: SandboxExecutionEnvironment) -> ToolDefinition {
    let approval_environment = environment.clone();
    ToolDefinition::new_with_run_context(sandboxed_bash_schema(), move |run| {
        execute_sandboxed_bash(&environment, run)
    })
    .with_approval_requirement(move |input| {
        let arguments = sandboxed_bash_arguments(input.arguments())?;
        let session = approval_environment
            .live_session(input.session_id())
            .map_err(|error| sandbox_error_message(&error))?;
        let policy = approval_environment
            .resolve(
                SandboxPolicyRequest::for_session(&session)
                    .with_call_id(input.call_id())
                    .map_err(|error| sandbox_error_message(&error))?,
            )
            .map_err(|error| sandbox_error_message(&error))?;
        resolve_bash_workdir(policy.workspace_root(), arguments.workdir.as_deref())
            .map_err(|error| sandbox_process_error_message(&error))?;
        plan_sandbox_escalation_approval(
            input,
            &policy,
            arguments.sandbox_permissions,
            arguments.justification.as_deref(),
            "command",
        )
        .map_err(|error| sandbox_error_message(&error))
    })
    .with_output_renderer(|_, value| {
        let output = value
            .get("output")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "bash result output is invalid".to_string())?;
        Ok(vec![SessionContentBlock::Text {
            text: output.to_string(),
        }])
    })
}

pub(crate) fn sandboxed_bash_schema() -> SessionToolSchema {
    let properties = serde_json::Map::from_iter([
        (
            "command".into(),
            serde_json::json!({
                "type": "string",
                "description": "Shell command to execute in a fresh foreground bash process"
            }),
        ),
        (
            "description".into(),
            serde_json::json!({
                "type": "string",
                "description": "Short explanation of what the command does"
            }),
        ),
        (
            "workdir".into(),
            serde_json::json!({
                "type": "string",
                "description": "Working directory for this call; relative paths resolve from the session workspace"
            }),
        ),
        (
            "timeoutMs".into(),
            serde_json::json!({
                "type": "number",
                "description": "Foreground timeout in milliseconds; defaults to 120000 and is capped at 600000"
            }),
        ),
        (
            "sandbox_permissions".into(),
            serde_json::json!({
                "type": "string",
                "enum": ["workspace-write", "danger-full-access"],
                "description": "One wider sandbox mode for this exact call; requires justification and user approval"
            }),
        ),
        (
            "justification".into(),
            serde_json::json!({
                "type": "string",
                "description": "Required with sandbox_permissions: why this exact command needs wider file access"
            }),
        ),
    ]);
    SessionToolSchema {
        name: "bash".into(),
        description: "Run one foreground bash command through the Desktop sandbox. Each call uses a fresh shell; workdir defaults to the session workspace and timeoutMs defaults to 120000 with a 600000 cap. Trusted current-Session facts are available through managed $DSH_* variables. A denied command may be retried once with the narrowest wider sandbox_permissions plus justification; the retry asks the user before execution.".into(),
        parameters: serde_json::Map::from_iter([
            ("type".into(), serde_json::json!("object")),
            ("additionalProperties".into(), serde_json::json!(false)),
            ("properties".into(), serde_json::Value::Object(properties)),
            (
                "required".into(),
                serde_json::json!(["command", "description"]),
            ),
        ]),
    }
}

fn execute_sandboxed_bash(
    environment: &SandboxExecutionEnvironment,
    run: &ToolRunContext,
) -> Result<serde_json::Value, String> {
    let arguments = sandboxed_bash_arguments(run.arguments())?;
    let session = environment
        .live_session(run.session_id())
        .map_err(|error| sandbox_error_message(&error))?;
    let standing_policy = environment
        .resolve(
            SandboxPolicyRequest::for_session(&session)
                .with_call_id(run.call_id())
                .map_err(|error| sandbox_error_message(&error))?,
        )
        .map_err(|error| sandbox_error_message(&error))?;
    let working_directory = resolve_bash_workdir(
        standing_policy.workspace_root(),
        arguments.workdir.as_deref(),
    )
    .map_err(|error| sandbox_process_error_message(&error))?;
    let escalation = consume_sandbox_escalation_approval(
        run,
        &standing_policy,
        arguments.sandbox_permissions,
        arguments.justification.as_deref(),
        "command",
    )
    .map_err(|error| sandbox_error_message(&error))?;
    let mut policy_request = SandboxPolicyRequest::for_session(&session)
        .with_call_id(run.call_id())
        .map_err(|error| sandbox_error_message(&error))?;
    if let Some(escalation) = escalation {
        policy_request = policy_request.with_escalation(escalation);
    }
    let managed_environment = [
        ("DSH_SHELL", "1"),
        ("DSH_SESSION_ID", run.session_id().as_str()),
    ];
    let outcome = run_sandboxed_process_in_environment_with_limits(
        environment,
        vec![
            OsString::from("/bin/bash"),
            OsString::from("-c"),
            OsString::from(arguments.command),
        ],
        policy_request,
        Some(&working_directory),
        &managed_environment,
        run.cancellation(),
        SandboxProcessLimits::with_timeout(arguments.timeout),
    )
    .map_err(|error| sandbox_process_error_message(&error))?;
    if outcome.termination == SandboxProcessTermination::Cancelled {
        return Err("tool call cancelled".into());
    }
    Ok(sandboxed_bash_result(&outcome))
}

struct SandboxedBashArguments {
    command: String,
    workdir: Option<String>,
    timeout: ResolvedBashTimeout,
    sandbox_permissions: Option<SandboxMode>,
    justification: Option<String>,
}

fn sandboxed_bash_arguments(
    arguments: &serde_json::Value,
) -> Result<SandboxedBashArguments, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "bash arguments must be an object".to_string())?;
    if object.keys().any(|key| {
        key != "command"
            && key != "description"
            && key != "workdir"
            && key != "timeoutMs"
            && key != "sandbox_permissions"
            && key != "justification"
    }) {
        return Err(
            "bash arguments may contain only command, description, workdir, timeoutMs, sandbox_permissions, and justification"
                .into(),
        );
    }
    let command = non_blank_bash_argument(object, "command")?;
    let _description = non_blank_bash_argument(object, "description")?;
    let workdir = match object.get("workdir") {
        None => None,
        Some(serde_json::Value::String(workdir)) => Some(workdir.clone()),
        Some(_) => return Err("bash argument workdir must be a string".into()),
    };
    let timeout = match object.get("timeoutMs") {
        None => ResolvedBashTimeout::default(),
        Some(serde_json::Value::Number(value)) => {
            let value = value
                .as_f64()
                .ok_or_else(|| "bash argument timeoutMs must be a finite number".to_string())?;
            resolve_bash_timeout(Some(value))?
        }
        Some(_) => return Err("bash argument timeoutMs must be a number".into()),
    };
    let sandbox_permissions = match object.get("sandbox_permissions") {
        None => None,
        Some(serde_json::Value::String(mode)) if mode == "workspace-write" => {
            Some(SandboxMode::WorkspaceWrite)
        }
        Some(serde_json::Value::String(mode)) if mode == "danger-full-access" => {
            Some(SandboxMode::DangerFullAccess)
        }
        Some(_) => {
            return Err(
                "bash argument sandbox_permissions must be workspace-write or danger-full-access"
                    .into(),
            );
        }
    };
    let justification = match object.get("justification") {
        None => None,
        Some(serde_json::Value::String(justification)) => Some(justification.clone()),
        Some(_) => return Err("bash argument justification must be a string".into()),
    };
    validate_sandbox_escalation_args(sandbox_permissions, justification.as_deref())
        .map_err(|error| error.to_string())?;
    Ok(SandboxedBashArguments {
        command,
        workdir,
        timeout,
        sandbox_permissions,
        justification,
    })
}

fn resolve_bash_timeout(requested: Option<f64>) -> Result<ResolvedBashTimeout, String> {
    let requested = requested.unwrap_or(SANDBOX_PROCESS_TIMEOUT_MS);
    if !requested.is_finite() || requested <= 0.0 {
        return Err("bash argument timeoutMs must be a positive finite number".into());
    }
    let milliseconds = requested.min(SANDBOX_PROCESS_MAX_TIMEOUT_MS);
    Ok(ResolvedBashTimeout {
        duration: Duration::from_secs_f64(milliseconds / 1_000.0),
        milliseconds,
    })
}

fn resolve_bash_workdir(
    workspace_root: &Path,
    requested: Option<&str>,
) -> Result<PathBuf, SandboxProcessError> {
    let requested = requested.map(Path::new);
    let working_directory = match requested {
        None => workspace_root.to_path_buf(),
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => workspace_root.join(path),
    };
    usable_working_directory(&working_directory)
}

fn non_blank_bash_argument(
    arguments: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<String, String> {
    let value = arguments
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("bash argument {name} must be a string"))?;
    if value.trim().is_empty() {
        return Err(format!("bash argument {name} must not be blank"));
    }
    Ok(value.to_string())
}

fn sandbox_error_message(error: &SandboxError) -> String {
    error
        .code()
        .map_or_else(|| error.to_string(), |code| format!("{code}: {error}"))
}

fn sandbox_process_error_message(error: &SandboxProcessError) -> String {
    if matches!(error, SandboxProcessError::CancelledBeforeSpawn) {
        "tool call cancelled".into()
    } else {
        error
            .code()
            .map_or_else(|| error.to_string(), |code| format!("{code}: {error}"))
    }
}

fn sandboxed_bash_result(outcome: &SandboxedProcessOutcome) -> serde_json::Value {
    let classification = match outcome.classification.as_ref() {
        None => "unconfined",
        Some(SandboxProcessClassification::Success) => "success",
        Some(SandboxProcessClassification::Signalled) => "signalled",
        Some(SandboxProcessClassification::RunnerFailure { .. }) => "runner-failure",
        Some(SandboxProcessClassification::Denied) => "denied",
        Some(SandboxProcessClassification::CommandFailure) => "command-failure",
    };
    let termination = match outcome.termination {
        SandboxProcessTermination::Completed => "completed",
        SandboxProcessTermination::TimedOut => "timed-out",
        SandboxProcessTermination::Cancelled => "cancelled",
    };
    let enforcement = match outcome.enforcement {
        None => "unconfined",
        Some(SandboxEnforcement::Full) => "full",
        Some(SandboxEnforcement::Partial) => "partial",
    };
    let output = sandboxed_bash_output(outcome, classification, enforcement);
    serde_json::json!({
        "output": output,
        "exitCode": outcome.exit_code,
        "termination": termination,
        "timeoutMs": outcome.timeout_ms,
        "classification": classification,
        "mode": outcome.mode.as_str(),
        "enforcement": enforcement,
        "stdoutByteCount": outcome.stdout.byte_count,
        "stdoutTruncated": outcome.stdout.truncated,
        "stderrByteCount": outcome.stderr.byte_count,
        "stderrTruncated": outcome.stderr.truncated
    })
}

fn sandboxed_bash_output(
    outcome: &SandboxedProcessOutcome,
    classification: &str,
    enforcement: &str,
) -> String {
    let mut sections = Vec::new();
    if !outcome.stdout.bytes.is_empty() {
        sections.push(String::from_utf8_lossy(&outcome.stdout.bytes).into_owned());
    }
    if !outcome.stderr.bytes.is_empty() {
        sections.push(format!(
            "[stderr]\n{}",
            String::from_utf8_lossy(&outcome.stderr.bytes)
        ));
    }
    if outcome.stdout.truncated {
        sections.push("[stdout truncated; retained tail shown]".into());
    }
    if outcome.stderr.truncated {
        sections.push("[stderr truncated; retained tail shown]".into());
    }
    if outcome.termination == SandboxProcessTermination::TimedOut {
        sections.push(format!("[timed out after {}ms]", outcome.timeout_ms));
    }
    if classification == "denied" {
        sections.push(format!(
            "[sandbox denied file access under {} mode]",
            outcome.mode
        ));
    }
    sections.push(format!(
        "[sandbox: {}, {enforcement} enforcement]",
        outcome.mode
    ));
    match outcome.exit_code {
        Some(exit_code) if exit_code != 0 => {
            sections.push(format!("[exit code: {exit_code}]"));
        }
        None if outcome.termination == SandboxProcessTermination::Completed => {
            sections.push("[terminated by signal]".into());
        }
        Some(_) | None => {}
    }
    sections.join("\n")
}

fn usable_workspace(workspace: &Path) -> Result<PathBuf, SandboxProcessError> {
    canonical_searchable_directory(workspace)
        .map_err(|detail| SandboxProcessError::UnusableWorkspace { detail })
}

fn usable_working_directory(workdir: &Path) -> Result<PathBuf, SandboxProcessError> {
    canonical_searchable_directory(workdir)
        .map_err(|detail| SandboxProcessError::UnusableWorkingDirectory { detail })
}

fn canonical_searchable_directory(directory: &Path) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(directory).map_err(|error| error.to_string())?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("path is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("directory is not searchable".into());
        }
    }
    Ok(canonical)
}

fn directory_still_usable(directory: &Path) -> bool {
    canonical_searchable_directory(directory).is_ok() && std::fs::read_dir(directory).is_ok()
}

fn spawn_error(
    plan: &SandboxExecutionPlan,
    working_directory: &Path,
    source: io::Error,
) -> SandboxProcessError {
    let runner_failed = plan.confined_command().is_some()
        && directory_still_usable(working_directory)
        && matches!(
            source.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        );
    if runner_failed {
        let runner = plan
            .argv()
            .first()
            .map_or_else(|| "<missing>".into(), |value| value.to_string_lossy());
        SandboxError::ProviderUnavailable {
            mode: plan.mode(),
            detail: format!("failed to spawn sandbox runner `{runner}`: {source}"),
        }
        .into()
    } else {
        SandboxProcessError::Spawn { source }
    }
}

fn wait_for_process(
    child: &mut GroupChild,
    cancellation: &LifecycleCancellation,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<(ExitStatus, SandboxProcessTermination), SandboxProcessError> {
    loop {
        if cancellation.is_cancelled() {
            return terminate_group(child, SandboxProcessTermination::Cancelled);
        }
        if Instant::now() >= deadline {
            return terminate_group(child, SandboxProcessTermination::TimedOut);
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, SandboxProcessTermination::Completed)),
            Ok(None) => thread::sleep(poll_interval),
            Err(source) => {
                terminate_group_best_effort(child);
                return Err(SandboxProcessError::Lifecycle { source });
            }
        }
    }
}

fn terminate_group(
    child: &mut GroupChild,
    termination: SandboxProcessTermination,
) -> Result<(ExitStatus, SandboxProcessTermination), SandboxProcessError> {
    let _ = child.kill();
    child
        .wait()
        .map(|status| (status, termination))
        .map_err(|source| SandboxProcessError::Lifecycle { source })
}

fn terminate_group_best_effort(child: &mut GroupChild) {
    let _ = child.kill();
    let _ = child.wait();
}

fn spawn_output_collector<R>(
    name: &str,
    reader: R,
    maximum: usize,
) -> io::Result<JoinHandle<io::Result<SandboxProcessOutput>>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || collect_output_tail(reader, maximum))
}

fn collect_output_tail(mut reader: impl Read, maximum: usize) -> io::Result<SandboxProcessOutput> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut byte_count = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        byte_count = byte_count.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        retain_tail(&mut bytes, &buffer[..read], maximum);
    }
    Ok(SandboxProcessOutput {
        truncated: byte_count > u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        bytes,
        byte_count,
    })
}

fn retain_tail(retained: &mut Vec<u8>, incoming: &[u8], maximum: usize) {
    if incoming.len() >= maximum {
        retained.clear();
        retained.extend_from_slice(&incoming[incoming.len() - maximum..]);
        return;
    }
    let overflow = retained
        .len()
        .saturating_add(incoming.len())
        .saturating_sub(maximum);
    if overflow > 0 {
        retained.drain(..overflow);
    }
    retained.extend_from_slice(incoming);
}

fn join_output_collector(
    reader: JoinHandle<io::Result<SandboxProcessOutput>>,
) -> Result<SandboxProcessOutput, SandboxProcessError> {
    reader
        .join()
        .map_err(|_| SandboxProcessError::OutputCollectorStopped)?
        .map_err(|source| SandboxProcessError::Output { source })
}

fn settle_sandboxed_process(
    plan: &SandboxExecutionPlan,
    status: ExitStatus,
    termination: SandboxProcessTermination,
    timeout_ms: f64,
    stdout: SandboxProcessOutput,
    stderr: SandboxProcessOutput,
) -> Result<SandboxedProcessOutcome, SandboxProcessError> {
    let classification = match (termination, plan.confined_command()) {
        (SandboxProcessTermination::Completed, Some(command)) => {
            let stderr_text = String::from_utf8_lossy(&stderr.bytes);
            match classify_sandbox_process(status.code(), &stderr_text, command) {
                SandboxProcessClassification::RunnerFailure { detail } => {
                    return Err(SandboxError::ProviderUnavailable {
                        mode: plan.mode(),
                        detail,
                    }
                    .into());
                }
                classification => Some(classification),
            }
        }
        (SandboxProcessTermination::TimedOut | SandboxProcessTermination::Cancelled, Some(_)) => {
            Some(SandboxProcessClassification::Signalled)
        }
        (_, None) => None,
    };
    Ok(SandboxedProcessOutcome {
        exit_code: status.code(),
        termination,
        timeout_ms,
        mode: plan.mode(),
        enforcement: plan.enforcement(),
        classification,
        stdout,
        stderr,
    })
}

fn seatbelt_profile(policy: &ConfinedSandboxPolicy) -> Result<String, SandboxProviderUnavailable> {
    let mut profile = SEATBELT_READ_ONLY_PROFILE.to_string();
    if policy.mode() == ConfinedSandboxMode::WorkspaceWrite {
        let grants = writable_roots(policy.workspace_root())
            .iter()
            .map(|root| sbpl_string(root).map(|root| format!("(subpath {root})")))
            .collect::<Result<Vec<_>, _>>()?;
        profile.push_str(" (allow file-write* ");
        profile.push_str(&grants.join(" "));
        profile.push(')');
    }
    Ok(profile)
}

fn writable_roots(workspace_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(3);
    for root in [
        workspace_root.to_path_buf(),
        PathBuf::from("/tmp"),
        std::env::temp_dir(),
    ] {
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

fn sbpl_string(path: &Path) -> Result<String, SandboxProviderUnavailable> {
    let path = path.to_str().ok_or_else(|| {
        SandboxProviderUnavailable::new("Seatbelt cannot encode a non-UTF-8 writable root")
    })?;
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[cfg(unix)]
    use hartevo_cordis::SANDBOX_UNAVAILABLE;
    use hartevo_cordis::{
        ConfinedArgv, ConfinedSandboxPolicy, Context, CordisHost, LifecycleCancellation,
        SandboxEnforcement, SandboxExecutionEnvironment, SandboxExecutionPlan, SandboxMode,
        SandboxPolicyRequest, SandboxPolicyService, SandboxProcessClassification, SandboxProvider,
        SandboxProviderService, SandboxProviderUnavailable, SandboxRunnerFailureRule, keys,
        prepare_sandbox_execution, register_sandbox_provider, resolve_sandbox_policy,
    };

    use super::{
        MacosSeatbeltSandboxProvider, SEATBELT_EXEC, SEATBELT_READ_ONLY_PROFILE,
        SandboxProcessError, SandboxProcessLimits, SandboxProcessTermination,
        configure_bash_environment, mount_macos_sandbox_provider, resolve_bash_timeout,
        resolve_bash_workdir, run_sandboxed_process, run_sandboxed_process_in_environment,
        run_sandboxed_process_with_limits, sandboxed_bash_arguments, sandboxed_bash_result,
        sandboxed_bash_schema, sbpl_string, scrubbed_parent_environment,
    };

    struct FixedProvider {
        wrapped: Vec<OsString>,
        enforcement: SandboxEnforcement,
        denial_signatures: Vec<String>,
        runner_failure_rules: Vec<SandboxRunnerFailureRule>,
    }

    impl SandboxProvider for FixedProvider {
        fn confine(
            &self,
            _argv: &[OsString],
            _policy: &ConfinedSandboxPolicy,
        ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
            Ok(ConfinedArgv::new(
                self.wrapped.clone(),
                self.enforcement,
                self.denial_signatures.clone(),
                self.runner_failure_rules.clone(),
            ))
        }
    }

    struct NeverProvider;

    impl SandboxProvider for NeverProvider {
        fn confine(
            &self,
            _argv: &[OsString],
            _policy: &ConfinedSandboxPolicy,
        ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
            panic!("danger-full-access must not call the sandbox provider")
        }
    }

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    fn desktop_runtime_projection() -> crate::runtime_plane::DesktopRuntimeProjection {
        use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

        DesktopRuntimeProjection {
            status: DesktopRuntimeAvailabilityStatus::NotConfigured,
            target: None,
            release: "test".to_string(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    fn context(mode: SandboxMode, root: &std::path::Path) -> Context {
        context_with_provider(mode, root, MacosSeatbeltSandboxProvider)
    }

    fn context_with_provider(
        mode: SandboxMode,
        root: &std::path::Path,
        provider: impl SandboxProvider,
    ) -> Context {
        let mut ctx = Context::new();
        ctx.provide(
            keys::SANDBOX_POLICY,
            SandboxPolicyService::new(mode, root).unwrap(),
        )
        .unwrap();
        register_sandbox_provider(&mut ctx, provider).unwrap();
        ctx
    }

    fn fixed_context(
        mode: SandboxMode,
        root: &std::path::Path,
        wrapped: Vec<OsString>,
        enforcement: SandboxEnforcement,
        denial_signatures: &[&str],
        runner_failure_signatures: &[&str],
    ) -> Context {
        context_with_provider(
            mode,
            root,
            FixedProvider {
                wrapped,
                enforcement,
                denial_signatures: denial_signatures.iter().map(ToString::to_string).collect(),
                runner_failure_rules: runner_failure_signatures
                    .iter()
                    .map(|signature| SandboxRunnerFailureRule::new([*signature]))
                    .collect(),
            },
        )
    }

    fn plan(
        ctx: &Context,
        argv: Vec<OsString>,
    ) -> Result<SandboxExecutionPlan, hartevo_cordis::SandboxError> {
        prepare_sandbox_execution(
            ctx,
            argv,
            resolve_sandbox_policy(ctx, SandboxPolicyRequest::default()).unwrap(),
        )
    }

    #[test]
    fn bash_optional_schema_and_parser_keep_workdir_timeout_and_unknown_keys_closed() {
        let schema = sandboxed_bash_schema();
        assert!(schema.description.contains("$DSH_*"));
        let properties = schema.parameters["properties"].as_object().unwrap();
        assert_eq!(properties["workdir"]["type"], "string");
        assert_eq!(properties["timeoutMs"]["type"], "number");
        assert_eq!(
            schema.parameters["required"],
            serde_json::json!(["command", "description"])
        );

        let parsed = sandboxed_bash_arguments(&serde_json::json!({
            "command": "pwd",
            "description": "Show the selected directory",
            "workdir": "nested",
            "timeoutMs": 1234.5
        }))
        .unwrap();
        assert_eq!(parsed.workdir.as_deref(), Some("nested"));
        assert_eq!(parsed.timeout.milliseconds.to_bits(), 1234.5_f64.to_bits());
        assert!(
            sandboxed_bash_arguments(&serde_json::json!({
                "command": "pwd",
                "description": "Reject a non-string directory",
                "workdir": 1
            }))
            .err()
            .unwrap()
            .contains("workdir must be a string")
        );
        assert!(
            sandboxed_bash_arguments(&serde_json::json!({
                "command": "pwd",
                "description": "Reject a non-number timeout",
                "timeoutMs": "soon"
            }))
            .err()
            .unwrap()
            .contains("timeoutMs must be a number")
        );
        assert!(
            sandboxed_bash_arguments(&serde_json::json!({
                "command": "pwd",
                "description": "Reject an unknown argument",
                "cwd": "nested"
            }))
            .is_err()
        );
    }

    #[test]
    fn bash_timeout_defaults_caps_and_rejects_non_positive_or_non_finite_values() {
        let default = sandboxed_bash_arguments(&serde_json::json!({
            "command": "true",
            "description": "Use the default timeout"
        }))
        .unwrap();
        assert_eq!(
            default.timeout.milliseconds.to_bits(),
            120_000.0_f64.to_bits()
        );
        assert_eq!(
            resolve_bash_timeout(Some(999_999.0))
                .unwrap()
                .milliseconds
                .to_bits(),
            600_000.0_f64.to_bits()
        );
        for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(resolve_bash_timeout(Some(invalid)).is_err());
        }
    }

    #[test]
    fn bash_workdir_defaults_and_resolves_relative_or_absolute_directories() {
        let workspace = tempfile::tempdir().unwrap();
        let nested = workspace.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let workspace = workspace.path().canonicalize().unwrap();
        let nested = nested.canonicalize().unwrap();
        let outside = outside.path().canonicalize().unwrap();

        assert_eq!(resolve_bash_workdir(&workspace, None).unwrap(), workspace);
        assert_eq!(
            resolve_bash_workdir(&workspace, Some("nested")).unwrap(),
            nested
        );
        assert_eq!(
            resolve_bash_workdir(&workspace, outside.to_str()).unwrap(),
            outside
        );
    }

    #[test]
    fn unusable_bash_workdir_fails_before_child_spawn() {
        let workspace = tempfile::tempdir().unwrap();
        let missing = workspace.path().join("missing-workdir");
        let marker = workspace.path().join("must-not-exist");
        let ctx = context_with_provider(
            SandboxMode::DangerFullAccess,
            workspace.path(),
            NeverProvider,
        );
        let environment = SandboxExecutionEnvironment::capture(&ctx).unwrap();

        let error = run_sandboxed_process_in_environment(
            &environment,
            vec![OsString::from("/usr/bin/touch"), marker.clone().into()],
            SandboxPolicyRequest::default(),
            Some(&missing),
            &LifecycleCancellation::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            SandboxProcessError::UnusableWorkingDirectory { .. }
        ));
        assert!(!marker.exists());
    }

    #[test]
    fn desktop_mount_registers_exact_read_only_seatbelt_wrap() {
        let mut host = CordisHost::boot(false).unwrap();
        mount_macos_sandbox_provider(&mut host).unwrap();
        assert!(host.context().sandbox::<SandboxProviderService>().is_some());
        let original = argv(&["tool", "", "literal argument"]);

        let wrapped = plan(host.context(), original.clone()).unwrap();

        assert!(matches!(wrapped, SandboxExecutionPlan::Confined { .. }));
        assert_eq!(wrapped.mode(), SandboxMode::ReadOnly);
        assert_eq!(wrapped.enforcement(), Some(SandboxEnforcement::Full));
        assert_eq!(
            wrapped.argv(),
            [
                OsString::from(SEATBELT_EXEC),
                OsString::from("-p"),
                OsString::from(SEATBELT_READ_ONLY_PROFILE),
                OsString::from("--"),
                original[0].clone(),
                original[1].clone(),
                original[2].clone(),
            ]
        );
        let command = wrapped.confined_command().unwrap();
        assert_eq!(command.denial_signatures(), ["operation not permitted"]);
        assert_eq!(command.runner_failure_rules().len(), 1);
        assert_eq!(
            command.runner_failure_rules()[0].fatal_signatures(),
            ["sandbox-exec: "]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn production_desktop_host_mounts_the_macos_provider() {
        let host = crate::cordis_host::mount_cordis_host(&desktop_runtime_projection()).unwrap();

        assert!(host.context().sandbox::<SandboxProviderService>().is_some());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_desktop_does_not_advertise_the_macos_provider_elsewhere() {
        let host = crate::cordis_host::mount_cordis_host(&desktop_runtime_projection()).unwrap();

        assert!(host.context().sandbox::<SandboxProviderService>().is_none());
    }

    #[test]
    fn workspace_write_profile_canonicalizes_deduplicates_and_escapes_roots() {
        let current = std::env::current_dir().unwrap();
        let workspace = tempfile::Builder::new()
            .prefix("n88-quoted\"slash\\")
            .tempdir_in(current)
            .unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let ctx = context(SandboxMode::WorkspaceWrite, workspace.path());

        let wrapped = plan(&ctx, argv(&["tool"])).unwrap();

        let profile = wrapped.argv()[2].to_str().unwrap();
        let workspace_grant = format!("(subpath {})", sbpl_string(&canonical_workspace).unwrap());
        assert!(profile.starts_with(SEATBELT_READ_ONLY_PROFILE));
        assert_eq!(profile.matches(&workspace_grant).count(), 1);
        for root in [std::path::Path::new("/tmp"), std::env::temp_dir().as_path()] {
            let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
            let grant = format!("(subpath {})", sbpl_string(&canonical).unwrap());
            assert_eq!(profile.matches(&grant).count(), 1);
        }
        assert!(profile.contains("quoted\\\"slash\\\\"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_workspace_root_fails_closed_without_lossy_grant() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::path::PathBuf::from(OsString::from_vec(vec![b'/', b'n', b'8', b'8', 0xff]));
        let ctx = context(SandboxMode::WorkspaceWrite, &root);

        let error = plan(&ctx, argv(&["tool"])).unwrap_err();

        assert_eq!(error.code(), Some(SANDBOX_UNAVAILABLE));
        assert!(error.to_string().contains("non-UTF-8 writable root"));
    }

    #[test]
    fn consumer_runs_only_the_provider_argv_and_reports_its_exact_facts() {
        let workspace = tempfile::tempdir().unwrap();
        let ctx = fixed_context(
            SandboxMode::ReadOnly,
            workspace.path(),
            argv(&[
                "/bin/sh",
                "-c",
                "printf 'provider-argv'; printf 'blocked-by-policy' >&2; exit 7",
            ]),
            SandboxEnforcement::Partial,
            &["blocked-by-policy"],
            &["runner-fatal"],
        );

        let outcome = run_sandboxed_process(
            &ctx,
            argv(&["definitely-not-the-selected-program", "original argument"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap();

        assert_eq!(outcome.exit_code, Some(7));
        assert_eq!(outcome.termination, SandboxProcessTermination::Completed);
        assert_eq!(outcome.mode, SandboxMode::ReadOnly);
        assert_eq!(outcome.enforcement, Some(SandboxEnforcement::Partial));
        assert_eq!(
            outcome.classification,
            Some(SandboxProcessClassification::Denied)
        );
        assert_eq!(outcome.stdout.bytes, b"provider-argv");
        assert_eq!(outcome.stderr.bytes, b"blocked-by-policy");
    }

    #[test]
    fn danger_full_access_bypasses_the_provider_and_preserves_original_argv() {
        let workspace = tempfile::tempdir().unwrap();
        let ctx = context_with_provider(
            SandboxMode::DangerFullAccess,
            workspace.path(),
            NeverProvider,
        );

        let outcome = run_sandboxed_process(
            &ctx,
            argv(&["/usr/bin/printf", "%s", "exact argument"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap();

        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.mode, SandboxMode::DangerFullAccess);
        assert_eq!(outcome.enforcement, None);
        assert_eq!(outcome.classification, None);
        assert_eq!(outcome.stdout.bytes, b"exact argument");
    }

    #[cfg(unix)]
    #[test]
    fn bash_environment_scrubs_parent_and_sets_terminal_and_managed_facts() {
        let parent = [
            ("PATH", "/fixture/bin"),
            ("HOME", "/fixture/home"),
            ("HTTP_PROXY", "http://proxy.invalid"),
            ("DSH_STALE", "fixture-value"),
            ("dsh_lower", "fixture-value"),
            ("SERVICE_API_KEY", "fixture-value"),
            ("DB_PASSWORD", "fixture-value"),
            ("CLIENT_SECRET", "fixture-value"),
            ("AUTH_TOKEN", "fixture-value"),
            ("DSH_SHELL", "stale"),
            ("DSH_SESSION_ID", "stale"),
            ("TERM", "parent-term"),
        ]
        .map(|(key, value)| (OsString::from(key), OsString::from(value)));
        let managed = [("DSH_SHELL", "1"), ("DSH_SESSION_ID", "session-n96")];
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            concat!(
                "test \"$PATH\" = /fixture/bin && ",
                "test \"$HOME\" = /fixture/home && ",
                "test \"$HTTP_PROXY\" = http://proxy.invalid && ",
                "test -z \"${DSH_STALE+x}\" && ",
                "test -z \"${dsh_lower+x}\" && ",
                "test -z \"${SERVICE_API_KEY+x}\" && ",
                "test -z \"${DB_PASSWORD+x}\" && ",
                "test -z \"${CLIENT_SECRET+x}\" && ",
                "test -z \"${AUTH_TOKEN+x}\" && ",
                "printf '%s' \"$NO_COLOR|$TERM|$PAGER|$GIT_PAGER|$DSH_SHELL|$DSH_SESSION_ID\""
            ),
        ]);
        configure_bash_environment(&mut command, parent, &managed);

        let output = command.output().unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"1|dumb|cat|cat|1|session-n96");
        assert!(output.stderr.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn bash_environment_omits_non_utf8_names_that_cannot_be_audited() {
        use std::os::unix::ffi::OsStringExt;

        let ordinary = (OsString::from("PATH"), OsString::from("/fixture/bin"));
        let unauditable = (
            OsString::from_vec(vec![b'N', b'9', b'5', 0xff]),
            OsString::from("fixture-value"),
        );

        assert_eq!(
            scrubbed_parent_environment([ordinary.clone(), unauditable]),
            vec![ordinary]
        );
    }

    #[cfg(unix)]
    #[test]
    fn foreground_timeout_is_a_settled_result_with_the_effective_millisecond_marker() {
        let workspace = tempfile::tempdir().unwrap();
        let ctx = context_with_provider(
            SandboxMode::DangerFullAccess,
            workspace.path(),
            NeverProvider,
        );
        let timeout = resolve_bash_timeout(Some(50.0)).unwrap();

        let outcome = run_sandboxed_process_with_limits(
            &ctx,
            argv(&["/bin/sh", "-c", "sleep 30"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
            SandboxProcessLimits::with_timeout(timeout),
        )
        .unwrap();

        assert_eq!(outcome.termination, SandboxProcessTermination::TimedOut);
        assert_eq!(outcome.timeout_ms.to_bits(), 50.0_f64.to_bits());
        let result = sandboxed_bash_result(&outcome);
        assert_eq!(result["timeoutMs"], 50.0);
        assert!(
            result["output"]
                .as_str()
                .unwrap()
                .contains("[timed out after 50ms]")
        );
    }

    #[test]
    fn confined_runner_spawn_refusal_is_sandbox_unavailable() {
        let workspace = tempfile::tempdir().unwrap();
        let runner = workspace.path().join("missing-sandbox-runner");
        let ctx = fixed_context(
            SandboxMode::ReadOnly,
            workspace.path(),
            vec![runner.into_os_string()],
            SandboxEnforcement::Full,
            &[],
            &[],
        );

        let error = run_sandboxed_process(
            &ctx,
            argv(&["unreachable"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), Some(SANDBOX_UNAVAILABLE));
        assert!(error.to_string().contains("missing-sandbox-runner"));
    }

    #[test]
    fn unusable_workspace_is_not_misclassified_as_runner_failure() {
        let parent = tempfile::tempdir().unwrap();
        let missing_workspace = parent.path().join("missing-workspace");
        let ctx = fixed_context(
            SandboxMode::ReadOnly,
            &missing_workspace,
            vec![parent.path().join("missing-runner").into_os_string()],
            SandboxEnforcement::Full,
            &[],
            &[],
        );

        let error = run_sandboxed_process(
            &ctx,
            argv(&["unreachable"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            SandboxProcessError::UnusableWorkspace { .. }
        ));
        assert_eq!(error.code(), None);
    }

    #[test]
    fn settled_runner_failure_outranks_denial_and_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let ctx = fixed_context(
            SandboxMode::ReadOnly,
            workspace.path(),
            argv(&[
                "/bin/sh",
                "-c",
                "printf 'runner-fatal: permission denied\\n' >&2; exit 125",
            ]),
            SandboxEnforcement::Full,
            &["permission denied"],
            &["runner-fatal: "],
        );

        let error = run_sandboxed_process(
            &ctx,
            argv(&["unreachable"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), Some(SANDBOX_UNAVAILABLE));
        assert!(
            error
                .to_string()
                .contains("runner-fatal: permission denied")
        );
    }

    #[test]
    fn output_capture_is_bounded_and_debug_redacts_retained_bytes() {
        let workspace = tempfile::tempdir().unwrap();
        let ctx = context_with_provider(
            SandboxMode::DangerFullAccess,
            workspace.path(),
            NeverProvider,
        );

        let outcome = run_sandboxed_process(
            &ctx,
            argv(&["/bin/sh", "-c", "printf '%070000dN89-SECRET-TAIL' 0"]),
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap();

        assert_eq!(outcome.stdout.byte_count, 70_015);
        assert!(outcome.stdout.truncated);
        assert_eq!(outcome.stdout.bytes.len(), 64_000);
        assert!(outcome.stdout.bytes.ends_with(b"N89-SECRET-TAIL"));
        assert!(!format!("{outcome:?}").contains("N89-SECRET-TAIL"));
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_kills_and_reaps_the_whole_process_group() {
        let workspace = tempfile::tempdir().unwrap();
        let ctx = fixed_context(
            SandboxMode::ReadOnly,
            workspace.path(),
            argv(&[
                "/bin/sh",
                "-c",
                "sleep 30 & child=$!; printf '%s\\n' \"$child\"; wait \"$child\"",
            ]),
            SandboxEnforcement::Full,
            &[],
            &[],
        );
        let cancellation = LifecycleCancellation::default();
        let cancelling = cancellation.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            cancelling.cancel();
        });

        let outcome = run_sandboxed_process_with_limits(
            &ctx,
            argv(&["unreachable"]),
            SandboxPolicyRequest::default(),
            &cancellation,
            SandboxProcessLimits {
                timeout: Duration::from_secs(5),
                timeout_ms: 5_000.0,
                output_bytes: 64_000,
                poll_interval: Duration::from_millis(5),
            },
        )
        .unwrap();
        canceller.join().unwrap();

        assert_eq!(outcome.termination, SandboxProcessTermination::Cancelled);
        assert_eq!(
            outcome.classification,
            Some(SandboxProcessClassification::Signalled)
        );
        let child = String::from_utf8(outcome.stdout.bytes).unwrap();
        let child = child.trim();
        assert!(!child.is_empty());
        assert!(
            !Command::new("/bin/kill")
                .args(["-0", child])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn absolute_bash_workdir_does_not_widen_the_workspace_write_root() {
        let current = std::env::current_dir().unwrap();
        let workspace = tempfile::tempdir_in(&current).unwrap();
        let outside = tempfile::tempdir_in(&current).unwrap();
        let marker = outside.path().join("must-not-exist");
        let ctx = context(SandboxMode::WorkspaceWrite, workspace.path());
        let environment = SandboxExecutionEnvironment::capture(&ctx).unwrap();

        let outcome = run_sandboxed_process_in_environment(
            &environment,
            argv(&["/usr/bin/touch", "must-not-exist"]),
            SandboxPolicyRequest::default(),
            Some(outside.path()),
            &LifecycleCancellation::default(),
        )
        .unwrap();

        assert_ne!(outcome.exit_code, Some(0));
        assert_eq!(
            outcome.classification,
            Some(SandboxProcessClassification::Denied)
        );
        assert!(!marker.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_seatbelt_enforces_read_only_and_workspace_write_boundaries() {
        let current = std::env::current_dir().unwrap();
        let workspace = tempfile::tempdir_in(&current).unwrap();
        let outside = tempfile::tempdir_in(&current).unwrap();
        let denied_read_only = workspace.path().join("read-only-denied");
        let allowed = workspace.path().join("workspace-allowed");
        let denied_outside = outside.path().join("outside-denied");

        let read_only = context(SandboxMode::ReadOnly, workspace.path());
        let read_only_output = run_sandboxed_process(
            &read_only,
            vec![
                OsString::from("/usr/bin/touch"),
                denied_read_only.clone().into(),
            ],
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap();
        assert_ne!(read_only_output.exit_code, Some(0));
        assert!(!denied_read_only.exists());
        assert_eq!(
            read_only_output.classification,
            Some(SandboxProcessClassification::Denied)
        );

        let workspace_write = context(SandboxMode::WorkspaceWrite, workspace.path());
        let allowed_output = run_sandboxed_process(
            &workspace_write,
            vec![OsString::from("/usr/bin/touch"), allowed.clone().into()],
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap();
        assert_eq!(allowed_output.exit_code, Some(0));
        assert_eq!(
            allowed_output.classification,
            Some(SandboxProcessClassification::Success)
        );
        assert!(allowed.exists());

        let denied_output = run_sandboxed_process(
            &workspace_write,
            vec![
                OsString::from("/usr/bin/touch"),
                denied_outside.clone().into(),
            ],
            SandboxPolicyRequest::default(),
            &LifecycleCancellation::default(),
        )
        .unwrap();
        assert_ne!(denied_output.exit_code, Some(0));
        assert!(!denied_outside.exists());
        assert_eq!(
            denied_output.classification,
            Some(SandboxProcessClassification::Denied)
        );
    }
}

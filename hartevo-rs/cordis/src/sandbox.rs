//! Durable sandbox policy and one-shot escalation adapted from DeepSeek Harness.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::approval::{ApprovalError, ApprovalOutcome, ApprovalRequest, request_approval};
use crate::context::{Context, CordisError, ProviderHandle, keys};
use crate::fiber::LifecycleCancellation;
use crate::session::{SessionError, SessionHandle, SessionId, SessionStore};
use crate::surface::{AgentRef, ToolApprovalRequirement, ToolExecutionInput, ToolRunContext};

/// Every supported file-effect mode, from narrowest to widest.
pub const SANDBOX_MODES: &[SandboxMode] = &[
    SandboxMode::ReadOnly,
    SandboxMode::WorkspaceWrite,
    SandboxMode::DangerFullAccess,
];

/// Closed targets a confined call may request through one-shot escalation.
pub const SANDBOX_ESCALATION_TARGETS: &[SandboxMode] =
    &[SandboxMode::WorkspaceWrite, SandboxMode::DangerFullAccess];

/// Structured error code for a confined call that cannot be enforced.
pub const SANDBOX_UNAVAILABLE: &str = "SANDBOX_UNAVAILABLE";

/// File-effect policy. Network and process visibility are separate concerns.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    #[default]
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl SandboxMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }

    #[must_use]
    pub const fn is_strictly_wider_than(self, current: Self) -> bool {
        matches!(
            (current, self),
            (
                Self::ReadOnly,
                Self::WorkspaceWrite | Self::DangerFullAccess
            ) | (Self::WorkspaceWrite, Self::DangerFullAccess)
        )
    }
}

impl std::fmt::Display for SandboxMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Modes that must pass through an enforcing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfinedSandboxMode {
    ReadOnly,
    WorkspaceWrite,
}

impl ConfinedSandboxMode {
    #[must_use]
    pub const fn as_mode(self) -> SandboxMode {
        match self {
            Self::ReadOnly => SandboxMode::ReadOnly,
            Self::WorkspaceWrite => SandboxMode::WorkspaceWrite,
        }
    }
}

/// How completely one selected backend enforces its promised file effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxEnforcement {
    Full,
    Partial,
}

/// Fully resolved policy supplied to one provider call.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfinedSandboxPolicy {
    mode: ConfinedSandboxMode,
    workspace_root: PathBuf,
    session_id: Option<SessionId>,
    call_id: Option<String>,
}

impl ConfinedSandboxPolicy {
    #[must_use]
    pub const fn mode(&self) -> ConfinedSandboxMode {
        self.mode
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }
}

/// Evidence that a sandbox runner failed before it executed the child argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRunnerFailureRule {
    allowed_exit_codes: Option<Vec<i32>>,
    fatal_signatures: Vec<String>,
    informational_lines: Vec<String>,
}

impl SandboxRunnerFailureRule {
    #[must_use]
    pub fn new<I, S>(fatal_signatures: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_exit_codes: None,
            fatal_signatures: fatal_signatures.into_iter().map(Into::into).collect(),
            informational_lines: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_allowed_exit_codes<I>(mut self, exit_codes: I) -> Self
    where
        I: IntoIterator<Item = i32>,
    {
        self.allowed_exit_codes = Some(exit_codes.into_iter().collect());
        self
    }

    #[must_use]
    pub fn with_informational_lines<I, S>(mut self, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.informational_lines = lines.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn allowed_exit_codes(&self) -> Option<&[i32]> {
        self.allowed_exit_codes.as_deref()
    }

    #[must_use]
    pub fn fatal_signatures(&self) -> &[String] {
        &self.fatal_signatures
    }

    #[must_use]
    pub fn informational_lines(&self) -> &[String] {
        &self.informational_lines
    }
}

/// One provider's owned replacement argv and per-call enforcement dialect.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfinedArgv {
    argv: Vec<OsString>,
    enforcement: SandboxEnforcement,
    denial_signatures: Vec<String>,
    runner_failure_rules: Vec<SandboxRunnerFailureRule>,
}

impl ConfinedArgv {
    #[must_use]
    pub fn new(
        argv: Vec<OsString>,
        enforcement: SandboxEnforcement,
        denial_signatures: Vec<String>,
        runner_failure_rules: Vec<SandboxRunnerFailureRule>,
    ) -> Self {
        Self {
            argv,
            enforcement,
            denial_signatures,
            runner_failure_rules,
        }
    }

    #[must_use]
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }

    #[must_use]
    pub const fn enforcement(&self) -> SandboxEnforcement {
        self.enforcement
    }

    #[must_use]
    pub fn denial_signatures(&self) -> &[String] {
        &self.denial_signatures
    }

    #[must_use]
    pub fn runner_failure_rules(&self) -> &[SandboxRunnerFailureRule] {
        &self.runner_failure_rules
    }
}

/// Provider-owned reason a confined policy cannot be enforced on this host.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[error("{detail}")]
pub struct SandboxProviderUnavailable {
    detail: String,
}

impl SandboxProviderUnavailable {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            detail: if detail.trim().is_empty() {
                "sandbox provider is unavailable".to_string()
            } else {
                detail
            },
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Same-world confinement mechanism. Policy is supplied per call.
pub trait SandboxProvider: Send + Sync + 'static {
    fn confine(
        &self,
        argv: &[OsString],
        policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable>;
}

/// Type-erased Cordis service mounted at [`keys::SANDBOX`].
#[derive(Clone)]
pub struct SandboxProviderService {
    provider: Arc<dyn SandboxProvider>,
}

impl SandboxProviderService {
    #[must_use]
    pub fn new(provider: impl SandboxProvider) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    #[must_use]
    pub fn from_shared(provider: Arc<dyn SandboxProvider>) -> Self {
        Self { provider }
    }

    fn confine(
        &self,
        argv: &[OsString],
        policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        self.provider.confine(argv, policy)
    }
}

impl std::fmt::Debug for SandboxProviderService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxProviderService")
            .finish_non_exhaustive()
    }
}

/// Mount one Fiber-owned sandbox provider. Disposal removes the capability.
pub fn register_sandbox_provider(
    ctx: &mut Context,
    provider: impl SandboxProvider,
) -> Result<ProviderHandle, CordisError> {
    ctx.provide(keys::SANDBOX, SandboxProviderService::new(provider))
}

/// Why one durable session override was appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxModeSource {
    Delegation,
}

/// Durable, non-surface `sandbox/mode` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionSandboxMode {
    mode: SandboxMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<SandboxModeSource>,
}

impl SessionSandboxMode {
    #[must_use]
    pub const fn new(mode: SandboxMode, source: Option<SandboxModeSource>) -> Self {
        Self { mode, source }
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let sandbox: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidSandboxPolicyEncoding)?;
        if sandbox.to_json_value()? != *value {
            return Err(SessionError::InvalidSandboxPolicyEncoding);
        }
        Ok(sandbox)
    }

    pub fn to_json_value(self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidSandboxPolicyEncoding)
    }

    #[must_use]
    pub const fn mode(self) -> SandboxMode {
        self.mode
    }

    #[must_use]
    pub const fn source(self) -> Option<SandboxModeSource> {
        self.source
    }
}

/// Deployment defaults shared by every future enforcing capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicyService {
    default_mode: SandboxMode,
    workspace_root: PathBuf,
}

impl SandboxPolicyService {
    pub fn new(
        default_mode: SandboxMode,
        workspace_root: impl Into<PathBuf>,
    ) -> Result<Self, SandboxError> {
        Ok(Self {
            default_mode,
            workspace_root: absolute_workspace_root(workspace_root.into())?,
        })
    }

    pub(crate) fn from_process() -> Result<Self, SandboxError> {
        Self::new(SandboxMode::ReadOnly, current_directory()?)
    }

    #[must_use]
    pub const fn default_mode(&self) -> SandboxMode {
        self.default_mode
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    fn resolve(
        &self,
        request: SandboxPolicyRequest,
    ) -> Result<SandboxExecutionPolicy, SandboxError> {
        let session_mode = request
            .session
            .as_ref()
            .map(SessionHandle::sandbox_mode)
            .transpose()?
            .flatten();
        let standing_mode = session_mode.unwrap_or(self.default_mode);
        let workspace_root = request
            .workspace_root
            .map_or_else(|| Ok(self.workspace_root.clone()), absolute_workspace_root)?;
        let mode = if let Some(grant) = request.escalation {
            let session = request
                .session
                .as_ref()
                .ok_or(SandboxError::EscalationGrantMismatch)?;
            if session.id() != &grant.session_id
                || request.call_id.as_deref() != Some(grant.call_id.as_str())
                || standing_mode != grant.from_mode
                || workspace_root != grant.workspace_root
            {
                return Err(SandboxError::EscalationGrantMismatch);
            }
            grant.mode
        } else {
            standing_mode
        };
        Ok(SandboxExecutionPolicy {
            mode,
            workspace_root,
            session_id: request.session.map(|session| session.id().clone()),
            call_id: request.call_id,
        })
    }
}

/// Inputs resolved once at an exact capability-call boundary.
#[derive(Debug, Default)]
pub struct SandboxPolicyRequest {
    session: Option<SessionHandle>,
    call_id: Option<String>,
    workspace_root: Option<PathBuf>,
    escalation: Option<SandboxEscalationGrant>,
}

impl SandboxPolicyRequest {
    #[must_use]
    pub fn for_session(session: &SessionHandle) -> Self {
        Self {
            session: Some(session.clone()),
            ..Self::default()
        }
    }

    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Result<Self, SandboxError> {
        let call_id = call_id.into();
        if call_id.is_empty() {
            return Err(SandboxError::EmptyCallId);
        }
        self.call_id = Some(call_id);
        Ok(self)
    }

    #[must_use]
    pub fn with_workspace_root(mut self, workspace_root: impl Into<PathBuf>) -> Self {
        self.workspace_root = Some(workspace_root.into());
        self
    }

    #[must_use]
    pub fn with_escalation(mut self, grant: SandboxEscalationGrant) -> Self {
        self.escalation = Some(grant);
        self
    }
}

/// Fully resolved policy. Private fields prevent callers from forging a wider mode.
#[derive(Debug, PartialEq, Eq)]
pub struct SandboxExecutionPolicy {
    mode: SandboxMode,
    workspace_root: PathBuf,
    session_id: Option<SessionId>,
    call_id: Option<String>,
}

/// Cloneable handles needed to resolve and prepare sandbox work from a tool
/// executor running outside the mutable Cordis [`Context`] thread.
#[derive(Clone)]
pub struct SandboxExecutionEnvironment {
    policy: Arc<SandboxPolicyService>,
    sessions: Option<Arc<SessionStore>>,
    provider: Option<Arc<SandboxProviderService>>,
}

impl std::fmt::Debug for SandboxExecutionEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxExecutionEnvironment")
            .field("has_sessions", &self.sessions.is_some())
            .field("has_provider", &self.provider.is_some())
            .finish_non_exhaustive()
    }
}

impl SandboxExecutionEnvironment {
    /// Capture the exact root services while the owning tool registration is
    /// mounted. The registration is disposed before its provider on teardown.
    pub fn capture(ctx: &Context) -> Result<Self, SandboxError> {
        let policy = ctx
            .get::<SandboxPolicyService>(keys::SANDBOX_POLICY)
            .ok_or(SandboxError::ServiceUnavailable {
                key: keys::SANDBOX_POLICY,
            })?;
        Ok(Self {
            policy,
            sessions: ctx.sessions::<SessionStore>(),
            provider: ctx.sandbox::<SandboxProviderService>(),
        })
    }

    /// Resolve the current live handle for one durable Session identity.
    pub fn live_session(&self, id: &SessionId) -> Result<SessionHandle, SandboxError> {
        self.sessions
            .as_ref()
            .ok_or(SandboxError::ServiceUnavailable {
                key: keys::SESSIONS,
            })?
            .get(id)?
            .ok_or_else(|| SessionError::SessionNotFound { id: id.clone() }.into())
    }

    pub fn resolve(
        &self,
        request: SandboxPolicyRequest,
    ) -> Result<SandboxExecutionPolicy, SandboxError> {
        if request.session.is_none() {
            return self.policy.resolve(request);
        }
        let sessions = self
            .sessions
            .as_ref()
            .ok_or(SandboxError::ServiceUnavailable {
                key: keys::SESSIONS,
            })?;
        resolve_sandbox_policy_with_services(&self.policy, sessions, request)
    }

    pub fn prepare(
        &self,
        argv: Vec<OsString>,
        policy: SandboxExecutionPolicy,
    ) -> Result<SandboxExecutionPlan, SandboxError> {
        prepare_sandbox_execution_with_provider(self.provider.as_deref(), argv, policy)
    }
}

impl SandboxExecutionPolicy {
    #[must_use]
    pub const fn mode(&self) -> SandboxMode {
        self.mode
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }
}

/// Spawn plan selected from one resolved policy. Confined variants never
/// contain the caller's argv as a fallback path.
#[derive(Debug, PartialEq, Eq)]
pub enum SandboxExecutionPlan {
    Unconfined {
        policy: SandboxExecutionPolicy,
        argv: Vec<OsString>,
    },
    Confined {
        policy: ConfinedSandboxPolicy,
        command: ConfinedArgv,
    },
}

impl SandboxExecutionPlan {
    #[must_use]
    pub fn argv(&self) -> &[OsString] {
        match self {
            Self::Unconfined { argv, .. } => argv,
            Self::Confined { command, .. } => command.argv(),
        }
    }

    #[must_use]
    pub const fn mode(&self) -> SandboxMode {
        match self {
            Self::Unconfined { policy, .. } => policy.mode,
            Self::Confined { policy, .. } => policy.mode.as_mode(),
        }
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        match self {
            Self::Unconfined { policy, .. } => &policy.workspace_root,
            Self::Confined { policy, .. } => &policy.workspace_root,
        }
    }

    #[must_use]
    pub const fn enforcement(&self) -> Option<SandboxEnforcement> {
        match self {
            Self::Unconfined { .. } => None,
            Self::Confined { command, .. } => Some(command.enforcement),
        }
    }

    #[must_use]
    pub const fn confined_policy(&self) -> Option<&ConfinedSandboxPolicy> {
        match self {
            Self::Unconfined { .. } => None,
            Self::Confined { policy, .. } => Some(policy),
        }
    }

    #[must_use]
    pub const fn confined_command(&self) -> Option<&ConfinedArgv> {
        match self {
            Self::Unconfined { .. } => None,
            Self::Confined { command, .. } => Some(command),
        }
    }
}

/// Classification of one settled process under a confined execution plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxProcessClassification {
    Success,
    Signalled,
    RunnerFailure { detail: String },
    Denied,
    CommandFailure,
}

/// Select bypass versus confinement exactly once. Missing or unusable
/// confinement is a structured refusal, never an unconfined fallback.
pub fn prepare_sandbox_execution(
    ctx: &Context,
    argv: Vec<OsString>,
    policy: SandboxExecutionPolicy,
) -> Result<SandboxExecutionPlan, SandboxError> {
    let provider = ctx.sandbox::<SandboxProviderService>();
    prepare_sandbox_execution_with_provider(provider.as_deref(), argv, policy)
}

fn prepare_sandbox_execution_with_provider(
    provider: Option<&SandboxProviderService>,
    argv: Vec<OsString>,
    policy: SandboxExecutionPolicy,
) -> Result<SandboxExecutionPlan, SandboxError> {
    validate_command_argv(&argv)?;
    if policy.mode == SandboxMode::DangerFullAccess {
        return Ok(SandboxExecutionPlan::Unconfined { policy, argv });
    }

    let mode = match policy.mode {
        SandboxMode::ReadOnly => ConfinedSandboxMode::ReadOnly,
        SandboxMode::WorkspaceWrite => ConfinedSandboxMode::WorkspaceWrite,
        SandboxMode::DangerFullAccess => unreachable!("handled before provider lookup"),
    };
    let confined_policy = ConfinedSandboxPolicy {
        mode,
        workspace_root: policy.workspace_root,
        session_id: policy.session_id,
        call_id: policy.call_id,
    };
    let provider = provider.ok_or_else(|| SandboxError::ProviderUnavailable {
        mode: mode.as_mode(),
        detail: format!(
            "Cordis sandbox provider service `{}` is unavailable",
            keys::SANDBOX
        ),
    })?;
    let command = provider.confine(&argv, &confined_policy).map_err(|error| {
        SandboxError::ProviderUnavailable {
            mode: mode.as_mode(),
            detail: error.detail,
        }
    })?;
    if let Some(detail) = unusable_argv_detail(command.argv()) {
        return Err(SandboxError::ProviderUnavailable {
            mode: mode.as_mode(),
            detail: format!("sandbox provider returned unusable argv: {detail}"),
        });
    }
    Ok(SandboxExecutionPlan::Confined {
        policy: confined_policy,
        command,
    })
}

/// Classify settled output using only this call's selected backend dialect.
/// Runner failure takes precedence because it proves the child never ran.
#[must_use]
pub fn classify_sandbox_process(
    exit_code: Option<i32>,
    stderr: &str,
    command: &ConfinedArgv,
) -> SandboxProcessClassification {
    let Some(exit_code) = exit_code else {
        return SandboxProcessClassification::Signalled;
    };
    if exit_code == 0 {
        return SandboxProcessClassification::Success;
    }

    let lines: Vec<&str> = stderr
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    for rule in command.runner_failure_rules() {
        if rule
            .allowed_exit_codes()
            .is_some_and(|codes| !codes.contains(&exit_code))
        {
            continue;
        }
        for line in &lines {
            if rule
                .informational_lines()
                .iter()
                .any(|informational| informational.eq_ignore_ascii_case(line))
            {
                continue;
            }
            if rule.fatal_signatures().iter().any(|signature| {
                !signature.trim().is_empty() && contains_ignore_ascii_case(line, signature)
            }) {
                return SandboxProcessClassification::RunnerFailure {
                    detail: (*line).to_string(),
                };
            }
        }
    }

    if command.denial_signatures().iter().any(|signature| {
        !signature.trim().is_empty() && contains_ignore_ascii_case(stderr, signature)
    }) {
        SandboxProcessClassification::Denied
    } else {
        SandboxProcessClassification::CommandFailure
    }
}

fn validate_command_argv(argv: &[OsString]) -> Result<(), SandboxError> {
    match unusable_argv_detail(argv) {
        None => Ok(()),
        Some("argv is empty") => Err(SandboxError::EmptyCommandArgv),
        Some("program is empty") => Err(SandboxError::EmptyCommandProgram),
        Some(_) => unreachable!("closed argv validation detail"),
    }
}

fn unusable_argv_detail(argv: &[OsString]) -> Option<&'static str> {
    if argv.is_empty() {
        Some("argv is empty")
    } else if argv[0].as_os_str() == OsStr::new("") {
        Some("program is empty")
    } else {
        None
    }
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Resolve through the mounted service and reject a stale/foreign Session handle.
pub fn resolve_sandbox_policy(
    ctx: &Context,
    request: SandboxPolicyRequest,
) -> Result<SandboxExecutionPolicy, SandboxError> {
    let policy = ctx
        .get::<SandboxPolicyService>(keys::SANDBOX_POLICY)
        .ok_or(SandboxError::ServiceUnavailable {
            key: keys::SANDBOX_POLICY,
        })?;
    if request.session.is_none() {
        return policy.resolve(request);
    }
    let sessions = ctx
        .sessions::<SessionStore>()
        .ok_or(SandboxError::ServiceUnavailable {
            key: keys::SESSIONS,
        })?;
    resolve_sandbox_policy_with_services(&policy, &sessions, request)
}

fn resolve_sandbox_policy_with_services(
    policy: &SandboxPolicyService,
    sessions: &SessionStore,
    request: SandboxPolicyRequest,
) -> Result<SandboxExecutionPolicy, SandboxError> {
    if let Some(session) = request.session.as_ref() {
        sessions.require_live(session)?;
    }
    policy.resolve(request)
}

/// Append and flush exactly one session mode switch before returning.
pub async fn set_sandbox_mode(
    ctx: &Context,
    session: &SessionHandle,
    mode: SandboxMode,
    source: Option<SandboxModeSource>,
) -> Result<(), SandboxError> {
    let _policy = ctx
        .get::<SandboxPolicyService>(keys::SANDBOX_POLICY)
        .ok_or(SandboxError::ServiceUnavailable {
            key: keys::SANDBOX_POLICY,
        })?;
    let sessions = ctx
        .sessions::<SessionStore>()
        .ok_or(SandboxError::ServiceUnavailable {
            key: keys::SESSIONS,
        })?;
    sessions.require_live(session)?;
    session.append_sandbox_mode(mode, source)?;
    sessions.flush(session).await?;
    Ok(())
}

/// Validate the optional schema fields before constructing an escalation request.
pub fn validate_sandbox_escalation_args(
    requested_mode: Option<SandboxMode>,
    justification: Option<&str>,
) -> Result<(), SandboxError> {
    match (requested_mode, justification) {
        (None, None) | (Some(_), Some(_)) => {}
        (Some(_), None) => return Err(SandboxError::MissingJustification),
        (None, Some(_)) => return Err(SandboxError::OrphanJustification),
    }
    if justification.is_some_and(|justification| justification.trim().is_empty()) {
        return Err(SandboxError::BlankJustification);
    }
    Ok(())
}

#[derive(Debug)]
struct PendingSandboxEscalation {
    requested_mode: SandboxMode,
    effective_mode: SandboxMode,
    justification: String,
    subject: String,
    workspace_root: PathBuf,
    session_id: SessionId,
    tool_name: String,
    call_id: String,
}

/// Prepare the definition-owned approval requirement for one exact sandbox
/// escalation. The opaque payload cannot reach the tool body until the
/// canonical Agent approval path returns `allowed-once`.
pub fn plan_sandbox_escalation_approval(
    input: &ToolExecutionInput,
    policy: &SandboxExecutionPolicy,
    requested_mode: Option<SandboxMode>,
    justification: Option<&str>,
    subject: &str,
) -> Result<Option<ToolApprovalRequirement>, SandboxError> {
    validate_sandbox_escalation_args(requested_mode, justification)?;
    let (Some(requested_mode), Some(justification)) = (requested_mode, justification) else {
        return Ok(None);
    };
    if subject.is_empty() {
        return Err(SandboxError::EmptySubject);
    }
    if !requested_mode.is_strictly_wider_than(policy.mode()) {
        return Err(SandboxError::NotStrictlyWider {
            requested: requested_mode,
            current: policy.mode(),
        });
    }
    if policy.session_id() != Some(input.session_id()) || policy.call_id() != Some(input.call_id())
    {
        return Err(SandboxError::EscalationGrantMismatch);
    }
    let pending = PendingSandboxEscalation {
        requested_mode,
        effective_mode: policy.mode(),
        justification: justification.to_string(),
        subject: subject.to_string(),
        workspace_root: policy.workspace_root().to_path_buf(),
        session_id: input.session_id().clone(),
        tool_name: input.name().to_string(),
        call_id: input.call_id().to_string(),
    };
    Ok(Some(ToolApprovalRequirement::new(
        format!("escalate sandbox to {requested_mode}: {justification}"),
        pending,
    )))
}

/// Consume the approved definition payload and mint the existing exact
/// sandbox grant only when the live policy and immutable call still match.
pub fn consume_sandbox_escalation_approval(
    run: &ToolRunContext,
    policy: &SandboxExecutionPolicy,
    requested_mode: Option<SandboxMode>,
    justification: Option<&str>,
    subject: &str,
) -> Result<Option<SandboxEscalationGrant>, SandboxError> {
    validate_sandbox_escalation_args(requested_mode, justification)?;
    let (Some(requested_mode), Some(justification)) = (requested_mode, justification) else {
        return Ok(None);
    };
    let pending = run
        .take_approval_payload::<PendingSandboxEscalation>()
        .ok_or(SandboxError::EscalationGrantMismatch)?;
    if !requested_mode.is_strictly_wider_than(policy.mode())
        || pending.requested_mode != requested_mode
        || pending.effective_mode != policy.mode()
        || pending.justification != justification
        || pending.subject != subject
        || pending.workspace_root != policy.workspace_root()
        || pending.session_id != *run.session_id()
        || pending.tool_name != run.name()
        || pending.call_id != run.call_id()
        || policy.session_id() != Some(run.session_id())
        || policy.call_id() != Some(run.call_id())
    {
        return Err(SandboxError::EscalationGrantMismatch);
    }
    Ok(Some(SandboxEscalationGrant {
        mode: requested_mode,
        from_mode: pending.effective_mode,
        session_id: pending.session_id,
        call_id: pending.call_id,
        workspace_root: pending.workspace_root,
    }))
}

/// Exact approval-routing identity held by an escalating tool call.
#[derive(Debug, Clone)]
pub struct SandboxEscalationApproval {
    agent: AgentRef,
    session_id: SessionId,
    tool_name: String,
    call_id: String,
    cancellation: LifecycleCancellation,
}

impl SandboxEscalationApproval {
    pub fn new(
        agent: AgentRef,
        session_id: SessionId,
        tool_name: impl Into<String>,
        call_id: impl Into<String>,
        cancellation: LifecycleCancellation,
    ) -> Result<Self, SandboxError> {
        let tool_name = tool_name.into();
        if tool_name.is_empty() {
            return Err(SandboxError::EmptyToolName);
        }
        let call_id = call_id.into();
        if call_id.is_empty() {
            return Err(SandboxError::EmptyCallId);
        }
        Ok(Self {
            agent,
            session_id,
            tool_name,
            call_id,
            cancellation,
        })
    }
}

/// One request to retry the exact call under a strictly wider mode.
#[derive(Debug, Clone)]
pub struct SandboxEscalationRequest {
    requested_mode: SandboxMode,
    effective_mode: SandboxMode,
    justification: String,
    subject: String,
    workspace_root: PathBuf,
    approval: SandboxEscalationApproval,
}

impl SandboxEscalationRequest {
    pub fn new(
        requested_mode: SandboxMode,
        effective_mode: SandboxMode,
        justification: impl Into<String>,
        subject: impl Into<String>,
        workspace_root: impl Into<PathBuf>,
        approval: SandboxEscalationApproval,
    ) -> Result<Self, SandboxError> {
        let justification = justification.into();
        validate_sandbox_escalation_args(Some(requested_mode), Some(&justification))?;
        let subject = subject.into();
        if subject.is_empty() {
            return Err(SandboxError::EmptySubject);
        }
        let workspace_root = absolute_workspace_root(workspace_root.into())?;
        Ok(Self {
            requested_mode,
            effective_mode,
            justification,
            subject,
            workspace_root,
            approval,
        })
    }
}

/// Unforgeable, non-cloneable grant consumed by one exact policy resolution.
#[derive(Debug)]
pub struct SandboxEscalationGrant {
    mode: SandboxMode,
    from_mode: SandboxMode,
    session_id: SessionId,
    call_id: String,
    workspace_root: PathBuf,
}

impl SandboxEscalationGrant {
    #[must_use]
    pub const fn mode(&self) -> SandboxMode {
        self.mode
    }
}

/// Ask once before execution and return a grant only for `allowed-once`.
pub async fn approve_sandbox_escalation(
    ctx: &mut Context,
    session: &SessionHandle,
    request: SandboxEscalationRequest,
) -> Result<SandboxEscalationGrant, SandboxError> {
    if !request
        .requested_mode
        .is_strictly_wider_than(request.effective_mode)
    {
        return Err(SandboxError::NotStrictlyWider {
            requested: request.requested_mode,
            current: request.effective_mode,
        });
    }
    let approval = request.approval;
    let call_id = approval.call_id.clone();
    let session_id = approval.session_id.clone();
    let prompt = ApprovalRequest::for_session(
        approval.agent,
        approval.session_id,
        approval.tool_name,
        approval.cancellation,
    )?
    .with_call_id(call_id.clone())?
    .with_reason(format!(
        "escalate sandbox to {}: {}",
        request.requested_mode, request.justification
    ))?;
    match request_approval(ctx, session, prompt).await? {
        ApprovalOutcome::AllowedOnce => Ok(SandboxEscalationGrant {
            mode: request.requested_mode,
            from_mode: request.effective_mode,
            session_id,
            call_id,
            workspace_root: request.workspace_root,
        }),
        ApprovalOutcome::Rejected => Err(SandboxError::EscalationRejected {
            subject: request.subject,
            mode: request.requested_mode,
        }),
        ApprovalOutcome::Cancelled => Err(SandboxError::EscalationCancelled {
            mode: request.requested_mode,
        }),
        ApprovalOutcome::Unavailable => Err(SandboxError::EscalationUnavailable {
            mode: request.requested_mode,
        }),
    }
}

fn current_directory() -> Result<PathBuf, SandboxError> {
    std::env::current_dir().map_err(|error| SandboxError::CurrentDirectoryUnavailable {
        detail: error.to_string(),
    })
}

fn absolute_workspace_root(path: PathBuf) -> Result<PathBuf, SandboxError> {
    if path.as_os_str().is_empty() {
        return Err(SandboxError::EmptyWorkspaceRoot);
    }
    let absolute = if path.is_absolute() {
        path
    } else {
        current_directory()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if !normalized.is_absolute() {
        return Err(SandboxError::WorkspaceRootNotAbsolute { path: normalized });
    }
    Ok(normalized)
}

/// Fail-closed policy, resolution, and escalation errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SandboxError {
    #[error("Cordis sandbox policy service `{key}` is unavailable")]
    ServiceUnavailable { key: &'static str },
    #[error("sandbox command argv must contain a program")]
    EmptyCommandArgv,
    #[error("sandbox command program must not be empty")]
    EmptyCommandProgram,
    #[error("sandbox mode `{mode}` is unavailable; refusing to run unconfined: {detail}")]
    ProviderUnavailable { mode: SandboxMode, detail: String },
    #[error("sandbox workspace root must not be empty")]
    EmptyWorkspaceRoot,
    #[error("sandbox workspace root `{path}` is not absolute")]
    WorkspaceRootNotAbsolute { path: PathBuf },
    #[error("sandbox current directory is unavailable: {detail}")]
    CurrentDirectoryUnavailable { detail: String },
    #[error("sandbox escalation call id must not be empty")]
    EmptyCallId,
    #[error("sandbox escalation tool name must not be empty")]
    EmptyToolName,
    #[error("sandbox escalation subject must not be empty")]
    EmptySubject,
    #[error("sandbox_permissions requires a justification")]
    MissingJustification,
    #[error("justification is only valid together with sandbox_permissions")]
    OrphanJustification,
    #[error("sandbox escalation justification must be a non-empty sentence")]
    BlankJustification,
    #[error("sandbox escalation to `{requested}` is not strictly wider than `{current}`")]
    NotStrictlyWider {
        requested: SandboxMode,
        current: SandboxMode,
    },
    #[error(
        "sandbox escalation grant does not match the exact live Session, call, or standing mode"
    )]
    EscalationGrantMismatch,
    #[error("the user rejected escalating this {subject} to `{mode}`")]
    EscalationRejected { subject: String, mode: SandboxMode },
    #[error("approval for escalating to `{mode}` was cancelled")]
    EscalationCancelled { mode: SandboxMode },
    #[error(
        "sandbox escalation to `{mode}` requires approval, but no approval channel is available"
    )]
    EscalationUnavailable { mode: SandboxMode },
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl SandboxError {
    /// Structured error identity preserved through future tool-result adapters.
    #[must_use]
    pub const fn code(&self) -> Option<&'static str> {
        match self {
            Self::ProviderUnavailable { .. } => Some(SANDBOX_UNAVAILABLE),
            _ => None,
        }
    }
}

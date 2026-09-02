//! Durable sandbox policy and one-shot escalation adapted from DeepSeek Harness.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::approval::{ApprovalError, ApprovalOutcome, ApprovalRequest, request_approval};
use crate::context::{Context, keys};
use crate::fiber::LifecycleCancellation;
use crate::session::{SessionError, SessionHandle, SessionId, SessionStore};
use crate::surface::AgentRef;

/// Every supported file-effect mode, from narrowest to widest.
pub const SANDBOX_MODES: &[SandboxMode] = &[
    SandboxMode::ReadOnly,
    SandboxMode::WorkspaceWrite,
    SandboxMode::DangerFullAccess,
];

/// Closed targets a confined call may request through one-shot escalation.
pub const SANDBOX_ESCALATION_TARGETS: &[SandboxMode] =
    &[SandboxMode::WorkspaceWrite, SandboxMode::DangerFullAccess];

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
    if let Some(session) = request.session.as_ref() {
        let sessions = ctx
            .sessions::<SessionStore>()
            .ok_or(SandboxError::ServiceUnavailable {
                key: keys::SESSIONS,
            })?;
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

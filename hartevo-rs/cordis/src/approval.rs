//! Durable, fail-closed one-shot approval adapted from DeepSeek Harness.

use std::fmt;
use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;
use serde::{Deserialize, Serialize};

use crate::context::{Context, CordisError, keys};
use crate::event::{BailOutcome, EventKey, EventSchemaId, Serial};
use crate::fiber::LifecycleCancellation;
use crate::session::{SessionError, SessionHandle, SessionStore};
use crate::surface::{AgentRef, AgentsSurface};

/// Typed request event consumed by the first answerer that bails.
pub mod events {
    use super::{ApprovalOutcome, ApprovalPrompt, BailOutcome, EventKey, EventSchemaId, Serial};

    pub const APPROVAL_REQUEST: EventKey<Serial, ApprovalPrompt, BailOutcome<ApprovalOutcome>> =
        EventKey::new(
            EventSchemaId::new("hartevo.approval.request.v1"),
            "approval/request",
        );
}

/// Stable identity of one durable approval request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ApprovalRequestId(String);

impl ApprovalRequestId {
    pub fn new(id: impl Into<String>) -> Result<Self, SessionError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SessionError::EmptyApprovalId);
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApprovalRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for ApprovalRequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ApprovalRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = String::deserialize(deserializer)?;
        Self::new(id).map_err(serde::de::Error::custom)
    }
}

/// Closed result vocabulary. Only `AllowedOnce` grants one execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalOutcome {
    AllowedOnce,
    Rejected,
    Cancelled,
    Unavailable,
}

/// Session approval policy. `Never` rejects without dispatching an answerer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPolicy {
    #[default]
    Ask,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPolicySource {
    Delegation,
}

/// Durable `approval/asked` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionApprovalAsked {
    id: ApprovalRequestId,
    tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl SessionApprovalAsked {
    pub fn new(
        id: ApprovalRequestId,
        tool_name: String,
        call_id: Option<String>,
        reason: Option<String>,
    ) -> Result<Self, SessionError> {
        if tool_name.is_empty() {
            return Err(SessionError::InvalidApproval {
                expected: "a non-empty toolName",
            });
        }
        if call_id.as_ref().is_some_and(String::is_empty) {
            return Err(SessionError::InvalidApproval {
                expected: "a non-empty callId when present",
            });
        }
        if reason.as_ref().is_some_and(String::is_empty) {
            return Err(SessionError::InvalidApproval {
                expected: "a non-empty reason when present",
            });
        }
        Ok(Self {
            id,
            tool_name,
            call_id,
            reason,
        })
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let asked: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidApprovalEncoding)?;
        let asked = Self::new(asked.id, asked.tool_name, asked.call_id, asked.reason)?;
        if asked.to_json_value()? != *value {
            return Err(SessionError::InvalidApprovalEncoding);
        }
        Ok(asked)
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidApprovalEncoding)
    }

    #[must_use]
    pub const fn id(&self) -> &ApprovalRequestId {
        &self.id
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// Durable `approval/decided` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionApprovalDecided {
    id: ApprovalRequestId,
    outcome: ApprovalOutcome,
}

impl SessionApprovalDecided {
    #[must_use]
    pub const fn new(id: ApprovalRequestId, outcome: ApprovalOutcome) -> Self {
        Self { id, outcome }
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let decided: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidApprovalEncoding)?;
        Ok(decided)
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidApprovalEncoding)
    }

    #[must_use]
    pub const fn id(&self) -> &ApprovalRequestId {
        &self.id
    }

    #[must_use]
    pub const fn outcome(&self) -> ApprovalOutcome {
        self.outcome
    }
}

/// Durable `approval/policy` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionApprovalPolicy {
    policy: ApprovalPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<ApprovalPolicySource>,
}

impl SessionApprovalPolicy {
    #[must_use]
    pub const fn new(policy: ApprovalPolicy, source: Option<ApprovalPolicySource>) -> Self {
        Self { policy, source }
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let policy: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidApprovalEncoding)?;
        if policy.to_json_value()? != *value {
            return Err(SessionError::InvalidApprovalEncoding);
        }
        Ok(policy)
    }

    pub fn to_json_value(self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidApprovalEncoding)
    }

    #[must_use]
    pub const fn policy(self) -> ApprovalPolicy {
        self.policy
    }

    #[must_use]
    pub const fn source(self) -> Option<ApprovalPolicySource> {
        self.source
    }
}

/// Caller-owned request before Cordis assigns its durable identity.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    agent: AgentRef,
    tool_name: String,
    call_id: Option<String>,
    reason: Option<String>,
    cancellation: LifecycleCancellation,
}

impl ApprovalRequest {
    pub fn new(
        agent: AgentRef,
        tool_name: impl Into<String>,
        cancellation: LifecycleCancellation,
    ) -> Result<Self, ApprovalError> {
        let tool_name = tool_name.into();
        if tool_name.is_empty() {
            return Err(ApprovalError::EmptyToolName);
        }
        Ok(Self {
            agent,
            tool_name,
            call_id: None,
            reason: None,
            cancellation,
        })
    }

    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Result<Self, ApprovalError> {
        let call_id = call_id.into();
        if call_id.is_empty() {
            return Err(ApprovalError::EmptyCallId);
        }
        self.call_id = Some(call_id);
        Ok(self)
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Result<Self, ApprovalError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(ApprovalError::EmptyReason);
        }
        self.reason = Some(reason);
        Ok(self)
    }
}

/// Immutable payload visible to approval answerers after `approval/asked` is durable.
#[derive(Debug, Clone)]
pub struct ApprovalPrompt {
    id: ApprovalRequestId,
    request: ApprovalRequest,
}

impl ApprovalPrompt {
    #[must_use]
    pub const fn id(&self) -> &ApprovalRequestId {
        &self.id
    }

    #[must_use]
    pub const fn agent(&self) -> &AgentRef {
        &self.request.agent
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.request.tool_name
    }

    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.request.call_id.as_deref()
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.request.reason.as_deref()
    }

    #[must_use]
    pub const fn cancellation(&self) -> &LifecycleCancellation {
        &self.request.cancellation
    }
}

/// Marker service proving that the canonical approval capability is mounted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalSurface;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("Cordis approval service `{key}` is unavailable")]
    ServiceUnavailable { key: &'static str },
    #[error("approval tool name must not be empty")]
    EmptyToolName,
    #[error("approval call id must not be empty")]
    EmptyCallId,
    #[error("approval reason must not be empty")]
    EmptyReason,
    #[error("approval agent `{agent_id}` does not own session `{session_id}`")]
    AgentSessionMismatch {
        agent_id: String,
        session_id: String,
    },
    #[error("approval agent `{agent_id}` is not the exact live Cordis agent")]
    AgentUnavailable { agent_id: String },
    #[error(transparent)]
    Cordis(#[from] CordisError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

/// Ask exactly once and audit both sides of the decision before returning it.
pub async fn request_approval(
    ctx: &mut Context,
    session: &SessionHandle,
    request: ApprovalRequest,
) -> Result<ApprovalOutcome, ApprovalError> {
    let _surface =
        ctx.get::<ApprovalSurface>(keys::APPROVAL)
            .ok_or(ApprovalError::ServiceUnavailable {
                key: keys::APPROVAL,
            })?;
    let sessions = ctx
        .sessions::<SessionStore>()
        .ok_or(ApprovalError::ServiceUnavailable {
            key: keys::SESSIONS,
        })?;
    let agents = ctx
        .agents::<AgentsSurface>()
        .ok_or(ApprovalError::ServiceUnavailable { key: keys::AGENTS })?;
    sessions.require_live(session)?;
    if request.agent.id != session.id().as_str() {
        return Err(ApprovalError::AgentSessionMismatch {
            agent_id: request.agent.id.clone(),
            session_id: session.id().as_str().to_owned(),
        });
    }
    if !agents.contains_exact(&request.agent)? {
        return Err(ApprovalError::AgentUnavailable {
            agent_id: request.agent.id.clone(),
        });
    }

    let id = session.begin_approval(
        request.tool_name.clone(),
        request.call_id.clone(),
        request.reason.clone(),
    )?;
    if let Err(error) = sessions.flush(session).await {
        session.decide_approval(id, ApprovalOutcome::Unavailable)?;
        let _ = sessions.flush(session).await;
        return Err(error.into());
    }

    let cancellation = request.cancellation.clone();
    let outcome = if cancellation.is_cancelled() {
        ApprovalOutcome::Cancelled
    } else if session.approval_policy()? == ApprovalPolicy::Never {
        ApprovalOutcome::Rejected
    } else {
        let dispatch = AssertUnwindSafe(ctx.serial(
            events::APPROVAL_REQUEST,
            ApprovalPrompt {
                id: id.clone(),
                request,
            },
        ))
        .catch_unwind();
        tokio::pin!(dispatch);
        let answer = tokio::select! {
            biased;
            () = cancellation.cancelled() => ApprovalOutcome::Cancelled,
            result = &mut dispatch => match result {
                Ok(Ok(BailOutcome::Bail(outcome))) => outcome,
                Ok(Ok(BailOutcome::Continue(_)) | Err(_)) | Err(_) => {
                    ApprovalOutcome::Unavailable
                }
            },
        };
        if cancellation.is_cancelled() {
            ApprovalOutcome::Cancelled
        } else {
            answer
        }
    };

    session.decide_approval(id, outcome)?;
    sessions.flush(session).await?;
    Ok(outcome)
}

/// Persist a changed policy before the caller observes it.
pub async fn set_approval_policy(
    ctx: &Context,
    session: &SessionHandle,
    policy: ApprovalPolicy,
    source: Option<ApprovalPolicySource>,
) -> Result<bool, ApprovalError> {
    let _surface =
        ctx.get::<ApprovalSurface>(keys::APPROVAL)
            .ok_or(ApprovalError::ServiceUnavailable {
                key: keys::APPROVAL,
            })?;
    let sessions = ctx
        .sessions::<SessionStore>()
        .ok_or(ApprovalError::ServiceUnavailable {
            key: keys::SESSIONS,
        })?;
    sessions.require_live(session)?;
    let changed = session.set_approval_policy(policy, source)?;
    if changed {
        sessions.flush(session).await?;
    }
    Ok(changed)
}

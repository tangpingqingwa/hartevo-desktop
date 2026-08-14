use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AccountId, DeviceId, IdentityAccessMode, IdentityBootstrapError, IdentityBootstrapState,
    IdentityScopeFence, IdentitySessionError, IdentitySessionId, IdentitySessionStatus, MemberId,
    Mission, MissionId, ProjectId, TeamId, TenantId,
};

/// A project and mission binding for the identity facts a plugin may consume.
///
/// The binding deliberately carries the complete identity revision fence. A plugin
/// cannot turn a handle mounted for one project, mission, issuer, subject, or
/// revision into a handle for another scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPluginScope {
    tenant_id: TenantId,
    account_id: AccountId,
    team_id: TeamId,
    member_id: MemberId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    device_id: DeviceId,
    session_id: IdentitySessionId,
    session_revision: u64,
    provider_id: String,
    issuer_url: String,
    subject_digest: String,
    fence: IdentityScopeFence,
}

impl IdentityPluginScope {
    /// Builds the supported scope shape from a validated local identity state.
    pub fn from_bootstrap_state(
        state: &IdentityBootstrapState,
        mission_id: MissionId,
        mission_revision: u64,
    ) -> Result<Self, IdentityPluginError> {
        state
            .validate()
            .map_err(|_| IdentityPluginError::InvalidScope)?;
        if mission_id.as_str().trim().is_empty() || mission_revision == 0 {
            return Err(IdentityPluginError::InvalidScope);
        }
        let scope = Self {
            tenant_id: state.account.tenant_id.clone(),
            account_id: state.account.id.clone(),
            team_id: state.team.id.clone(),
            member_id: state.membership.id.clone(),
            project_id: state.project.id.clone(),
            mission_id,
            mission_revision,
            device_id: state.device.id.clone(),
            session_id: state.session.id.clone(),
            session_revision: state.session.revision,
            provider_id: state.session.provider_id.clone(),
            issuer_url: state.account.issuer_url.clone(),
            subject_digest: state.account.subject_digest.clone(),
            fence: state.session.scope.clone(),
        };
        scope.validate_against_state(state)
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    pub fn member_id(&self) -> &MemberId {
        &self.member_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        &self.session_id
    }

    pub fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub fn fence(&self) -> &IdentityScopeFence {
        &self.fence
    }

    fn validate_against_state(
        &self,
        state: &IdentityBootstrapState,
    ) -> Result<Self, IdentityPluginError> {
        if self.tenant_id != state.account.tenant_id
            || self.account_id != state.account.id
            || self.team_id != state.team.id
            || self.member_id != state.membership.id
            || self.project_id != state.project.id
            || self.device_id != state.device.id
            || self.session_id != state.session.id
            || self.session_revision != state.session.revision
            || self.provider_id != state.session.provider_id
            || self.issuer_url != state.account.issuer_url
            || self.subject_digest != state.account.subject_digest
            || self.fence != state.session.scope
            || self.fence.tenant_id != state.account.tenant_id
            || self.fence.team_id != state.team.id
            || self.fence.project_id != state.project.id
            || self.fence.device_id != state.device.id
        {
            return Err(IdentityPluginError::ScopeMismatch);
        }
        Ok(self.clone())
    }

    pub fn validate_against_mission(&self, mission: &Mission) -> Result<(), IdentityPluginError> {
        if self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.mission_revision != mission.revision
        {
            return Err(IdentityPluginError::ScopeMismatch);
        }
        Ok(())
    }
}

/// The host's request to mount one plugin consumer for one mission scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPluginMountRequest {
    consumer_id: String,
    scope: IdentityPluginScope,
}

impl IdentityPluginMountRequest {
    pub fn new(
        consumer_id: impl Into<String>,
        scope: IdentityPluginScope,
    ) -> Result<Self, IdentityPluginError> {
        let consumer_id = consumer_id.into().trim().to_owned();
        if consumer_id.is_empty() || consumer_id.chars().any(char::is_control) {
            return Err(IdentityPluginError::InvalidConsumer);
        }
        Ok(Self { consumer_id, scope })
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn scope(&self) -> &IdentityPluginScope {
        &self.scope
    }
}

/// An opaque capability identifier. The identifier has no scope or secret material
/// encoded in it; authority comes only from the host-owned mounted-handle registry.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct IdentityPluginHandle(Uuid);

impl IdentityPluginHandle {
    /// Creates an opaque candidate handle. Only a host service's mounted registry
    /// can make a handle useful; arbitrary candidates are rejected as unmounted.
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for IdentityPluginHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for IdentityPluginHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityPluginHandle([REDACTED])")
    }
}

/// Non-sensitive identity facts released after the host validates an opaque handle.
///
/// This type intentionally has no token, keyring, secret-reference, or Store field.
/// Its fields are private so consumers must obtain facts from an
/// [`IdentityPluginProvider`] using a mounted handle.
#[derive(Clone, Eq, PartialEq)]
pub struct IdentityPluginSessionFacts {
    scope: IdentityPluginScope,
    access_mode: IdentityAccessMode,
    status: IdentitySessionStatus,
    access_expires_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl IdentityPluginSessionFacts {
    /// Constructs provider facts from a validated bootstrap projection.
    #[doc(hidden)]
    pub fn from_bootstrap_state(
        state: &IdentityBootstrapState,
        mission_id: MissionId,
        mission_revision: u64,
    ) -> Result<Self, IdentityPluginError> {
        let scope = IdentityPluginScope::from_bootstrap_state(state, mission_id, mission_revision)?;
        let access_mode = match state.session.status {
            IdentitySessionStatus::Online => IdentityAccessMode::Online,
            IdentitySessionStatus::Offline => IdentityAccessMode::Offline,
            IdentitySessionStatus::Expired | IdentitySessionStatus::Revoked => {
                return Err(IdentityPluginError::SessionUnavailable);
            }
        };
        Ok(Self {
            scope,
            access_mode,
            status: state.session.status,
            access_expires_at: state.session.access_expires_at,
            expires_at: state.session.expires_at,
        })
    }

    pub fn scope(&self) -> &IdentityPluginScope {
        &self.scope
    }

    pub fn tenant_id(&self) -> &TenantId {
        self.scope.tenant_id()
    }

    pub fn account_id(&self) -> &AccountId {
        self.scope.account_id()
    }

    pub fn team_id(&self) -> &TeamId {
        self.scope.team_id()
    }

    pub fn member_id(&self) -> &MemberId {
        self.scope.member_id()
    }

    pub fn project_id(&self) -> &ProjectId {
        self.scope.project_id()
    }

    pub fn mission_id(&self) -> &MissionId {
        self.scope.mission_id()
    }

    pub fn issuer_url(&self) -> &str {
        self.scope.issuer_url()
    }

    pub fn provider_id(&self) -> &str {
        self.scope.provider_id()
    }

    pub fn subject_digest(&self) -> &str {
        self.scope.subject_digest()
    }

    pub fn access_mode(&self) -> IdentityAccessMode {
        self.access_mode
    }

    pub fn status(&self) -> IdentitySessionStatus {
        self.status
    }

    pub fn access_expires_at(&self) -> DateTime<Utc> {
        self.access_expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for IdentityPluginSessionFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityPluginSessionFacts")
            .field("scope", &self.scope)
            .field("access_mode", &self.access_mode)
            .field("status", &self.status)
            .field("access_expires_at", &self.access_expires_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentityPluginError {
    #[error("identity plugin scope is invalid")]
    InvalidScope,
    #[error("identity plugin consumer identifier is invalid")]
    InvalidConsumer,
    #[error("identity plugin scope does not match the persisted identity state")]
    ScopeMismatch,
    #[error("identity plugin session is unavailable")]
    SessionUnavailable,
    #[error("identity plugin session has been revoked")]
    Revoked,
    #[error("identity plugin session has expired")]
    Expired,
    #[error("identity plugin handle is not mounted")]
    HandleNotMounted,
    #[error("identity plugin persistence rejected the request: {0}")]
    Persistence(String),
}

/// Provider boundary visible to a plugin consumer. It releases facts only after
/// validating a host-owned opaque handle and its current scope fence.
pub trait IdentityPluginProvider {
    fn provide_identity_facts(
        &mut self,
        handle: &IdentityPluginHandle,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginSessionFacts, IdentityPluginError>;
}

/// Host-owned lifecycle boundary for project/mission plugin identity handles.
pub trait IdentityPluginService: IdentityPluginProvider {
    fn mount_identity(
        &mut self,
        request: &IdentityPluginMountRequest,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityPluginError>;

    fn unmount_identity(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityPluginError>;

    fn revoke_identity_handle(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityPluginError>;

    fn reclaim_crashed_consumer(&mut self, consumer_id: &str) -> usize;
}

/// Consumer boundary: the plugin receives only the opaque handle and a provider
/// seam. It never receives a Store, SecretStore, keyring, or token.
pub trait IdentityPluginConsumer {
    fn mount_identity(
        &mut self,
        provider: &mut dyn IdentityPluginProvider,
        handle: IdentityPluginHandle,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityPluginError>;

    fn unmount_identity(&mut self, handle: &IdentityPluginHandle);
}

impl From<IdentityBootstrapError> for IdentityPluginError {
    fn from(_: IdentityBootstrapError) -> Self {
        Self::InvalidScope
    }
}

impl From<IdentitySessionError> for IdentityPluginError {
    fn from(error: IdentitySessionError) -> Self {
        match error {
            IdentitySessionError::ScopeMismatch => Self::ScopeMismatch,
            IdentitySessionError::Revoked => Self::Revoked,
            IdentitySessionError::Expired | IdentitySessionError::AccessTokenExpired => {
                Self::Expired
            }
            IdentitySessionError::InvalidSession
            | IdentitySessionError::OfflineCloudUnavailable
            | IdentitySessionError::InvalidRefreshExpiry
            | IdentitySessionError::TimestampRegression
            | IdentitySessionError::SessionStillValid
            | IdentitySessionError::RevisionOverflow => Self::SessionUnavailable,
        }
    }
}

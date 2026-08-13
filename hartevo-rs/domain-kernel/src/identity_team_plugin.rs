use std::collections::{BTreeMap, HashMap};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AccountId, ActorId, IdentityMembershipReceiptId, IdentitySessionId, MemberId, Mission,
    MissionId, ProjectId, TeamId, TenantId,
};

pub const DEFAULT_OFFLINE_MEMBERSHIP_CACHE_TTL: Duration = Duration::days(30);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTeamRole {
    Viewer,
    Member,
    Admin,
    Owner,
}

impl IdentityTeamRole {
    pub fn rank(self) -> u8 {
        match self {
            Self::Viewer => 1,
            Self::Member => 2,
            Self::Admin => 3,
            Self::Owner => 4,
        }
    }

    pub fn satisfies(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTeamMembershipStatus {
    Invited,
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTeamMembership {
    id: MemberId,
    tenant_id: TenantId,
    team_id: TeamId,
    account_id: AccountId,
    role: IdentityTeamRole,
    status: IdentityTeamMembershipStatus,
    membership_revision: u64,
    role_revision: u64,
}

impl IdentityTeamMembership {
    pub fn invited(
        id: MemberId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        role: IdentityTeamRole,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let membership = Self {
            id,
            tenant_id,
            team_id,
            account_id,
            role,
            status: IdentityTeamMembershipStatus::Invited,
            membership_revision: 1,
            role_revision: 1,
        };
        membership.validate()?;
        Ok(membership)
    }

    pub fn active(
        id: MemberId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        role: IdentityTeamRole,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let mut membership = Self::invited(id, tenant_id, team_id, account_id, role)?;
        membership.status = IdentityTeamMembershipStatus::Active;
        Ok(membership)
    }

    pub fn id(&self) -> &MemberId {
        &self.id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn role(&self) -> IdentityTeamRole {
        self.role
    }

    pub fn status(&self) -> IdentityTeamMembershipStatus {
        self.status
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    fn validate(&self) -> Result<(), IdentityTeamMembershipError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.membership_revision == 0
            || self.role_revision == 0
            || self.role_revision > self.membership_revision
            || (self.status == IdentityTeamMembershipStatus::Invited
                && self.membership_revision != 1)
        {
            return Err(IdentityTeamMembershipError::InvalidMembership);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IdentityMembershipReceiptKind {
    Invited {
        role: IdentityTeamRole,
    },
    AcceptedInvite,
    RoleChanged {
        from: IdentityTeamRole,
        to: IdentityTeamRole,
    },
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityMembershipReceipt {
    id: IdentityMembershipReceiptId,
    tenant_id: TenantId,
    team_id: TeamId,
    member_id: MemberId,
    account_id: AccountId,
    previous_membership_revision: u64,
    membership_revision: u64,
    previous_role_revision: u64,
    role_revision: u64,
    kind: IdentityMembershipReceiptKind,
    actor_id: ActorId,
    evidence_digest: String,
    issued_at: DateTime<Utc>,
}

impl IdentityMembershipReceipt {
    pub fn id(&self) -> &IdentityMembershipReceiptId {
        &self.id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    pub fn member_id(&self) -> &MemberId {
        &self.member_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn previous_membership_revision(&self) -> u64 {
        self.previous_membership_revision
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn previous_role_revision(&self) -> u64 {
        self.previous_role_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    pub fn kind(&self) -> &IdentityMembershipReceiptKind {
        &self.kind
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    fn validate(&self) -> Result<(), IdentityTeamMembershipError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.member_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.actor_id.as_str().trim().is_empty()
            || !is_sha256(&self.evidence_digest)
            || self.membership_revision == 0
            || self.role_revision == 0
            || self.issued_at.timestamp() < 0
        {
            return Err(IdentityTeamMembershipError::InvalidReceipt);
        }
        let membership_advanced =
            self.previous_membership_revision.checked_add(1) == Some(self.membership_revision);
        match &self.kind {
            IdentityMembershipReceiptKind::Invited { .. } => {
                if self.previous_membership_revision != 0
                    || self.previous_role_revision != 0
                    || self.membership_revision != 1
                    || self.role_revision != 1
                {
                    return Err(IdentityTeamMembershipError::InvalidReceipt);
                }
            }
            IdentityMembershipReceiptKind::AcceptedInvite
            | IdentityMembershipReceiptKind::Revoked => {
                if !membership_advanced || self.previous_role_revision != self.role_revision {
                    return Err(IdentityTeamMembershipError::InvalidReceipt);
                }
            }
            IdentityMembershipReceiptKind::RoleChanged { from, to } => {
                if !membership_advanced
                    || self.previous_role_revision.checked_add(1) != Some(self.role_revision)
                    || from == to
                {
                    return Err(IdentityTeamMembershipError::InvalidReceipt);
                }
            }
        }
        Ok(())
    }
}

/// Exact Project/Mission composition scope. Team membership is deliberately not
/// inferred from a Project ID or a Mission ID alone.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityMissionScope {
    tenant_id: TenantId,
    team_id: TeamId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
}

impl IdentityMissionScope {
    pub fn new(
        tenant_id: TenantId,
        team_id: TeamId,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let scope = Self {
            tenant_id,
            team_id,
            project_id,
            mission_id,
            mission_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_mission(
        mission: &Mission,
        team_id: TeamId,
    ) -> Result<Self, IdentityTeamMembershipError> {
        Self::new(
            mission.tenant_id.clone(),
            team_id,
            mission.project_id.clone(),
            mission.id.clone(),
            mission.revision,
        )
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn team_id(&self) -> &TeamId {
        &self.team_id
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

    pub fn validate(&self) -> Result<(), IdentityTeamMembershipError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.mission_revision == 0
        {
            return Err(IdentityTeamMembershipError::InvalidScope);
        }
        Ok(())
    }

    pub fn matches_mission(&self, mission: &Mission) -> bool {
        self.tenant_id == mission.tenant_id
            && self.project_id == mission.project_id
            && self.mission_id == mission.id
            && self.mission_revision == mission.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityOidcSession {
    issuer_url: String,
    subject_digest: String,
    tenant_id: TenantId,
    account_id: AccountId,
    session_id: IdentitySessionId,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl IdentityOidcSession {
    pub fn new(
        issuer_url: impl Into<String>,
        subject_digest: impl Into<String>,
        tenant_id: TenantId,
        account_id: AccountId,
        session_id: IdentitySessionId,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let session = Self {
            issuer_url: issuer_url.into().trim().trim_end_matches('/').to_owned(),
            subject_digest: subject_digest.into(),
            tenant_id,
            account_id,
            session_id,
            issued_at,
            expires_at,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        &self.session_id
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn validate(&self) -> Result<(), IdentityTeamMembershipError> {
        if !is_https_url(&self.issuer_url)
            || !is_sha256(&self.subject_digest)
            || self.tenant_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.session_id.as_str().trim().is_empty()
            || self.issued_at.timestamp() < 0
            || self.expires_at <= self.issued_at
        {
            return Err(IdentityTeamMembershipError::InvalidOidcSession);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySessionHeadStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySessionHead {
    session_id: IdentitySessionId,
    scope: IdentityMissionScope,
    account_id: AccountId,
    member_id: MemberId,
    issuer_url: String,
    subject_digest: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revision: u64,
    status: IdentitySessionHeadStatus,
}

impl IdentitySessionHead {
    fn from_oidc(
        session: &IdentityOidcSession,
        scope: &IdentityMissionScope,
        membership: &IdentityTeamMembership,
    ) -> Self {
        Self {
            session_id: session.session_id.clone(),
            scope: scope.clone(),
            account_id: session.account_id.clone(),
            member_id: membership.id.clone(),
            issuer_url: session.issuer_url.clone(),
            subject_digest: session.subject_digest.clone(),
            issued_at: session.issued_at,
            expires_at: session.expires_at,
            revision: 1,
            status: IdentitySessionHeadStatus::Active,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "rehydration requires every persisted session and exact scope field"
    )]
    pub fn active(
        session_id: IdentitySessionId,
        scope: IdentityMissionScope,
        account_id: AccountId,
        member_id: MemberId,
        issuer_url: impl Into<String>,
        subject_digest: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let head = Self {
            session_id,
            scope,
            account_id,
            member_id,
            issuer_url: issuer_url.into().trim().trim_end_matches('/').to_owned(),
            subject_digest: subject_digest.into(),
            issued_at,
            expires_at,
            revision,
            status: IdentitySessionHeadStatus::Active,
        };
        head.validate()?;
        Ok(head)
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        &self.session_id
    }

    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn member_id(&self) -> &MemberId {
        &self.member_id
    }

    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn status(&self) -> IdentitySessionHeadStatus {
        self.status
    }

    fn validate(&self) -> Result<(), IdentityTeamMembershipError> {
        self.scope.validate()?;
        if self.session_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.member_id.as_str().trim().is_empty()
            || !is_https_url(&self.issuer_url)
            || !is_sha256(&self.subject_digest)
            || self.issued_at.timestamp() < 0
            || self.expires_at <= self.issued_at
            || self.revision == 0
        {
            return Err(IdentityTeamMembershipError::InvalidSessionHead);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySessionAccessMode {
    Online,
    Offline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityOfflineMembershipCache {
    scope: IdentityMissionScope,
    session_head: IdentitySessionHead,
    membership_id: MemberId,
    role: IdentityTeamRole,
    membership_revision: u64,
    role_revision: u64,
    cached_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl IdentityOfflineMembershipCache {
    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }

    pub fn session_head(&self) -> &IdentitySessionHead {
        &self.session_head
    }

    pub fn membership_id(&self) -> &MemberId {
        &self.membership_id
    }

    pub fn role(&self) -> IdentityTeamRole {
        self.role
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    pub fn cached_at(&self) -> DateTime<Utc> {
        self.cached_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn validate(&self) -> Result<(), IdentityTeamMembershipError> {
        self.scope.validate()?;
        self.session_head.validate()?;
        if self.session_head.scope != self.scope
            || self.session_head.member_id != self.membership_id
            || self.membership_revision == 0
            || self.role_revision == 0
            || self.cached_at.timestamp() < 0
            || self.expires_at <= self.cached_at
            || self.expires_at > self.session_head.expires_at
            || self.session_head.status != IdentitySessionHeadStatus::Active
        {
            return Err(IdentityTeamMembershipError::InvalidOfflineCache);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct IdentityPluginHandle(Uuid);

impl IdentityPluginHandle {
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

#[derive(Clone, Eq, PartialEq)]
pub struct IdentityPluginSessionFacts {
    scope: IdentityMissionScope,
    session_head: IdentitySessionHead,
    role: IdentityTeamRole,
    membership_revision: u64,
    role_revision: u64,
    mode: IdentitySessionAccessMode,
    cached_at: DateTime<Utc>,
    offline_expires_at: DateTime<Utc>,
}

impl IdentityPluginSessionFacts {
    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }

    pub fn session_head(&self) -> &IdentitySessionHead {
        &self.session_head
    }

    pub fn account_id(&self) -> &AccountId {
        self.session_head.account_id()
    }

    pub fn membership_id(&self) -> &MemberId {
        self.session_head.member_id()
    }

    pub fn issuer_url(&self) -> &str {
        self.session_head.issuer_url()
    }

    pub fn subject_digest(&self) -> &str {
        self.session_head.subject_digest()
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        self.session_head.session_id()
    }

    pub fn session_revision(&self) -> u64 {
        self.session_head.revision()
    }

    pub fn role(&self) -> IdentityTeamRole {
        self.role
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    pub fn mode(&self) -> IdentitySessionAccessMode {
        self.mode
    }

    pub fn session_expires_at(&self) -> DateTime<Utc> {
        self.session_head.expires_at()
    }

    pub fn offline_expires_at(&self) -> DateTime<Utc> {
        self.offline_expires_at
    }

    pub fn policy_expires_at(&self) -> DateTime<Utc> {
        match self.mode {
            IdentitySessionAccessMode::Online => self.session_head.expires_at(),
            IdentitySessionAccessMode::Offline => self.offline_expires_at,
        }
    }

    pub fn provider_digest(&self) -> String {
        identity_provider_digest(self)
    }

    pub fn authorize_capability(
        &self,
        requirement: &IdentityCapabilityRequirement,
    ) -> Result<IdentityPluginPolicyDecision, IdentityTeamMembershipError> {
        if self.scope != requirement.scope {
            return Err(IdentityTeamMembershipError::CapabilityScopeMismatch);
        }
        if !self.role.satisfies(requirement.minimum_role) {
            return Err(IdentityTeamMembershipError::InsufficientRole);
        }
        Ok(IdentityPluginPolicyDecision {
            capability_id: requirement.capability_id.clone(),
            scope: self.scope.clone(),
            role: self.role,
            minimum_role: requirement.minimum_role,
            membership_revision: self.membership_revision,
            role_revision: self.role_revision,
            session_revision: self.session_head.revision,
            mode: self.mode,
            expires_at: self.policy_expires_at(),
            provider_digest: self.provider_digest(),
        })
    }

    pub fn offline_cache(&self) -> IdentityOfflineMembershipCache {
        IdentityOfflineMembershipCache {
            scope: self.scope.clone(),
            session_head: self.session_head.clone(),
            membership_id: self.session_head.member_id.clone(),
            role: self.role,
            membership_revision: self.membership_revision,
            role_revision: self.role_revision,
            cached_at: self.cached_at,
            expires_at: self.offline_expires_at,
        }
    }
}

impl fmt::Debug for IdentityPluginSessionFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityPluginSessionFacts")
            .field("scope", &self.scope)
            .field("role", &self.role)
            .field("membership_revision", &self.membership_revision)
            .field("role_revision", &self.role_revision)
            .field("mode", &self.mode)
            .field("cached_at", &self.cached_at)
            .field("session_revision", &self.session_head.revision)
            .field("offline_expires_at", &self.offline_expires_at)
            .finish()
    }
}

/// Naming alias for the exact live Team/Mission binding consumed by the
/// capability-policy projection. The alias keeps the lower-level identity
/// facts type stable while making the boundary explicit to policy code.
pub type IdentityTeamMembershipBinding = IdentityPluginSessionFacts;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCapabilityRequirement {
    capability_id: String,
    scope: IdentityMissionScope,
    minimum_role: IdentityTeamRole,
}

impl IdentityCapabilityRequirement {
    pub fn new(
        capability_id: impl Into<String>,
        scope: IdentityMissionScope,
        minimum_role: IdentityTeamRole,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let capability_id = capability_id.into().trim().to_owned();
        if capability_id.is_empty() || capability_id.chars().any(char::is_control) {
            return Err(IdentityTeamMembershipError::InvalidCapabilityRequirement);
        }
        scope.validate()?;
        Ok(Self {
            capability_id,
            scope,
            minimum_role,
        })
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }

    pub fn minimum_role(&self) -> IdentityTeamRole {
        self.minimum_role
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCapabilityPolicyRoles {
    granted: IdentityTeamRole,
    required: IdentityTeamRole,
}

impl IdentityCapabilityPolicyRoles {
    pub fn granted(&self) -> IdentityTeamRole {
        self.granted
    }

    pub fn required(&self) -> IdentityTeamRole {
        self.required
    }

    pub fn is_satisfied(&self) -> bool {
        self.granted.satisfies(self.required)
    }
}

/// Content-free, exact-scope policy material delivered to a capability
/// consumer. The skipped handle is an internal live-binding fence: it is
/// never serialized or exposed, and every authorization revalidates it with
/// the host-owned provider.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCapabilityPolicyInput {
    capability_id: String,
    scope: IdentityMissionScope,
    roles: IdentityCapabilityPolicyRoles,
    membership_revision: u64,
    role_revision: u64,
    session_revision: u64,
    mode: IdentitySessionAccessMode,
    expires_at: DateTime<Utc>,
    provider_digest: String,
    #[serde(skip)]
    handle: IdentityPluginHandle,
}

impl IdentityCapabilityPolicyInput {
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }

    pub fn roles(&self) -> IdentityCapabilityPolicyRoles {
        self.roles
    }

    pub fn granted_role(&self) -> IdentityTeamRole {
        self.roles.granted
    }

    pub fn required_role(&self) -> IdentityTeamRole {
        self.roles.required
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    pub fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub fn mode(&self) -> IdentitySessionAccessMode {
        self.mode
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Revalidate and authorize this content-free input through the host.
    /// Keeping the live binding check here prevents a consumer from treating
    /// a cached input as authority after a role change, revoke, or expiry.
    pub fn authorize(
        &self,
        provider: &mut dyn IdentityCapabilityPolicyProvider,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginPolicyDecision, IdentityTeamMembershipError> {
        self.validate_shape()?;
        provider.validate_capability_policy_input(self, now)?;
        if !self.roles.is_satisfied() {
            return Err(IdentityTeamMembershipError::InsufficientRole);
        }
        Ok(IdentityPluginPolicyDecision::from_policy_input(self))
    }

    fn from_facts(
        handle: &IdentityPluginHandle,
        facts: &IdentityPluginSessionFacts,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<Self, IdentityTeamMembershipError> {
        if facts.scope != requirement.scope {
            return Err(IdentityTeamMembershipError::CapabilityScopeMismatch);
        }
        let expires_at = facts.policy_expires_at();
        if expires_at <= now {
            return Err(match facts.mode {
                IdentitySessionAccessMode::Online => IdentityTeamMembershipError::SessionExpired,
                IdentitySessionAccessMode::Offline => {
                    IdentityTeamMembershipError::OfflineMembershipExpired
                }
            });
        }
        let input = Self {
            capability_id: requirement.capability_id.clone(),
            scope: facts.scope.clone(),
            roles: IdentityCapabilityPolicyRoles {
                granted: facts.role,
                required: requirement.minimum_role,
            },
            membership_revision: facts.membership_revision,
            role_revision: facts.role_revision,
            session_revision: facts.session_head.revision,
            mode: facts.mode,
            expires_at,
            provider_digest: identity_provider_digest(facts),
            handle: handle.clone(),
        };
        input.validate_shape()?;
        Ok(input)
    }

    fn validate_shape(&self) -> Result<(), IdentityTeamMembershipError> {
        if self.capability_id.trim().is_empty()
            || self.capability_id.chars().any(char::is_control)
            || self.membership_revision == 0
            || self.role_revision == 0
            || self.session_revision == 0
            || !is_sha256(&self.provider_digest)
            || self.expires_at.timestamp() < 0
        {
            return Err(IdentityTeamMembershipError::InvalidCapabilityPolicyInput);
        }
        self.scope.validate()
    }

    fn same_material(&self, other: &Self) -> bool {
        self.capability_id == other.capability_id
            && self.scope == other.scope
            && self.roles == other.roles
            && self.membership_revision == other.membership_revision
            && self.role_revision == other.role_revision
            && self.session_revision == other.session_revision
            && self.mode == other.mode
            && self.expires_at == other.expires_at
            && self.provider_digest == other.provider_digest
    }
}

impl fmt::Debug for IdentityCapabilityPolicyInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityCapabilityPolicyInput")
            .field("capability_id", &self.capability_id)
            .field("scope", &self.scope)
            .field("roles", &self.roles)
            .field("membership_revision", &self.membership_revision)
            .field("role_revision", &self.role_revision)
            .field("session_revision", &self.session_revision)
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .field("provider_digest", &self.provider_digest)
            .finish_non_exhaustive()
    }
}

impl PartialEq for IdentityCapabilityPolicyInput {
    fn eq(&self, other: &Self) -> bool {
        self.same_material(other)
    }
}

impl Eq for IdentityCapabilityPolicyInput {}

/// Identity-owned spelling for the generic capability policy contract.
pub type CapabilityPolicyInput = IdentityCapabilityPolicyInput;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPluginPolicyDecision {
    capability_id: String,
    scope: IdentityMissionScope,
    role: IdentityTeamRole,
    minimum_role: IdentityTeamRole,
    membership_revision: u64,
    role_revision: u64,
    session_revision: u64,
    mode: IdentitySessionAccessMode,
    expires_at: DateTime<Utc>,
    provider_digest: String,
}

impl IdentityPluginPolicyDecision {
    fn from_policy_input(input: &IdentityCapabilityPolicyInput) -> Self {
        Self {
            capability_id: input.capability_id.clone(),
            scope: input.scope.clone(),
            role: input.roles.granted,
            minimum_role: input.roles.required,
            membership_revision: input.membership_revision,
            role_revision: input.role_revision,
            session_revision: input.session_revision,
            mode: input.mode,
            expires_at: input.expires_at,
            provider_digest: input.provider_digest.clone(),
        }
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }

    pub fn role(&self) -> IdentityTeamRole {
        self.role
    }

    pub fn minimum_role(&self) -> IdentityTeamRole {
        self.minimum_role
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    pub fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub fn mode(&self) -> IdentitySessionAccessMode {
        self.mode
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }
}

#[derive(Clone, Debug)]
struct MountedIdentityBinding {
    consumer_id: String,
    facts: IdentityPluginSessionFacts,
    invalidation: Option<BindingInvalidation>,
}

#[derive(Clone, Debug)]
enum BindingInvalidation {
    Stale(IdentityMembershipReceiptId),
    Revoked(IdentityMembershipReceiptId),
    SessionStale,
    SessionRevoked,
}

/// The host-owned service/provider implementation. Its public provider surface
/// contains only typed identity facts and policy decisions; it has no Store,
/// keyring, or token access.
#[derive(Debug)]
pub struct ProjectMissionIdentityService {
    offline_cache_ttl: Duration,
    memberships: BTreeMap<MemberId, IdentityTeamMembership>,
    session_heads: BTreeMap<IdentitySessionId, IdentitySessionHead>,
    bindings: HashMap<IdentityPluginHandle, MountedIdentityBinding>,
    policy_inputs: HashMap<IdentityPluginHandle, HashMap<String, IdentityCapabilityPolicyInput>>,
    receipts: Vec<IdentityMembershipReceipt>,
}

impl ProjectMissionIdentityService {
    pub fn new(offline_cache_ttl: Duration) -> Result<Self, IdentityTeamMembershipError> {
        if offline_cache_ttl <= Duration::zero() {
            return Err(IdentityTeamMembershipError::InvalidOfflineCacheTtl);
        }
        Ok(Self {
            offline_cache_ttl,
            memberships: BTreeMap::new(),
            session_heads: BTreeMap::new(),
            bindings: HashMap::new(),
            policy_inputs: HashMap::new(),
            receipts: Vec::new(),
        })
    }

    pub fn with_default_offline_cache_ttl() -> Self {
        Self::new(DEFAULT_OFFLINE_MEMBERSHIP_CACHE_TTL).expect("default offline TTL is valid")
    }

    pub fn register_membership(
        &mut self,
        membership: IdentityTeamMembership,
    ) -> Result<(), IdentityTeamMembershipError> {
        membership.validate()?;
        if let Some(existing) = self.memberships.get(membership.id()) {
            if existing != &membership {
                return Err(IdentityTeamMembershipError::MembershipProjectionMismatch);
            }
            return Ok(());
        }
        if self.memberships.values().any(|existing| {
            existing.tenant_id == membership.tenant_id
                && existing.team_id == membership.team_id
                && existing.account_id == membership.account_id
                && existing.status != IdentityTeamMembershipStatus::Revoked
        }) {
            return Err(IdentityTeamMembershipError::AmbiguousMembership);
        }
        self.memberships.insert(membership.id.clone(), membership);
        Ok(())
    }

    pub fn register_session_head(
        &mut self,
        head: IdentitySessionHead,
    ) -> Result<(), IdentityTeamMembershipError> {
        head.validate()?;
        if let Some(existing) = self.session_heads.get(head.session_id()) {
            if existing.status == IdentitySessionHeadStatus::Revoked {
                return Err(IdentityTeamMembershipError::SessionRevoked);
            }
            if existing.revision > head.revision {
                return Err(IdentityTeamMembershipError::StaleSession);
            }
            if existing.revision == head.revision {
                if existing != &head {
                    return Err(IdentityTeamMembershipError::SessionProjectionMismatch);
                }
                return Ok(());
            }
            self.invalidate_session_bindings(head.session_id(), false);
        }
        self.session_heads.insert(head.session_id.clone(), head);
        Ok(())
    }

    pub fn receipts(&self) -> &[IdentityMembershipReceipt] {
        &self.receipts
    }

    pub fn active_binding_count(&self) -> usize {
        self.bindings
            .values()
            .filter(|binding| binding.invalidation.is_none())
            .count()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "membership invitation is one typed transition with explicit audit fields"
    )]
    pub fn invite(
        &mut self,
        id: MemberId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        role: IdentityTeamRole,
        actor_id: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<IdentityMembershipReceipt, IdentityTeamMembershipError> {
        let membership = IdentityTeamMembership::invited(id, tenant_id, team_id, account_id, role)?;
        let receipt = self.append_membership_transition(
            membership,
            IdentityMembershipReceiptKind::Invited { role },
            actor_id,
            evidence_digest.into(),
            now,
        )?;
        Ok(receipt)
    }

    pub fn accept_invite(
        &mut self,
        member_id: &MemberId,
        actor_id: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<IdentityMembershipReceipt, IdentityTeamMembershipError> {
        let previous = self
            .memberships
            .get(member_id)
            .cloned()
            .ok_or(IdentityTeamMembershipError::MembershipNotFound)?;
        if previous.status != IdentityTeamMembershipStatus::Invited {
            return Err(IdentityTeamMembershipError::InvalidMembershipTransition);
        }
        let mut next = previous.clone();
        next.status = IdentityTeamMembershipStatus::Active;
        next.membership_revision = next
            .membership_revision
            .checked_add(1)
            .ok_or(IdentityTeamMembershipError::RevisionOverflow)?;
        self.append_membership_transition(
            next,
            IdentityMembershipReceiptKind::AcceptedInvite,
            actor_id,
            evidence_digest.into(),
            now,
        )
    }

    pub fn change_role(
        &mut self,
        member_id: &MemberId,
        role: IdentityTeamRole,
        actor_id: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<IdentityMembershipReceipt, IdentityTeamMembershipError> {
        let previous = self
            .memberships
            .get(member_id)
            .cloned()
            .ok_or(IdentityTeamMembershipError::MembershipNotFound)?;
        if previous.status != IdentityTeamMembershipStatus::Active || previous.role == role {
            return Err(IdentityTeamMembershipError::InvalidMembershipTransition);
        }
        let mut next = previous.clone();
        next.role = role;
        next.membership_revision = next
            .membership_revision
            .checked_add(1)
            .ok_or(IdentityTeamMembershipError::RevisionOverflow)?;
        next.role_revision = next
            .role_revision
            .checked_add(1)
            .ok_or(IdentityTeamMembershipError::RevisionOverflow)?;
        let receipt = self.append_membership_transition(
            next,
            IdentityMembershipReceiptKind::RoleChanged {
                from: previous.role,
                to: role,
            },
            actor_id,
            evidence_digest.into(),
            now,
        )?;
        self.bump_member_session_heads(member_id, false)?;
        self.invalidate_member_bindings(member_id, &BindingInvalidation::Stale(receipt.id.clone()));
        Ok(receipt)
    }

    pub fn revoke_member(
        &mut self,
        member_id: &MemberId,
        actor_id: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<IdentityMembershipReceipt, IdentityTeamMembershipError> {
        let previous = self
            .memberships
            .get(member_id)
            .cloned()
            .ok_or(IdentityTeamMembershipError::MembershipNotFound)?;
        if previous.status == IdentityTeamMembershipStatus::Revoked {
            return Err(IdentityTeamMembershipError::InvalidMembershipTransition);
        }
        let mut next = previous.clone();
        next.status = IdentityTeamMembershipStatus::Revoked;
        next.membership_revision = next
            .membership_revision
            .checked_add(1)
            .ok_or(IdentityTeamMembershipError::RevisionOverflow)?;
        let receipt = self.append_membership_transition(
            next,
            IdentityMembershipReceiptKind::Revoked,
            actor_id,
            evidence_digest.into(),
            now,
        )?;
        self.bump_member_session_heads(member_id, true)?;
        self.invalidate_member_bindings(
            member_id,
            &BindingInvalidation::Revoked(receipt.id.clone()),
        );
        Ok(receipt)
    }

    pub fn mount_online(
        &mut self,
        request: &IdentityPluginMountRequest,
        session: &IdentityOidcSession,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityTeamMembershipError> {
        validate_consumer_id(&request.consumer_id)?;
        request.scope.validate()?;
        session.validate()?;
        if session.tenant_id != request.scope.tenant_id {
            return Err(IdentityTeamMembershipError::ScopeMismatch);
        }
        if session.expires_at <= now {
            return Err(IdentityTeamMembershipError::SessionExpired);
        }
        let membership = self.find_membership_for_session(session, &request.scope)?;
        let head = IdentitySessionHead::from_oidc(session, &request.scope, &membership);
        self.register_or_reuse_online_head(head.clone(), now)?;
        let head = self
            .session_heads
            .get(&session.session_id)
            .cloned()
            .ok_or(IdentityTeamMembershipError::StaleSession)?;
        let offline_expires_at = min_expiry(
            session.expires_at,
            now.checked_add_signed(self.offline_cache_ttl)
                .ok_or(IdentityTeamMembershipError::RevisionOverflow)?,
        );
        if offline_expires_at <= now {
            return Err(IdentityTeamMembershipError::SessionExpired);
        }
        let facts = IdentityPluginSessionFacts {
            scope: request.scope.clone(),
            session_head: head,
            role: membership.role,
            membership_revision: membership.membership_revision,
            role_revision: membership.role_revision,
            mode: IdentitySessionAccessMode::Online,
            cached_at: now,
            offline_expires_at,
        };
        Ok(self.insert_binding(request, facts))
    }

    pub fn reopen_offline(
        &mut self,
        request: &IdentityPluginMountRequest,
        cache: &IdentityOfflineMembershipCache,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityTeamMembershipError> {
        validate_consumer_id(&request.consumer_id)?;
        request.scope.validate()?;
        cache.validate()?;
        if cache.scope != request.scope {
            return Err(IdentityTeamMembershipError::ScopeMismatch);
        }
        if cache.cached_at > now || cache.expires_at <= now {
            return Err(IdentityTeamMembershipError::OfflineMembershipExpired);
        }
        let membership = self
            .memberships
            .get(&cache.membership_id)
            .ok_or(IdentityTeamMembershipError::MembershipNotFound)?;
        if membership.status != IdentityTeamMembershipStatus::Active {
            return Err(IdentityTeamMembershipError::MembershipRevoked);
        }
        if membership.tenant_id != cache.scope.tenant_id
            || membership.team_id != cache.scope.team_id
            || membership.account_id != cache.session_head.account_id
            || membership.membership_revision != cache.membership_revision
            || membership.role_revision != cache.role_revision
            || membership.role != cache.role
        {
            return Err(IdentityTeamMembershipError::StaleMembership);
        }
        let head = self
            .session_heads
            .get(cache.session_head.session_id())
            .ok_or(IdentityTeamMembershipError::StaleSession)?;
        if head != &cache.session_head {
            return if head.status == IdentitySessionHeadStatus::Revoked {
                Err(IdentityTeamMembershipError::SessionRevoked)
            } else {
                Err(IdentityTeamMembershipError::StaleSession)
            };
        }
        if head.status != IdentitySessionHeadStatus::Active || head.expires_at <= now {
            return Err(if head.status == IdentitySessionHeadStatus::Revoked {
                IdentityTeamMembershipError::SessionRevoked
            } else {
                IdentityTeamMembershipError::SessionExpired
            });
        }
        let facts = IdentityPluginSessionFacts {
            scope: cache.scope.clone(),
            session_head: head.clone(),
            role: cache.role,
            membership_revision: cache.membership_revision,
            role_revision: cache.role_revision,
            mode: IdentitySessionAccessMode::Offline,
            cached_at: cache.cached_at,
            offline_expires_at: cache.expires_at,
        };
        Ok(self.insert_binding(request, facts))
    }

    pub fn provide_capability_policy_input(
        &mut self,
        handle: &IdentityPluginHandle,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<IdentityCapabilityPolicyInput, IdentityTeamMembershipError> {
        let facts = self.provide_identity_facts(handle, requirement.scope(), now)?;
        let input = IdentityCapabilityPolicyInput::from_facts(handle, &facts, requirement, now)?;
        self.policy_inputs
            .entry(handle.clone())
            .or_default()
            .insert(input.capability_id.clone(), input.clone());
        Ok(input)
    }

    pub fn validate_capability_policy_input(
        &mut self,
        input: &IdentityCapabilityPolicyInput,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityTeamMembershipError> {
        input.validate_shape()?;
        if input.is_expired(now) {
            return Err(IdentityTeamMembershipError::CapabilityPolicyInputExpired);
        }
        let issued = self
            .policy_inputs
            .get(&input.handle)
            .and_then(|inputs| inputs.get(&input.capability_id))
            .cloned()
            .ok_or(IdentityTeamMembershipError::BindingNotFound)?;
        if !issued.same_material(input) {
            return Err(IdentityTeamMembershipError::CapabilityPolicyInputStale);
        }
        let requirement = IdentityCapabilityRequirement::new(
            issued.capability_id.clone(),
            issued.scope.clone(),
            issued.required_role(),
        )?;
        let facts = self.provide_identity_facts(&issued.handle, &requirement.scope, now)?;
        let expected =
            IdentityCapabilityPolicyInput::from_facts(&issued.handle, &facts, &requirement, now)?;
        if input.same_material(&expected) {
            Ok(())
        } else {
            Err(IdentityTeamMembershipError::CapabilityPolicyInputStale)
        }
    }

    pub fn unmount(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityTeamMembershipError> {
        if self.bindings.remove(handle).is_some() {
            self.policy_inputs.remove(handle);
            Ok(())
        } else {
            Err(IdentityTeamMembershipError::BindingNotFound)
        }
    }

    pub fn reclaim_consumer(&mut self, consumer_id: &str) -> usize {
        let handles = self
            .bindings
            .iter()
            .filter(|(_, binding)| binding.consumer_id == consumer_id)
            .map(|(handle, _)| handle.clone())
            .collect::<Vec<_>>();
        for handle in &handles {
            self.bindings.remove(handle);
            self.policy_inputs.remove(handle);
        }
        handles.len()
    }

    fn append_membership_transition(
        &mut self,
        next: IdentityTeamMembership,
        kind: IdentityMembershipReceiptKind,
        actor_id: ActorId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<IdentityMembershipReceipt, IdentityTeamMembershipError> {
        next.validate()?;
        if actor_id.as_str().trim().is_empty()
            || !is_sha256(&evidence_digest)
            || now.timestamp() < 0
        {
            return Err(IdentityTeamMembershipError::InvalidReceipt);
        }
        let previous = self.memberships.get(next.id()).cloned();
        let Some(previous) = previous else {
            if !matches!(kind, IdentityMembershipReceiptKind::Invited { .. }) {
                return Err(IdentityTeamMembershipError::MembershipNotFound);
            }
            let receipt = IdentityMembershipReceipt {
                id: IdentityMembershipReceiptId::new(),
                tenant_id: next.tenant_id.clone(),
                team_id: next.team_id.clone(),
                member_id: next.id.clone(),
                account_id: next.account_id.clone(),
                previous_membership_revision: 0,
                membership_revision: next.membership_revision,
                previous_role_revision: 0,
                role_revision: next.role_revision,
                kind,
                actor_id,
                evidence_digest,
                issued_at: now,
            };
            receipt.validate()?;
            self.memberships.insert(next.id.clone(), next);
            self.receipts.push(receipt.clone());
            return Ok(receipt);
        };
        let expected_membership_revision = previous
            .membership_revision
            .checked_add(1)
            .ok_or(IdentityTeamMembershipError::RevisionOverflow)?;
        if next.id != previous.id
            || next.tenant_id != previous.tenant_id
            || next.team_id != previous.team_id
            || next.account_id != previous.account_id
            || next.membership_revision != expected_membership_revision
        {
            return Err(IdentityTeamMembershipError::StaleMembership);
        }
        let receipt = IdentityMembershipReceipt {
            id: IdentityMembershipReceiptId::new(),
            tenant_id: next.tenant_id.clone(),
            team_id: next.team_id.clone(),
            member_id: next.id.clone(),
            account_id: next.account_id.clone(),
            previous_membership_revision: previous.membership_revision,
            membership_revision: next.membership_revision,
            previous_role_revision: previous.role_revision,
            role_revision: next.role_revision,
            kind,
            actor_id,
            evidence_digest,
            issued_at: now,
        };
        receipt.validate()?;
        self.memberships.insert(next.id.clone(), next);
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    fn find_membership_for_session(
        &self,
        session: &IdentityOidcSession,
        scope: &IdentityMissionScope,
    ) -> Result<IdentityTeamMembership, IdentityTeamMembershipError> {
        let mut same_account = self.memberships.values().filter(|membership| {
            membership.tenant_id == session.tenant_id && membership.account_id == session.account_id
        });
        let exact = same_account
            .find(|membership| membership.team_id == scope.team_id)
            .cloned();
        let Some(membership) = exact else {
            if self.memberships.values().any(|membership| {
                membership.tenant_id == session.tenant_id
                    && membership.account_id == session.account_id
                    && membership.team_id != scope.team_id
                    && membership.status == IdentityTeamMembershipStatus::Active
            }) {
                return Err(IdentityTeamMembershipError::CrossTeamScope);
            }
            return Err(IdentityTeamMembershipError::MembershipNotFound);
        };
        if membership.status != IdentityTeamMembershipStatus::Active {
            return Err(
                if membership.status == IdentityTeamMembershipStatus::Revoked {
                    IdentityTeamMembershipError::MembershipRevoked
                } else {
                    IdentityTeamMembershipError::MembershipNotActive
                },
            );
        }
        Ok(membership)
    }

    fn register_or_reuse_online_head(
        &mut self,
        candidate: IdentitySessionHead,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityTeamMembershipError> {
        if let Some(existing) = self.session_heads.get(candidate.session_id()) {
            if existing.status == IdentitySessionHeadStatus::Revoked {
                return Err(IdentityTeamMembershipError::SessionRevoked);
            }
            if existing.scope != candidate.scope
                || existing.account_id != candidate.account_id
                || existing.member_id != candidate.member_id
                || existing.issuer_url != candidate.issuer_url
                || existing.subject_digest != candidate.subject_digest
            {
                return Err(IdentityTeamMembershipError::StaleSession);
            }
            if existing.expires_at <= now {
                return Err(IdentityTeamMembershipError::SessionExpired);
            }
            return Ok(());
        }
        self.session_heads
            .insert(candidate.session_id.clone(), candidate);
        Ok(())
    }

    fn insert_binding(
        &mut self,
        request: &IdentityPluginMountRequest,
        facts: IdentityPluginSessionFacts,
    ) -> IdentityPluginHandle {
        let handle = IdentityPluginHandle::new();
        self.bindings.insert(
            handle.clone(),
            MountedIdentityBinding {
                consumer_id: request.consumer_id.clone(),
                facts,
                invalidation: None,
            },
        );
        handle
    }

    fn invalidate_member_bindings(
        &mut self,
        member_id: &MemberId,
        invalidation: &BindingInvalidation,
    ) {
        for binding in self.bindings.values_mut() {
            if binding.facts.membership_id() == member_id {
                binding.invalidation = Some(invalidation.clone());
            }
        }
    }

    fn invalidate_session_bindings(&mut self, session_id: &IdentitySessionId, revoked: bool) {
        for binding in self.bindings.values_mut() {
            if binding.facts.session_id() == session_id {
                binding.invalidation = Some(if revoked {
                    BindingInvalidation::SessionRevoked
                } else {
                    BindingInvalidation::SessionStale
                });
            }
        }
    }

    fn bump_member_session_heads(
        &mut self,
        member_id: &MemberId,
        revoked: bool,
    ) -> Result<(), IdentityTeamMembershipError> {
        let session_ids = self
            .session_heads
            .values()
            .filter(|head| head.member_id == *member_id)
            .map(|head| head.session_id.clone())
            .collect::<Vec<_>>();
        for session_id in session_ids {
            let head = self
                .session_heads
                .get_mut(&session_id)
                .ok_or(IdentityTeamMembershipError::StaleSession)?;
            head.revision = head
                .revision
                .checked_add(1)
                .ok_or(IdentityTeamMembershipError::RevisionOverflow)?;
            if revoked {
                head.status = IdentitySessionHeadStatus::Revoked;
            }
            self.invalidate_session_bindings(&session_id, revoked);
        }
        Ok(())
    }
}

impl Drop for ProjectMissionIdentityService {
    fn drop(&mut self) {
        self.bindings.clear();
        self.policy_inputs.clear();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPluginMountRequest {
    consumer_id: String,
    scope: IdentityMissionScope,
}

impl IdentityPluginMountRequest {
    pub fn new(
        consumer_id: impl Into<String>,
        scope: IdentityMissionScope,
    ) -> Result<Self, IdentityTeamMembershipError> {
        let consumer_id = consumer_id.into().trim().to_owned();
        validate_consumer_id(&consumer_id)?;
        scope.validate()?;
        Ok(Self { consumer_id, scope })
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn scope(&self) -> &IdentityMissionScope {
        &self.scope
    }
}

pub trait IdentityTeamMembershipProvider {
    fn provide_identity_facts(
        &mut self,
        handle: &IdentityPluginHandle,
        expected_scope: &IdentityMissionScope,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginSessionFacts, IdentityTeamMembershipError>;
}

/// Narrow provider surface for capability consumers. It intentionally does
/// not inherit the identity-facts provider, so a policy consumer can only
/// request content-free scope, role, revision, expiry, and digest material.
pub trait IdentityCapabilityPolicyProvider {
    fn provide_capability_policy_input(
        &mut self,
        handle: &IdentityPluginHandle,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<IdentityCapabilityPolicyInput, IdentityTeamMembershipError>;

    fn validate_capability_policy_input(
        &mut self,
        input: &IdentityCapabilityPolicyInput,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityTeamMembershipError>;
}

pub trait IdentityTeamMembershipService: IdentityTeamMembershipProvider {
    fn mount_online(
        &mut self,
        request: &IdentityPluginMountRequest,
        session: &IdentityOidcSession,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityTeamMembershipError>;

    fn reopen_offline(
        &mut self,
        request: &IdentityPluginMountRequest,
        cache: &IdentityOfflineMembershipCache,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityTeamMembershipError>;

    fn unmount(&mut self, handle: &IdentityPluginHandle)
    -> Result<(), IdentityTeamMembershipError>;

    fn reclaim_consumer(&mut self, consumer_id: &str) -> usize;
}

pub trait IdentityTeamMembershipConsumer {
    fn consume_identity_policy(
        &mut self,
        provider: &mut dyn IdentityTeamMembershipProvider,
        handle: &IdentityPluginHandle,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginPolicyDecision, IdentityTeamMembershipError>;

    fn release_identity(&mut self, handle: &IdentityPluginHandle);
}

pub trait IdentityCapabilityPolicyConsumer {
    fn consume_capability_policy(
        &mut self,
        provider: &mut dyn IdentityCapabilityPolicyProvider,
        handle: &IdentityPluginHandle,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<IdentityCapabilityPolicyInput, IdentityTeamMembershipError>;

    fn evaluate_capability_policy(
        &mut self,
        provider: &mut dyn IdentityCapabilityPolicyProvider,
        handle: &IdentityPluginHandle,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginPolicyDecision, IdentityTeamMembershipError> {
        let input = self.consume_capability_policy(provider, handle, requirement, now)?;
        input.authorize(provider, now)
    }

    fn release_capability_policy(&mut self, handle: &IdentityPluginHandle);
}

impl IdentityTeamMembershipProvider for ProjectMissionIdentityService {
    fn provide_identity_facts(
        &mut self,
        handle: &IdentityPluginHandle,
        expected_scope: &IdentityMissionScope,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginSessionFacts, IdentityTeamMembershipError> {
        expected_scope.validate()?;
        let binding = self
            .bindings
            .get_mut(handle)
            .ok_or(IdentityTeamMembershipError::BindingNotFound)?;
        if let Some(invalidation) = &binding.invalidation {
            return Err(match invalidation {
                BindingInvalidation::Stale(receipt_id) => {
                    let _ = receipt_id;
                    IdentityTeamMembershipError::BindingStale
                }
                BindingInvalidation::Revoked(receipt_id) => {
                    let _ = receipt_id;
                    IdentityTeamMembershipError::BindingRevoked
                }
                BindingInvalidation::SessionStale => IdentityTeamMembershipError::StaleSession,
                BindingInvalidation::SessionRevoked => IdentityTeamMembershipError::SessionRevoked,
            });
        }
        if binding.facts.scope != *expected_scope {
            return Err(IdentityTeamMembershipError::ScopeMismatch);
        }
        if binding.facts.mode == IdentitySessionAccessMode::Offline
            && binding.facts.offline_expires_at <= now
        {
            return Err(IdentityTeamMembershipError::OfflineMembershipExpired);
        }
        if binding.facts.session_head.expires_at <= now {
            return Err(IdentityTeamMembershipError::SessionExpired);
        }
        let membership = self
            .memberships
            .get(binding.facts.membership_id())
            .ok_or(IdentityTeamMembershipError::MembershipNotFound)?;
        if membership.status != IdentityTeamMembershipStatus::Active {
            return Err(IdentityTeamMembershipError::MembershipRevoked);
        }
        if membership.membership_revision != binding.facts.membership_revision
            || membership.role_revision != binding.facts.role_revision
            || membership.role != binding.facts.role
        {
            binding.invalidation = Some(BindingInvalidation::SessionStale);
            return Err(IdentityTeamMembershipError::StaleMembership);
        }
        let head = self
            .session_heads
            .get(binding.facts.session_id())
            .ok_or(IdentityTeamMembershipError::StaleSession)?;
        if head != &binding.facts.session_head {
            binding.invalidation = Some(if head.status == IdentitySessionHeadStatus::Revoked {
                BindingInvalidation::SessionRevoked
            } else {
                BindingInvalidation::SessionStale
            });
            return Err(if head.status == IdentitySessionHeadStatus::Revoked {
                IdentityTeamMembershipError::SessionRevoked
            } else {
                IdentityTeamMembershipError::StaleSession
            });
        }
        Ok(binding.facts.clone())
    }
}

impl IdentityCapabilityPolicyProvider for ProjectMissionIdentityService {
    fn provide_capability_policy_input(
        &mut self,
        handle: &IdentityPluginHandle,
        requirement: &IdentityCapabilityRequirement,
        now: DateTime<Utc>,
    ) -> Result<IdentityCapabilityPolicyInput, IdentityTeamMembershipError> {
        ProjectMissionIdentityService::provide_capability_policy_input(
            self,
            handle,
            requirement,
            now,
        )
    }

    fn validate_capability_policy_input(
        &mut self,
        input: &IdentityCapabilityPolicyInput,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityTeamMembershipError> {
        ProjectMissionIdentityService::validate_capability_policy_input(self, input, now)
    }
}

impl IdentityTeamMembershipService for ProjectMissionIdentityService {
    fn mount_online(
        &mut self,
        request: &IdentityPluginMountRequest,
        session: &IdentityOidcSession,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityTeamMembershipError> {
        self.mount_online(request, session, now)
    }

    fn reopen_offline(
        &mut self,
        request: &IdentityPluginMountRequest,
        cache: &IdentityOfflineMembershipCache,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityTeamMembershipError> {
        self.reopen_offline(request, cache, now)
    }

    fn unmount(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityTeamMembershipError> {
        self.unmount(handle)
    }

    fn reclaim_consumer(&mut self, consumer_id: &str) -> usize {
        self.reclaim_consumer(consumer_id)
    }
}

/// Alias used by provider wiring that is explicitly OIDC-backed.
pub type OidcIdentityTeamMembershipService = ProjectMissionIdentityService;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IdentityTeamMembershipError {
    #[error("OIDC identity session is invalid")]
    InvalidOidcSession,
    #[error("team membership projection is invalid")]
    InvalidMembership,
    #[error("identity Mission scope is invalid")]
    InvalidScope,
    #[error("identity session head is invalid")]
    InvalidSessionHead,
    #[error("offline membership cache is invalid")]
    InvalidOfflineCache,
    #[error("offline membership cache TTL is invalid")]
    InvalidOfflineCacheTtl,
    #[error("identity receipt is invalid")]
    InvalidReceipt,
    #[error("identity capability requirement is invalid")]
    InvalidCapabilityRequirement,
    #[error("identity capability policy input is invalid")]
    InvalidCapabilityPolicyInput,
    #[error("identity capability policy input has expired")]
    CapabilityPolicyInputExpired,
    #[error("identity capability policy input is stale")]
    CapabilityPolicyInputStale,
    #[error("identity consumer identifier is invalid")]
    InvalidConsumer,
    #[error("team membership was not found")]
    MembershipNotFound,
    #[error("team membership is not active")]
    MembershipNotActive,
    #[error("team membership is already revoked or has an invalid transition")]
    InvalidMembershipTransition,
    #[error("team membership is revoked")]
    MembershipRevoked,
    #[error("multiple active memberships make the identity ambiguous")]
    AmbiguousMembership,
    #[error("OIDC session is bound to another team")]
    CrossTeamScope,
    #[error("identity scope does not match the requested Project or Mission")]
    ScopeMismatch,
    #[error("identity membership revision is stale")]
    StaleMembership,
    #[error("identity session revision is stale")]
    StaleSession,
    #[error("identity session has expired")]
    SessionExpired,
    #[error("identity session has been revoked")]
    SessionRevoked,
    #[error("identity session head projection does not match")]
    SessionProjectionMismatch,
    #[error("identity membership projection does not match")]
    MembershipProjectionMismatch,
    #[error("offline membership cache has expired")]
    OfflineMembershipExpired,
    #[error("plugin identity binding was not found")]
    BindingNotFound,
    #[error("plugin identity binding was invalidated by a membership change")]
    BindingStale,
    #[error("plugin identity binding was invalidated by membership revocation")]
    BindingRevoked,
    #[error("capability requirement has a different exact Mission scope")]
    CapabilityScopeMismatch,
    #[error("team role is insufficient for the capability")]
    InsufficientRole,
    #[error("identity revision overflowed")]
    RevisionOverflow,
}

fn validate_consumer_id(value: &str) -> Result<(), IdentityTeamMembershipError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(IdentityTeamMembershipError::InvalidConsumer)
    } else {
        Ok(())
    }
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() > "https://".len()
        && !value.chars().any(char::is_whitespace)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn identity_provider_digest(facts: &IdentityPluginSessionFacts) -> String {
    let mut digest = Sha256::new();
    for value in [
        "hartevo.identity.capability-policy-provider.v1",
        facts.issuer_url(),
        facts.subject_digest(),
        facts.session_id().as_str(),
        facts.membership_id().as_str(),
        facts.account_id().as_str(),
        facts.scope.tenant_id.as_str(),
        facts.scope.team_id.as_str(),
        facts.scope.project_id.as_str(),
        facts.scope.mission_id.as_str(),
    ] {
        digest_field(&mut digest, value.as_bytes());
    }
    for value in [
        facts.scope.mission_revision,
        facts.membership_revision,
        facts.role_revision,
        facts.session_head.revision,
    ] {
        digest_field(&mut digest, &value.to_be_bytes());
    }
    digest_field(&mut digest, &[facts.role.rank()]);
    digest_field(
        &mut digest,
        &[match facts.mode {
            IdentitySessionAccessMode::Online => 1,
            IdentitySessionAccessMode::Offline => 2,
        }],
    );
    let expires_at = facts.policy_expires_at();
    digest_field(&mut digest, &expires_at.timestamp().to_be_bytes());
    digest_field(
        &mut digest,
        &expires_at.timestamp_subsec_nanos().to_be_bytes(),
    );
    format!("{:x}", digest.finalize())
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn min_expiry(left: DateTime<Utc>, right: DateTime<Utc>) -> DateTime<Utc> {
    left.min(right)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;

    const ISSUER: &str = "https://sso.example.test/realms/hartevo";
    const TENANT: &str = "tenant-team-plugin";
    const ACCOUNT: &str = "account-team-plugin";
    const TEAM: &str = "team-growth";
    const PROJECT: &str = "project-launch";
    const MISSION: &str = "mission-launch";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0)
            .single()
            .expect("fixed test time")
    }

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn scope(team: &str, project: &str, mission: &str, revision: u64) -> IdentityMissionScope {
        IdentityMissionScope::new(
            TenantId::from(TENANT),
            TeamId::from(team),
            ProjectId::from(project),
            MissionId::from(mission),
            revision,
        )
        .expect("scope")
    }

    fn active_membership() -> IdentityTeamMembership {
        IdentityTeamMembership::active(
            MemberId::from("member-growth"),
            TenantId::from(TENANT),
            TeamId::from(TEAM),
            AccountId::from(ACCOUNT),
            IdentityTeamRole::Admin,
        )
        .expect("membership")
    }

    fn session(_scope: &IdentityMissionScope, session_id: &str) -> IdentityOidcSession {
        IdentityOidcSession::new(
            ISSUER,
            digest("oidc-subject"),
            TenantId::from(TENANT),
            AccountId::from(ACCOUNT),
            IdentitySessionId::from(session_id),
            now(),
            now() + Duration::hours(4),
        )
        .expect("session")
    }

    fn request(scope: IdentityMissionScope, consumer: &str) -> IdentityPluginMountRequest {
        IdentityPluginMountRequest::new(consumer, scope).expect("request")
    }

    fn seeded_service(ttl: Duration) -> ProjectMissionIdentityService {
        let mut service = ProjectMissionIdentityService::new(ttl).expect("service");
        service
            .register_membership(active_membership())
            .expect("membership projection");
        service
    }

    #[derive(Default)]
    struct TestPluginConsumer {
        decision: Option<IdentityPluginPolicyDecision>,
    }

    impl IdentityTeamMembershipConsumer for TestPluginConsumer {
        fn consume_identity_policy(
            &mut self,
            provider: &mut dyn IdentityTeamMembershipProvider,
            handle: &IdentityPluginHandle,
            requirement: &IdentityCapabilityRequirement,
            now: DateTime<Utc>,
        ) -> Result<IdentityPluginPolicyDecision, IdentityTeamMembershipError> {
            let facts = provider.provide_identity_facts(handle, requirement.scope(), now)?;
            let decision = facts.authorize_capability(requirement)?;
            self.decision = Some(decision.clone());
            Ok(decision)
        }

        fn release_identity(&mut self, _handle: &IdentityPluginHandle) {
            self.decision = None;
        }
    }

    #[derive(Default)]
    struct TestCapabilityPolicyConsumer {
        input: Option<IdentityCapabilityPolicyInput>,
    }

    impl IdentityCapabilityPolicyConsumer for TestCapabilityPolicyConsumer {
        fn consume_capability_policy(
            &mut self,
            provider: &mut dyn IdentityCapabilityPolicyProvider,
            handle: &IdentityPluginHandle,
            requirement: &IdentityCapabilityRequirement,
            now: DateTime<Utc>,
        ) -> Result<IdentityCapabilityPolicyInput, IdentityTeamMembershipError> {
            let input = provider.provide_capability_policy_input(handle, requirement, now)?;
            self.input = Some(input.clone());
            Ok(input)
        }

        fn release_capability_policy(&mut self, _handle: &IdentityPluginHandle) {
            self.input = None;
        }
    }

    #[test]
    fn oidc_session_maps_membership_role_and_exact_mission_scope_to_plugin_policy() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let mut service = seeded_service(Duration::hours(1));
        let handle = service
            .mount_online(
                &request(exact_scope.clone(), "capability-plugin"),
                &session(&exact_scope, "session-exact"),
                now(),
            )
            .expect("online mount");
        let requirement = IdentityCapabilityRequirement::new(
            "research.discover",
            exact_scope.clone(),
            IdentityTeamRole::Member,
        )
        .expect("capability requirement");
        let mut consumer = TestPluginConsumer::default();
        let decision = consumer
            .consume_identity_policy(&mut service, &handle, &requirement, now())
            .expect("policy decision");
        assert_eq!(decision.role(), IdentityTeamRole::Admin);
        assert_eq!(decision.membership_revision(), 1);
        assert_eq!(decision.role_revision(), 1);
        assert_eq!(decision.session_revision(), 1);
        assert_eq!(decision.scope(), &exact_scope);
        let facts = service
            .provide_identity_facts(&handle, &exact_scope, now())
            .expect("facts");
        assert_eq!(facts.mode(), IdentitySessionAccessMode::Online);
        assert_eq!(facts.issuer_url(), ISSUER);
        assert_eq!(facts.subject_digest(), digest("oidc-subject"));
        assert_eq!(format!("{handle:?}"), "IdentityPluginHandle([REDACTED])");
        assert!(!format!("{facts:?}").contains("token"));
    }

    #[test]
    fn capability_policy_input_is_exact_content_free_and_live_revalidated() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let mut service = seeded_service(Duration::hours(1));
        let oidc = session(&exact_scope, "session-policy-input");
        let handle = service
            .mount_online(&request(exact_scope.clone(), "policy-plugin"), &oidc, now())
            .expect("online mount");
        let requirement = IdentityCapabilityRequirement::new(
            "research.discover",
            exact_scope.clone(),
            IdentityTeamRole::Member,
        )
        .expect("capability requirement");
        let mut consumer = TestCapabilityPolicyConsumer::default();
        let input = consumer
            .consume_capability_policy(&mut service, &handle, &requirement, now())
            .expect("policy input");
        assert_eq!(input.scope(), &exact_scope);
        assert_eq!(input.roles().granted(), IdentityTeamRole::Admin);
        assert_eq!(input.roles().required(), IdentityTeamRole::Member);
        assert!(input.roles().is_satisfied());
        assert_eq!(input.membership_revision(), 1);
        assert_eq!(input.role_revision(), 1);
        assert_eq!(input.session_revision(), 1);
        assert_eq!(input.mode(), IdentitySessionAccessMode::Online);
        assert_eq!(input.expires_at(), now() + Duration::hours(4));
        assert!(is_sha256(input.provider_digest()));
        let decision = input.authorize(&mut service, now()).expect("live policy");
        assert_eq!(decision.provider_digest(), input.provider_digest());
        assert_eq!(decision.expires_at(), input.expires_at());
        let serialized = serde_json::to_string(&input).expect("policy input json");
        assert!(serialized.contains("providerDigest"));
        assert!(!serialized.contains("handle"));
        assert!(!serialized.contains("issuer"));
        assert!(!serialized.contains("subject"));
        assert!(!serialized.contains("access_token"));
        assert!(!serialized.contains("SecretStore"));
        assert!(!format!("{input:?}").contains("token"));

        let mut lowered_requirement = input.clone();
        lowered_requirement.roles.required = IdentityTeamRole::Viewer;
        assert_eq!(
            lowered_requirement.authorize(&mut service, now()),
            Err(IdentityTeamMembershipError::CapabilityPolicyInputStale)
        );

        service
            .change_role(
                &MemberId::from("member-growth"),
                IdentityTeamRole::Owner,
                ActorId::from("owner"),
                digest("policy-role-change"),
                now() + Duration::minutes(1),
            )
            .expect("role change");
        assert_eq!(
            input.authorize(&mut service, now() + Duration::minutes(1)),
            Err(IdentityTeamMembershipError::BindingStale)
        );

        let new_handle = service
            .mount_online(
                &request(exact_scope.clone(), "policy-plugin"),
                &oidc,
                now() + Duration::minutes(1),
            )
            .expect("new role mount");
        let new_input = service
            .provide_capability_policy_input(&new_handle, &requirement, now())
            .expect("new policy input");
        assert_eq!(new_input.granted_role(), IdentityTeamRole::Owner);
        assert_ne!(new_input.provider_digest(), input.provider_digest());
        service
            .revoke_member(
                &MemberId::from("member-growth"),
                ActorId::from("owner"),
                digest("policy-revoke"),
                now() + Duration::minutes(2),
            )
            .expect("revoke");
        assert_eq!(
            new_input.authorize(&mut service, now() + Duration::minutes(2)),
            Err(IdentityTeamMembershipError::BindingRevoked)
        );
    }

    #[test]
    fn cross_team_and_cross_mission_policy_composition_fails_closed() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let foreign_team_scope = scope("team-foreign", PROJECT, MISSION, 7);
        let foreign_project_scope = scope(TEAM, "project-foreign", MISSION, 7);
        let mut service = seeded_service(Duration::hours(1));
        let oidc = session(&exact_scope, "session-cross-scope");
        assert_eq!(
            service.mount_online(&request(foreign_team_scope, "foreign"), &oidc, now()),
            Err(IdentityTeamMembershipError::CrossTeamScope)
        );
        let handle = service
            .mount_online(&request(exact_scope.clone(), "exact"), &oidc, now())
            .expect("exact mount");
        let requirement = IdentityCapabilityRequirement::new(
            "research.discover",
            foreign_project_scope.clone(),
            IdentityTeamRole::Viewer,
        )
        .expect("foreign requirement");
        assert_eq!(
            service.provide_identity_facts(&handle, &foreign_project_scope, now()),
            Err(IdentityTeamMembershipError::ScopeMismatch)
        );
        assert_eq!(
            service.provide_capability_policy_input(&handle, &requirement, now(),),
            Err(IdentityTeamMembershipError::ScopeMismatch)
        );
        assert_eq!(
            service
                .provide_identity_facts(&handle, &exact_scope, now())
                .expect("exact facts")
                .authorize_capability(&requirement),
            Err(IdentityTeamMembershipError::CapabilityScopeMismatch)
        );
    }

    #[test]
    fn offline_cache_reopen_requires_exact_projection_session_head_and_expiry() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let ttl = Duration::minutes(20);
        let mut service = seeded_service(ttl);
        let oidc = session(&exact_scope, "session-offline");
        let online_handle = service
            .mount_online(
                &request(exact_scope.clone(), "offline-plugin"),
                &oidc,
                now(),
            )
            .expect("online mount");
        let facts = service
            .provide_identity_facts(&online_handle, &exact_scope, now())
            .expect("online facts");
        let cache = facts.offline_cache();
        service.unmount(&online_handle).expect("unmount online");
        let offline_handle = service
            .reopen_offline(
                &request(exact_scope.clone(), "offline-plugin"),
                &cache,
                now() + Duration::minutes(5),
            )
            .expect("offline reopen");
        assert_eq!(
            service
                .provide_identity_facts(
                    &offline_handle,
                    &exact_scope,
                    now() + Duration::minutes(5),
                )
                .expect("offline facts")
                .mode(),
            IdentitySessionAccessMode::Offline
        );
        let mut tampered = cache.clone();
        tampered.scope = scope(TEAM, "project-foreign", MISSION, 7);
        assert_eq!(
            service.reopen_offline(
                &request(exact_scope.clone(), "offline-plugin"),
                &tampered,
                now() + Duration::minutes(5),
            ),
            Err(IdentityTeamMembershipError::InvalidOfflineCache)
        );
        assert_eq!(
            service.reopen_offline(
                &request(exact_scope.clone(), "offline-plugin"),
                &cache,
                now() + Duration::minutes(21),
            ),
            Err(IdentityTeamMembershipError::OfflineMembershipExpired)
        );
        let mut restarted = seeded_service(ttl);
        restarted
            .register_session_head(cache.session_head().clone())
            .expect("rehydrate session head");
        let reopened = restarted
            .reopen_offline(
                &request(exact_scope, "offline-plugin"),
                &cache,
                now() + Duration::minutes(5),
            )
            .expect("reopen after projection rehydrate");
        assert_eq!(restarted.active_binding_count(), 1);
        restarted.unmount(&reopened).expect("cleanup");
    }

    #[test]
    fn offline_reopen_rejects_identity_scope_and_role_drift() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let mut service = seeded_service(Duration::hours(1));
        let oidc = session(&exact_scope, "session-offline-adversarial");
        let handle = service
            .mount_online(
                &request(exact_scope.clone(), "offline-adversarial"),
                &oidc,
                now(),
            )
            .expect("online mount");
        let cache = service
            .provide_identity_facts(&handle, &exact_scope, now())
            .expect("online facts")
            .offline_cache();

        let mut issuer_drift = cache.clone();
        issuer_drift.session_head.issuer_url = "https://other.example.test/realm".to_owned();
        assert_eq!(
            service.reopen_offline(
                &request(exact_scope.clone(), "offline-adversarial"),
                &issuer_drift,
                now() + Duration::minutes(1),
            ),
            Err(IdentityTeamMembershipError::StaleSession)
        );

        let mut subject_drift = cache.clone();
        subject_drift.session_head.subject_digest = digest("other-subject");
        assert_eq!(
            service.reopen_offline(
                &request(exact_scope.clone(), "offline-adversarial"),
                &subject_drift,
                now() + Duration::minutes(1),
            ),
            Err(IdentityTeamMembershipError::StaleSession)
        );

        let foreign_team_scope = scope("team-foreign", PROJECT, MISSION, 7);
        let mut team_drift = cache.clone();
        team_drift.scope = foreign_team_scope.clone();
        team_drift.session_head.scope = foreign_team_scope.clone();
        assert_eq!(
            service.reopen_offline(
                &request(foreign_team_scope, "offline-adversarial"),
                &team_drift,
                now() + Duration::minutes(1),
            ),
            Err(IdentityTeamMembershipError::StaleMembership)
        );

        let foreign_project_scope = scope(TEAM, "project-foreign", MISSION, 7);
        let mut project_drift = cache.clone();
        project_drift.scope = foreign_project_scope.clone();
        project_drift.session_head.scope = foreign_project_scope.clone();
        assert_eq!(
            service.reopen_offline(
                &request(foreign_project_scope, "offline-adversarial"),
                &project_drift,
                now() + Duration::minutes(1),
            ),
            Err(IdentityTeamMembershipError::StaleSession)
        );

        let revision_drift_scope = scope(TEAM, PROJECT, MISSION, 8);
        let mut revision_drift = cache.clone();
        revision_drift.scope = revision_drift_scope.clone();
        revision_drift.session_head.scope = revision_drift_scope.clone();
        assert_eq!(
            service.reopen_offline(
                &request(revision_drift_scope, "offline-adversarial"),
                &revision_drift,
                now() + Duration::minutes(1),
            ),
            Err(IdentityTeamMembershipError::StaleSession)
        );

        let mut role_changed = seeded_service(Duration::hours(1));
        let role_handle = role_changed
            .mount_online(
                &request(exact_scope.clone(), "offline-role-drift"),
                &session(&exact_scope, "session-offline-role-drift"),
                now(),
            )
            .expect("role drift mount");
        let role_cache = role_changed
            .provide_identity_facts(&role_handle, &exact_scope, now())
            .expect("role drift facts")
            .offline_cache();
        role_changed
            .change_role(
                &MemberId::from("member-growth"),
                IdentityTeamRole::Owner,
                ActorId::from("owner"),
                digest("offline-role-drift"),
                now() + Duration::minutes(1),
            )
            .expect("role change");
        assert_eq!(
            role_changed.reopen_offline(
                &request(exact_scope, "offline-role-drift"),
                &role_cache,
                now() + Duration::minutes(2),
            ),
            Err(IdentityTeamMembershipError::StaleMembership)
        );
    }

    #[test]
    fn offline_policy_input_expires_and_reopens_deterministically() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let ttl = Duration::minutes(20);
        let mut service = seeded_service(ttl);
        let oidc = session(&exact_scope, "session-policy-offline");
        let online_handle = service
            .mount_online(
                &request(exact_scope.clone(), "offline-policy-plugin"),
                &oidc,
                now(),
            )
            .expect("online mount");
        let requirement = IdentityCapabilityRequirement::new(
            "research.discover",
            exact_scope.clone(),
            IdentityTeamRole::Member,
        )
        .expect("capability requirement");
        let cache = service
            .provide_identity_facts(&online_handle, &exact_scope, now())
            .expect("online facts")
            .offline_cache();
        service.unmount(&online_handle).expect("unmount online");
        let offline_handle = service
            .reopen_offline(
                &request(exact_scope.clone(), "offline-policy-plugin"),
                &cache,
                now() + Duration::minutes(5),
            )
            .expect("offline reopen");
        let offline_input = service
            .provide_capability_policy_input(
                &offline_handle,
                &requirement,
                now() + Duration::minutes(5),
            )
            .expect("offline policy input");
        assert_eq!(offline_input.mode(), IdentitySessionAccessMode::Offline);
        assert_eq!(offline_input.expires_at(), now() + ttl);
        assert!(
            offline_input
                .authorize(&mut service, now() + Duration::minutes(19))
                .is_ok()
        );
        assert_eq!(
            offline_input.authorize(&mut service, now() + Duration::minutes(20)),
            Err(IdentityTeamMembershipError::CapabilityPolicyInputExpired)
        );
        assert_eq!(
            service.reopen_offline(
                &request(exact_scope.clone(), "offline-policy-plugin"),
                &cache,
                now() + Duration::minutes(20),
            ),
            Err(IdentityTeamMembershipError::OfflineMembershipExpired)
        );

        let mut restarted = seeded_service(ttl);
        restarted
            .register_session_head(cache.session_head().clone())
            .expect("rehydrate session head");
        let reopened_handle = restarted
            .reopen_offline(
                &request(exact_scope.clone(), "offline-policy-plugin"),
                &cache,
                now() + Duration::minutes(5),
            )
            .expect("deterministic offline reopen");
        let reopened_input = restarted
            .provide_capability_policy_input(
                &reopened_handle,
                &requirement,
                now() + Duration::minutes(5),
            )
            .expect("reopened policy input");
        assert_eq!(reopened_input, offline_input);
        assert_eq!(
            reopened_input.provider_digest(),
            offline_input.provider_digest()
        );

        let serialized = serde_json::to_string(&offline_input).expect("offline policy json");
        let restored: IdentityCapabilityPolicyInput =
            serde_json::from_str(&serialized).expect("content-free policy restore");
        assert_eq!(
            restarted.validate_capability_policy_input(&restored, now() + Duration::minutes(5)),
            Err(IdentityTeamMembershipError::BindingNotFound)
        );

        let mut tampered = offline_input.clone();
        tampered.provider_digest = digest("tampered-provider");
        assert_eq!(
            tampered.authorize(&mut service, now() + Duration::minutes(5)),
            Err(IdentityTeamMembershipError::CapabilityPolicyInputStale)
        );
    }

    #[test]
    fn invite_role_change_and_revoke_receipts_invalidate_old_bindings() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let mut service = ProjectMissionIdentityService::new(Duration::hours(1)).expect("service");
        let invite = service
            .invite(
                MemberId::from("member-role"),
                TenantId::from(TENANT),
                TeamId::from(TEAM),
                AccountId::from(ACCOUNT),
                IdentityTeamRole::Viewer,
                ActorId::from("owner"),
                digest("invite-evidence"),
                now(),
            )
            .expect("invite");
        assert!(matches!(
            invite.kind(),
            IdentityMembershipReceiptKind::Invited {
                role: IdentityTeamRole::Viewer
            }
        ));
        service
            .accept_invite(
                &MemberId::from("member-role"),
                ActorId::from("member-role"),
                digest("accept-evidence"),
                now() + Duration::minutes(1),
            )
            .expect("accept");
        let oidc = session(&exact_scope, "session-role");
        let old_handle = service
            .mount_online(&request(exact_scope.clone(), "role-plugin"), &oidc, now())
            .expect("old mount");
        let role_change = service
            .change_role(
                &MemberId::from("member-role"),
                IdentityTeamRole::Admin,
                ActorId::from("owner"),
                digest("role-change-evidence"),
                now() + Duration::minutes(2),
            )
            .expect("role change");
        assert!(matches!(
            role_change.kind(),
            IdentityMembershipReceiptKind::RoleChanged {
                from: IdentityTeamRole::Viewer,
                to: IdentityTeamRole::Admin
            }
        ));
        assert_eq!(role_change.membership_revision(), 3);
        assert_eq!(role_change.role_revision(), 2);
        assert_eq!(
            service.provide_identity_facts(&old_handle, &exact_scope, now()),
            Err(IdentityTeamMembershipError::BindingStale)
        );
        let new_handle = service
            .mount_online(&request(exact_scope.clone(), "role-plugin"), &oidc, now())
            .expect("new role mount");
        assert_eq!(
            service
                .provide_identity_facts(&new_handle, &exact_scope, now())
                .expect("new role facts")
                .role(),
            IdentityTeamRole::Admin
        );
        let revoke = service
            .revoke_member(
                &MemberId::from("member-role"),
                ActorId::from("owner"),
                digest("revoke-evidence"),
                now() + Duration::minutes(3),
            )
            .expect("revoke");
        assert_eq!(revoke.kind(), &IdentityMembershipReceiptKind::Revoked);
        assert_eq!(
            service.provide_identity_facts(&new_handle, &exact_scope, now()),
            Err(IdentityTeamMembershipError::BindingRevoked)
        );
        let cache = service
            .provide_identity_facts(&new_handle, &exact_scope, now())
            .err();
        assert_eq!(cache, Some(IdentityTeamMembershipError::BindingRevoked));
    }

    #[test]
    fn stale_session_projection_and_reopen_fail_closed() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let mut service = seeded_service(Duration::hours(1));
        let oidc = session(&exact_scope, "session-stale");
        let handle = service
            .mount_online(&request(exact_scope.clone(), "stale-plugin"), &oidc, now())
            .expect("mount");
        let cache = service
            .provide_identity_facts(&handle, &exact_scope, now())
            .expect("facts")
            .offline_cache();
        let requirement = IdentityCapabilityRequirement::new(
            "research.discover",
            exact_scope.clone(),
            IdentityTeamRole::Viewer,
        )
        .expect("capability requirement");
        let policy_input = service
            .provide_capability_policy_input(&handle, &requirement, now())
            .expect("policy input");
        let newer_head = IdentitySessionHead::active(
            IdentitySessionId::from("session-stale"),
            exact_scope.clone(),
            AccountId::from(ACCOUNT),
            MemberId::from("member-growth"),
            ISSUER,
            digest("oidc-subject"),
            now(),
            now() + Duration::hours(4),
            2,
        )
        .expect("new session head");
        service
            .register_session_head(newer_head)
            .expect("advance session head");
        assert_eq!(
            service.provide_identity_facts(&handle, &exact_scope, now()),
            Err(IdentityTeamMembershipError::StaleSession)
        );
        assert_eq!(
            policy_input.authorize(&mut service, now()),
            Err(IdentityTeamMembershipError::StaleSession)
        );
        assert_eq!(
            service.reopen_offline(
                &request(exact_scope, "stale-plugin"),
                &cache,
                now() + Duration::minutes(1),
            ),
            Err(IdentityTeamMembershipError::StaleSession)
        );
    }

    #[test]
    fn typed_receipts_are_serializable_without_tokens_or_store_authority() {
        let mut service = seeded_service(Duration::hours(1));
        let receipt = service
            .invite(
                MemberId::from("member-json"),
                TenantId::from(TENANT),
                TeamId::from(TEAM),
                AccountId::from(ACCOUNT),
                IdentityTeamRole::Member,
                ActorId::from("owner"),
                digest("receipt-json"),
                now(),
            )
            .expect("receipt");
        let json = serde_json::to_string(&receipt).expect("receipt json");
        assert!(json.contains("invited"));
        assert!(!json.contains("access_token"));
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("SecretStore"));
        assert_eq!(service.receipts(), &[receipt]);
    }

    #[test]
    fn service_reclaims_consumer_bindings_on_unmount_and_crash_cleanup() {
        let exact_scope = scope(TEAM, PROJECT, MISSION, 7);
        let mut service = seeded_service(Duration::hours(1));
        let oidc = session(&exact_scope, "session-reclaim");
        let first = service
            .mount_online(&request(exact_scope.clone(), "consumer-a"), &oidc, now())
            .expect("first");
        let second = service
            .mount_online(&request(exact_scope.clone(), "consumer-a"), &oidc, now())
            .expect("second");
        assert_eq!(service.active_binding_count(), 2);
        assert_eq!(service.reclaim_consumer("consumer-a"), 2);
        assert_eq!(service.active_binding_count(), 0);
        assert_eq!(
            service.provide_identity_facts(&first, &exact_scope, now()),
            Err(IdentityTeamMembershipError::BindingNotFound)
        );
        assert_eq!(
            service.provide_identity_facts(&second, &exact_scope, now()),
            Err(IdentityTeamMembershipError::BindingNotFound)
        );
    }

    #[test]
    fn mission_scope_constructor_binds_exact_project_and_revision() {
        let mission = Mission::compile(
            TenantId::from(TENANT),
            MissionId::from(MISSION),
            ProjectId::from(PROJECT),
            "Launch",
            crate::MissionContract::bootstrap("Launch", ["research.discover".into()], now()),
            now(),
        )
        .expect("mission");
        let scope =
            IdentityMissionScope::for_mission(&mission, TeamId::from(TEAM)).expect("mission scope");
        assert!(scope.matches_mission(&mission));
        let mut changed = mission.clone();
        changed.revision = 2;
        assert!(!scope.matches_mission(&changed));
        assert_eq!(
            serde_json::to_value(&scope).expect("scope json")["teamId"],
            json!(TEAM)
        );
    }
}

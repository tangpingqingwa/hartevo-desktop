//! Host-owned Team/Project invite composition seam.
//!
//! This module deliberately accepts only an invitee identity digest. It never
//! accepts or stores an email address, OIDC token, keyring handle, or Store
//! reference. A plugin consumer receives typed, scope-bound projections and
//! opaque draft handles; the host remains the authority for approval,
//! issuance, acceptance, replay, and membership invalidation.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AccountId, ActorId, ApprovalId, IdentitySessionId, MemberId, ProjectId,
    ProjectInviteDecisionReceiptId, ProjectInviteEventId, ProjectInviteId, ProjectInviteReceiptId,
    ProjectInviteRevocationReceiptId, ProjectMembershipBindingId, TeamId, TenantId,
};

pub const DEFAULT_PROJECT_INVITE_TTL: Duration = Duration::days(7);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInviteRole {
    Viewer,
    Member,
    Admin,
    Owner,
}

impl ProjectInviteRole {
    pub fn rank(self) -> u8 {
        match self {
            Self::Viewer => 1,
            Self::Member => 2,
            Self::Admin => 3,
            Self::Owner => 4,
        }
    }

    pub fn allows(self, scope: ProjectInviteScope) -> bool {
        match self {
            Self::Viewer => matches!(scope, ProjectInviteScope::Read),
            Self::Member => matches!(scope, ProjectInviteScope::Read | ProjectInviteScope::Write),
            Self::Admin | Self::Owner => true,
        }
    }

    pub fn can_invite(self) -> bool {
        matches!(self, Self::Admin | Self::Owner)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInviteScope {
    Read,
    Write,
    ManageMembers,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInviteStatus {
    Draft,
    Approved,
    Emitted,
    Accepted,
    Declined,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInviteDecision {
    Accepted,
    Declined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInviteMembershipStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInviteSessionStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectMembershipBindingStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInviteProjectScope {
    tenant_id: TenantId,
    team_id: TeamId,
    project_id: ProjectId,
    project_revision: u64,
}

impl ProjectInviteProjectScope {
    pub fn new(
        tenant_id: TenantId,
        team_id: TeamId,
        project_id: ProjectId,
        project_revision: u64,
    ) -> Result<Self, ProjectInviteError> {
        let scope = Self {
            tenant_id,
            team_id,
            project_id,
            project_revision,
        };
        scope.validate()?;
        Ok(scope)
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

    pub fn project_revision(&self) -> u64 {
        self.project_revision
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.project_revision == 0
        {
            return Err(ProjectInviteError::InvalidProjectScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInviteTeamMembership {
    member_id: MemberId,
    tenant_id: TenantId,
    team_id: TeamId,
    account_id: AccountId,
    role: ProjectInviteRole,
    status: ProjectInviteMembershipStatus,
    membership_revision: u64,
    role_revision: u64,
}

impl ProjectInviteTeamMembership {
    #[allow(
        clippy::too_many_arguments,
        reason = "rehydration requires the complete identity membership projection"
    )]
    pub fn active(
        member_id: MemberId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        role: ProjectInviteRole,
        membership_revision: u64,
        role_revision: u64,
    ) -> Result<Self, ProjectInviteError> {
        let membership = Self {
            member_id,
            tenant_id,
            team_id,
            account_id,
            role,
            status: ProjectInviteMembershipStatus::Active,
            membership_revision,
            role_revision,
        };
        membership.validate()?;
        Ok(membership)
    }

    pub fn member_id(&self) -> &MemberId {
        &self.member_id
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

    pub fn role(&self) -> ProjectInviteRole {
        self.role
    }

    pub fn status(&self) -> ProjectInviteMembershipStatus {
        self.status
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        if self.member_id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.membership_revision == 0
            || self.role_revision == 0
            || self.role_revision > self.membership_revision
        {
            return Err(ProjectInviteError::InvalidTeamMembership);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInviteSession {
    session_id: IdentitySessionId,
    tenant_id: TenantId,
    team_id: TeamId,
    account_id: AccountId,
    identity_digest: String,
    identity_provider_digest: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revision: u64,
    status: ProjectInviteSessionStatus,
}

impl ProjectInviteSession {
    #[allow(
        clippy::too_many_arguments,
        reason = "session rehydration must bind every identity and expiry field"
    )]
    pub fn new(
        session_id: IdentitySessionId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        identity_digest: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self, ProjectInviteError> {
        let identity_digest = identity_digest.into();
        Self::new_with_identity_provider_digest(
            session_id,
            tenant_id,
            team_id,
            account_id,
            identity_digest.clone(),
            identity_provider_digest(&identity_digest),
            issued_at,
            expires_at,
            revision,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "OIDC rehydration must bind the subject and provider digests to the session"
    )]
    pub fn new_with_identity_provider_digest(
        session_id: IdentitySessionId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        identity_digest: impl Into<String>,
        identity_provider_digest: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self, ProjectInviteError> {
        let session = Self {
            session_id,
            tenant_id,
            team_id,
            account_id,
            identity_digest: identity_digest.into(),
            identity_provider_digest: identity_provider_digest.into(),
            issued_at,
            expires_at,
            revision,
            status: ProjectInviteSessionStatus::Active,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        &self.session_id
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

    pub fn identity_digest(&self) -> &str {
        &self.identity_digest
    }

    pub fn identity_provider_digest(&self) -> &str {
        &self.identity_provider_digest
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

    pub fn status(&self) -> ProjectInviteSessionStatus {
        self.status
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        if self.session_id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.identity_provider_digest)
            || self.issued_at.timestamp() < 0
            || self.expires_at <= self.issued_at
            || self.revision == 0
        {
            return Err(ProjectInviteError::InvalidSession);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DraftInviteRequest {
    invite_id: ProjectInviteId,
    invite_revision: u64,
    scope: ProjectInviteProjectScope,
    inviter_membership_id: MemberId,
    inviter_membership_revision: u64,
    invitee_identity_digest: String,
    invitee_identity_provider_digest: String,
    role: ProjectInviteRole,
    scopes: BTreeSet<ProjectInviteScope>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    idempotency_key: String,
}

impl DraftInviteRequest {
    #[allow(
        clippy::too_many_arguments,
        reason = "draft creation explicitly binds scope, inviter, invitee, role, expiry, and replay key"
    )]
    pub fn new(
        invite_id: ProjectInviteId,
        scope: ProjectInviteProjectScope,
        inviter_membership_id: MemberId,
        inviter_membership_revision: u64,
        invitee_identity_digest: impl Into<String>,
        role: ProjectInviteRole,
        scopes: BTreeSet<ProjectInviteScope>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, ProjectInviteError> {
        let invitee_identity_digest = invitee_identity_digest.into();
        Self::new_with_revision_and_provider_digest(
            invite_id,
            1,
            scope,
            inviter_membership_id,
            inviter_membership_revision,
            invitee_identity_digest.clone(),
            identity_provider_digest(&invitee_identity_digest),
            role,
            scopes,
            created_at,
            expires_at,
            idempotency_key,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "draft creation binds the invite revision and exact identity-provider projection"
    )]
    pub fn new_with_revision_and_provider_digest(
        invite_id: ProjectInviteId,
        invite_revision: u64,
        scope: ProjectInviteProjectScope,
        inviter_membership_id: MemberId,
        inviter_membership_revision: u64,
        invitee_identity_digest: impl Into<String>,
        invitee_identity_provider_digest: impl Into<String>,
        role: ProjectInviteRole,
        scopes: BTreeSet<ProjectInviteScope>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, ProjectInviteError> {
        let request = Self {
            invite_id,
            invite_revision,
            scope,
            inviter_membership_id,
            inviter_membership_revision,
            invitee_identity_digest: invitee_identity_digest.into(),
            invitee_identity_provider_digest: invitee_identity_provider_digest.into(),
            role,
            scopes,
            created_at,
            expires_at,
            idempotency_key: idempotency_key.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn inviter_membership_id(&self) -> &MemberId {
        &self.inviter_membership_id
    }

    pub fn inviter_membership_revision(&self) -> u64 {
        self.inviter_membership_revision
    }

    pub fn invitee_identity_digest(&self) -> &str {
        &self.invitee_identity_digest
    }

    pub fn invitee_identity_provider_digest(&self) -> &str {
        &self.invitee_identity_provider_digest
    }

    pub fn role(&self) -> ProjectInviteRole {
        self.role
    }

    pub fn scopes(&self) -> &BTreeSet<ProjectInviteScope> {
        &self.scopes
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn intent_digest(&self) -> String {
        draft_intent_digest(
            &self.invite_id,
            self.invite_revision,
            &self.scope,
            &self.inviter_membership_id,
            self.inviter_membership_revision,
            &self.invitee_identity_digest,
            &self.invitee_identity_provider_digest,
            self.role,
            &self.scopes,
            self.created_at,
            self.expires_at,
        )
    }

    fn idempotency_key_digest(&self) -> String {
        digest_fields([
            b"hartevo.project-invite.idempotency-key.v1".to_vec(),
            self.idempotency_key.as_bytes().to_vec(),
        ])
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        self.scope.validate()?;
        if self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || !is_sha256(&self.invitee_identity_digest)
            || !is_sha256(&self.invitee_identity_provider_digest)
            || self.scopes.is_empty()
            || self.scopes.iter().any(|scope| !self.role.allows(*scope))
            || self.created_at.timestamp() < 0
            || self.expires_at <= self.created_at
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.chars().any(char::is_control)
        {
            return Err(ProjectInviteError::InvalidDraftInvite);
        }
        Ok(())
    }
}

impl fmt::Debug for DraftInviteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DraftInviteRequest")
            .field("invite_id", &self.invite_id)
            .field("invite_revision", &self.invite_revision)
            .field("scope", &self.scope)
            .field("inviter_membership_id", &self.inviter_membership_id)
            .field(
                "inviter_membership_revision",
                &self.inviter_membership_revision,
            )
            .field("invitee_identity_digest", &self.invitee_identity_digest)
            .field(
                "invitee_identity_provider_digest",
                &self.invitee_identity_provider_digest,
            )
            .field("role", &self.role)
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("idempotency_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftInvite {
    invite_id: ProjectInviteId,
    invite_revision: u64,
    scope: ProjectInviteProjectScope,
    inviter_membership_id: MemberId,
    inviter_account_id: AccountId,
    inviter_membership_revision: u64,
    invitee_identity_digest: String,
    invitee_identity_provider_digest: String,
    role: ProjectInviteRole,
    scopes: BTreeSet<ProjectInviteScope>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    intent_digest: String,
    idempotency_key_digest: String,
}

impl DraftInvite {
    fn from_request(
        request: &DraftInviteRequest,
        inviter_account_id: AccountId,
    ) -> Result<Self, ProjectInviteError> {
        let draft = Self {
            invite_id: request.invite_id.clone(),
            invite_revision: request.invite_revision,
            scope: request.scope.clone(),
            inviter_membership_id: request.inviter_membership_id.clone(),
            inviter_account_id,
            inviter_membership_revision: request.inviter_membership_revision,
            invitee_identity_digest: request.invitee_identity_digest.clone(),
            invitee_identity_provider_digest: request.invitee_identity_provider_digest.clone(),
            role: request.role,
            scopes: request.scopes.clone(),
            created_at: request.created_at,
            expires_at: request.expires_at,
            intent_digest: request.intent_digest(),
            idempotency_key_digest: request.idempotency_key_digest(),
        };
        draft.validate()?;
        Ok(draft)
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn inviter_membership_id(&self) -> &MemberId {
        &self.inviter_membership_id
    }

    pub fn inviter_account_id(&self) -> &AccountId {
        &self.inviter_account_id
    }

    pub fn inviter_membership_revision(&self) -> u64 {
        self.inviter_membership_revision
    }

    pub fn invitee_identity_digest(&self) -> &str {
        &self.invitee_identity_digest
    }

    pub fn invitee_identity_provider_digest(&self) -> &str {
        &self.invitee_identity_provider_digest
    }

    pub fn role(&self) -> ProjectInviteRole {
        self.role
    }

    pub fn scopes(&self) -> &BTreeSet<ProjectInviteScope> {
        &self.scopes
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        self.scope.validate()?;
        if self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_account_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || !is_sha256(&self.invitee_identity_digest)
            || !is_sha256(&self.invitee_identity_provider_digest)
            || self.scopes.is_empty()
            || self.scopes.iter().any(|scope| !self.role.allows(*scope))
            || self.created_at.timestamp() < 0
            || self.expires_at <= self.created_at
            || !is_sha256(&self.intent_digest)
            || !is_sha256(&self.idempotency_key_digest)
        {
            return Err(ProjectInviteError::InvalidDraftInvite);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DraftInviteHandle(Uuid);

impl DraftInviteHandle {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for DraftInviteHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DraftInviteHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DraftInviteHandle([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteApproval {
    approval_id: ApprovalId,
    invite_id: ProjectInviteId,
    invite_revision: u64,
    approver_actor_id: ActorId,
    approver_membership_id: MemberId,
    approver_membership_revision: u64,
    evidence_digest: String,
    approved_at: DateTime<Utc>,
}

impl InviteApproval {
    #[allow(
        clippy::too_many_arguments,
        reason = "approval must bind actor, membership revision, evidence, and exact invite"
    )]
    pub fn new(
        approval_id: ApprovalId,
        invite_id: ProjectInviteId,
        approver_actor_id: ActorId,
        approver_membership_id: MemberId,
        approver_membership_revision: u64,
        evidence_digest: impl Into<String>,
        approved_at: DateTime<Utc>,
    ) -> Result<Self, ProjectInviteError> {
        Self::new_with_invite_revision(
            approval_id,
            invite_id,
            1,
            approver_actor_id,
            approver_membership_id,
            approver_membership_revision,
            evidence_digest,
            approved_at,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "approval binds the exact invite revision and approver membership projection"
    )]
    pub fn new_with_invite_revision(
        approval_id: ApprovalId,
        invite_id: ProjectInviteId,
        invite_revision: u64,
        approver_actor_id: ActorId,
        approver_membership_id: MemberId,
        approver_membership_revision: u64,
        evidence_digest: impl Into<String>,
        approved_at: DateTime<Utc>,
    ) -> Result<Self, ProjectInviteError> {
        let approval = Self {
            approval_id,
            invite_id,
            invite_revision,
            approver_actor_id,
            approver_membership_id,
            approver_membership_revision,
            evidence_digest: evidence_digest.into(),
            approved_at,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn approver_actor_id(&self) -> &ActorId {
        &self.approver_actor_id
    }

    pub fn approver_membership_id(&self) -> &MemberId {
        &self.approver_membership_id
    }

    pub fn approver_membership_revision(&self) -> u64 {
        self.approver_membership_revision
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn approved_at(&self) -> DateTime<Utc> {
        self.approved_at
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        if self.approval_id.as_str().trim().is_empty()
            || self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.approver_actor_id.as_str().trim().is_empty()
            || self.approver_membership_id.as_str().trim().is_empty()
            || self.approver_membership_revision == 0
            || !is_sha256(&self.evidence_digest)
            || self.approved_at.timestamp() < 0
        {
            return Err(ProjectInviteError::InvalidInviteApproval);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedInvite {
    handle: DraftInviteHandle,
    draft: DraftInvite,
    approval: InviteApproval,
}

impl ApprovedInvite {
    pub fn handle(&self) -> &DraftInviteHandle {
        &self.handle
    }

    pub fn draft(&self) -> &DraftInvite {
        &self.draft
    }

    pub fn approval(&self) -> &InviteApproval {
        &self.approval
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteReceipt {
    receipt_id: ProjectInviteReceiptId,
    invite_id: ProjectInviteId,
    invite_revision: u64,
    scope: ProjectInviteProjectScope,
    invitee_identity_digest: String,
    invitee_identity_provider_digest: String,
    role: ProjectInviteRole,
    scopes: BTreeSet<ProjectInviteScope>,
    inviter_membership_id: MemberId,
    inviter_membership_revision: u64,
    approval_id: ApprovalId,
    expires_at: DateTime<Utc>,
    emitted_at: DateTime<Utc>,
    provider_digest: String,
}

impl InviteReceipt {
    fn issue(
        draft: &DraftInvite,
        approval: &InviteApproval,
        emitted_at: DateTime<Utc>,
    ) -> Result<Self, ProjectInviteError> {
        let receipt = Self {
            receipt_id: ProjectInviteReceiptId::new(),
            invite_id: draft.invite_id.clone(),
            invite_revision: draft.invite_revision,
            scope: draft.scope.clone(),
            invitee_identity_digest: draft.invitee_identity_digest.clone(),
            invitee_identity_provider_digest: draft.invitee_identity_provider_digest.clone(),
            role: draft.role,
            scopes: draft.scopes.clone(),
            inviter_membership_id: draft.inviter_membership_id.clone(),
            inviter_membership_revision: draft.inviter_membership_revision,
            approval_id: approval.approval_id.clone(),
            expires_at: draft.expires_at,
            emitted_at,
            provider_digest: invite_provider_digest(draft, approval),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn receipt_id(&self) -> &ProjectInviteReceiptId {
        &self.receipt_id
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn invitee_identity_digest(&self) -> &str {
        &self.invitee_identity_digest
    }

    pub fn invitee_identity_provider_digest(&self) -> &str {
        &self.invitee_identity_provider_digest
    }

    pub fn role(&self) -> ProjectInviteRole {
        self.role
    }

    pub fn scopes(&self) -> &BTreeSet<ProjectInviteScope> {
        &self.scopes
    }

    pub fn inviter_membership_id(&self) -> &MemberId {
        &self.inviter_membership_id
    }

    pub fn inviter_membership_revision(&self) -> u64 {
        self.inviter_membership_revision
    }

    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn emitted_at(&self) -> DateTime<Utc> {
        self.emitted_at
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        if self.receipt_id.as_str().trim().is_empty()
            || self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || !is_sha256(&self.invitee_identity_digest)
            || !is_sha256(&self.invitee_identity_provider_digest)
            || self.scopes.is_empty()
            || self.scopes.iter().any(|scope| !self.role.allows(*scope))
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || self.approval_id.as_str().trim().is_empty()
            || self.expires_at.timestamp() < 0
            || self.emitted_at.timestamp() < 0
            || !is_sha256(&self.provider_digest)
        {
            return Err(ProjectInviteError::InvalidInviteReceipt);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteDecisionReceipt {
    receipt_id: ProjectInviteDecisionReceiptId,
    invite_id: ProjectInviteId,
    invite_revision: u64,
    scope: ProjectInviteProjectScope,
    inviter_membership_id: MemberId,
    inviter_membership_revision: u64,
    invitee_identity_digest: String,
    invitee_identity_provider_digest: String,
    session_id: IdentitySessionId,
    session_revision: u64,
    decision: ProjectInviteDecision,
    binding_id: Option<ProjectMembershipBindingId>,
    membership_revision: Option<u64>,
    decided_at: DateTime<Utc>,
    provider_digest: String,
}

impl InviteDecisionReceipt {
    fn issue(
        invite: &InviteReceipt,
        session: &ProjectInviteSession,
        decision: ProjectInviteDecision,
        binding: Option<&ProjectMembershipBinding>,
        decided_at: DateTime<Utc>,
    ) -> Result<Self, ProjectInviteError> {
        let receipt = Self {
            receipt_id: ProjectInviteDecisionReceiptId::new(),
            invite_id: invite.invite_id.clone(),
            invite_revision: invite.invite_revision,
            scope: invite.scope.clone(),
            inviter_membership_id: invite.inviter_membership_id.clone(),
            inviter_membership_revision: invite.inviter_membership_revision,
            invitee_identity_digest: invite.invitee_identity_digest.clone(),
            invitee_identity_provider_digest: session.identity_provider_digest.clone(),
            session_id: session.session_id.clone(),
            session_revision: session.revision,
            decision,
            binding_id: binding.map(|value| value.binding_id.clone()),
            membership_revision: binding.map(|value| value.membership_revision),
            decided_at,
            provider_digest: invite_decision_provider_digest(invite, session, decision, binding),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn receipt_id(&self) -> &ProjectInviteDecisionReceiptId {
        &self.receipt_id
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn inviter_membership_id(&self) -> &MemberId {
        &self.inviter_membership_id
    }

    pub fn inviter_membership_revision(&self) -> u64 {
        self.inviter_membership_revision
    }

    pub fn invitee_identity_digest(&self) -> &str {
        &self.invitee_identity_digest
    }

    pub fn invitee_identity_provider_digest(&self) -> &str {
        &self.invitee_identity_provider_digest
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        &self.session_id
    }

    pub fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub fn decision(&self) -> ProjectInviteDecision {
        self.decision
    }

    pub fn binding_id(&self) -> Option<&ProjectMembershipBindingId> {
        self.binding_id.as_ref()
    }

    pub fn membership_revision(&self) -> Option<u64> {
        self.membership_revision
    }

    pub fn decided_at(&self) -> DateTime<Utc> {
        self.decided_at
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        self.scope.validate()?;
        let decision_shape_is_valid = match self.decision {
            ProjectInviteDecision::Accepted => {
                self.binding_id.is_some() && self.membership_revision.is_some()
            }
            ProjectInviteDecision::Declined => {
                self.binding_id.is_none() && self.membership_revision.is_none()
            }
        };
        if self.receipt_id.as_str().trim().is_empty()
            || self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || !is_sha256(&self.invitee_identity_digest)
            || !is_sha256(&self.invitee_identity_provider_digest)
            || self.session_id.as_str().trim().is_empty()
            || self.session_revision == 0
            || !decision_shape_is_valid
            || self
                .membership_revision
                .is_some_and(|revision| revision == 0)
            || self.decided_at.timestamp() < 0
            || !is_sha256(&self.provider_digest)
        {
            return Err(ProjectInviteError::InvalidInviteDecisionReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteAcceptance {
    receipt: InviteDecisionReceipt,
    binding: ProjectMembershipBinding,
}

impl InviteAcceptance {
    pub fn receipt(&self) -> &InviteDecisionReceipt {
        &self.receipt
    }

    pub fn binding(&self) -> &ProjectMembershipBinding {
        &self.binding
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InviteRevocationRequest {
    invite_id: ProjectInviteId,
    invite_revision: u64,
    scope: ProjectInviteProjectScope,
    owner_actor_id: ActorId,
    owner_membership_id: MemberId,
    owner_membership_revision: u64,
    owner_session_id: IdentitySessionId,
    owner_session_revision: u64,
    evidence_digest: String,
    revoked_at: DateTime<Utc>,
    idempotency_key: String,
}

impl InviteRevocationRequest {
    #[allow(
        clippy::too_many_arguments,
        reason = "revocation binds the exact invite, owner membership, owner session, and replay key"
    )]
    pub fn new(
        invite_id: ProjectInviteId,
        invite_revision: u64,
        scope: ProjectInviteProjectScope,
        owner_actor_id: ActorId,
        owner_membership_id: MemberId,
        owner_membership_revision: u64,
        owner_session_id: IdentitySessionId,
        owner_session_revision: u64,
        evidence_digest: impl Into<String>,
        revoked_at: DateTime<Utc>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, ProjectInviteError> {
        let request = Self {
            invite_id,
            invite_revision,
            scope,
            owner_actor_id,
            owner_membership_id,
            owner_membership_revision,
            owner_session_id,
            owner_session_revision,
            evidence_digest: evidence_digest.into(),
            revoked_at,
            idempotency_key: idempotency_key.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn owner_actor_id(&self) -> &ActorId {
        &self.owner_actor_id
    }

    pub fn owner_membership_id(&self) -> &MemberId {
        &self.owner_membership_id
    }

    pub fn owner_membership_revision(&self) -> u64 {
        self.owner_membership_revision
    }

    pub fn owner_session_id(&self) -> &IdentitySessionId {
        &self.owner_session_id
    }

    pub fn owner_session_revision(&self) -> u64 {
        self.owner_session_revision
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn revoked_at(&self) -> DateTime<Utc> {
        self.revoked_at
    }

    pub fn intent_digest(&self) -> String {
        invite_revocation_intent_digest(
            &self.invite_id,
            self.invite_revision,
            &self.scope,
            &self.owner_actor_id,
            &self.owner_membership_id,
            self.owner_membership_revision,
            &self.owner_session_id,
            self.owner_session_revision,
            &self.evidence_digest,
            self.revoked_at,
        )
    }

    fn idempotency_key_digest(&self) -> String {
        digest_fields([
            b"hartevo.project-invite.revocation-idempotency-key.v1".to_vec(),
            self.idempotency_key.as_bytes().to_vec(),
        ])
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        self.scope.validate()?;
        if self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.owner_actor_id.as_str().trim().is_empty()
            || self.owner_membership_id.as_str().trim().is_empty()
            || self.owner_membership_revision == 0
            || self.owner_session_id.as_str().trim().is_empty()
            || self.owner_session_revision == 0
            || !is_sha256(&self.evidence_digest)
            || self.revoked_at.timestamp() < 0
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.chars().any(char::is_control)
        {
            return Err(ProjectInviteError::InvalidInviteRevocationRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for InviteRevocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InviteRevocationRequest")
            .field("invite_id", &self.invite_id)
            .field("invite_revision", &self.invite_revision)
            .field("scope", &self.scope)
            .field("owner_actor_id", &self.owner_actor_id)
            .field("owner_membership_id", &self.owner_membership_id)
            .field("owner_membership_revision", &self.owner_membership_revision)
            .field("owner_session_id", &self.owner_session_id)
            .field("owner_session_revision", &self.owner_session_revision)
            .field("evidence_digest", &self.evidence_digest)
            .field("revoked_at", &self.revoked_at)
            .field("idempotency_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteRevocationReceipt {
    receipt_id: ProjectInviteRevocationReceiptId,
    invite_id: ProjectInviteId,
    invite_revision: u64,
    scope: ProjectInviteProjectScope,
    owner_actor_id: ActorId,
    owner_membership_id: MemberId,
    owner_membership_revision: u64,
    owner_session_id: IdentitySessionId,
    owner_session_revision: u64,
    owner_identity_provider_digest: String,
    evidence_digest: String,
    binding_id: Option<ProjectMembershipBindingId>,
    membership_revision: Option<u64>,
    revoked_at: DateTime<Utc>,
    provider_digest: String,
    idempotency_key_digest: String,
}

impl InviteRevocationReceipt {
    fn issue(
        request: &InviteRevocationRequest,
        session: &ProjectInviteSession,
        binding: Option<&ProjectMembershipBinding>,
    ) -> Result<Self, ProjectInviteError> {
        let receipt = Self {
            receipt_id: ProjectInviteRevocationReceiptId::new(),
            invite_id: request.invite_id.clone(),
            invite_revision: request.invite_revision,
            scope: request.scope.clone(),
            owner_actor_id: request.owner_actor_id.clone(),
            owner_membership_id: request.owner_membership_id.clone(),
            owner_membership_revision: request.owner_membership_revision,
            owner_session_id: request.owner_session_id.clone(),
            owner_session_revision: request.owner_session_revision,
            owner_identity_provider_digest: session.identity_provider_digest.clone(),
            evidence_digest: request.evidence_digest.clone(),
            binding_id: binding.map(|value| value.binding_id.clone()),
            membership_revision: binding.map(|value| value.membership_revision),
            revoked_at: request.revoked_at,
            provider_digest: invite_revocation_provider_digest(request, session, binding),
            idempotency_key_digest: request.idempotency_key_digest(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn receipt_id(&self) -> &ProjectInviteRevocationReceiptId {
        &self.receipt_id
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn owner_actor_id(&self) -> &ActorId {
        &self.owner_actor_id
    }

    pub fn owner_membership_id(&self) -> &MemberId {
        &self.owner_membership_id
    }

    pub fn owner_membership_revision(&self) -> u64 {
        self.owner_membership_revision
    }

    pub fn owner_session_id(&self) -> &IdentitySessionId {
        &self.owner_session_id
    }

    pub fn owner_session_revision(&self) -> u64 {
        self.owner_session_revision
    }

    pub fn owner_identity_provider_digest(&self) -> &str {
        &self.owner_identity_provider_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn binding_id(&self) -> Option<&ProjectMembershipBindingId> {
        self.binding_id.as_ref()
    }

    pub fn membership_revision(&self) -> Option<u64> {
        self.membership_revision
    }

    pub fn revoked_at(&self) -> DateTime<Utc> {
        self.revoked_at
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        self.scope.validate()?;
        if self.receipt_id.as_str().trim().is_empty()
            || self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.owner_actor_id.as_str().trim().is_empty()
            || self.owner_membership_id.as_str().trim().is_empty()
            || self.owner_membership_revision == 0
            || self.owner_session_id.as_str().trim().is_empty()
            || self.owner_session_revision == 0
            || !is_sha256(&self.owner_identity_provider_digest)
            || !is_sha256(&self.evidence_digest)
            || self
                .membership_revision
                .is_some_and(|revision| revision == 0)
            || self.revoked_at.timestamp() < 0
            || !is_sha256(&self.provider_digest)
            || !is_sha256(&self.idempotency_key_digest)
        {
            return Err(ProjectInviteError::InvalidInviteRevocationReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMembershipBinding {
    binding_id: ProjectMembershipBindingId,
    invite_id: ProjectInviteId,
    invite_revision: u64,
    receipt_id: ProjectInviteReceiptId,
    member_id: MemberId,
    scope: ProjectInviteProjectScope,
    account_id: AccountId,
    identity_digest: String,
    identity_provider_digest: String,
    role: ProjectInviteRole,
    scopes: BTreeSet<ProjectInviteScope>,
    inviter_membership_id: MemberId,
    inviter_membership_revision: u64,
    membership_revision: u64,
    role_revision: u64,
    session_id: IdentitySessionId,
    session_revision: u64,
    bound_at: DateTime<Utc>,
    status: ProjectMembershipBindingStatus,
}

impl ProjectMembershipBinding {
    fn from_accept(
        receipt: &InviteReceipt,
        draft: &DraftInvite,
        session: &ProjectInviteSession,
        bound_at: DateTime<Utc>,
    ) -> Result<Self, ProjectInviteError> {
        let binding = Self {
            binding_id: ProjectMembershipBindingId::new(),
            invite_id: receipt.invite_id.clone(),
            invite_revision: receipt.invite_revision,
            receipt_id: receipt.receipt_id.clone(),
            member_id: MemberId::new(),
            scope: receipt.scope.clone(),
            account_id: session.account_id.clone(),
            identity_digest: session.identity_digest.clone(),
            identity_provider_digest: session.identity_provider_digest.clone(),
            role: receipt.role,
            scopes: receipt.scopes.clone(),
            inviter_membership_id: draft.inviter_membership_id.clone(),
            inviter_membership_revision: draft.inviter_membership_revision,
            membership_revision: 1,
            role_revision: 1,
            session_id: session.session_id.clone(),
            session_revision: session.revision,
            bound_at,
            status: ProjectMembershipBindingStatus::Active,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn binding_id(&self) -> &ProjectMembershipBindingId {
        &self.binding_id
    }

    pub fn invite_id(&self) -> &ProjectInviteId {
        &self.invite_id
    }

    pub fn invite_revision(&self) -> u64 {
        self.invite_revision
    }

    pub fn receipt_id(&self) -> &ProjectInviteReceiptId {
        &self.receipt_id
    }

    pub fn member_id(&self) -> &MemberId {
        &self.member_id
    }

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn identity_digest(&self) -> &str {
        &self.identity_digest
    }

    pub fn identity_provider_digest(&self) -> &str {
        &self.identity_provider_digest
    }

    pub fn role(&self) -> ProjectInviteRole {
        self.role
    }

    pub fn scopes(&self) -> &BTreeSet<ProjectInviteScope> {
        &self.scopes
    }

    pub fn inviter_membership_revision(&self) -> u64 {
        self.inviter_membership_revision
    }

    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub fn role_revision(&self) -> u64 {
        self.role_revision
    }

    pub fn session_id(&self) -> &IdentitySessionId {
        &self.session_id
    }

    pub fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub fn bound_at(&self) -> DateTime<Utc> {
        self.bound_at
    }

    pub fn status(&self) -> ProjectMembershipBindingStatus {
        self.status
    }

    fn validate(&self) -> Result<(), ProjectInviteError> {
        self.scope.validate()?;
        if self.binding_id.as_str().trim().is_empty()
            || self.invite_id.as_str().trim().is_empty()
            || self.invite_revision == 0
            || self.receipt_id.as_str().trim().is_empty()
            || self.member_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.identity_provider_digest)
            || self.scopes.is_empty()
            || self.scopes.iter().any(|scope| !self.role.allows(*scope))
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || self.membership_revision == 0
            || self.role_revision == 0
            || self.role_revision > self.membership_revision
            || self.session_id.as_str().trim().is_empty()
            || self.session_revision == 0
            || self.bound_at.timestamp() < 0
        {
            return Err(ProjectInviteError::InvalidMembershipBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ProjectInviteEvent {
    DraftCreated {
        event_id: ProjectInviteEventId,
        handle: DraftInviteHandle,
        draft: DraftInvite,
    },
    DraftApproved {
        event_id: ProjectInviteEventId,
        invite_id: ProjectInviteId,
        approval: InviteApproval,
    },
    InviteReceiptIssued {
        event_id: ProjectInviteEventId,
        receipt: InviteReceipt,
    },
    InviteDecisionRecorded {
        event_id: ProjectInviteEventId,
        receipt: InviteDecisionReceipt,
        binding: Option<ProjectMembershipBinding>,
    },
    InviteRevoked {
        event_id: ProjectInviteEventId,
        receipt: InviteRevocationReceipt,
        binding: Option<ProjectMembershipBinding>,
    },
    MembershipBindingCreated {
        event_id: ProjectInviteEventId,
        binding: ProjectMembershipBinding,
    },
    MembershipBindingUpdated {
        event_id: ProjectInviteEventId,
        binding: ProjectMembershipBinding,
    },
}

impl ProjectInviteEvent {
    pub fn event_id(&self) -> &ProjectInviteEventId {
        match self {
            Self::DraftCreated { event_id, .. }
            | Self::DraftApproved { event_id, .. }
            | Self::InviteReceiptIssued { event_id, .. }
            | Self::InviteDecisionRecorded { event_id, .. }
            | Self::InviteRevoked { event_id, .. }
            | Self::MembershipBindingCreated { event_id, .. }
            | Self::MembershipBindingUpdated { event_id, .. } => event_id,
        }
    }
}

#[derive(Clone)]
struct InviteProjection {
    draft: DraftInvite,
    handle: DraftInviteHandle,
    approval: Option<InviteApproval>,
    receipt: Option<InviteReceipt>,
    decision: Option<InviteDecisionReceipt>,
    revocation: Option<InviteRevocationReceipt>,
    binding: Option<ProjectMembershipBinding>,
}

impl InviteProjection {
    fn status(&self, now: DateTime<Utc>) -> ProjectInviteStatus {
        if self.revocation.is_some() {
            return ProjectInviteStatus::Revoked;
        }
        if self
            .decision
            .as_ref()
            .is_some_and(|receipt| receipt.decision == ProjectInviteDecision::Declined)
        {
            return ProjectInviteStatus::Declined;
        }
        if self.binding.is_some() {
            return ProjectInviteStatus::Accepted;
        }
        if self.draft.expires_at <= now {
            return ProjectInviteStatus::Expired;
        }
        if self.receipt.is_some() {
            return ProjectInviteStatus::Emitted;
        }
        if self.approval.is_some() {
            return ProjectInviteStatus::Approved;
        }
        ProjectInviteStatus::Draft
    }
}

/// Host-owned invite service. It contains only identity projections and
/// content-free event material; it has no Store, keyring, email, or token
/// authority.
pub struct ProjectInvitePluginService {
    projects: BTreeMap<ProjectId, ProjectInviteProjectScope>,
    team_memberships: BTreeMap<MemberId, ProjectInviteTeamMembership>,
    sessions: BTreeMap<IdentitySessionId, ProjectInviteSession>,
    invites: BTreeMap<ProjectInviteId, InviteProjection>,
    handles: HashMap<DraftInviteHandle, ProjectInviteId>,
    idempotency: HashMap<String, (String, DraftInviteHandle)>,
    bindings: BTreeMap<ProjectMembershipBindingId, ProjectMembershipBinding>,
    binding_by_invite: HashMap<ProjectInviteId, ProjectMembershipBindingId>,
    events: Vec<ProjectInviteEvent>,
    event_ids: BTreeMap<ProjectInviteEventId, usize>,
}

impl fmt::Debug for ProjectInvitePluginService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectInvitePluginService")
            .field("project_scope_count", &self.projects.len())
            .field("team_membership_count", &self.team_memberships.len())
            .field("session_count", &self.sessions.len())
            .field("invite_count", &self.invites.len())
            .field("handle_count", &self.handles.len())
            .field("idempotency_count", &self.idempotency.len())
            .field("binding_count", &self.bindings.len())
            .field("binding_index_count", &self.binding_by_invite.len())
            .field("event_count", &self.events.len())
            .field("event_index_count", &self.event_ids.len())
            .finish()
    }
}

impl ProjectInvitePluginService {
    pub fn new() -> Self {
        Self {
            projects: BTreeMap::new(),
            team_memberships: BTreeMap::new(),
            sessions: BTreeMap::new(),
            invites: BTreeMap::new(),
            handles: HashMap::new(),
            idempotency: HashMap::new(),
            bindings: BTreeMap::new(),
            binding_by_invite: HashMap::new(),
            events: Vec::new(),
            event_ids: BTreeMap::new(),
        }
    }

    pub fn register_project_scope(
        &mut self,
        scope: ProjectInviteProjectScope,
    ) -> Result<(), ProjectInviteError> {
        scope.validate()?;
        if let Some(existing) = self.projects.get(scope.project_id()) {
            if existing == &scope {
                return Ok(());
            }
            return Err(ProjectInviteError::ProjectScopeMismatch);
        }
        if self.projects.values().any(|existing| {
            existing.tenant_id() == scope.tenant_id()
                && existing.project_id() == scope.project_id()
                && existing.team_id() != scope.team_id()
        }) {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        self.projects.insert(scope.project_id.clone(), scope);
        Ok(())
    }

    pub fn register_team_membership(
        &mut self,
        membership: ProjectInviteTeamMembership,
    ) -> Result<(), ProjectInviteError> {
        membership.validate()?;
        if let Some(existing) = self.team_memberships.get(membership.member_id()) {
            if existing == &membership {
                return Ok(());
            }
            return Err(ProjectInviteError::MembershipProjectionMismatch);
        }
        if membership.status == ProjectInviteMembershipStatus::Active
            && self.team_memberships.values().any(|existing| {
                existing.status == ProjectInviteMembershipStatus::Active
                    && existing.tenant_id == membership.tenant_id
                    && existing.team_id == membership.team_id
                    && existing.account_id == membership.account_id
            })
        {
            return Err(ProjectInviteError::AmbiguousMembership);
        }
        self.team_memberships
            .insert(membership.member_id.clone(), membership);
        Ok(())
    }

    pub fn register_session(
        &mut self,
        session: ProjectInviteSession,
    ) -> Result<(), ProjectInviteError> {
        session.validate()?;
        if let Some(existing) = self.sessions.get(session.session_id()) {
            if existing.status == ProjectInviteSessionStatus::Revoked {
                return Err(ProjectInviteError::SessionRevoked);
            }
            if existing.revision > session.revision {
                return Err(ProjectInviteError::StaleSession);
            }
            if existing.revision == session.revision {
                if existing == &session {
                    return Ok(());
                }
                return Err(ProjectInviteError::SessionProjectionMismatch);
            }
            if existing.tenant_id != session.tenant_id
                || existing.team_id != session.team_id
                || existing.account_id != session.account_id
                || existing.identity_digest != session.identity_digest
            {
                return Err(ProjectInviteError::SessionProjectionMismatch);
            }
        }
        self.sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    pub fn events(&self) -> &[ProjectInviteEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn draft(&self, handle: &DraftInviteHandle) -> Result<DraftInvite, ProjectInviteError> {
        let invite_id = self
            .handles
            .get(handle)
            .ok_or(ProjectInviteError::DraftNotFound)?;
        self.invites
            .get(invite_id)
            .map(|projection| projection.draft.clone())
            .ok_or(ProjectInviteError::DraftNotFound)
    }

    pub fn status(
        &self,
        handle: &DraftInviteHandle,
        now: DateTime<Utc>,
    ) -> Result<ProjectInviteStatus, ProjectInviteError> {
        let invite_id = self
            .handles
            .get(handle)
            .ok_or(ProjectInviteError::DraftNotFound)?;
        self.invites
            .get(invite_id)
            .map(|projection| projection.status(now))
            .ok_or(ProjectInviteError::DraftNotFound)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the provider owns the request at the command boundary"
    )]
    pub fn create_draft(
        &mut self,
        request: DraftInviteRequest,
    ) -> Result<DraftInviteHandle, ProjectInviteError> {
        request.validate()?;
        let membership = self
            .team_memberships
            .get(request.inviter_membership_id())
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if membership.tenant_id() != request.scope.tenant_id()
            || membership.team_id() != request.scope.team_id()
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        if membership.status() != ProjectInviteMembershipStatus::Active {
            return Err(ProjectInviteError::MembershipRevoked);
        }
        if membership.membership_revision() != request.inviter_membership_revision()
            || !membership.role().can_invite()
        {
            return Err(
                if membership.membership_revision() == request.inviter_membership_revision() {
                    ProjectInviteError::InsufficientRole
                } else {
                    ProjectInviteError::StaleMembership
                },
            );
        }
        let project_scope = self
            .projects
            .get(request.scope.project_id())
            .ok_or(ProjectInviteError::ProjectScopeNotFound)?;
        if project_scope != request.scope() {
            return Err(if project_scope.team_id() == request.scope.team_id() {
                ProjectInviteError::ProjectScopeMismatch
            } else {
                ProjectInviteError::CrossTeamScope
            });
        }
        let intent_digest = request.intent_digest();
        let key_digest = request.idempotency_key_digest();
        if let Some((existing_intent, handle)) = self.idempotency.get(&key_digest) {
            if existing_intent != &intent_digest {
                return Err(ProjectInviteError::IdempotencyConflict);
            }
            return Ok(handle.clone());
        }
        if let Some(existing) = self.invites.get(request.invite_id()) {
            if existing.draft.intent_digest() == intent_digest {
                return Ok(existing.handle.clone());
            }
            return Err(ProjectInviteError::DuplicateInvite);
        }
        let draft = DraftInvite::from_request(&request, membership.account_id().clone())?;
        let handle = DraftInviteHandle::new();
        self.record_event(ProjectInviteEvent::DraftCreated {
            event_id: ProjectInviteEventId::new(),
            handle: handle.clone(),
            draft,
        })?;
        Ok(handle)
    }

    pub fn approve_draft(
        &mut self,
        handle: &DraftInviteHandle,
        approval: InviteApproval,
    ) -> Result<ApprovedInvite, ProjectInviteError> {
        let invite_id = self
            .handles
            .get(handle)
            .cloned()
            .ok_or(ProjectInviteError::DraftNotFound)?;
        let projection = self
            .invites
            .get(&invite_id)
            .cloned()
            .ok_or(ProjectInviteError::DraftNotFound)?;
        approval.validate()?;
        if approval.invite_id() != &invite_id {
            return Err(ProjectInviteError::ApprovalInviteMismatch);
        }
        if approval.invite_revision() != projection.draft.invite_revision() {
            return Err(ProjectInviteError::StaleInvite);
        }
        if let Some(existing) = projection.approval {
            if existing == approval {
                return Ok(ApprovedInvite {
                    handle: handle.clone(),
                    draft: projection.draft,
                    approval: existing,
                });
            }
            return Err(ProjectInviteError::ApprovalConflict);
        }
        if projection.revocation.is_some() {
            return Err(ProjectInviteError::InviteRevoked);
        }
        if projection.decision.is_some() {
            return Err(ProjectInviteError::DecisionConflict);
        }
        self.validate_inviter_membership(&projection.draft, approval.approved_at())?;
        let approver = self
            .team_memberships
            .get(approval.approver_membership_id())
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if approver.tenant_id() != projection.draft.scope.tenant_id()
            || approver.team_id() != projection.draft.scope.team_id()
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        if approver.status() != ProjectInviteMembershipStatus::Active {
            return Err(ProjectInviteError::MembershipRevoked);
        }
        if approver.membership_revision() != approval.approver_membership_revision() {
            return Err(ProjectInviteError::StaleMembership);
        }
        if !approver.role().can_invite() {
            return Err(ProjectInviteError::InsufficientRole);
        }
        self.record_event(ProjectInviteEvent::DraftApproved {
            event_id: ProjectInviteEventId::new(),
            invite_id,
            approval: approval.clone(),
        })?;
        Ok(ApprovedInvite {
            handle: handle.clone(),
            draft: projection.draft,
            approval,
        })
    }

    pub fn emit_invite_receipt(
        &mut self,
        handle: &DraftInviteHandle,
        now: DateTime<Utc>,
    ) -> Result<InviteReceipt, ProjectInviteError> {
        let invite_id = self
            .handles
            .get(handle)
            .cloned()
            .ok_or(ProjectInviteError::DraftNotFound)?;
        let projection = self
            .invites
            .get(&invite_id)
            .cloned()
            .ok_or(ProjectInviteError::DraftNotFound)?;
        if let Some(receipt) = projection.receipt {
            return Ok(receipt);
        }
        if projection.revocation.is_some() {
            return Err(ProjectInviteError::InviteRevoked);
        }
        if projection.decision.is_some() {
            return Err(ProjectInviteError::DecisionConflict);
        }
        let approval = projection
            .approval
            .clone()
            .ok_or(ProjectInviteError::ApprovalRequired)?;
        if now >= projection.draft.expires_at() {
            return Err(ProjectInviteError::InviteExpired);
        }
        self.validate_inviter_membership(&projection.draft, now)?;
        self.validate_approval_membership(&projection.draft, &approval)?;
        let receipt = InviteReceipt::issue(&projection.draft, &approval, now)?;
        self.record_event(ProjectInviteEvent::InviteReceiptIssued {
            event_id: ProjectInviteEventId::new(),
            receipt: receipt.clone(),
        })?;
        Ok(receipt)
    }

    pub fn accept_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<ProjectMembershipBinding, ProjectInviteError> {
        Ok(self
            .accept_invite_with_receipt(receipt, session, now)?
            .binding)
    }

    pub fn accept_invite_with_receipt(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteAcceptance, ProjectInviteError> {
        let decision_receipt =
            self.respond_to_invite(receipt, session, ProjectInviteDecision::Accepted, now)?;
        let binding_id = decision_receipt
            .binding_id()
            .ok_or(ProjectInviteError::BindingNotFound)?;
        let binding = self
            .bindings
            .get(binding_id)
            .cloned()
            .ok_or(ProjectInviteError::BindingNotFound)?;
        Ok(InviteAcceptance {
            receipt: decision_receipt,
            binding,
        })
    }

    pub fn decline_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteDecisionReceipt, ProjectInviteError> {
        self.respond_to_invite(receipt, session, ProjectInviteDecision::Declined, now)
    }

    pub fn respond_to_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        decision: ProjectInviteDecision,
        now: DateTime<Utc>,
    ) -> Result<InviteDecisionReceipt, ProjectInviteError> {
        receipt.validate()?;
        let projection = self
            .invites
            .get(receipt.invite_id())
            .cloned()
            .ok_or(ProjectInviteError::ReceiptNotFound)?;
        if projection.receipt.as_ref() != Some(receipt) {
            return Err(ProjectInviteError::ReceiptProjectionMismatch);
        }
        if projection.revocation.is_some() {
            return Err(ProjectInviteError::InviteRevoked);
        }
        if let Some(existing) = projection.decision.clone() {
            if existing.decision != decision {
                return Err(ProjectInviteError::DecisionConflict);
            }
            self.validate_session_for_receipt(receipt, session, now)?;
            if existing.session_id() != session.session_id()
                || existing.session_revision() != session.revision()
                || existing.invitee_identity_provider_digest() != session.identity_provider_digest()
            {
                return Err(ProjectInviteError::AcceptanceConflict);
            }
            if let Some(binding_id) = existing.binding_id() {
                let binding = self
                    .bindings
                    .get(binding_id)
                    .cloned()
                    .ok_or(ProjectInviteError::BindingNotFound)?;
                self.validate_binding(&binding, now)?;
            }
            return Ok(existing);
        }
        if let Some(binding) = projection.binding.clone() {
            if decision == ProjectInviteDecision::Declined {
                return Err(ProjectInviteError::DecisionConflict);
            }
            self.validate_binding(&binding, now)?;
            self.validate_session_for_receipt(receipt, session, now)?;
            if binding.session_id() != session.session_id()
                || binding.account_id() != session.account_id()
                || binding.identity_provider_digest() != session.identity_provider_digest()
            {
                return Err(ProjectInviteError::AcceptanceConflict);
            }
            let decision_receipt = InviteDecisionReceipt::issue(
                receipt,
                session,
                ProjectInviteDecision::Accepted,
                Some(&binding),
                now,
            )?;
            self.record_event(ProjectInviteEvent::InviteDecisionRecorded {
                event_id: ProjectInviteEventId::new(),
                receipt: decision_receipt.clone(),
                binding: Some(binding),
            })?;
            return Ok(decision_receipt);
        }
        if now >= receipt.expires_at() {
            return Err(ProjectInviteError::InviteExpired);
        }
        self.validate_inviter_membership(&projection.draft, now)?;
        self.validate_session_for_receipt(receipt, session, now)?;
        let binding = match decision {
            ProjectInviteDecision::Accepted => Some(ProjectMembershipBinding::from_accept(
                receipt,
                &projection.draft,
                session,
                now,
            )?),
            ProjectInviteDecision::Declined => None,
        };
        let decision_receipt =
            InviteDecisionReceipt::issue(receipt, session, decision, binding.as_ref(), now)?;
        self.record_event(ProjectInviteEvent::InviteDecisionRecorded {
            event_id: ProjectInviteEventId::new(),
            receipt: decision_receipt.clone(),
            binding,
        })?;
        Ok(decision_receipt)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the provider owns the revocation command at the durable boundary"
    )]
    pub fn revoke_invite(
        &mut self,
        request: InviteRevocationRequest,
    ) -> Result<InviteRevocationReceipt, ProjectInviteError> {
        request.validate()?;
        let projection = self
            .invites
            .get(&request.invite_id)
            .cloned()
            .ok_or(ProjectInviteError::DraftNotFound)?;
        if let Some(existing) = projection.revocation.clone() {
            if revocation_matches_request(&existing, &request) {
                return Ok(existing);
            }
            return Err(ProjectInviteError::RevocationConflict);
        }
        if projection.draft.scope != request.scope {
            return Err(
                if projection.draft.scope.team_id() == request.scope.team_id() {
                    ProjectInviteError::ProjectScopeMismatch
                } else {
                    ProjectInviteError::CrossTeamScope
                },
            );
        }
        if projection.draft.invite_revision != request.invite_revision {
            return Err(ProjectInviteError::StaleInvite);
        }
        if projection
            .decision
            .as_ref()
            .is_some_and(|receipt| receipt.decision == ProjectInviteDecision::Declined)
        {
            return Err(ProjectInviteError::InviteAlreadyDeclined);
        }
        if request.revoked_at >= projection.draft.expires_at {
            return Err(ProjectInviteError::InviteExpired);
        }
        let owner_session = self.validate_owner_for_revocation(&request, &projection.draft)?;
        let revoked_binding = if let Some(binding) = projection.binding.as_ref() {
            let current = self
                .bindings
                .get(binding.binding_id())
                .ok_or(ProjectInviteError::BindingNotFound)?;
            if current != binding {
                return Err(ProjectInviteError::BindingStale);
            }
            if current.status() == ProjectMembershipBindingStatus::Revoked {
                return Err(ProjectInviteError::BindingRevoked);
            }
            let mut revoked = current.clone();
            revoked.status = ProjectMembershipBindingStatus::Revoked;
            revoked.membership_revision = revoked
                .membership_revision
                .checked_add(1)
                .ok_or(ProjectInviteError::RevisionOverflow)?;
            revoked.validate()?;
            Some(revoked)
        } else {
            None
        };
        let revocation =
            InviteRevocationReceipt::issue(&request, &owner_session, revoked_binding.as_ref())?;
        self.record_event(ProjectInviteEvent::InviteRevoked {
            event_id: ProjectInviteEventId::new(),
            receipt: revocation.clone(),
            binding: revoked_binding,
        })?;
        Ok(revocation)
    }

    pub fn validate_binding(
        &self,
        binding: &ProjectMembershipBinding,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError> {
        binding.validate()?;
        let current = self
            .bindings
            .get(binding.binding_id())
            .ok_or(ProjectInviteError::BindingNotFound)?;
        if current.status() == ProjectMembershipBindingStatus::Revoked {
            return Err(ProjectInviteError::BindingRevoked);
        }
        if current != binding {
            return Err(ProjectInviteError::BindingStale);
        }
        let projection = self
            .invites
            .get(binding.invite_id())
            .ok_or(ProjectInviteError::ReceiptNotFound)?;
        self.validate_inviter_membership_without_expiry(&projection.draft)?;
        self.validate_current_session_for_binding(binding, now)?;
        Ok(())
    }

    pub fn change_team_membership_role(
        &mut self,
        member_id: &MemberId,
        role: ProjectInviteRole,
    ) -> Result<ProjectInviteTeamMembership, ProjectInviteError> {
        let mut membership = self
            .team_memberships
            .get(member_id)
            .cloned()
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if membership.status == ProjectInviteMembershipStatus::Revoked || membership.role == role {
            return Err(ProjectInviteError::InvalidMembershipTransition);
        }
        membership.role = role;
        membership.membership_revision = membership
            .membership_revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        membership.role_revision = membership
            .role_revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        membership.validate()?;
        self.team_memberships
            .insert(member_id.clone(), membership.clone());
        Ok(membership)
    }

    pub fn revoke_team_membership(
        &mut self,
        member_id: &MemberId,
    ) -> Result<ProjectInviteTeamMembership, ProjectInviteError> {
        let mut membership = self
            .team_memberships
            .get(member_id)
            .cloned()
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if membership.status == ProjectInviteMembershipStatus::Revoked {
            return Err(ProjectInviteError::InvalidMembershipTransition);
        }
        membership.status = ProjectInviteMembershipStatus::Revoked;
        membership.membership_revision = membership
            .membership_revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        membership.validate()?;
        self.team_memberships
            .insert(member_id.clone(), membership.clone());
        Ok(membership)
    }

    pub fn revoke_session(
        &mut self,
        session_id: &IdentitySessionId,
    ) -> Result<ProjectInviteSession, ProjectInviteError> {
        let mut session = self
            .sessions
            .get(session_id)
            .cloned()
            .ok_or(ProjectInviteError::SessionNotFound)?;
        if session.status == ProjectInviteSessionStatus::Revoked {
            return Err(ProjectInviteError::SessionRevoked);
        }
        session.status = ProjectInviteSessionStatus::Revoked;
        session.revision = session
            .revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        self.sessions.insert(session_id.clone(), session.clone());
        Ok(session)
    }

    pub fn change_binding_role(
        &mut self,
        binding_id: &ProjectMembershipBindingId,
        role: ProjectInviteRole,
    ) -> Result<ProjectMembershipBinding, ProjectInviteError> {
        let mut binding = self
            .bindings
            .get(binding_id)
            .cloned()
            .ok_or(ProjectInviteError::BindingNotFound)?;
        if binding.status == ProjectMembershipBindingStatus::Revoked
            || binding.role == role
            || binding.scopes.iter().any(|scope| !role.allows(*scope))
        {
            return Err(ProjectInviteError::InvalidMembershipTransition);
        }
        binding.role = role;
        binding.membership_revision = binding
            .membership_revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        binding.role_revision = binding
            .role_revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        binding.validate()?;
        self.record_event(ProjectInviteEvent::MembershipBindingUpdated {
            event_id: ProjectInviteEventId::new(),
            binding: binding.clone(),
        })?;
        Ok(binding)
    }

    pub fn revoke_binding(
        &mut self,
        binding_id: &ProjectMembershipBindingId,
    ) -> Result<ProjectMembershipBinding, ProjectInviteError> {
        let mut binding = self
            .bindings
            .get(binding_id)
            .cloned()
            .ok_or(ProjectInviteError::BindingNotFound)?;
        if binding.status == ProjectMembershipBindingStatus::Revoked {
            return Err(ProjectInviteError::InvalidMembershipTransition);
        }
        binding.status = ProjectMembershipBindingStatus::Revoked;
        binding.membership_revision = binding
            .membership_revision
            .checked_add(1)
            .ok_or(ProjectInviteError::RevisionOverflow)?;
        binding.validate()?;
        self.record_event(ProjectInviteEvent::MembershipBindingUpdated {
            event_id: ProjectInviteEventId::new(),
            binding: binding.clone(),
        })?;
        Ok(binding)
    }

    pub fn replay_event(&mut self, event: ProjectInviteEvent) -> Result<(), ProjectInviteError> {
        self.record_event(event)
    }

    fn validate_inviter_membership(
        &self,
        draft: &DraftInvite,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError> {
        if now >= draft.expires_at {
            return Err(ProjectInviteError::InviteExpired);
        }
        self.validate_inviter_membership_without_expiry(draft)
    }

    fn validate_inviter_membership_without_expiry(
        &self,
        draft: &DraftInvite,
    ) -> Result<(), ProjectInviteError> {
        let project_scope = self
            .projects
            .get(draft.scope.project_id())
            .ok_or(ProjectInviteError::ProjectScopeNotFound)?;
        if project_scope != &draft.scope {
            return Err(if project_scope.team_id() == draft.scope.team_id() {
                ProjectInviteError::ProjectScopeMismatch
            } else {
                ProjectInviteError::CrossTeamScope
            });
        }
        let membership = self
            .team_memberships
            .get(draft.inviter_membership_id())
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if membership.tenant_id() != draft.scope.tenant_id()
            || membership.team_id() != draft.scope.team_id()
            || membership.account_id() != draft.inviter_account_id()
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        if membership.status() != ProjectInviteMembershipStatus::Active {
            return Err(ProjectInviteError::MembershipRevoked);
        }
        if membership.membership_revision() != draft.inviter_membership_revision {
            return Err(ProjectInviteError::StaleMembership);
        }
        if !membership.role().can_invite() {
            return Err(ProjectInviteError::InsufficientRole);
        }
        Ok(())
    }

    fn validate_approval_membership(
        &self,
        draft: &DraftInvite,
        approval: &InviteApproval,
    ) -> Result<(), ProjectInviteError> {
        let membership = self
            .team_memberships
            .get(approval.approver_membership_id())
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if membership.tenant_id() != draft.scope.tenant_id()
            || membership.team_id() != draft.scope.team_id()
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        if membership.status() != ProjectInviteMembershipStatus::Active {
            return Err(ProjectInviteError::MembershipRevoked);
        }
        if membership.membership_revision() != approval.approver_membership_revision {
            return Err(ProjectInviteError::StaleMembership);
        }
        if !membership.role().can_invite() {
            return Err(ProjectInviteError::InsufficientRole);
        }
        Ok(())
    }

    fn validate_session_for_receipt(
        &self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError> {
        session.validate()?;
        let current = self
            .sessions
            .get(session.session_id())
            .ok_or(ProjectInviteError::SessionNotFound)?;
        if current != session {
            return Err(ProjectInviteError::StaleSession);
        }
        if current.status() == ProjectInviteSessionStatus::Revoked {
            return Err(ProjectInviteError::SessionRevoked);
        }
        if current.expires_at() <= now {
            return Err(ProjectInviteError::SessionExpired);
        }
        if current.tenant_id() != receipt.scope.tenant_id()
            || current.team_id() != receipt.scope.team_id()
            || current.identity_digest() != receipt.invitee_identity_digest()
            || current.identity_provider_digest() != receipt.invitee_identity_provider_digest()
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        Ok(())
    }

    fn validate_owner_for_revocation(
        &self,
        request: &InviteRevocationRequest,
        draft: &DraftInvite,
    ) -> Result<ProjectInviteSession, ProjectInviteError> {
        let membership = self
            .team_memberships
            .get(request.owner_membership_id())
            .ok_or(ProjectInviteError::MembershipNotFound)?;
        if membership.tenant_id() != draft.scope.tenant_id()
            || membership.team_id() != draft.scope.team_id()
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        if membership.status() != ProjectInviteMembershipStatus::Active {
            return Err(ProjectInviteError::MembershipRevoked);
        }
        if membership.membership_revision() != request.owner_membership_revision() {
            return Err(ProjectInviteError::StaleMembership);
        }
        if membership.role() != ProjectInviteRole::Owner {
            return Err(ProjectInviteError::UnauthorizedOwner);
        }
        let session = self
            .sessions
            .get(request.owner_session_id())
            .cloned()
            .ok_or(ProjectInviteError::SessionNotFound)?;
        if session.status() == ProjectInviteSessionStatus::Revoked {
            return Err(ProjectInviteError::SessionRevoked);
        }
        if session.expires_at() <= request.revoked_at() {
            return Err(ProjectInviteError::SessionExpired);
        }
        if session.revision() != request.owner_session_revision()
            || session.tenant_id() != membership.tenant_id()
            || session.team_id() != membership.team_id()
            || session.account_id() != membership.account_id()
        {
            return Err(ProjectInviteError::StaleSession);
        }
        Ok(session)
    }

    fn validate_current_session_for_binding(
        &self,
        binding: &ProjectMembershipBinding,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError> {
        let session = self
            .sessions
            .get(binding.session_id())
            .ok_or(ProjectInviteError::SessionNotFound)?;
        if session.status() == ProjectInviteSessionStatus::Revoked {
            return Err(ProjectInviteError::SessionRevoked);
        }
        if session.expires_at() <= now {
            return Err(ProjectInviteError::SessionExpired);
        }
        if session.revision() != binding.session_revision
            || session.account_id() != &binding.account_id
            || session.identity_digest() != binding.identity_digest
            || session.identity_provider_digest() != binding.identity_provider_digest
            || session.tenant_id() != binding.scope.tenant_id()
            || session.team_id() != binding.scope.team_id()
        {
            return Err(ProjectInviteError::StaleSession);
        }
        Ok(())
    }

    fn validate_decision_binding(
        &self,
        projection: &InviteProjection,
        receipt: &InviteDecisionReceipt,
        binding: &ProjectMembershipBinding,
    ) -> Result<(), ProjectInviteError> {
        let invite_receipt = projection
            .receipt
            .as_ref()
            .ok_or(ProjectInviteError::ReceiptNotFound)?;
        binding.validate()?;
        if receipt.decision != ProjectInviteDecision::Accepted
            || receipt.binding_id != Some(binding.binding_id.clone())
            || receipt.membership_revision != Some(binding.membership_revision)
            || binding.invite_id != receipt.invite_id
            || binding.invite_revision != receipt.invite_revision
            || binding.receipt_id != invite_receipt.receipt_id
            || binding.scope != receipt.scope
            || binding.inviter_membership_id != receipt.inviter_membership_id
            || binding.inviter_membership_revision != receipt.inviter_membership_revision
            || binding.identity_digest != receipt.invitee_identity_digest
            || binding.identity_provider_digest != receipt.invitee_identity_provider_digest
            || binding.session_id != receipt.session_id
            || binding.session_revision != receipt.session_revision
            || binding.role != invite_receipt.role
            || binding.scopes != invite_receipt.scopes
            || binding.status != ProjectMembershipBindingStatus::Active
        {
            return Err(ProjectInviteError::DecisionBindingMismatch);
        }
        if let Some(existing_id) = self.binding_by_invite.get(binding.invite_id())
            && self.bindings.get(existing_id) != Some(binding)
        {
            return Err(ProjectInviteError::AcceptanceConflict);
        }
        if let Some(existing) = self.bindings.get(binding.binding_id())
            && existing != binding
        {
            return Err(ProjectInviteError::AcceptanceConflict);
        }
        Ok(())
    }

    fn validate_revocation_binding(
        &self,
        projection: &InviteProjection,
        receipt: &InviteRevocationReceipt,
        binding: Option<&ProjectMembershipBinding>,
    ) -> Result<(), ProjectInviteError> {
        match (projection.binding.as_ref(), binding) {
            (None, None) => {
                if receipt.binding_id.is_some() || receipt.membership_revision.is_some() {
                    return Err(ProjectInviteError::RevocationBindingMismatch);
                }
            }
            (Some(current), Some(revoked)) => {
                if self.bindings.get(current.binding_id()) != Some(current) {
                    return Err(ProjectInviteError::BindingStale);
                }
                let expected_membership_revision = current
                    .membership_revision
                    .checked_add(1)
                    .ok_or(ProjectInviteError::RevisionOverflow)?;
                if receipt.binding_id != Some(revoked.binding_id.clone())
                    || receipt.membership_revision != Some(revoked.membership_revision)
                    || revoked.binding_id != current.binding_id
                    || revoked.invite_id != current.invite_id
                    || revoked.invite_revision != current.invite_revision
                    || revoked.member_id != current.member_id
                    || revoked.scope != current.scope
                    || revoked.account_id != current.account_id
                    || revoked.identity_digest != current.identity_digest
                    || revoked.identity_provider_digest != current.identity_provider_digest
                    || revoked.role != current.role
                    || revoked.scopes != current.scopes
                    || revoked.inviter_membership_id != current.inviter_membership_id
                    || revoked.inviter_membership_revision != current.inviter_membership_revision
                    || revoked.role_revision != current.role_revision
                    || revoked.session_id != current.session_id
                    || revoked.session_revision != current.session_revision
                    || revoked.status != ProjectMembershipBindingStatus::Revoked
                    || revoked.membership_revision != expected_membership_revision
                {
                    return Err(ProjectInviteError::RevocationBindingMismatch);
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ProjectInviteError::RevocationBindingMismatch);
            }
        }
        Ok(())
    }

    fn record_event(&mut self, event: ProjectInviteEvent) -> Result<(), ProjectInviteError> {
        let event_id = event.event_id().clone();
        if let Some(index) = self.event_ids.get(&event_id) {
            if self.events.get(*index) == Some(&event) {
                return Ok(());
            }
            return Err(ProjectInviteError::EventConflict);
        }
        self.apply_event_projection(&event)?;
        self.event_ids.insert(event_id, self.events.len());
        self.events.push(event);
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the event projector keeps all invite transitions in one atomic match"
    )]
    fn apply_event_projection(
        &mut self,
        event: &ProjectInviteEvent,
    ) -> Result<(), ProjectInviteError> {
        match event {
            ProjectInviteEvent::DraftCreated { handle, draft, .. } => {
                draft.validate()?;
                if self.handles.contains_key(handle)
                    || self.invites.contains_key(draft.invite_id())
                    || self.idempotency.contains_key(&draft.idempotency_key_digest)
                {
                    return Err(ProjectInviteError::DuplicateInvite);
                }
                self.handles.insert(handle.clone(), draft.invite_id.clone());
                self.idempotency.insert(
                    draft.idempotency_key_digest.clone(),
                    (draft.intent_digest.clone(), handle.clone()),
                );
                self.invites.insert(
                    draft.invite_id.clone(),
                    InviteProjection {
                        draft: draft.clone(),
                        handle: handle.clone(),
                        approval: None,
                        receipt: None,
                        decision: None,
                        revocation: None,
                        binding: None,
                    },
                );
            }
            ProjectInviteEvent::DraftApproved {
                invite_id,
                approval,
                ..
            } => {
                approval.validate()?;
                if approval.invite_id() != invite_id {
                    return Err(ProjectInviteError::ApprovalInviteMismatch);
                }
                let draft = self
                    .invites
                    .get(invite_id)
                    .ok_or(ProjectInviteError::DraftNotFound)?
                    .draft
                    .clone();
                if approval.invite_revision() != draft.invite_revision() {
                    return Err(ProjectInviteError::StaleInvite);
                }
                let projection = self
                    .invites
                    .get_mut(invite_id)
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                if let Some(existing) = &projection.approval {
                    if existing == approval {
                        return Err(ProjectInviteError::DuplicateApproval);
                    }
                    return Err(ProjectInviteError::ApprovalConflict);
                }
                if projection.receipt.is_some() {
                    return Err(ProjectInviteError::InviteAlreadyEmitted);
                }
                projection.approval = Some(approval.clone());
            }
            ProjectInviteEvent::InviteReceiptIssued { receipt, .. } => {
                receipt.validate()?;
                let projection = self
                    .invites
                    .get_mut(receipt.invite_id())
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                if let Some(existing) = &projection.receipt {
                    if existing == receipt {
                        return Err(ProjectInviteError::DuplicateReceipt);
                    }
                    return Err(ProjectInviteError::ReceiptProjectionMismatch);
                }
                if projection
                    .approval
                    .as_ref()
                    .map(InviteApproval::approval_id)
                    != Some(&receipt.approval_id)
                {
                    return Err(ProjectInviteError::ApprovalRequired);
                }
                if receipt.invite_revision != projection.draft.invite_revision
                    || receipt.scope != projection.draft.scope
                    || receipt.invitee_identity_digest != projection.draft.invitee_identity_digest
                    || receipt.invitee_identity_provider_digest
                        != projection.draft.invitee_identity_provider_digest
                    || receipt.role != projection.draft.role
                    || receipt.scopes != projection.draft.scopes
                    || receipt.inviter_membership_id != projection.draft.inviter_membership_id
                    || receipt.inviter_membership_revision
                        != projection.draft.inviter_membership_revision
                    || receipt.expires_at != projection.draft.expires_at
                    || projection.approval.as_ref().is_none_or(|approval| {
                        receipt.provider_digest
                            != invite_provider_digest(&projection.draft, approval)
                    })
                {
                    return Err(ProjectInviteError::ReceiptProjectionMismatch);
                }
                projection.receipt = Some(receipt.clone());
            }
            ProjectInviteEvent::InviteDecisionRecorded {
                receipt, binding, ..
            } => {
                receipt.validate()?;
                let projection = self
                    .invites
                    .get(receipt.invite_id())
                    .cloned()
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                let invite_receipt = projection
                    .receipt
                    .as_ref()
                    .ok_or(ProjectInviteError::ReceiptNotFound)?;
                if receipt.invite_id != invite_receipt.invite_id
                    || receipt.invite_revision != projection.draft.invite_revision
                    || receipt.scope != invite_receipt.scope
                    || receipt.invitee_identity_digest != invite_receipt.invitee_identity_digest
                    || receipt.invitee_identity_provider_digest
                        != invite_receipt.invitee_identity_provider_digest
                    || receipt.invite_revision != invite_receipt.invite_revision
                    || receipt.inviter_membership_id != invite_receipt.inviter_membership_id
                    || receipt.inviter_membership_revision
                        != invite_receipt.inviter_membership_revision
                    || projection.revocation.is_some()
                {
                    return Err(ProjectInviteError::ReceiptProjectionMismatch);
                }
                let session = self
                    .sessions
                    .get(&receipt.session_id)
                    .ok_or(ProjectInviteError::SessionNotFound)?;
                if session.revision != receipt.session_revision
                    || session.tenant_id != receipt.scope.tenant_id
                    || session.team_id != receipt.scope.team_id
                    || session.identity_digest != receipt.invitee_identity_digest
                    || session.identity_provider_digest != receipt.invitee_identity_provider_digest
                {
                    return Err(ProjectInviteError::StaleSession);
                }
                if let Some(existing) = &projection.decision {
                    if existing == receipt {
                        return Err(ProjectInviteError::DuplicateDecision);
                    }
                    return Err(ProjectInviteError::DecisionConflict);
                }
                match (receipt.decision, binding) {
                    (ProjectInviteDecision::Accepted, Some(binding)) => {
                        self.validate_decision_binding(&projection, receipt, binding)?;
                    }
                    (ProjectInviteDecision::Declined, None) => {}
                    _ => return Err(ProjectInviteError::DecisionBindingMismatch),
                }
                if receipt.provider_digest
                    != invite_decision_provider_digest(
                        invite_receipt,
                        session,
                        receipt.decision,
                        binding.as_ref(),
                    )
                {
                    return Err(ProjectInviteError::DecisionBindingMismatch);
                }
                let projection = self
                    .invites
                    .get_mut(receipt.invite_id())
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                projection.decision = Some(receipt.clone());
                if let Some(binding) = binding {
                    projection.binding = Some(binding.clone());
                    self.binding_by_invite
                        .insert(binding.invite_id.clone(), binding.binding_id.clone());
                    self.bindings
                        .insert(binding.binding_id.clone(), binding.clone());
                }
            }
            ProjectInviteEvent::InviteRevoked {
                receipt, binding, ..
            } => {
                receipt.validate()?;
                let projection = self
                    .invites
                    .get(receipt.invite_id())
                    .cloned()
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                if receipt.invite_revision != projection.draft.invite_revision
                    || receipt.scope != projection.draft.scope
                    || projection.revocation.is_some()
                {
                    return Err(ProjectInviteError::RevocationConflict);
                }
                if let Some(existing) = &projection.decision
                    && existing.decision == ProjectInviteDecision::Declined
                {
                    return Err(ProjectInviteError::InviteAlreadyDeclined);
                }
                let owner_membership = self
                    .team_memberships
                    .get(&receipt.owner_membership_id)
                    .ok_or(ProjectInviteError::MembershipNotFound)?;
                if owner_membership.tenant_id != receipt.scope.tenant_id
                    || owner_membership.team_id != receipt.scope.team_id
                    || owner_membership.membership_revision != receipt.owner_membership_revision
                    || owner_membership.status != ProjectInviteMembershipStatus::Active
                    || owner_membership.role != ProjectInviteRole::Owner
                {
                    return Err(ProjectInviteError::UnauthorizedOwner);
                }
                let owner_session = self
                    .sessions
                    .get(&receipt.owner_session_id)
                    .ok_or(ProjectInviteError::SessionNotFound)?;
                if owner_session.revision != receipt.owner_session_revision
                    || owner_session.tenant_id != receipt.scope.tenant_id
                    || owner_session.team_id != receipt.scope.team_id
                    || owner_session.identity_provider_digest
                        != receipt.owner_identity_provider_digest
                    || receipt.provider_digest
                        != invite_revocation_provider_digest_from_receipt(
                            receipt,
                            owner_session,
                            binding.as_ref(),
                        )
                {
                    return Err(ProjectInviteError::RevocationBindingMismatch);
                }
                self.validate_revocation_binding(&projection, receipt, binding.as_ref())?;
                let projection = self
                    .invites
                    .get_mut(receipt.invite_id())
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                projection.revocation = Some(receipt.clone());
                if let Some(binding) = binding {
                    projection.binding = Some(binding.clone());
                    self.bindings
                        .insert(binding.binding_id.clone(), binding.clone());
                }
            }
            ProjectInviteEvent::MembershipBindingCreated { binding, .. } => {
                binding.validate()?;
                if let Some(existing_id) = self.binding_by_invite.get(binding.invite_id()) {
                    if self.bindings.get(existing_id) == Some(binding) {
                        return Err(ProjectInviteError::DuplicateBinding);
                    }
                    return Err(ProjectInviteError::AcceptanceConflict);
                }
                let projection = self
                    .invites
                    .get_mut(binding.invite_id())
                    .ok_or(ProjectInviteError::DraftNotFound)?;
                if projection.receipt.as_ref().map(InviteReceipt::receipt_id)
                    != Some(binding.receipt_id())
                    || projection.receipt.as_ref().is_none_or(|receipt| {
                        binding.invite_revision != receipt.invite_revision
                            || binding.scope != receipt.scope
                            || binding.identity_digest != receipt.invitee_identity_digest
                            || binding.identity_provider_digest
                                != receipt.invitee_identity_provider_digest
                            || binding.role != receipt.role
                            || binding.scopes != receipt.scopes
                    })
                {
                    return Err(ProjectInviteError::ReceiptProjectionMismatch);
                }
                projection.binding = Some(binding.clone());
                self.binding_by_invite
                    .insert(binding.invite_id.clone(), binding.binding_id.clone());
                self.bindings
                    .insert(binding.binding_id.clone(), binding.clone());
            }
            ProjectInviteEvent::MembershipBindingUpdated { binding, .. } => {
                binding.validate()?;
                let current = self
                    .bindings
                    .get(binding.binding_id())
                    .cloned()
                    .ok_or(ProjectInviteError::BindingNotFound)?;
                if current.status == ProjectMembershipBindingStatus::Revoked {
                    return Err(ProjectInviteError::BindingRevoked);
                }
                let expected_membership_revision = current
                    .membership_revision
                    .checked_add(1)
                    .ok_or(ProjectInviteError::RevisionOverflow)?;
                if binding.membership_revision != expected_membership_revision {
                    return Err(ProjectInviteError::StaleMembership);
                }
                if binding.invite_id != current.invite_id
                    || binding.invite_revision != current.invite_revision
                    || binding.member_id != current.member_id
                    || binding.account_id != current.account_id
                    || binding.scope != current.scope
                    || binding.session_id != current.session_id
                    || binding.identity_provider_digest != current.identity_provider_digest
                {
                    return Err(ProjectInviteError::MembershipProjectionMismatch);
                }
                if binding.status == ProjectMembershipBindingStatus::Revoked {
                    if binding.role != current.role
                        || binding.role_revision != current.role_revision
                    {
                        return Err(ProjectInviteError::MembershipProjectionMismatch);
                    }
                } else if binding.status != ProjectMembershipBindingStatus::Active
                    || binding.role == current.role
                    || binding.role_revision
                        != current
                            .role_revision
                            .checked_add(1)
                            .ok_or(ProjectInviteError::RevisionOverflow)?
                {
                    return Err(ProjectInviteError::MembershipProjectionMismatch);
                }
                self.bindings
                    .insert(binding.binding_id.clone(), binding.clone());
                if let Some(projection) = self.invites.get_mut(binding.invite_id()) {
                    projection.binding = Some(binding.clone());
                }
            }
        }
        Ok(())
    }
}

impl Default for ProjectInvitePluginService {
    fn default() -> Self {
        Self::new()
    }
}

pub trait ProjectInviteProvider {
    fn create_draft(
        &mut self,
        request: DraftInviteRequest,
    ) -> Result<DraftInviteHandle, ProjectInviteError>;

    fn read_draft(&self, handle: &DraftInviteHandle) -> Result<DraftInvite, ProjectInviteError>;

    fn approve_draft(
        &mut self,
        handle: &DraftInviteHandle,
        approval: InviteApproval,
    ) -> Result<ApprovedInvite, ProjectInviteError>;

    fn emit_invite_receipt(
        &mut self,
        handle: &DraftInviteHandle,
        now: DateTime<Utc>,
    ) -> Result<InviteReceipt, ProjectInviteError>;

    fn accept_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<ProjectMembershipBinding, ProjectInviteError>;

    fn accept_invite_with_receipt(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteAcceptance, ProjectInviteError>;

    fn decline_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteDecisionReceipt, ProjectInviteError>;

    fn revoke_invite(
        &mut self,
        request: InviteRevocationRequest,
    ) -> Result<InviteRevocationReceipt, ProjectInviteError>;

    fn validate_binding(
        &self,
        binding: &ProjectMembershipBinding,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError>;

    fn replay_event(&mut self, event: ProjectInviteEvent) -> Result<(), ProjectInviteError>;
}

pub trait ProjectInviteService: ProjectInviteProvider {
    fn events(&self) -> &[ProjectInviteEvent];
}

pub trait ProjectInviteConsumer {
    fn prepare_invite(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        request: DraftInviteRequest,
    ) -> Result<DraftInviteHandle, ProjectInviteError>;

    fn approve_invite(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        handle: &DraftInviteHandle,
        approval: InviteApproval,
    ) -> Result<ApprovedInvite, ProjectInviteError>;

    fn issue_invite_receipt(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        handle: &DraftInviteHandle,
        now: DateTime<Utc>,
    ) -> Result<InviteReceipt, ProjectInviteError>;

    fn accept_project_invite(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<ProjectMembershipBinding, ProjectInviteError>;

    fn accept_project_invite_with_receipt(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteAcceptance, ProjectInviteError> {
        provider.accept_invite_with_receipt(receipt, session, now)
    }

    fn decline_project_invite(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteDecisionReceipt, ProjectInviteError> {
        provider.decline_invite(receipt, session, now)
    }

    fn revoke_project_invite(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        request: InviteRevocationRequest,
    ) -> Result<InviteRevocationReceipt, ProjectInviteError> {
        provider.revoke_invite(request)
    }

    fn validate_project_membership(
        &mut self,
        provider: &mut dyn ProjectInviteProvider,
        binding: &ProjectMembershipBinding,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError>;
}

impl ProjectInviteProvider for ProjectInvitePluginService {
    fn create_draft(
        &mut self,
        request: DraftInviteRequest,
    ) -> Result<DraftInviteHandle, ProjectInviteError> {
        ProjectInvitePluginService::create_draft(self, request)
    }

    fn read_draft(&self, handle: &DraftInviteHandle) -> Result<DraftInvite, ProjectInviteError> {
        ProjectInvitePluginService::draft(self, handle)
    }

    fn approve_draft(
        &mut self,
        handle: &DraftInviteHandle,
        approval: InviteApproval,
    ) -> Result<ApprovedInvite, ProjectInviteError> {
        ProjectInvitePluginService::approve_draft(self, handle, approval)
    }

    fn emit_invite_receipt(
        &mut self,
        handle: &DraftInviteHandle,
        now: DateTime<Utc>,
    ) -> Result<InviteReceipt, ProjectInviteError> {
        ProjectInvitePluginService::emit_invite_receipt(self, handle, now)
    }

    fn accept_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<ProjectMembershipBinding, ProjectInviteError> {
        ProjectInvitePluginService::accept_invite(self, receipt, session, now)
    }

    fn accept_invite_with_receipt(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteAcceptance, ProjectInviteError> {
        ProjectInvitePluginService::accept_invite_with_receipt(self, receipt, session, now)
    }

    fn decline_invite(
        &mut self,
        receipt: &InviteReceipt,
        session: &ProjectInviteSession,
        now: DateTime<Utc>,
    ) -> Result<InviteDecisionReceipt, ProjectInviteError> {
        ProjectInvitePluginService::decline_invite(self, receipt, session, now)
    }

    fn revoke_invite(
        &mut self,
        request: InviteRevocationRequest,
    ) -> Result<InviteRevocationReceipt, ProjectInviteError> {
        ProjectInvitePluginService::revoke_invite(self, request)
    }

    fn validate_binding(
        &self,
        binding: &ProjectMembershipBinding,
        now: DateTime<Utc>,
    ) -> Result<(), ProjectInviteError> {
        ProjectInvitePluginService::validate_binding(self, binding, now)
    }

    fn replay_event(&mut self, event: ProjectInviteEvent) -> Result<(), ProjectInviteError> {
        ProjectInvitePluginService::replay_event(self, event)
    }
}

impl ProjectInviteService for ProjectInvitePluginService {
    fn events(&self) -> &[ProjectInviteEvent] {
        &self.events
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProjectInviteError {
    #[error("project invite scope is invalid")]
    InvalidProjectScope,
    #[error("team membership projection is invalid")]
    InvalidTeamMembership,
    #[error("invite session projection is invalid")]
    InvalidSession,
    #[error("draft invite is invalid")]
    InvalidDraftInvite,
    #[error("invite approval is invalid")]
    InvalidInviteApproval,
    #[error("invite receipt is invalid")]
    InvalidInviteReceipt,
    #[error("invite decision receipt is invalid")]
    InvalidInviteDecisionReceipt,
    #[error("invite revocation request is invalid")]
    InvalidInviteRevocationRequest,
    #[error("invite revocation receipt is invalid")]
    InvalidInviteRevocationReceipt,
    #[error("project membership binding is invalid")]
    InvalidMembershipBinding,
    #[error("project scope was not found")]
    ProjectScopeNotFound,
    #[error("project scope projection does not match")]
    ProjectScopeMismatch,
    #[error("project scope was rebound to another team")]
    CrossTeamScope,
    #[error("team membership was not found")]
    MembershipNotFound,
    #[error("team membership is revoked")]
    MembershipRevoked,
    #[error("team membership revision is stale")]
    StaleMembership,
    #[error("invite revision is stale")]
    StaleInvite,
    #[error("team role cannot invite or approve")]
    InsufficientRole,
    #[error("only an active project owner may revoke an invite")]
    UnauthorizedOwner,
    #[error("team membership projection does not match")]
    MembershipProjectionMismatch,
    #[error("multiple active memberships make identity ambiguous")]
    AmbiguousMembership,
    #[error("session was not found")]
    SessionNotFound,
    #[error("session is revoked")]
    SessionRevoked,
    #[error("session has expired")]
    SessionExpired,
    #[error("session revision is stale")]
    StaleSession,
    #[error("session projection does not match")]
    SessionProjectionMismatch,
    #[error("draft invite was not found")]
    DraftNotFound,
    #[error("invite has expired")]
    InviteExpired,
    #[error("invite requires explicit approval")]
    ApprovalRequired,
    #[error("approval refers to another invite")]
    ApprovalInviteMismatch,
    #[error("approval conflicts with an existing approval")]
    ApprovalConflict,
    #[error("duplicate approval was replayed")]
    DuplicateApproval,
    #[error("invite was already emitted")]
    InviteAlreadyEmitted,
    #[error("invite receipt was not found")]
    ReceiptNotFound,
    #[error("invite receipt projection does not match")]
    ReceiptProjectionMismatch,
    #[error("invite receipt was duplicated")]
    DuplicateReceipt,
    #[error("invite decision conflicts with an existing decision")]
    DecisionConflict,
    #[error("invite decision was duplicated")]
    DuplicateDecision,
    #[error("invite decision and binding do not match")]
    DecisionBindingMismatch,
    #[error("invite was already declined")]
    InviteAlreadyDeclined,
    #[error("invite was revoked")]
    InviteRevoked,
    #[error("invite revocation conflicts with an existing revocation")]
    RevocationConflict,
    #[error("invite revocation and binding do not match")]
    RevocationBindingMismatch,
    #[error("acceptance conflicts with an existing binding")]
    AcceptanceConflict,
    #[error("membership binding was not found")]
    BindingNotFound,
    #[error("membership binding is stale")]
    BindingStale,
    #[error("membership binding is revoked")]
    BindingRevoked,
    #[error("membership binding was duplicated")]
    DuplicateBinding,
    #[error("membership transition is invalid")]
    InvalidMembershipTransition,
    #[error("invite idempotency key conflicts with another intent")]
    IdempotencyConflict,
    #[error("invite id was already used by another intent")]
    DuplicateInvite,
    #[error("invite event conflicts with a previously replayed event")]
    EventConflict,
    #[error("invite revision overflowed")]
    RevisionOverflow,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the canonical digest binds every invite intent field"
)]
fn draft_intent_digest(
    invite_id: &ProjectInviteId,
    invite_revision: u64,
    scope: &ProjectInviteProjectScope,
    inviter_membership_id: &MemberId,
    inviter_membership_revision: u64,
    invitee_identity_digest: &str,
    invitee_identity_provider_digest: &str,
    role: ProjectInviteRole,
    scopes: &BTreeSet<ProjectInviteScope>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> String {
    let mut fields = vec![
        b"hartevo.project-invite.intent.v1".to_vec(),
        invite_id.as_str().as_bytes().to_vec(),
        invite_revision.to_be_bytes().to_vec(),
        scope.tenant_id.as_str().as_bytes().to_vec(),
        scope.team_id.as_str().as_bytes().to_vec(),
        scope.project_id.as_str().as_bytes().to_vec(),
        scope.project_revision.to_be_bytes().to_vec(),
        inviter_membership_id.as_str().as_bytes().to_vec(),
        inviter_membership_revision.to_be_bytes().to_vec(),
        invitee_identity_digest.as_bytes().to_vec(),
        invitee_identity_provider_digest.as_bytes().to_vec(),
        role_tag(role).as_bytes().to_vec(),
        created_at.timestamp().to_be_bytes().to_vec(),
        created_at.timestamp_subsec_nanos().to_be_bytes().to_vec(),
        expires_at.timestamp().to_be_bytes().to_vec(),
        expires_at.timestamp_subsec_nanos().to_be_bytes().to_vec(),
    ];
    fields.extend(
        scopes
            .iter()
            .map(|scope| scope_tag(*scope).as_bytes().to_vec()),
    );
    digest_fields(fields)
}

fn invite_provider_digest(draft: &DraftInvite, approval: &InviteApproval) -> String {
    let mut fields = vec![
        b"hartevo.project-invite.provider.v1".to_vec(),
        draft.intent_digest.as_bytes().to_vec(),
        draft.invitee_identity_provider_digest.as_bytes().to_vec(),
        approval.approval_id.as_str().as_bytes().to_vec(),
        approval.evidence_digest.as_bytes().to_vec(),
        approval.approved_at.timestamp().to_be_bytes().to_vec(),
        approval
            .approved_at
            .timestamp_subsec_nanos()
            .to_be_bytes()
            .to_vec(),
    ];
    fields.extend(
        draft
            .scopes
            .iter()
            .map(|scope| scope_tag(*scope).as_bytes().to_vec()),
    );
    digest_fields(fields)
}

fn identity_provider_digest(identity_digest: &str) -> String {
    digest_fields([
        b"hartevo.project-invite.identity-provider.v1".to_vec(),
        identity_digest.as_bytes().to_vec(),
    ])
}

#[allow(
    clippy::too_many_arguments,
    reason = "the revocation intent digest binds every owner and invite revision"
)]
fn invite_revocation_intent_digest(
    invite_id: &ProjectInviteId,
    invite_revision: u64,
    scope: &ProjectInviteProjectScope,
    owner_actor_id: &ActorId,
    owner_membership_id: &MemberId,
    owner_membership_revision: u64,
    owner_session_id: &IdentitySessionId,
    owner_session_revision: u64,
    evidence_digest: &str,
    revoked_at: DateTime<Utc>,
) -> String {
    digest_fields([
        b"hartevo.project-invite.revocation-intent.v1".to_vec(),
        invite_id.as_str().as_bytes().to_vec(),
        invite_revision.to_be_bytes().to_vec(),
        scope.tenant_id.as_str().as_bytes().to_vec(),
        scope.team_id.as_str().as_bytes().to_vec(),
        scope.project_id.as_str().as_bytes().to_vec(),
        scope.project_revision.to_be_bytes().to_vec(),
        owner_actor_id.as_str().as_bytes().to_vec(),
        owner_membership_id.as_str().as_bytes().to_vec(),
        owner_membership_revision.to_be_bytes().to_vec(),
        owner_session_id.as_str().as_bytes().to_vec(),
        owner_session_revision.to_be_bytes().to_vec(),
        evidence_digest.as_bytes().to_vec(),
        revoked_at.timestamp().to_be_bytes().to_vec(),
        revoked_at.timestamp_subsec_nanos().to_be_bytes().to_vec(),
    ])
}

fn invite_decision_provider_digest(
    invite: &InviteReceipt,
    session: &ProjectInviteSession,
    decision: ProjectInviteDecision,
    binding: Option<&ProjectMembershipBinding>,
) -> String {
    let mut fields = vec![
        b"hartevo.project-invite.decision.v1".to_vec(),
        invite.provider_digest.as_bytes().to_vec(),
        invite.invite_id.as_str().as_bytes().to_vec(),
        invite.invite_revision.to_be_bytes().to_vec(),
        invite.scope.tenant_id.as_str().as_bytes().to_vec(),
        invite.scope.team_id.as_str().as_bytes().to_vec(),
        invite.scope.project_id.as_str().as_bytes().to_vec(),
        invite.scope.project_revision.to_be_bytes().to_vec(),
        invite.invitee_identity_digest.as_bytes().to_vec(),
        session.identity_provider_digest.as_bytes().to_vec(),
        session.session_id.as_str().as_bytes().to_vec(),
        session.revision.to_be_bytes().to_vec(),
        match decision {
            ProjectInviteDecision::Accepted => b"accepted".to_vec(),
            ProjectInviteDecision::Declined => b"declined".to_vec(),
        },
    ];
    if let Some(binding) = binding {
        fields.push(binding.binding_id.as_str().as_bytes().to_vec());
        fields.push(binding.membership_revision.to_be_bytes().to_vec());
    }
    digest_fields(fields)
}

fn invite_revocation_provider_digest(
    request: &InviteRevocationRequest,
    session: &ProjectInviteSession,
    binding: Option<&ProjectMembershipBinding>,
) -> String {
    let mut fields = vec![
        b"hartevo.project-invite.revocation.v1".to_vec(),
        request.intent_digest().as_bytes().to_vec(),
        session.identity_provider_digest.as_bytes().to_vec(),
        request.owner_session_id.as_str().as_bytes().to_vec(),
        request.owner_session_revision.to_be_bytes().to_vec(),
    ];
    if let Some(binding) = binding {
        fields.push(binding.binding_id.as_str().as_bytes().to_vec());
        fields.push(binding.membership_revision.to_be_bytes().to_vec());
    }
    digest_fields(fields)
}

fn invite_revocation_provider_digest_from_receipt(
    receipt: &InviteRevocationReceipt,
    session: &ProjectInviteSession,
    binding: Option<&ProjectMembershipBinding>,
) -> String {
    let mut fields = vec![
        b"hartevo.project-invite.revocation.v1".to_vec(),
        invite_revocation_intent_digest(
            &receipt.invite_id,
            receipt.invite_revision,
            &receipt.scope,
            &receipt.owner_actor_id,
            &receipt.owner_membership_id,
            receipt.owner_membership_revision,
            &receipt.owner_session_id,
            receipt.owner_session_revision,
            &receipt.evidence_digest,
            receipt.revoked_at,
        )
        .as_bytes()
        .to_vec(),
        session.identity_provider_digest.as_bytes().to_vec(),
        receipt.owner_session_id.as_str().as_bytes().to_vec(),
        receipt.owner_session_revision.to_be_bytes().to_vec(),
    ];
    if let Some(binding) = binding {
        fields.push(binding.binding_id.as_str().as_bytes().to_vec());
        fields.push(binding.membership_revision.to_be_bytes().to_vec());
    }
    digest_fields(fields)
}

fn revocation_matches_request(
    receipt: &InviteRevocationReceipt,
    request: &InviteRevocationRequest,
) -> bool {
    receipt.invite_id == request.invite_id
        && receipt.invite_revision == request.invite_revision
        && receipt.scope == request.scope
        && receipt.owner_actor_id == request.owner_actor_id
        && receipt.owner_membership_id == request.owner_membership_id
        && receipt.owner_membership_revision == request.owner_membership_revision
        && receipt.owner_session_id == request.owner_session_id
        && receipt.owner_session_revision == request.owner_session_revision
        && receipt.evidence_digest == request.evidence_digest
        && receipt.revoked_at == request.revoked_at
        && receipt.idempotency_key_digest == request.idempotency_key_digest()
}

fn digest_fields(fields: impl IntoIterator<Item = Vec<u8>>) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("{:x}", digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn role_tag(role: ProjectInviteRole) -> &'static str {
    match role {
        ProjectInviteRole::Viewer => "viewer",
        ProjectInviteRole::Member => "member",
        ProjectInviteRole::Admin => "admin",
        ProjectInviteRole::Owner => "owner",
    }
}

fn scope_tag(scope: ProjectInviteScope) -> &'static str {
    match scope {
        ProjectInviteScope::Read => "read",
        ProjectInviteScope::Write => "write",
        ProjectInviteScope::ManageMembers => "manage_members",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{DateTime, Duration, TimeZone, Utc};

    use super::*;

    const RAW_EMAIL: &str = "invitee@example.test";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 8, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn digest(value: &str) -> String {
        digest_fields([value.as_bytes().to_vec()])
    }

    fn project_scope() -> ProjectInviteProjectScope {
        ProjectInviteProjectScope::new(
            TenantId::from("tenant-growth"),
            TeamId::from("team-growth"),
            ProjectId::from("project-alpha"),
            3,
        )
        .expect("valid project scope")
    }

    fn inviter_membership() -> ProjectInviteTeamMembership {
        ProjectInviteTeamMembership::active(
            MemberId::from("member-inviter"),
            TenantId::from("tenant-growth"),
            TeamId::from("team-growth"),
            AccountId::from("account-inviter"),
            ProjectInviteRole::Admin,
            4,
            2,
        )
        .expect("valid inviter membership")
    }

    fn owner_membership() -> ProjectInviteTeamMembership {
        ProjectInviteTeamMembership::active(
            MemberId::from("member-owner"),
            TenantId::from("tenant-growth"),
            TeamId::from("team-growth"),
            AccountId::from("account-owner"),
            ProjectInviteRole::Owner,
            7,
            3,
        )
        .expect("valid owner membership")
    }

    fn invitee_session(expires_at: DateTime<Utc>) -> ProjectInviteSession {
        ProjectInviteSession::new(
            IdentitySessionId::from("session-invitee"),
            TenantId::from("tenant-growth"),
            TeamId::from("team-growth"),
            AccountId::from("account-invitee"),
            digest(RAW_EMAIL),
            now() - Duration::minutes(5),
            expires_at,
            1,
        )
        .expect("valid invitee session")
    }

    fn owner_session(expires_at: DateTime<Utc>) -> ProjectInviteSession {
        ProjectInviteSession::new(
            IdentitySessionId::from("session-owner"),
            TenantId::from("tenant-growth"),
            TeamId::from("team-growth"),
            AccountId::from("account-owner"),
            digest("owner-subject"),
            now() - Duration::minutes(5),
            expires_at,
            2,
        )
        .expect("valid owner session")
    }

    fn invite_scopes() -> BTreeSet<ProjectInviteScope> {
        BTreeSet::from([ProjectInviteScope::Read, ProjectInviteScope::Write])
    }

    fn invite_request(expires_at: DateTime<Utc>, idempotency_key: &str) -> DraftInviteRequest {
        DraftInviteRequest::new(
            ProjectInviteId::from("invite-alpha"),
            project_scope(),
            MemberId::from("member-inviter"),
            4,
            digest(RAW_EMAIL),
            ProjectInviteRole::Member,
            invite_scopes(),
            now(),
            expires_at,
            idempotency_key,
        )
        .expect("valid invite request")
    }

    fn approval() -> InviteApproval {
        InviteApproval::new(
            ApprovalId::from("approval-alpha"),
            ProjectInviteId::from("invite-alpha"),
            ActorId::from("actor-inviter"),
            MemberId::from("member-inviter"),
            4,
            digest("approval-evidence"),
            now() + Duration::minutes(1),
        )
        .expect("valid invite approval")
    }

    fn seeded_service(session_expires_at: DateTime<Utc>) -> ProjectInvitePluginService {
        let mut service = ProjectInvitePluginService::new();
        service
            .register_project_scope(project_scope())
            .expect("register project scope");
        service
            .register_team_membership(inviter_membership())
            .expect("register inviter membership");
        service
            .register_session(invitee_session(session_expires_at))
            .expect("register invitee session");
        service
    }

    fn seeded_owner_service(session_expires_at: DateTime<Utc>) -> ProjectInvitePluginService {
        let mut service = seeded_service(session_expires_at);
        service
            .register_team_membership(owner_membership())
            .expect("register owner membership");
        service
            .register_session(owner_session(session_expires_at))
            .expect("register owner session");
        service
    }

    fn revocation_request(
        invite_revision: u64,
        revoked_at: DateTime<Utc>,
        idempotency_key: &str,
    ) -> InviteRevocationRequest {
        InviteRevocationRequest::new(
            ProjectInviteId::from("invite-alpha"),
            invite_revision,
            project_scope(),
            ActorId::from("actor-owner"),
            MemberId::from("member-owner"),
            7,
            IdentitySessionId::from("session-owner"),
            2,
            digest("revocation-evidence"),
            revoked_at,
            idempotency_key,
        )
        .expect("valid revocation request")
    }

    fn emitted_invite(
        service: &mut ProjectInvitePluginService,
        expires_at: DateTime<Utc>,
        idempotency_key: &str,
    ) -> (DraftInviteHandle, InviteReceipt) {
        let handle = service
            .create_draft(invite_request(expires_at, idempotency_key))
            .expect("create draft");
        service
            .approve_draft(&handle, approval())
            .expect("approve draft");
        let receipt = service
            .emit_invite_receipt(&handle, now() + Duration::minutes(2))
            .expect("emit receipt");
        (handle, receipt)
    }

    #[derive(Default)]
    struct TestConsumer;

    impl ProjectInviteConsumer for TestConsumer {
        fn prepare_invite(
            &mut self,
            provider: &mut dyn ProjectInviteProvider,
            request: DraftInviteRequest,
        ) -> Result<DraftInviteHandle, ProjectInviteError> {
            provider.create_draft(request)
        }

        fn approve_invite(
            &mut self,
            provider: &mut dyn ProjectInviteProvider,
            handle: &DraftInviteHandle,
            approval: InviteApproval,
        ) -> Result<ApprovedInvite, ProjectInviteError> {
            provider.approve_draft(handle, approval)
        }

        fn issue_invite_receipt(
            &mut self,
            provider: &mut dyn ProjectInviteProvider,
            handle: &DraftInviteHandle,
            at: DateTime<Utc>,
        ) -> Result<InviteReceipt, ProjectInviteError> {
            provider.emit_invite_receipt(handle, at)
        }

        fn accept_project_invite(
            &mut self,
            provider: &mut dyn ProjectInviteProvider,
            receipt: &InviteReceipt,
            session: &ProjectInviteSession,
            at: DateTime<Utc>,
        ) -> Result<ProjectMembershipBinding, ProjectInviteError> {
            provider.accept_invite(receipt, session, at)
        }

        fn validate_project_membership(
            &mut self,
            provider: &mut dyn ProjectInviteProvider,
            binding: &ProjectMembershipBinding,
            at: DateTime<Utc>,
        ) -> Result<(), ProjectInviteError> {
            provider.validate_binding(binding, at)
        }
    }

    #[test]
    fn consumer_lifecycle_only_exposes_scoped_identity_projections() {
        let expires_at = now() + Duration::hours(1);
        let mut service = seeded_service(expires_at);
        let mut consumer = TestConsumer;
        let request = invite_request(expires_at, "idem-lifecycle");

        let handle = consumer
            .prepare_invite(&mut service, request.clone())
            .expect("prepare invite");
        assert_eq!(
            service.status(&handle, now()),
            Ok(ProjectInviteStatus::Draft)
        );
        let draft = service.read_draft(&handle).expect("read draft projection");
        assert_eq!(draft.scope().team_id(), &TeamId::from("team-growth"));
        assert_eq!(
            draft.scope().project_id(),
            &ProjectId::from("project-alpha")
        );
        assert_eq!(draft.inviter_membership_revision(), 4);
        assert_eq!(draft.invitee_identity_digest(), digest(RAW_EMAIL));
        assert_eq!(draft.role(), ProjectInviteRole::Member);
        assert_eq!(draft.scopes(), &invite_scopes());

        assert_eq!(
            consumer.issue_invite_receipt(&mut service, &handle, now()),
            Err(ProjectInviteError::ApprovalRequired)
        );
        let approved = consumer
            .approve_invite(&mut service, &handle, approval())
            .expect("explicit approval");
        assert_eq!(approved.draft(), &draft);
        assert_eq!(
            service.status(&handle, now() + Duration::minutes(1)),
            Ok(ProjectInviteStatus::Approved)
        );

        let receipt = consumer
            .issue_invite_receipt(&mut service, &handle, now() + Duration::minutes(2))
            .expect("issue receipt");
        assert_eq!(
            service.status(&handle, now() + Duration::minutes(2)),
            Ok(ProjectInviteStatus::Emitted)
        );
        assert_eq!(receipt.scope(), draft.scope());
        assert_eq!(receipt.invitee_identity_digest(), digest(RAW_EMAIL));
        assert_eq!(receipt.approval_id(), approved.approval().approval_id());

        let session = invitee_session(expires_at);
        let binding = consumer
            .accept_project_invite(
                &mut service,
                &receipt,
                &session,
                now() + Duration::minutes(3),
            )
            .expect("accept invite");
        assert_eq!(binding.scope(), draft.scope());
        assert_eq!(binding.account_id(), &AccountId::from("account-invitee"));
        assert_eq!(binding.identity_digest(), digest(RAW_EMAIL));
        assert_eq!(binding.session_revision(), session.revision());
        consumer
            .validate_project_membership(&mut service, &binding, now() + Duration::minutes(3))
            .expect("validate project binding");
        assert_eq!(
            service.status(&handle, now() + Duration::minutes(3)),
            Ok(ProjectInviteStatus::Accepted)
        );

        let debug_material = format!("{request:?}{draft:?}{receipt:?}{binding:?}{service:?}");
        assert!(!debug_material.contains(RAW_EMAIL));
        assert!(!debug_material.contains("access_token"));
        assert!(!debug_material.contains("refresh_token"));
        let event_material = serde_json::to_string(service.events()).expect("serialize events");
        assert!(!event_material.contains(RAW_EMAIL));
        assert!(!event_material.contains("access_token"));
        assert!(!event_material.contains("refresh_token"));
    }

    #[test]
    fn duplicate_retry_is_exactly_once_and_idempotency_conflicts_fail_closed() {
        let expires_at = now() + Duration::hours(1);
        let mut service = seeded_service(expires_at);
        let request = invite_request(expires_at, "idem-exact-once");
        let handle = service
            .create_draft(request.clone())
            .expect("create first draft");
        assert_eq!(
            service.create_draft(request.clone()).expect("retry draft"),
            handle
        );
        let count_after_draft = service.event_count();

        let approval = approval();
        let approved = service
            .approve_draft(&handle, approval.clone())
            .expect("approve first time");
        assert_eq!(
            service
                .approve_draft(&handle, approval)
                .expect("retry approval"),
            approved
        );
        let receipt = service
            .emit_invite_receipt(&handle, now() + Duration::minutes(2))
            .expect("emit first receipt");
        assert_eq!(
            service.emit_invite_receipt(&handle, now() + Duration::minutes(2)),
            Ok(receipt.clone())
        );
        let session = invitee_session(expires_at);
        let binding = service
            .accept_invite(&receipt, &session, now() + Duration::minutes(3))
            .expect("accept first time");
        assert_eq!(
            service
                .accept_invite(&receipt, &session, now() + Duration::minutes(3))
                .expect("retry acceptance"),
            binding
        );
        assert_eq!(service.event_count(), count_after_draft + 3);

        let conflicting_request = DraftInviteRequest::new(
            ProjectInviteId::from("invite-conflict"),
            project_scope(),
            MemberId::from("member-inviter"),
            4,
            digest(RAW_EMAIL),
            ProjectInviteRole::Viewer,
            BTreeSet::from([ProjectInviteScope::Read]),
            now(),
            expires_at,
            "idem-exact-once",
        )
        .expect("valid conflicting intent");
        assert_eq!(
            service.create_draft(conflicting_request),
            Err(ProjectInviteError::IdempotencyConflict)
        );
    }

    #[test]
    fn restart_replay_rehydrates_the_same_invite_and_receipt() {
        let expires_at = now() + Duration::hours(1);
        let mut original = seeded_service(expires_at);
        let request = invite_request(expires_at, "idem-restart");
        let handle = original
            .create_draft(request.clone())
            .expect("create draft");
        original
            .approve_draft(&handle, approval())
            .expect("approve draft");
        let receipt = original
            .emit_invite_receipt(&handle, now() + Duration::minutes(2))
            .expect("emit receipt");
        let binding = original
            .accept_invite(
                &receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            )
            .expect("accept invite");
        let events = original.events().to_vec();

        let mut reopened = seeded_service(expires_at);
        for event in &events {
            reopened
                .replay_event(event.clone())
                .expect("replay persisted event");
        }
        assert_eq!(reopened.event_count(), events.len());
        assert_eq!(reopened.create_draft(request), Ok(handle.clone()));
        assert_eq!(
            reopened
                .approve_draft(&handle, approval())
                .expect("replayed approval")
                .draft(),
            &reopened.draft(&handle).expect("replayed draft")
        );
        assert_eq!(
            reopened
                .emit_invite_receipt(&handle, now() + Duration::minutes(4))
                .expect("replayed receipt"),
            receipt
        );
        assert_eq!(
            reopened
                .accept_invite(
                    &receipt,
                    &invitee_session(expires_at),
                    now() + Duration::minutes(4),
                )
                .expect("replayed binding"),
            binding
        );
        for event in events {
            reopened
                .replay_event(event)
                .expect("duplicate persisted event is harmless");
        }
        assert_eq!(reopened.event_count(), 4);
    }

    #[test]
    fn role_change_revoke_expiry_and_cross_team_are_fenced() {
        let expires_at = now() + Duration::hours(1);
        let mut role_changed = seeded_service(expires_at);
        let handle = role_changed
            .create_draft(invite_request(expires_at, "idem-role-change"))
            .expect("create role-change draft");
        role_changed
            .change_team_membership_role(
                &MemberId::from("member-inviter"),
                ProjectInviteRole::Viewer,
            )
            .expect("change inviter role");
        assert_eq!(
            role_changed.approve_draft(&handle, approval()),
            Err(ProjectInviteError::StaleMembership)
        );

        let mut revoked = seeded_service(expires_at);
        let revoked_handle = revoked
            .create_draft(invite_request(expires_at, "idem-revoked"))
            .expect("create revoked draft");
        revoked
            .revoke_team_membership(&MemberId::from("member-inviter"))
            .expect("revoke inviter membership");
        assert_eq!(
            revoked.approve_draft(&revoked_handle, approval()),
            Err(ProjectInviteError::MembershipRevoked)
        );

        let short_expiry = now() + Duration::minutes(5);
        let mut expired = seeded_service(now() + Duration::hours(1));
        let expired_handle = expired
            .create_draft(invite_request(short_expiry, "idem-expired"))
            .expect("create expiring draft");
        expired
            .approve_draft(&expired_handle, approval())
            .expect("approve before expiry");
        assert_eq!(
            expired.emit_invite_receipt(&expired_handle, short_expiry),
            Err(ProjectInviteError::InviteExpired)
        );
        assert_eq!(
            expired.status(&expired_handle, short_expiry),
            Ok(ProjectInviteStatus::Expired)
        );

        let mut cross_team = seeded_service(expires_at);
        let foreign_session = ProjectInviteSession::new(
            IdentitySessionId::from("session-foreign-team"),
            TenantId::from("tenant-growth"),
            TeamId::from("team-other"),
            AccountId::from("account-invitee"),
            digest(RAW_EMAIL),
            now() - Duration::minutes(5),
            expires_at,
            1,
        )
        .expect("valid foreign session projection");
        cross_team
            .register_session(foreign_session.clone())
            .expect("register foreign session projection");
        let (_handle, receipt) = emitted_invite(&mut cross_team, expires_at, "idem-cross-team");
        assert_eq!(
            cross_team.accept_invite(&receipt, &foreign_session, now() + Duration::minutes(3)),
            Err(ProjectInviteError::CrossTeamScope)
        );
        let foreign_scope = ProjectInviteProjectScope::new(
            TenantId::from("tenant-growth"),
            TeamId::from("team-other"),
            ProjectId::from("project-alpha"),
            3,
        )
        .expect("valid foreign project scope");
        let foreign_request = DraftInviteRequest::new(
            ProjectInviteId::from("invite-foreign-scope"),
            foreign_scope,
            MemberId::from("member-inviter"),
            4,
            digest(RAW_EMAIL),
            ProjectInviteRole::Member,
            invite_scopes(),
            now(),
            expires_at,
            "idem-foreign-scope",
        )
        .expect("valid foreign-scope request");
        assert_eq!(
            cross_team.create_draft(foreign_request),
            Err(ProjectInviteError::CrossTeamScope)
        );
    }

    #[test]
    fn binding_role_revoke_and_session_revocation_invalidate_old_material() {
        let expires_at = now() + Duration::hours(1);
        let mut service = seeded_service(expires_at);
        let (_, receipt) = emitted_invite(&mut service, expires_at, "idem-binding-role");
        let session = invitee_session(expires_at);
        let binding = service
            .accept_invite(&receipt, &session, now() + Duration::minutes(3))
            .expect("accept invite");
        service
            .validate_binding(&binding, now() + Duration::minutes(3))
            .expect("binding initially valid");

        let changed = service
            .change_binding_role(binding.binding_id(), ProjectInviteRole::Admin)
            .expect("change project role");
        assert_eq!(
            service.validate_binding(&binding, now() + Duration::minutes(3)),
            Err(ProjectInviteError::BindingStale)
        );
        service
            .validate_binding(&changed, now() + Duration::minutes(3))
            .expect("changed binding valid");
        let revoked = service
            .revoke_binding(changed.binding_id())
            .expect("revoke project binding");
        assert_eq!(
            service.validate_binding(&revoked, now() + Duration::minutes(3)),
            Err(ProjectInviteError::BindingRevoked)
        );

        let mut session_revoked_service = seeded_service(expires_at);
        let (_, session_receipt) = emitted_invite(
            &mut session_revoked_service,
            expires_at,
            "idem-session-revoke",
        );
        let session = invitee_session(expires_at);
        let session_binding = session_revoked_service
            .accept_invite(&session_receipt, &session, now() + Duration::minutes(3))
            .expect("accept session-bound invite");
        session_revoked_service
            .revoke_session(session.session_id())
            .expect("revoke identity session");
        assert_eq!(
            session_revoked_service
                .validate_binding(&session_binding, now() + Duration::minutes(3)),
            Err(ProjectInviteError::SessionRevoked)
        );
    }

    #[test]
    fn expired_session_and_raw_invitee_input_fail_closed() {
        let expires_at = now() + Duration::hours(1);
        let raw_request = DraftInviteRequest::new(
            ProjectInviteId::from("invite-raw-email"),
            project_scope(),
            MemberId::from("member-inviter"),
            4,
            RAW_EMAIL,
            ProjectInviteRole::Member,
            invite_scopes(),
            now(),
            expires_at,
            "idem-raw-email",
        );
        assert_eq!(raw_request, Err(ProjectInviteError::InvalidDraftInvite));

        let session_expiry = now() + Duration::minutes(5);
        let mut service = seeded_service(session_expiry);
        let (_, receipt) = emitted_invite(&mut service, expires_at, "idem-session-expiry");
        assert_eq!(
            service.accept_invite(&receipt, &invitee_session(session_expiry), session_expiry,),
            Err(ProjectInviteError::SessionExpired)
        );
    }

    #[test]
    fn consumer_accept_and_decline_return_durable_decision_receipts() {
        let expires_at = now() + Duration::hours(1);
        let mut accepting_service = seeded_service(expires_at);
        let (_, accepting_receipt) =
            emitted_invite(&mut accepting_service, expires_at, "idem-consumer-accept");
        let mut consumer = TestConsumer;
        let acceptance = consumer
            .accept_project_invite_with_receipt(
                &mut accepting_service,
                &accepting_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            )
            .expect("consumer acceptance");
        assert_eq!(
            acceptance.receipt().decision(),
            ProjectInviteDecision::Accepted
        );
        assert_eq!(
            acceptance.receipt().invite_revision(),
            accepting_receipt.invite_revision()
        );
        assert_eq!(
            acceptance.receipt().invitee_identity_provider_digest(),
            invitee_session(expires_at).identity_provider_digest()
        );
        assert_eq!(
            acceptance.binding().identity_provider_digest(),
            acceptance.receipt().invitee_identity_provider_digest()
        );
        assert_eq!(
            accepting_service.status(
                &accepting_service
                    .handles
                    .iter()
                    .find_map(|(handle, invite_id)| {
                        (invite_id == acceptance.binding().invite_id()).then_some(handle)
                    })
                    .cloned()
                    .expect("acceptance handle"),
                now() + Duration::minutes(3),
            ),
            Ok(ProjectInviteStatus::Accepted)
        );

        let mut declining_service = seeded_service(expires_at);
        let (decline_handle, decline_receipt) =
            emitted_invite(&mut declining_service, expires_at, "idem-consumer-decline");
        let decline = consumer
            .decline_project_invite(
                &mut declining_service,
                &decline_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            )
            .expect("consumer decline");
        assert_eq!(decline.decision(), ProjectInviteDecision::Declined);
        assert_eq!(
            declining_service.status(&decline_handle, now() + Duration::minutes(3)),
            Ok(ProjectInviteStatus::Declined)
        );
        assert_eq!(
            consumer
                .decline_project_invite(
                    &mut declining_service,
                    &decline_receipt,
                    &invitee_session(expires_at),
                    now() + Duration::minutes(3),
                )
                .expect("idempotent consumer decline"),
            decline
        );
        assert_eq!(
            declining_service.accept_invite(
                &decline_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            ),
            Err(ProjectInviteError::DecisionConflict)
        );
    }

    #[test]
    fn owner_revoke_is_exactly_once_and_fences_pending_and_accepted_invites() {
        let expires_at = now() + Duration::hours(1);
        let mut pending = seeded_owner_service(expires_at);
        let (pending_handle, pending_receipt) =
            emitted_invite(&mut pending, expires_at, "idem-owner-revoke-pending");
        let pending_event_count = pending.event_count();
        let pending_request = revocation_request(
            pending_receipt.invite_revision(),
            now() + Duration::minutes(3),
            "idem-owner-revoke-pending",
        );
        let pending_revocation = pending
            .revoke_invite(pending_request.clone())
            .expect("owner revokes pending invite");
        assert_eq!(pending_revocation.binding_id(), None);
        assert_eq!(pending.event_count(), pending_event_count + 1);
        assert_eq!(
            pending
                .revoke_invite(pending_request)
                .expect("idempotent owner revoke"),
            pending_revocation
        );
        assert_eq!(
            pending.status(&pending_handle, now() + Duration::minutes(3)),
            Ok(ProjectInviteStatus::Revoked)
        );
        assert_eq!(
            pending.accept_invite(
                &pending_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            ),
            Err(ProjectInviteError::InviteRevoked)
        );

        let mut accepted = seeded_owner_service(expires_at);
        let (_, accepted_receipt) =
            emitted_invite(&mut accepted, expires_at, "idem-owner-revoke-accepted");
        let acceptance = accepted
            .accept_invite_with_receipt(
                &accepted_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            )
            .expect("accept before owner revoke");
        let revocation = accepted
            .revoke_invite(revocation_request(
                accepted_receipt.invite_revision(),
                now() + Duration::minutes(4),
                "idem-owner-revoke-accepted",
            ))
            .expect("owner revokes accepted binding");
        assert_eq!(
            revocation.binding_id(),
            Some(acceptance.binding().binding_id())
        );
        assert_eq!(
            revocation.membership_revision(),
            Some(acceptance.binding().membership_revision() + 1)
        );
        assert_eq!(
            accepted.validate_binding(&acceptance.binding().clone(), now() + Duration::minutes(4)),
            Err(ProjectInviteError::BindingRevoked)
        );
    }

    #[test]
    fn owner_authority_expiry_and_cross_team_fences_fail_closed() {
        let expires_at = now() + Duration::hours(1);
        let mut unauthorized = seeded_owner_service(expires_at);
        let (_, receipt) = emitted_invite(&mut unauthorized, expires_at, "idem-owner-auth");
        let mut admin_request = revocation_request(
            receipt.invite_revision(),
            now() + Duration::minutes(3),
            "idem-owner-auth",
        );
        admin_request.owner_membership_id = MemberId::from("member-inviter");
        admin_request.owner_membership_revision = 4;
        admin_request.owner_session_id = IdentitySessionId::from("session-invitee");
        admin_request.owner_session_revision = 1;
        assert_eq!(
            unauthorized.revoke_invite(admin_request),
            Err(ProjectInviteError::UnauthorizedOwner)
        );

        let mut stale_owner = seeded_owner_service(expires_at);
        let (_, stale_receipt) =
            emitted_invite(&mut stale_owner, expires_at, "idem-owner-stale-membership");
        stale_owner
            .change_team_membership_role(&MemberId::from("member-owner"), ProjectInviteRole::Admin)
            .expect("owner role changes");
        assert_eq!(
            stale_owner.revoke_invite(revocation_request(
                stale_receipt.invite_revision(),
                now() + Duration::minutes(3),
                "idem-owner-stale-membership",
            )),
            Err(ProjectInviteError::StaleMembership)
        );

        let mut cross_team = seeded_owner_service(expires_at);
        let (_, cross_receipt) =
            emitted_invite(&mut cross_team, expires_at, "idem-owner-cross-team");
        let mut cross_request = revocation_request(
            cross_receipt.invite_revision(),
            now() + Duration::minutes(3),
            "idem-owner-cross-team",
        );
        cross_request.scope = ProjectInviteProjectScope::new(
            TenantId::from("tenant-growth"),
            TeamId::from("team-other"),
            ProjectId::from("project-alpha"),
            3,
        )
        .expect("foreign revocation scope");
        assert_eq!(
            cross_team.revoke_invite(cross_request),
            Err(ProjectInviteError::CrossTeamScope)
        );

        let short_expiry = now() + Duration::minutes(5);
        let mut expired = seeded_owner_service(short_expiry);
        let (_, expired_receipt) = emitted_invite(&mut expired, short_expiry, "idem-owner-expired");
        assert_eq!(
            expired.revoke_invite(revocation_request(
                expired_receipt.invite_revision(),
                short_expiry,
                "idem-owner-expired",
            )),
            Err(ProjectInviteError::InviteExpired)
        );
    }

    #[test]
    fn accept_decline_and_revoke_events_replay_exactly_once_after_restart() {
        let expires_at = now() + Duration::hours(1);
        let mut original = seeded_owner_service(expires_at);
        let (_, receipt) = emitted_invite(&mut original, expires_at, "idem-replay-accept");
        let acceptance = original
            .accept_invite_with_receipt(
                &receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            )
            .expect("accept before restart");
        let revocation_request = revocation_request(
            receipt.invite_revision(),
            now() + Duration::minutes(4),
            "idem-replay-revoke",
        );
        let revocation = original
            .revoke_invite(revocation_request.clone())
            .expect("revoke before restart");
        let events = original.events().to_vec();

        let mut reopened = seeded_owner_service(expires_at);
        for event in &events {
            reopened
                .replay_event(event.clone())
                .expect("replay invite event");
        }
        assert_eq!(reopened.event_count(), events.len());
        assert_eq!(
            reopened.accept_invite_with_receipt(
                &receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(4),
            ),
            Err(ProjectInviteError::InviteRevoked)
        );
        assert_eq!(
            reopened
                .revoke_invite(revocation_request)
                .expect("idempotent replayed revoke"),
            revocation
        );
        for event in events {
            reopened
                .replay_event(event)
                .expect("duplicate invite event replay");
        }
        assert_eq!(reopened.event_count(), 5);
        assert_eq!(
            acceptance.receipt().decision(),
            ProjectInviteDecision::Accepted
        );
    }

    #[test]
    fn invite_revision_and_identity_provider_digest_are_exactly_bound() {
        let expires_at = now() + Duration::hours(1);
        let identity_digest = digest(RAW_EMAIL);
        let provider_digest = digest("keycloak-issuer-growth");
        let session = ProjectInviteSession::new_with_identity_provider_digest(
            IdentitySessionId::from("session-versioned-invitee"),
            TenantId::from("tenant-growth"),
            TeamId::from("team-growth"),
            AccountId::from("account-invitee"),
            identity_digest.clone(),
            provider_digest.clone(),
            now() - Duration::minutes(5),
            expires_at,
            11,
        )
        .expect("versioned invitee session");
        let request = DraftInviteRequest::new_with_revision_and_provider_digest(
            ProjectInviteId::from("invite-versioned"),
            9,
            project_scope(),
            MemberId::from("member-inviter"),
            4,
            identity_digest,
            provider_digest.clone(),
            ProjectInviteRole::Member,
            invite_scopes(),
            now(),
            expires_at,
            "idem-versioned-invite",
        )
        .expect("versioned invite request");
        let versioned_approval = InviteApproval::new_with_invite_revision(
            ApprovalId::from("approval-versioned"),
            ProjectInviteId::from("invite-versioned"),
            9,
            ActorId::from("actor-inviter"),
            MemberId::from("member-inviter"),
            4,
            digest("versioned-approval"),
            now() + Duration::minutes(1),
        )
        .expect("versioned approval");

        let mut service = ProjectInvitePluginService::new();
        service
            .register_project_scope(project_scope())
            .expect("register project");
        service
            .register_team_membership(inviter_membership())
            .expect("register inviter");
        service
            .register_session(session.clone())
            .expect("register versioned session");
        let handle = service
            .create_draft(request)
            .expect("create versioned invite");
        let draft = service.draft(&handle).expect("read versioned draft");
        assert_eq!(draft.invite_revision(), 9);
        assert_eq!(draft.invitee_identity_provider_digest(), provider_digest);
        service
            .approve_draft(&handle, versioned_approval)
            .expect("approve versioned invite");
        let receipt = service
            .emit_invite_receipt(&handle, now() + Duration::minutes(2))
            .expect("emit versioned receipt");
        assert_eq!(receipt.invite_revision(), 9);
        assert_eq!(
            receipt.invitee_identity_provider_digest(),
            session.identity_provider_digest()
        );
        let acceptance = service
            .accept_invite_with_receipt(&receipt, &session, now() + Duration::minutes(3))
            .expect("accept versioned invite");
        assert_eq!(acceptance.binding().invite_revision(), 9);
        assert_eq!(acceptance.receipt().session_revision(), 11);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial fixture covers receipt, session, and event tampering"
    )]
    fn tampered_receipts_sessions_and_persisted_events_fail_closed() {
        let expires_at = now() + Duration::hours(1);
        let mut service = seeded_service(expires_at);
        let (_, receipt) = emitted_invite(&mut service, expires_at, "idem-tamper-receipt");
        let mut tampered_receipt = receipt.clone();
        tampered_receipt.invite_revision += 1;
        assert_eq!(
            service.accept_invite(
                &tampered_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            ),
            Err(ProjectInviteError::ReceiptProjectionMismatch)
        );
        let mut tampered_session = invitee_session(expires_at);
        tampered_session.identity_provider_digest = digest("foreign-issuer");
        assert_eq!(
            service.decline_invite(&receipt, &tampered_session, now() + Duration::minutes(3),),
            Err(ProjectInviteError::StaleSession)
        );

        let mut accepted = seeded_service(expires_at);
        let (_, accepted_receipt) = emitted_invite(&mut accepted, expires_at, "idem-tamper-event");
        accepted
            .accept_invite_with_receipt(
                &accepted_receipt,
                &invitee_session(expires_at),
                now() + Duration::minutes(3),
            )
            .expect("accept tamper fixture");
        let events = accepted.events().to_vec();
        let mut reopened = seeded_service(expires_at);
        for event in events.iter().take(3) {
            reopened
                .replay_event(event.clone())
                .expect("replay pre-decision event");
        }
        let tampered_event = events
            .iter()
            .find_map(|event| match event {
                ProjectInviteEvent::InviteDecisionRecorded {
                    event_id,
                    receipt,
                    binding,
                } => {
                    let mut tampered = receipt.clone();
                    tampered.provider_digest = digest("tampered-decision-provider");
                    Some(ProjectInviteEvent::InviteDecisionRecorded {
                        event_id: event_id.clone(),
                        receipt: tampered,
                        binding: binding.clone(),
                    })
                }
                _ => None,
            })
            .expect("decision event");
        assert_eq!(
            reopened.replay_event(tampered_event),
            Err(ProjectInviteError::DecisionBindingMismatch)
        );

        let mut revoked = seeded_owner_service(expires_at);
        let (_, revoked_receipt) =
            emitted_invite(&mut revoked, expires_at, "idem-tamper-revocation");
        let revocation = revoked
            .revoke_invite(revocation_request(
                revoked_receipt.invite_revision(),
                now() + Duration::minutes(3),
                "idem-tamper-revocation",
            ))
            .expect("create revocation event");
        let revoked_events = revoked.events().to_vec();
        let mut revoked_reopened = seeded_owner_service(expires_at);
        for event in revoked_events.iter().take(3) {
            revoked_reopened
                .replay_event(event.clone())
                .expect("replay pre-revocation event");
        }
        let tampered_revocation = revoked_events
            .iter()
            .find_map(|event| match event {
                ProjectInviteEvent::InviteRevoked {
                    event_id,
                    receipt,
                    binding,
                } => {
                    let mut tampered = receipt.clone();
                    tampered.provider_digest = digest("tampered-revocation-provider");
                    Some(ProjectInviteEvent::InviteRevoked {
                        event_id: event_id.clone(),
                        receipt: tampered,
                        binding: binding.clone(),
                    })
                }
                _ => None,
            })
            .expect("revocation event");
        assert_eq!(
            revoked_reopened.replay_event(tampered_revocation),
            Err(ProjectInviteError::RevocationBindingMismatch)
        );
        assert_eq!(
            revocation.invite_revision(),
            revoked_receipt.invite_revision()
        );
    }
}

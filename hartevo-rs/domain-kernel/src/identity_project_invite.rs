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
    AccountId, ActorId, ApprovalId, IdentitySessionId, MemberId, ProjectId, ProjectInviteEventId,
    ProjectInviteId, ProjectInviteReceiptId, ProjectMembershipBindingId, TeamId, TenantId,
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
    Expired,
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
        let session = Self {
            session_id,
            tenant_id,
            team_id,
            account_id,
            identity_digest: identity_digest.into(),
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
    scope: ProjectInviteProjectScope,
    inviter_membership_id: MemberId,
    inviter_membership_revision: u64,
    invitee_identity_digest: String,
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
        let request = Self {
            invite_id,
            scope,
            inviter_membership_id,
            inviter_membership_revision,
            invitee_identity_digest: invitee_identity_digest.into(),
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
            &self.scope,
            &self.inviter_membership_id,
            self.inviter_membership_revision,
            &self.invitee_identity_digest,
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
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || !is_sha256(&self.invitee_identity_digest)
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
            .field("scope", &self.scope)
            .field("inviter_membership_id", &self.inviter_membership_id)
            .field(
                "inviter_membership_revision",
                &self.inviter_membership_revision,
            )
            .field("invitee_identity_digest", &self.invitee_identity_digest)
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
    scope: ProjectInviteProjectScope,
    inviter_membership_id: MemberId,
    inviter_account_id: AccountId,
    inviter_membership_revision: u64,
    invitee_identity_digest: String,
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
            scope: request.scope.clone(),
            inviter_membership_id: request.inviter_membership_id.clone(),
            inviter_account_id,
            inviter_membership_revision: request.inviter_membership_revision,
            invitee_identity_digest: request.invitee_identity_digest.clone(),
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
            || self.inviter_membership_id.as_str().trim().is_empty()
            || self.inviter_account_id.as_str().trim().is_empty()
            || self.inviter_membership_revision == 0
            || !is_sha256(&self.invitee_identity_digest)
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
        let approval = Self {
            approval_id,
            invite_id,
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
    scope: ProjectInviteProjectScope,
    invitee_identity_digest: String,
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
            scope: draft.scope.clone(),
            invitee_identity_digest: draft.invitee_identity_digest.clone(),
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

    pub fn scope(&self) -> &ProjectInviteProjectScope {
        &self.scope
    }

    pub fn invitee_identity_digest(&self) -> &str {
        &self.invitee_identity_digest
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
            || !is_sha256(&self.invitee_identity_digest)
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
pub struct ProjectMembershipBinding {
    binding_id: ProjectMembershipBindingId,
    invite_id: ProjectInviteId,
    receipt_id: ProjectInviteReceiptId,
    member_id: MemberId,
    scope: ProjectInviteProjectScope,
    account_id: AccountId,
    identity_digest: String,
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
            receipt_id: receipt.receipt_id.clone(),
            member_id: MemberId::new(),
            scope: receipt.scope.clone(),
            account_id: session.account_id.clone(),
            identity_digest: session.identity_digest.clone(),
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
            || self.receipt_id.as_str().trim().is_empty()
            || self.member_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || !is_sha256(&self.identity_digest)
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
    binding: Option<ProjectMembershipBinding>,
}

impl InviteProjection {
    fn status(&self, now: DateTime<Utc>) -> ProjectInviteStatus {
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
        receipt.validate()?;
        let projection = self
            .invites
            .get(receipt.invite_id())
            .cloned()
            .ok_or(ProjectInviteError::ReceiptNotFound)?;
        if projection.receipt.as_ref() != Some(receipt) {
            return Err(ProjectInviteError::ReceiptProjectionMismatch);
        }
        if let Some(binding_id) = self.binding_by_invite.get(receipt.invite_id()) {
            let binding = self
                .bindings
                .get(binding_id)
                .cloned()
                .ok_or(ProjectInviteError::BindingNotFound)?;
            self.validate_binding(&binding, now)?;
            self.validate_session_for_receipt(receipt, session, now)?;
            if binding.session_id() != session.session_id()
                || binding.account_id() != session.account_id()
            {
                return Err(ProjectInviteError::AcceptanceConflict);
            }
            return Ok(binding);
        }
        if now >= receipt.expires_at() {
            return Err(ProjectInviteError::InviteExpired);
        }
        self.validate_inviter_membership(&projection.draft, now)?;
        self.validate_session_for_receipt(receipt, session, now)?;
        let binding =
            ProjectMembershipBinding::from_accept(receipt, &projection.draft, session, now)?;
        self.record_event(ProjectInviteEvent::MembershipBindingCreated {
            event_id: ProjectInviteEventId::new(),
            binding: binding.clone(),
        })?;
        Ok(binding)
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
        {
            return Err(ProjectInviteError::CrossTeamScope);
        }
        Ok(())
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
            || session.tenant_id() != binding.scope.tenant_id()
            || session.team_id() != binding.scope.team_id()
        {
            return Err(ProjectInviteError::StaleSession);
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
                projection.receipt = Some(receipt.clone());
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
                    || binding.member_id != current.member_id
                    || binding.account_id != current.account_id
                    || binding.scope != current.scope
                    || binding.session_id != current.session_id
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
    #[error("team role cannot invite or approve")]
    InsufficientRole,
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
    scope: &ProjectInviteProjectScope,
    inviter_membership_id: &MemberId,
    inviter_membership_revision: u64,
    invitee_identity_digest: &str,
    role: ProjectInviteRole,
    scopes: &BTreeSet<ProjectInviteScope>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> String {
    let mut fields = vec![
        b"hartevo.project-invite.intent.v1".to_vec(),
        invite_id.as_str().as_bytes().to_vec(),
        scope.tenant_id.as_str().as_bytes().to_vec(),
        scope.team_id.as_str().as_bytes().to_vec(),
        scope.project_id.as_str().as_bytes().to_vec(),
        scope.project_revision.to_be_bytes().to_vec(),
        inviter_membership_id.as_str().as_bytes().to_vec(),
        inviter_membership_revision.to_be_bytes().to_vec(),
        invitee_identity_digest.as_bytes().to_vec(),
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
}

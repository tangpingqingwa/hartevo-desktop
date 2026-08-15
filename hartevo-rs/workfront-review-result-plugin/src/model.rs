//! Opaque identifiers, exact scope, redacted projections, and bounded state.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Result, WorkfrontReviewResultError};
use crate::{
    MAX_IDENTIFIER_BYTES, MAX_REVIEWER_ROLE_DIGESTS, PLUGIN_VERSION, SERVICE_ID, sha256_hex,
};

/// A validated lowercase SHA-256 digest used for evidence and binding fences.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(String);

impl Digest {
    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self(sha256_hex(value.as_ref().as_bytes()))
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(value)))
    }

    pub fn from_parts(label: &str, parts: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(label.as_bytes());
        bytes.push(0);
        for (key, value) in parts {
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WorkfrontReviewResultError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if self.0.len() != 64
            || !self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WorkfrontReviewResultError::InvalidDigest);
        }
        Ok(())
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn valid_text(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(WorkfrontReviewResultError::InvalidText { field });
    }
    Ok(())
}

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                valid_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(&self.0)
            }

            pub fn validate(&self) -> Result<()> {
                valid_text(&self.0, $field)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.digest().serialize(serializer)
            }
        }
    };
}

opaque_id!(TenantId, "tenant");
opaque_id!(ProjectId, "project");
opaque_id!(TaskId, "task");
opaque_id!(DocumentId, "document");
opaque_id!(ReviewId, "review");
opaque_id!(ApprovalId, "approval");
opaque_id!(AssigneeId, "assignee");
opaque_id!(MissionId, "mission");
opaque_id!(HostProjectId, "host project");
opaque_id!(WorkProductId, "work product");

/// A positive revision fence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(WorkfrontReviewResultError::InvalidRevision);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A host Mission identity bound to one revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    id_digest: Digest,
    revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = MissionId::new(id)?;
        Ok(Self {
            id_digest: id.digest(),
            revision: Revision::new(revision)?,
        })
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-mission-identity/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

/// A host Project identity, distinct from the Workfront project in scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    id_digest: Digest,
    revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = HostProjectId::new(id)?;
        Ok(Self {
            id_digest: id.digest(),
            revision: Revision::new(revision)?,
        })
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-host-project-identity/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

/// A host Work Product identity, without content or bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    id_digest: Digest,
    revision: Revision,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = WorkProductId::new(id)?;
        Ok(Self {
            id_digest: id.digest(),
            revision: Revision::new(revision)?,
        })
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-work-product-identity/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

/// The only time interval within which evidence may be observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        if end <= start || end - start > Duration::days(366) {
            return Err(WorkfrontReviewResultError::InvalidTimeWindow);
        }
        Ok(Self { start, end })
    }

    pub const fn start(&self) -> DateTime<Utc> {
        self.start
    }

    pub const fn end(&self) -> DateTime<Utc> {
        self.end
    }

    pub fn contains(&self, observed_at: DateTime<Utc>) -> bool {
        observed_at >= self.start && observed_at <= self.end
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-time-window/v1",
            &[
                ("start", self.start.to_rfc3339()),
                ("end", self.end.to_rfc3339()),
            ],
        )
    }
}

/// Expected provider revisions used as stale-state fences.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionFences {
    pub project: Revision,
    pub task: Revision,
    pub review: Revision,
    pub approval: Revision,
}

impl RevisionFences {
    pub fn new(project: u64, task: u64, review: u64, approval: u64) -> Result<Self> {
        Ok(Self {
            project: Revision::new(project)?,
            task: Revision::new(task)?,
            review: Revision::new(review)?,
            approval: Revision::new(approval)?,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-revision-fences/v1",
            &[
                ("project", self.project.get().to_string()),
                ("task", self.task.get().to_string()),
                ("review", self.review.get().to_string()),
                ("approval", self.approval.get().to_string()),
            ],
        )
    }
}

/// Exact provider plus host scope for a Workfront review result.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkfrontReviewScope {
    tenant: TenantId,
    project: ProjectId,
    task: TaskId,
    document: DocumentId,
    review: ReviewId,
    approval: ApprovalId,
    assignee: AssigneeId,
    time_window: TimeWindow,
    mission: MissionIdentity,
    host_project: ProjectIdentity,
    work_product: WorkProductIdentity,
    revision_fences: RevisionFences,
}

impl fmt::Debug for WorkfrontReviewScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkfrontReviewScope")
            .field("digest", &self.digest())
            .field("tenant_digest", &self.tenant.digest())
            .field("project_digest", &self.project.digest())
            .field("task_digest", &self.task.digest())
            .field("document_digest", &self.document.digest())
            .field("review_digest", &self.review.digest())
            .field("approval_digest", &self.approval.digest())
            .field("assignee_digest", &self.assignee.digest())
            .field("mission", &self.mission)
            .field("host_project", &self.host_project)
            .field("work_product", &self.work_product)
            .field("revision_fences", &self.revision_fences)
            .finish()
    }
}

impl Serialize for WorkfrontReviewScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("WorkfrontReviewScope", 13)?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.serialize_field("tenantDigest", &self.tenant.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("taskDigest", &self.task.digest())?;
        state.serialize_field("documentDigest", &self.document.digest())?;
        state.serialize_field("reviewDigest", &self.review.digest())?;
        state.serialize_field("approvalDigest", &self.approval.digest())?;
        state.serialize_field("assigneeDigest", &self.assignee.digest())?;
        state.serialize_field("timeWindowDigest", &self.time_window.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("projectContextDigest", &self.host_project.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.serialize_field("revisionFences", &self.revision_fences)?;
        state.end()
    }
}

impl WorkfrontReviewScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        project: ProjectId,
        task: TaskId,
        document: DocumentId,
        review: ReviewId,
        approval: ApprovalId,
        assignee: AssigneeId,
        time_window: TimeWindow,
        mission: MissionIdentity,
        host_project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            tenant,
            project,
            task,
            document,
            review,
            approval,
            assignee,
            time_window,
            mission,
            host_project,
            work_product,
            revision_fences: RevisionFences::new(1, 1, 1, 1)?,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_revision_fences(mut self, revision_fences: RevisionFences) -> Result<Self> {
        self.revision_fences = revision_fences;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.tenant.validate()?;
        self.project.validate()?;
        self.task.validate()?;
        self.document.validate()?;
        self.review.validate()?;
        self.approval.validate()?;
        self.assignee.validate()?;
        if self.mission.revision().get() == 0
            || self.host_project.revision().get() == 0
            || self.work_product.revision().get() == 0
        {
            return Err(WorkfrontReviewResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-review-scope/v1",
            &[
                ("tenant", self.tenant.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("task", self.task.digest().as_str().to_owned()),
                ("document", self.document.digest().as_str().to_owned()),
                ("review", self.review.digest().as_str().to_owned()),
                ("approval", self.approval.digest().as_str().to_owned()),
                ("assignee", self.assignee.digest().as_str().to_owned()),
                ("time_window", self.time_window.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "host_project",
                    self.host_project.digest().as_str().to_owned(),
                ),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("fences", self.revision_fences.digest().as_str().to_owned()),
            ],
        )
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn task(&self) -> &TaskId {
        &self.task
    }

    pub fn document(&self) -> &DocumentId {
        &self.document
    }

    pub fn review(&self) -> &ReviewId {
        &self.review
    }

    pub fn approval(&self) -> &ApprovalId {
        &self.approval
    }

    pub fn assignee(&self) -> &AssigneeId {
        &self.assignee
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn host_project(&self) -> &ProjectIdentity {
        &self.host_project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub const fn revision_fences(&self) -> RevisionFences {
        self.revision_fences
    }
}

/// The exact allowlist of reads granted to this Layer-1 seam.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: Vec<String>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn layer_one() -> Self {
        let permissions = crate::LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<Vec<_>>();
        let permission_digest = Self::calculate_digest(&permissions);
        Self {
            permissions,
            permission_digest,
        }
    }

    pub fn new(permissions: Vec<String>) -> Result<Self> {
        let value = Self {
            permission_digest: Self::calculate_digest(&permissions),
            permissions,
        };
        value.validate()?;
        Ok(value)
    }

    fn calculate_digest(permissions: &[String]) -> Digest {
        let mut input = String::from("workfront-permissions/v1\0");
        for (index, permission) in permissions.iter().enumerate() {
            input.push_str(&index.to_string());
            input.push('=');
            input.push_str(permission);
            input.push('\0');
        }
        Digest::from_text(input)
    }

    pub fn validate(&self) -> Result<()> {
        let mut expected = crate::LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<Vec<_>>();
        expected.sort_unstable();
        let mut actual = self.permissions.clone();
        actual.sort_unstable();
        if self.permissions.len() != crate::LAYER1_PERMISSIONS.len()
            || actual != expected
            || self.permission_digest != Self::calculate_digest(&self.permissions)
        {
            return Err(WorkfrontReviewResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

/// A local consent fence. It is data, not kernel Consent authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    id_digest: Digest,
    revision: Revision,
    expires_at: DateTime<Utc>,
    permission_digest: Digest,
}

impl ConsentScope {
    pub fn for_layer_one(
        id: impl AsRef<str>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        valid_text(id.as_ref(), "consent")?;
        Ok(Self {
            id_digest: Digest::from_text(id.as_ref()),
            revision: Revision::new(revision)?,
            expires_at,
            permission_digest: PermissionSnapshot::layer_one().permission_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.permission_digest.validate()?;
        if self.revision.get() == 0 {
            return Err(WorkfrontReviewResultError::InvalidConsent);
        }
        Ok(())
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at >= now
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-consent/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("expires", self.expires_at.to_rfc3339()),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

/// The only credential-shaped value accepted by this crate. The input is
/// hashed into a host reference digest and dropped immediately; no material is
/// retained, serialized, or rendered in Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    scheme: SecretScheme,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScheme {
    OAuthApi,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("scheme", &self.scheme)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("scheme", &self.scheme)?;
        state.serialize_field("opaque", &true)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

impl SecretReference {
    pub fn oauth_api(
        opaque_host_reference: impl AsRef<str>,
        scope: &WorkfrontReviewScope,
        revision: u64,
    ) -> Result<Self> {
        let reference = opaque_host_reference.as_ref();
        valid_text(reference, "secret reference")?;
        let transient = Zeroizing::new(reference.as_bytes().to_vec());
        let reference_digest = Digest::from_bytes(&transient);
        let value = Self {
            scheme: SecretScheme::OAuthApi,
            reference_digest,
            scope_digest: scope.digest(),
            revision: Revision::new(revision)?,
            revoked: false,
        };
        value.validate(scope)?;
        Ok(value)
    }

    pub fn new(
        opaque_host_reference: impl AsRef<str>,
        scope: &WorkfrontReviewScope,
        revision: u64,
    ) -> Result<Self> {
        Self::oauth_api(opaque_host_reference, scope, revision)
    }

    pub fn oauth(
        opaque_host_reference: impl AsRef<str>,
        scope: &WorkfrontReviewScope,
        revision: u64,
    ) -> Result<Self> {
        Self::oauth_api(opaque_host_reference, scope, revision)
    }

    pub fn validate(&self, scope: &WorkfrontReviewScope) -> Result<()> {
        self.reference_digest.validate()?;
        self.scope_digest.validate()?;
        if self.scope_digest != scope.digest() || self.revision.get() == 0 {
            return Err(WorkfrontReviewResultError::InvalidSecretReference);
        }
        Ok(())
    }

    pub const fn scheme(&self) -> SecretScheme {
        self.scheme
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Transport provenance is deliberately honest for every Layer-1 transport.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectStatus {
    Active,
    Complete,
    OnHold,
    Closed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Complete,
    Blocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewStatus {
    Pending,
    InReview,
    Approved,
    Rejected,
    ChangesRequested,
    Expired,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalStatus {
    Pending,
    InReview,
    Approved,
    Rejected,
    ChangesRequested,
    Expired,
    Unknown,
}

/// The bounded Mission-level projection state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Pending,
    InReview,
    Approved,
    Rejected,
    ChangesRequested,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

/// A provider snapshot contains no document bytes, comments, names, or email
/// addresses. Identifiers are retained only inside the provider boundary and
/// become digests in projections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSnapshot {
    pub id: ProjectId,
    pub status: ProjectStatus,
    pub revision: Revision,
    pub updated_at: DateTime<Utc>,
}

impl ProjectSnapshot {
    pub fn new(
        id: ProjectId,
        status: ProjectStatus,
        revision: u64,
        updated_at: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            id,
            status,
            revision: Revision::new(revision)?,
            updated_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-project-read/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("revision", self.revision.get().to_string()),
                ("updated", self.updated_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskSnapshot {
    pub id: TaskId,
    pub status: TaskStatus,
    pub percent_complete: u8,
    pub revision: Revision,
    pub updated_at: DateTime<Utc>,
}

impl TaskSnapshot {
    pub fn new(
        id: TaskId,
        status: TaskStatus,
        percent_complete: u8,
        revision: u64,
        updated_at: DateTime<Utc>,
    ) -> Result<Self> {
        if percent_complete > 100 {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        Ok(Self {
            id,
            status,
            percent_complete,
            revision: Revision::new(revision)?,
            updated_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-task-read/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("percent", self.percent_complete.to_string()),
                ("revision", self.revision.get().to_string()),
                ("updated", self.updated_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewSnapshot {
    pub id: ReviewId,
    pub status: ReviewStatus,
    pub revision: Revision,
    pub submitted_at: Option<DateTime<Utc>>,
    pub decision_at: Option<DateTime<Utc>>,
    pub reviewer_role_digests: Vec<Digest>,
}

impl ReviewSnapshot {
    pub fn new<I, S>(
        id: ReviewId,
        status: ReviewStatus,
        revision: u64,
        submitted_at: Option<DateTime<Utc>>,
        decision_at: Option<DateTime<Utc>>,
        reviewer_roles: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let reviewer_role_digests = reviewer_roles
            .into_iter()
            .map(|role| {
                valid_text(role.as_ref(), "reviewer role")?;
                Ok(Digest::from_text(role.as_ref()))
            })
            .collect::<Result<Vec<_>>>()?;
        if reviewer_role_digests.len() > MAX_REVIEWER_ROLE_DIGESTS {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        Ok(Self {
            id,
            status,
            revision: Revision::new(revision)?,
            submitted_at,
            decision_at,
            reviewer_role_digests,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-review-read/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("revision", self.revision.get().to_string()),
                (
                    "submitted",
                    self.submitted_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "decision",
                    self.decision_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "roles",
                    self.reviewer_role_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSnapshot {
    pub id: ApprovalId,
    pub status: ApprovalStatus,
    pub revision: Revision,
    pub decision_at: Option<DateTime<Utc>>,
    pub reviewer_role_digests: Vec<Digest>,
}

impl ApprovalSnapshot {
    pub fn new<I, S>(
        id: ApprovalId,
        status: ApprovalStatus,
        revision: u64,
        decision_at: Option<DateTime<Utc>>,
        reviewer_roles: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let reviewer_role_digests = reviewer_roles
            .into_iter()
            .map(|role| {
                valid_text(role.as_ref(), "reviewer role")?;
                Ok(Digest::from_text(role.as_ref()))
            })
            .collect::<Result<Vec<_>>>()?;
        if reviewer_role_digests.len() > MAX_REVIEWER_ROLE_DIGESTS {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        Ok(Self {
            id,
            status,
            revision: Revision::new(revision)?,
            decision_at,
            reviewer_role_digests,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-approval-read/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("revision", self.revision.get().to_string()),
                (
                    "decision",
                    self.decision_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "roles",
                    self.reviewer_role_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub status: ProjectStatus,
    pub revision_digest: Digest,
    pub updated_at: DateTime<Utc>,
}

impl ProjectProjection {
    pub fn from_snapshot(snapshot: &ProjectSnapshot) -> Self {
        Self {
            status: snapshot.status,
            revision_digest: Digest::from_parts(
                "workfront-project-revision/v1",
                &[
                    ("id", snapshot.id.digest().as_str().to_owned()),
                    ("revision", snapshot.revision.get().to_string()),
                ],
            ),
            updated_at: snapshot.updated_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskProjection {
    pub status: TaskStatus,
    pub percent_complete: u8,
    pub revision_digest: Digest,
    pub updated_at: DateTime<Utc>,
}

impl TaskProjection {
    pub fn from_snapshot(snapshot: &TaskSnapshot) -> Self {
        Self {
            status: snapshot.status,
            percent_complete: snapshot.percent_complete,
            revision_digest: Digest::from_parts(
                "workfront-task-revision/v1",
                &[
                    ("id", snapshot.id.digest().as_str().to_owned()),
                    ("revision", snapshot.revision.get().to_string()),
                ],
            ),
            updated_at: snapshot.updated_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewProjection {
    pub status: ReviewStatus,
    pub revision_digest: Digest,
    pub submitted_at: Option<DateTime<Utc>>,
    pub decision_at: Option<DateTime<Utc>>,
    pub reviewer_role_digests: Vec<Digest>,
}

impl ReviewProjection {
    pub fn from_snapshot(snapshot: &ReviewSnapshot) -> Self {
        Self {
            status: snapshot.status,
            revision_digest: Digest::from_parts(
                "workfront-review-revision/v1",
                &[
                    ("id", snapshot.id.digest().as_str().to_owned()),
                    ("revision", snapshot.revision.get().to_string()),
                ],
            ),
            submitted_at: snapshot.submitted_at,
            decision_at: snapshot.decision_at,
            reviewer_role_digests: snapshot.reviewer_role_digests.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalProjection {
    pub status: ApprovalStatus,
    pub revision_digest: Digest,
    pub decision_at: Option<DateTime<Utc>>,
    pub reviewer_role_digests: Vec<Digest>,
}

impl ApprovalProjection {
    pub fn from_snapshot(snapshot: &ApprovalSnapshot) -> Self {
        Self {
            status: snapshot.status,
            revision_digest: Digest::from_parts(
                "workfront-approval-revision/v1",
                &[
                    ("id", snapshot.id.digest().as_str().to_owned()),
                    ("revision", snapshot.revision.get().to_string()),
                ],
            ),
            decision_at: snapshot.decision_at,
            reviewer_role_digests: snapshot.reviewer_role_digests.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

pub fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.id_digest().clone(),
        revision: identity.revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

pub fn project_projection(identity: &ProjectIdentity) -> HostProjectProjection {
    HostProjectProjection {
        id_digest: identity.id_digest().clone(),
        revision: identity.revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

pub fn work_product_projection(identity: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: identity.id_digest().clone(),
        revision: identity.revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionTimestamp {
    pub kind: DecisionKind,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Review,
    Approval,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub project_read_digest: Option<Digest>,
    pub task_read_digest: Option<Digest>,
    pub review_read_digest: Option<Digest>,
    pub approval_read_digest: Option<Digest>,
    pub pagination_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn empty(
        scope: &WorkfrontReviewScope,
        contract: Digest,
        provider: Digest,
        consent: Digest,
        permission: Digest,
    ) -> Self {
        let mut value = Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: contract,
            provider_digest: provider,
            permission_digest: permission,
            consent_digest: consent,
            scope_digest: scope.digest(),
            project_read_digest: None,
            task_read_digest: None,
            review_read_digest: None,
            approval_read_digest: None,
            pagination_digest: Digest::from_text("workfront-pagination-empty"),
            evidence_digest: Digest::from_text("unsealed-workfront-evidence"),
        };
        value.evidence_digest = value.calculate_digest(EvidenceState::ProviderUnknown, 0, false);
        value
    }

    pub fn calculate_digest(&self, state: EvidenceState, pages: u16, complete: bool) -> Digest {
        Digest::from_parts(
            "workfront-evidence/v1",
            &[
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "project",
                    self.project_read_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "task",
                    self.task_read_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "review",
                    self.review_read_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "approval",
                    self.approval_read_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("pagination", self.pagination_digest.as_str().to_owned()),
                ("state", format!("{state:?}")),
                ("pages", pages.to_string()),
                ("complete", complete.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub redacted: bool,
    pub raw_path_retained: bool,
    pub authorization_retained: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub cost_digest: Digest,
    pub redacted: bool,
    pub estimate_only: bool,
    pub durable_provider_receipt: bool,
}

/// An opaque cursor that cannot be used outside its bound request.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    cursor_digest: Digest,
    request_digest: Digest,
    scope_digest: Digest,
    page: u16,
}

impl Cursor {
    pub fn new(
        opaque_marker: impl AsRef<str>,
        request_digest: &Digest,
        scope_digest: &Digest,
        page: u16,
    ) -> Result<Self> {
        valid_text(opaque_marker.as_ref(), "cursor")?;
        if page == 0 || page > crate::MAX_PAGES {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        Ok(Self {
            cursor_digest: Digest::from_text(opaque_marker.as_ref()),
            request_digest: request_digest.clone(),
            scope_digest: scope_digest.clone(),
            page,
        })
    }

    pub fn from_digest(
        cursor_digest: Digest,
        request_digest: Digest,
        scope_digest: Digest,
        page: u16,
    ) -> Result<Self> {
        cursor_digest.validate()?;
        request_digest.validate()?;
        scope_digest.validate()?;
        if page == 0 || page > crate::MAX_PAGES {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        Ok(Self {
            cursor_digest,
            request_digest,
            scope_digest,
            page,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page(&self) -> u16 {
        self.page
    }
}

/// Used by consumers to prove that no proposal becomes an adoption effect.
pub const fn is_review_only() -> bool {
    true
}

/// Return the public service identity without exposing a provider credential.
pub fn service_id() -> &'static str {
    SERVICE_ID
}

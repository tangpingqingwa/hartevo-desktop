use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;

use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::CircleCiPipelineResultError;

pub const MAX_PAGE_SIZE: usize = 50;
pub const MAX_PAGES: usize = 16;
pub const MAX_WORKFLOWS: usize = 64;
pub const MAX_JOBS: usize = 256;
pub const MAX_APPROVALS: usize = 128;
pub const MAX_ARTIFACT_METADATA: usize = 256;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_METADATA_BYTES: usize = 512;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;

pub type Digest = String;

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing into String cannot fail");
    }
    output
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    sha256_digest(&bytes)
}

pub fn digest_parts<I, S>(parts: I) -> Digest
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut bytes = Vec::new();
    for part in parts {
        let part = part.as_ref();
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    sha256_digest(&bytes)
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), CircleCiPipelineResultError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(CircleCiPipelineResultError::InvalidDigest { field })
    }
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), CircleCiPipelineResultError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(CircleCiPipelineResultError::InvalidInput {
            field,
            reason: format!("must be non-empty, bounded to {max_bytes} bytes, and content-safe"),
        });
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), CircleCiPipelineResultError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:-~".contains(&byte))
    {
        return Err(CircleCiPipelineResultError::InvalidInput {
            field,
            reason: String::from("must contain only identifier characters"),
        });
    }
    Ok(())
}

fn validate_slug(value: &str, field: &'static str) -> Result<(), CircleCiPipelineResultError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(CircleCiPipelineResultError::InvalidInput {
            field,
            reason: String::from("must contain only slug characters"),
        });
    }
    Ok(())
}

fn redacted(value: &str) -> String {
    format!("sha256:{}", &sha256_digest(value.as_bytes())[..16])
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CircleCiPipelineResultError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                sha256_digest(self.0.as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple($field)
                    .field(&redacted(&self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identifier_type!(CircleCiOrganization, "organization");
identifier_type!(CircleCiPipelineId, "pipeline id");
identifier_type!(CircleCiWorkflowId, "workflow id");
identifier_type!(CircleCiAttemptId, "attempt id");
identifier_type!(MissionId, "mission id");
identifier_type!(ProjectId, "project id");
identifier_type!(WorkProductId, "work product id");

pub type PipelineId = CircleCiPipelineId;
pub type WorkflowId = CircleCiWorkflowId;
pub type AttemptId = CircleCiAttemptId;

/// Exact CircleCI HTTPS origin. Paths, query strings, fragments, credentials,
/// and whitespace are rejected so a registration cannot silently change host.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CircleCiHost(String);

impl CircleCiHost {
    pub fn new(value: impl Into<String>) -> Result<Self, CircleCiPipelineResultError> {
        let mut value = value.into();
        while value.ends_with('/') {
            value.pop();
        }
        let Some(authority) = value.strip_prefix("https://") else {
            return Err(CircleCiPipelineResultError::InvalidInput {
                field: "host",
                reason: String::from("must be an HTTPS origin"),
            });
        };
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
        {
            return Err(CircleCiPipelineResultError::InvalidInput {
                field: "host",
                reason: String::from("must be an exact HTTPS origin without path or credentials"),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

impl fmt::Debug for CircleCiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CircleCiHost")
            .field(&redacted(&self.0))
            .finish()
    }
}

impl fmt::Display for CircleCiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A lowercase hexadecimal VCS revision. CircleCI commonly reports a 40-byte
/// SHA-1, while allowing a 64-byte SHA-256 keeps the boundary future-proof.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, CircleCiPipelineResultError> {
        let value = value.into();
        if !(40..=64).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(CircleCiPipelineResultError::InvalidInput {
                field: "commit sha",
                reason: String::from("must be a lowercase hexadecimal SHA of 40 to 64 bytes"),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

impl fmt::Debug for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CommitSha")
            .field(&redacted(&self.0))
            .finish()
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiCredentialKind {
    Token,
    Oidc,
}

/// Opaque host-owned CircleCI token/OIDC identity. The supplied reference id
/// is hashed immediately; no token, OIDC assertion, or raw reference is ever
/// retained, serialized, formatted, or included in a digest.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: u64,
    credential_kind: CircleCiCredentialKind,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope_digest: impl Into<String>,
        credential_revision: u64,
        credential_kind: CircleCiCredentialKind,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let scope_digest = scope_digest.into();
        validate_text(
            reference_id.as_ref(),
            "secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_digest(&scope_digest, "secret scope digest")?;
        if credential_revision == 0 {
            return Err(CircleCiPipelineResultError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: digest_parts(["circleci-secret-reference", reference_id.as_ref()]),
            scope_digest,
            credential_revision,
            credential_kind,
            revoked: false,
        })
    }

    pub fn token(
        reference_id: impl AsRef<str>,
        scope_digest: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, CircleCiPipelineResultError> {
        Self::new(
            reference_id,
            scope_digest,
            credential_revision,
            CircleCiCredentialKind::Token,
        )
    }

    pub fn oidc(
        reference_id: impl AsRef<str>,
        scope_digest: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, CircleCiPipelineResultError> {
        Self::new(
            reference_id,
            scope_digest,
            credential_revision,
            CircleCiCredentialKind::Oidc,
        )
    }

    pub fn reference_digest(&self) -> &str {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn credential_kind(&self) -> CircleCiCredentialKind {
        self.credential_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn digest(&self) -> Digest {
        digest_parts([
            self.reference_digest.as_str(),
            self.scope_digest.as_str(),
            &self.credential_revision.to_string(),
            match self.credential_kind {
                CircleCiCredentialKind::Token => "token",
                CircleCiCredentialKind::Oidc => "oidc",
            },
            if self.revoked { "revoked" } else { "active" },
        ])
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        validate_digest(&self.reference_digest, "secret reference digest")?;
        validate_digest(&self.scope_digest, "secret scope digest")?;
        if self.credential_revision == 0 || self.revoked {
            return Err(CircleCiPipelineResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("credential_kind", &self.credential_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretReferenceWire {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: u64,
    credential_kind: CircleCiCredentialKind,
    revoked: bool,
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("credentialKind", &self.credential_kind)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SecretReferenceWire::deserialize(deserializer)?;
        let value = Self {
            reference_digest: wire.reference_digest,
            scope_digest: wire.scope_digest,
            credential_revision: wire.credential_revision,
            credential_kind: wire.credential_kind,
            revoked: wire.revoked,
        };
        if !is_sha256(&value.reference_digest)
            || !is_sha256(&value.scope_digest)
            || value.credential_revision == 0
        {
            return Err(D::Error::custom("invalid CircleCI SecretReference"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiRevisions {
    pub pipeline: u64,
    pub workflow: u64,
    pub job: u64,
    pub attempt: u64,
    pub commit: u64,
    pub mission: u64,
    pub project: u64,
    pub work_product: u64,
    pub permission: u64,
}

impl CircleCiRevisions {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pipeline: u64,
        workflow: u64,
        job: u64,
        attempt: u64,
        commit: u64,
        mission: u64,
        project: u64,
        work_product: u64,
        permission: u64,
    ) -> Self {
        Self {
            pipeline,
            workflow,
            job,
            attempt,
            commit,
            mission,
            project,
            work_product,
            permission,
        }
    }

    fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        if [
            self.pipeline,
            self.workflow,
            self.job,
            self.attempt,
            self.commit,
            self.mission,
            self.project,
            self.work_product,
            self.permission,
        ]
        .contains(&0)
        {
            return Err(CircleCiPipelineResultError::InvalidScope);
        }
        Ok(())
    }
}

/// Exact provider and Hartevo identity boundary for one pipeline result read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiScope {
    pub host: CircleCiHost,
    pub organization: String,
    pub project_slug: String,
    pub pipeline_id: String,
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub commit_sha: String,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub revisions: CircleCiRevisions,
}

impl CircleCiScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: impl Into<String>,
        organization: impl Into<String>,
        project_slug: impl Into<String>,
        pipeline_id: impl Into<String>,
        workflow_id: impl Into<String>,
        job_number: u64,
        attempt_id: impl Into<String>,
        commit_sha: impl Into<String>,
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        work_product_id: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        Self::with_revisions(
            Self {
                host: CircleCiHost::new(host)?,
                organization: organization.into(),
                project_slug: project_slug.into(),
                pipeline_id: pipeline_id.into(),
                workflow_id: workflow_id.into(),
                job_number,
                attempt_id: attempt_id.into(),
                commit_sha: commit_sha.into(),
                mission_id: mission_id.into(),
                project_id: project_id.into(),
                work_product_id: work_product_id.into(),
                revisions: CircleCiRevisions::new(1, 1, 1, 1, 1, 1, 1, 1, 1),
            },
            CircleCiRevisions::new(1, 1, 1, 1, 1, 1, 1, 1, 1),
        )
    }

    pub fn with_revisions(
        mut self,
        revisions: CircleCiRevisions,
    ) -> Result<Self, CircleCiPipelineResultError> {
        self.revisions = revisions;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        validate_slug(&self.organization, "organization")?;
        validate_slug(&self.project_slug, "project slug")?;
        validate_identifier(&self.pipeline_id, "pipeline id")?;
        validate_identifier(&self.workflow_id, "workflow id")?;
        validate_identifier(&self.attempt_id, "attempt id")?;
        validate_identifier(&self.mission_id, "mission id")?;
        validate_identifier(&self.project_id, "project id")?;
        validate_identifier(&self.work_product_id, "work product id")?;
        CommitSha::new(self.commit_sha.clone())?;
        if self.job_number == 0 {
            return Err(CircleCiPipelineResultError::InvalidScope);
        }
        self.revisions.validate()
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn mission(&self) -> &str {
        &self.mission_id
    }

    pub fn project(&self) -> &str {
        &self.project_id
    }

    pub fn work_product(&self) -> &str {
        &self.work_product_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiPermission {
    PipelineRead,
    WorkflowRead,
    JobRead,
    ApprovalRead,
    ArtifactMetadataRead,
}

impl CircleCiPermission {
    pub const ALL_READ: [Self; 5] = [
        Self::PipelineRead,
        Self::WorkflowRead,
        Self::JobRead,
        Self::ApprovalRead,
        Self::ArtifactMetadataRead,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiPermissionSnapshot {
    pub permissions: BTreeSet<CircleCiPermission>,
    pub revision: u64,
    pub snapshot_digest: Digest,
}

impl CircleCiPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = CircleCiPermission>,
        revision: u64,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let mut value = Self {
            permissions: permissions.into_iter().collect(),
            revision,
            snapshot_digest: String::new(),
        };
        value.snapshot_digest = canonical_digest(&(&value.permissions, value.revision));
        value.validate()?;
        Ok(value)
    }

    pub fn all_read(revision: u64) -> Result<Self, CircleCiPipelineResultError> {
        Self::new(CircleCiPermission::ALL_READ, revision)
    }

    pub fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        if self.revision == 0
            || !CircleCiPermission::ALL_READ
                .iter()
                .all(|permission| self.permissions.contains(permission))
            || self.snapshot_digest != canonical_digest(&(&self.permissions, self.revision))
        {
            return Err(CircleCiPipelineResultError::InvalidPermissionRegistration);
        }
        validate_digest(&self.snapshot_digest, "permission snapshot")
    }

    pub fn digest(&self) -> &str {
        &self.snapshot_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiRegistration {
    pub scope: CircleCiScope,
    pub secret_reference: SecretReference,
    pub permission_snapshot: CircleCiPermissionSnapshot,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: u64,
    pub registration_revision: u64,
    pub revoked: bool,
    pub reversed: bool,
}

impl CircleCiRegistration {
    pub fn new(
        scope: CircleCiScope,
        secret_reference: SecretReference,
        permission_snapshot: CircleCiPermissionSnapshot,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let value = Self {
            scope,
            secret_reference,
            permission_snapshot,
            contract_version: crate::CIRCLECI_RESULT_CONTRACT_VERSION.to_owned(),
            provider_id: crate::CIRCLECI_PROVIDER_ID.to_owned(),
            provider_version: crate::CIRCLECI_PROVIDER_VERSION,
            registration_revision: 1,
            revoked: false,
            reversed: false,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        if self.secret_reference.scope_digest() != self.scope.digest()
            || self.contract_version != crate::CIRCLECI_RESULT_CONTRACT_VERSION
            || self.provider_id != crate::CIRCLECI_PROVIDER_ID
            || self.provider_version != crate::CIRCLECI_PROVIDER_VERSION
            || self.registration_revision == 0
        {
            return Err(CircleCiPipelineResultError::RegistrationDrift);
        }
        if self.revoked {
            return Err(CircleCiPipelineResultError::RegistrationRevoked);
        }
        if self.reversed {
            return Err(CircleCiPipelineResultError::RegistrationReversed);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn revoke(&mut self) -> RegistrationRevocation {
        self.revoked = true;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.secret_reference.revoke();
        RegistrationRevocation {
            registration_revision: self.registration_revision,
            revoked: true,
            reason_digest: sha256_digest(b"circleci-registration-revoked"),
        }
    }

    pub fn reverse(&mut self) -> RegistrationReversal {
        self.reversed = true;
        self.registration_revision = self.registration_revision.saturating_add(1);
        RegistrationReversal {
            registration_revision: self.registration_revision,
            reversed: true,
            reason_digest: sha256_digest(b"circleci-registration-reversed"),
        }
    }

    pub fn is_active(&self) -> bool {
        !self.revoked && !self.reversed
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_revision: u64,
    pub revoked: bool,
    pub reason_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReversal {
    pub registration_revision: u64,
    pub reversed: bool,
    pub reason_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiStatus {
    Created,
    Queued,
    Running,
    Successful,
    Failed,
    Canceled,
    OnHold,
    NotRun,
    Blocked,
    Unknown,
}

impl CircleCiStatus {
    pub fn project(raw: &str) -> Self {
        let normalized = raw.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "created" => Self::Created,
            "queued" => Self::Queued,
            "running" => Self::Running,
            "success" | "successful" => Self::Successful,
            "failed" | "failing" | "infrastructure_fail" | "timedout" => Self::Failed,
            "canceled" | "cancelled" => Self::Canceled,
            "on_hold" | "onhold" => Self::OnHold,
            "not_run" | "notrun" => Self::NotRun,
            "blocked" => Self::Blocked,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiApprovalState {
    Pending,
    Approved,
    Rejected,
    NotRequired,
    Unknown,
}

impl CircleCiApprovalState {
    pub fn project(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "pending" | "on_hold" | "onhold" => Self::Pending,
            "approved" | "success" => Self::Approved,
            "rejected" | "failed" | "canceled" | "cancelled" => Self::Rejected,
            "not_required" | "notrequired" | "none" => Self::NotRequired,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl CircleCiProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiVcsRevision {
    pub commit_sha: String,
    pub branch: Option<String>,
    pub tag: Option<String>,
}

impl CircleCiVcsRevision {
    pub fn new(
        commit_sha: impl Into<String>,
        branch: Option<String>,
        tag: Option<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let commit_sha = commit_sha.into();
        CommitSha::new(commit_sha.clone())?;
        if branch
            .as_deref()
            .is_some_and(|value| validate_text(value, "branch", MAX_IDENTIFIER_BYTES).is_err())
            || tag
                .as_deref()
                .is_some_and(|value| validate_text(value, "tag", MAX_IDENTIFIER_BYTES).is_err())
        {
            return Err(CircleCiPipelineResultError::InvalidInput {
                field: "vcs ref",
                reason: String::from("branch and tag must be bounded and content-safe"),
            });
        }
        Ok(Self {
            commit_sha,
            branch,
            tag,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiPipelineProjection {
    pub pipeline_id: String,
    pub number: u64,
    pub attempt_id: String,
    pub status: CircleCiStatus,
    pub vcs: CircleCiVcsRevision,
    pub created_at: String,
    pub updated_at: String,
    pub revision: u64,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiWorkflowProjection {
    pub workflow_id: String,
    pub status: CircleCiStatus,
    pub approval: CircleCiApprovalState,
    pub name_digest: Digest,
    pub created_at: String,
    pub stopped_at: Option<String>,
    pub revision: u64,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiJobProjection {
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub status: CircleCiStatus,
    pub approval: CircleCiApprovalState,
    pub name_digest: Digest,
    pub commit_sha: String,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub revision: u64,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiApprovalProjection {
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub state: CircleCiApprovalState,
    pub revision: u64,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiArtifactMetadataProjection {
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub name_digest: Digest,
    pub path_digest: Digest,
    pub size_bytes: u64,
    pub media_type: Option<String>,
    pub content_digest: Option<Digest>,
    pub revision: u64,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiScopeDescription {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: u64,
    pub scope_digest: Digest,
    pub host: CircleCiHost,
    pub organization: String,
    pub project_slug: String,
    pub permission_snapshot: CircleCiPermissionSnapshot,
    pub provenance: CircleCiProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CircleCiPipelineResultEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: u64,
    pub scope_digest: Digest,
    pub pipeline: CircleCiPipelineProjection,
    pub workflows: Vec<CircleCiWorkflowProjection>,
    pub jobs: Vec<CircleCiJobProjection>,
    pub approvals: Vec<CircleCiApprovalProjection>,
    pub artifact_metadata: Vec<CircleCiArtifactMetadataProjection>,
    pub permission_digest: Digest,
    pub evidence_revision: u64,
    pub provenance: CircleCiProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub raw_logs_retained: bool,
    pub artifact_bytes_downloaded: bool,
    pub evidence_digest: Digest,
}

impl CircleCiPipelineResultEvidence {
    pub fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest.clear();
        canonical_digest(&value)
    }

    pub fn validate(&self, scope: &CircleCiScope) -> Result<(), CircleCiPipelineResultError> {
        scope.validate()?;
        if self.contract_version != crate::CIRCLECI_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::CIRCLECI_PROVIDER_ID
            || self.provider_version != crate::CIRCLECI_PROVIDER_VERSION
            || self.scope_digest != scope.digest()
            || !is_sha256(&self.permission_digest)
            || self.evidence_revision != scope.revisions.pipeline
            || self.native_transport
            || self.native_connected
            || self.raw_logs_retained
            || self.artifact_bytes_downloaded
            || self.workflows.len() > MAX_WORKFLOWS
            || self.jobs.len() > MAX_JOBS
            || self.approvals.len() > MAX_APPROVALS
            || self.artifact_metadata.len() > MAX_ARTIFACT_METADATA
            || self.evidence_digest != self.compute_digest()
        {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        if self.workflows.is_empty() {
            return Err(CircleCiPipelineResultError::MissingEvidence {
                resource: "workflow",
            });
        }
        if self.jobs.is_empty() {
            return Err(CircleCiPipelineResultError::MissingEvidence { resource: "job" });
        }
        if self.pipeline.pipeline_id != scope.pipeline_id
            || self.pipeline.attempt_id != scope.attempt_id
            || self.pipeline.vcs.commit_sha != scope.commit_sha
            || self.pipeline.revision != scope.revisions.pipeline
        {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        if self.workflows.iter().any(|workflow| {
            workflow.workflow_id != scope.workflow_id
                || workflow.revision != scope.revisions.workflow
        }) {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        if self.jobs.iter().any(|job| {
            job.workflow_id != scope.workflow_id
                || job.job_number != scope.job_number
                || job.attempt_id != scope.attempt_id
                || job.commit_sha != scope.commit_sha
                || job.revision != scope.revisions.job
        }) {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        if self.approvals.iter().any(|approval| {
            approval.workflow_id != scope.workflow_id
                || approval.job_number != scope.job_number
                || approval.attempt_id != scope.attempt_id
                || approval.revision != scope.revisions.job
        }) {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        if self.artifact_metadata.iter().any(|artifact| {
            artifact.workflow_id != scope.workflow_id
                || artifact.job_number != scope.job_number
                || artifact.attempt_id != scope.attempt_id
                || artifact.revision != scope.revisions.job
        }) {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiPipelineReadRequest {
    pub scope: CircleCiScope,
    pub max_pages: usize,
}

/// Opaque CircleCI `page-token`. The raw token is only available to the
/// transport implementation; all public formatting and serialization expose
/// a digest instead of the token itself.
#[derive(Clone, Eq, PartialEq)]
pub struct CircleCiPageToken {
    raw: String,
    token_digest: Digest,
}

impl CircleCiPageToken {
    pub(crate) fn new(raw: impl Into<String>) -> Result<Self, CircleCiPipelineResultError> {
        let raw = raw.into();
        validate_text(&raw, "page token", MAX_PAGE_TOKEN_BYTES)?;
        Ok(Self {
            token_digest: sha256_digest(raw.as_bytes()),
            raw,
        })
    }

    pub fn digest(&self) -> &str {
        &self.token_digest
    }

    pub(crate) fn raw(&self) -> &str {
        &self.raw
    }
}

impl fmt::Debug for CircleCiPageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircleCiPageToken")
            .field("token_digest", &self.token_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for CircleCiPageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CircleCiPageToken", 1)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CircleCiPageToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            token_digest: Digest,
        }
        let wire = Wire::deserialize(deserializer)?;
        if !is_sha256(&wire.token_digest) {
            return Err(D::Error::custom("invalid CircleCI page-token digest"));
        }
        Ok(Self {
            raw: String::new(),
            token_digest: wire.token_digest,
        })
    }
}

impl CircleCiPipelineReadRequest {
    pub fn new(scope: CircleCiScope) -> Result<Self, CircleCiPipelineResultError> {
        scope.validate()?;
        Ok(Self {
            scope,
            max_pages: MAX_PAGES,
        })
    }

    pub fn with_max_pages(mut self, max_pages: usize) -> Result<Self, CircleCiPipelineResultError> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(CircleCiPipelineResultError::InvalidInput {
                field: "max pages",
                reason: format!("must be between 1 and {MAX_PAGES}"),
            });
        }
        self.max_pages = max_pages;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProduct {
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub mission_revision: u64,
    pub project_revision: u64,
    pub work_product_revision: u64,
    pub content_digest: Digest,
    pub objective_digest: Digest,
}

impl MissionWorkProduct {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        work_product_id: impl Into<String>,
        mission_revision: u64,
        project_revision: u64,
        work_product_revision: u64,
        content_digest: impl Into<String>,
        objective_digest: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let value = Self {
            mission_id: mission_id.into(),
            project_id: project_id.into(),
            work_product_id: work_product_id.into(),
            mission_revision,
            project_revision,
            work_product_revision,
            content_digest: content_digest.into(),
            objective_digest: objective_digest.into(),
        };
        MissionId::new(value.mission_id.clone())?;
        ProjectId::new(value.project_id.clone())?;
        WorkProductId::new(value.work_product_id.clone())?;
        validate_digest(&value.content_digest, "work product content")?;
        validate_digest(&value.objective_digest, "work product objective")?;
        if [
            value.mission_revision,
            value.project_revision,
            value.work_product_revision,
        ]
        .contains(&0)
        {
            return Err(CircleCiPipelineResultError::InvalidInput {
                field: "work product revision",
                reason: String::from("must be non-zero"),
            });
        }
        Ok(value)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CircleCiPipelineResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_id: String,
    pub plugin_version: u64,
    pub provider_id: String,
    pub provider_version: u64,
    pub scope_digest: Digest,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub mission_revision: u64,
    pub project_revision: u64,
    pub work_product_revision: u64,
    pub evidence_digest: Digest,
    pub provenance: CircleCiProvenance,
    pub non_mutating: bool,
    pub external_write_performed: bool,
    pub durable_native_receipt: bool,
    pub kernel_outcome_authority: bool,
    pub native_connected: bool,
    pub proposal_digest: Digest,
}

impl CircleCiPipelineResultProposal {
    pub fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest.clear();
        canonical_digest(&value)
    }

    pub fn validate(
        &self,
        scope: &CircleCiScope,
        work_product: &MissionWorkProduct,
    ) -> Result<(), CircleCiPipelineResultError> {
        if self.contract_version != crate::CIRCLECI_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.plugin_id != crate::CIRCLECI_PLUGIN_ID
            || self.plugin_version != crate::CIRCLECI_PLUGIN_VERSION
            || self.provider_id != crate::CIRCLECI_PROVIDER_ID
            || self.provider_version != crate::CIRCLECI_PROVIDER_VERSION
            || self.scope_digest != scope.digest()
            || self.mission_id != work_product.mission_id
            || self.project_id != work_product.project_id
            || self.work_product_id != work_product.work_product_id
            || self.mission_revision != work_product.mission_revision
            || self.project_revision != work_product.project_revision
            || self.work_product_revision != work_product.work_product_revision
            || !self.non_mutating
            || self.external_write_performed
            || self.durable_native_receipt
            || self.kernel_outcome_authority
            || self.native_connected
            || self.proposal_digest != self.compute_digest()
        {
            return Err(CircleCiPipelineResultError::ProposalMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CircleCiPipelineResultReceipt {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: u64,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: CircleCiProvenance,
    pub recording_only: bool,
    pub durable_native_receipt: bool,
    pub external_write_performed: bool,
    pub kernel_outcome_authority: bool,
    pub native_connected: bool,
    pub receipt_digest: Digest,
}

impl CircleCiPipelineResultReceipt {
    pub fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.receipt_digest.clear();
        canonical_digest(&value)
    }

    pub fn validate(
        &self,
        scope: &CircleCiScope,
        proposal: &CircleCiPipelineResultProposal,
    ) -> Result<(), CircleCiPipelineResultError> {
        if self.contract_version != crate::CIRCLECI_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::CIRCLECI_PROVIDER_ID
            || self.provider_version != crate::CIRCLECI_PROVIDER_VERSION
            || self.scope_digest != scope.digest()
            || self.proposal_digest != proposal.proposal_digest
            || self.evidence_digest != proposal.evidence_digest
            || !self.recording_only
            || self.durable_native_receipt
            || self.external_write_performed
            || self.kernel_outcome_authority
            || self.native_connected
            || self.receipt_digest != self.compute_digest()
        {
            return Err(CircleCiPipelineResultError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerifiedCircleCiPipelineResult {
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub receipt_digest: Digest,
    pub verified: bool,
    pub adopted: bool,
    pub native_connected: bool,
    pub kernel_outcome_authority: bool,
}

impl VerifiedCircleCiPipelineResult {
    pub fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        if !self.verified || self.adopted || self.native_connected || self.kernel_outcome_authority
        {
            return Err(CircleCiPipelineResultError::StaleEvidence);
        }
        validate_digest(&self.scope_digest, "verified scope")?;
        validate_digest(&self.proposal_digest, "verified proposal")?;
        validate_digest(&self.receipt_digest, "verified receipt")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiMissionPipelineResult {
    pub evidence: CircleCiPipelineResultEvidence,
    pub proposal: CircleCiPipelineResultProposal,
    pub receipt: CircleCiPipelineResultReceipt,
    pub verification: VerifiedCircleCiPipelineResult,
}

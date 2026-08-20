//! Typed, bounded CodeDeploy scope and redacted deployment evidence models.
//!
//! The public model has no representation for a credential, log body, script,
//! artifact bytes, raw provider response, or deployment effect. Those values
//! cannot cross this Layer-1 boundary accidentally.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    API_REVISION, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION,
    canonical_digest, error::AwsCodeDeployDeploymentResultError,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: usize = 4;
pub const MAX_DEPLOYMENTS: usize = 64;
pub const MAX_TARGETS: usize = 256;
pub const MAX_LIFECYCLE_EVENTS: usize = 64;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

fn invalid(field: &'static str, reason: &'static str) -> AwsCodeDeployDeploymentResultError {
    AwsCodeDeployDeploymentResultError::InvalidInput { field, reason }
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), AwsCodeDeployDeploymentResultError> {
    if value.is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if value.len() > max {
        return Err(invalid(field, "exceeds the byte bound"));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "contains surrounding whitespace or a control character",
        ));
    }
    Ok(())
}

fn validate_positive(
    value: u64,
    field: &'static str,
) -> Result<(), AwsCodeDeployDeploymentResultError> {
    if value == 0 {
        Err(invalid(field, "must be positive"))
    } else {
        Ok(())
    }
}

/// A SHA-256 digest used for all cross-boundary identity and evidence fences.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = value.into();
        let digest = Self(value);
        digest.validate()?;
        Ok(digest)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        canonical_digest(value)
    }

    pub fn pending() -> Self {
        Self::from_text("pending")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        let Some(hex) = self.0.strip_prefix("sha256:") else {
            return Err(AwsCodeDeployDeploymentResultError::InvalidDigest { field: "digest" });
        };
        if hex.len() != 64 || hex.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
            return Err(AwsCodeDeployDeploymentResultError::InvalidDigest { field: "digest" });
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Digest {
    type Err = AwsCodeDeployDeploymentResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value.to_owned())
    }
}

macro_rules! bounded_text {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
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

bounded_text!(AccountId, "AWS account id");
bounded_text!(AwsRegion, "AWS region");
bounded_text!(ApplicationName, "CodeDeploy application name");
bounded_text!(DeploymentGroupName, "CodeDeploy deployment group name");
bounded_text!(DeploymentId, "CodeDeploy deployment id");
bounded_text!(TargetId, "CodeDeploy target id");
bounded_text!(RevisionId, "CodeDeploy revision id");
bounded_text!(ProjectId, "Hartevo project id");
bounded_text!(MissionId, "Mission id");
bounded_text!(WorkProductId, "Work Product id");

impl AccountId {
    pub fn aws(value: impl Into<String>) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(invalid(
                "AWS account id",
                "must contain exactly twelve digits",
            ));
        }
        Ok(Self(value))
    }
}

impl AwsRegion {
    pub fn aws(value: impl Into<String>) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(invalid("AWS region", "must not start or end with a hyphen"));
        }
        Ok(Self(value))
    }
}

/// A cursor whose raw provider value is kept only inside the transport seam.
/// Serialization exposes its digest, never the provider token.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueCursor {
    value: String,
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = value.into();
        validate_text(&value, "cursor", MAX_CURSOR_BYTES)?;
        if value.chars().any(char::is_whitespace) {
            return Err(AwsCodeDeployDeploymentResultError::InvalidCursor { field: "cursor" });
        }
        Ok(Self {
            digest: Digest::from_text(&value),
            value,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.digest.validate()?;
        validate_text(&self.value, "cursor", MAX_CURSOR_BYTES)
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.digest.as_str())
    }
}

impl<'de> Deserialize<'de> for OpaqueCursor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let digest = String::deserialize(deserializer)?;
        Self::new(digest).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.major > 0 || self.minor > 0 || self.patch > 0
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    S3,
    GitHub,
    AppSpecContent,
    Unknown,
}

/// Revision identity only. A source locator is represented by a digest; raw
/// S3 keys, repository paths, AppSpec content, and artifact bytes are absent.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployRevision {
    pub revision_id: RevisionId,
    pub kind: RevisionKind,
    pub source_digest: Digest,
    pub revision_digest: Digest,
}

impl CodeDeployRevision {
    pub fn new(
        revision_id: RevisionId,
        kind: RevisionKind,
        source_digest: Digest,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        source_digest.validate()?;
        let revision_digest = Digest::from_serializable(&(&revision_id, kind, &source_digest));
        let value = Self {
            revision_id,
            kind,
            source_digest,
            revision_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_digest(
        revision_id: RevisionId,
        kind: RevisionKind,
        source_digest: Digest,
        revision_digest: Digest,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = Self {
            revision_id,
            kind,
            source_digest,
            revision_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.source_digest.validate()?;
        self.revision_digest.validate()?;
        let expected =
            Digest::from_serializable(&(&self.revision_id, self.kind, &self.source_digest));
        if self.revision_digest != expected {
            return Err(AwsCodeDeployDeploymentResultError::RevisionMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CodeDeployDeploymentStatus {
    Created,
    Queued,
    InProgress,
    Baking,
    Ready,
    Succeeded,
    Failed,
    Stopped,
    Unknown,
}

impl CodeDeployDeploymentStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "Created" => Self::Created,
            "Queued" => Self::Queued,
            "InProgress" => Self::InProgress,
            "Baking" => Self::Baking,
            "Ready" => Self::Ready,
            "Succeeded" => Self::Succeeded,
            "Failed" => Self::Failed,
            "Stopped" => Self::Stopped,
            _ => Self::Unknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Stopped)
    }

    pub const fn is_success(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CodeDeployTargetKind {
    Instance,
    Lambda,
    Ecs,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CodeDeployTargetStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Skipped,
    Unknown,
}

impl CodeDeployTargetStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "Pending" => Self::Pending,
            "InProgress" => Self::InProgress,
            "Succeeded" => Self::Succeeded,
            "Failed" => Self::Failed,
            "Skipped" => Self::Skipped,
            _ => Self::Unknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Skipped)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CodeDeployLifecycleEventStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Unknown,
}

impl CodeDeployLifecycleEventStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// Only event names, statuses, timestamps, and a digest of diagnostics are
/// retained. Diagnostics, scripts, and logs never enter this type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployLifecycleEvent {
    pub name: String,
    pub status: CodeDeployLifecycleEventStatus,
    pub started_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub diagnostics_digest: Option<Digest>,
}

impl CodeDeployLifecycleEvent {
    pub fn new(
        name: impl Into<String>,
        status: CodeDeployLifecycleEventStatus,
        started_at: Option<u64>,
        ended_at: Option<u64>,
        diagnostics_digest: Option<Digest>,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = Self {
            name: name.into(),
            status,
            started_at,
            ended_at,
            diagnostics_digest,
        };
        value.validate().map(|()| value)
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        validate_text(&self.name, "lifecycle event name", MAX_IDENTIFIER_BYTES)?;
        if let (Some(started), Some(ended)) = (self.started_at, self.ended_at)
            && ended < started
        {
            return Err(invalid(
                "lifecycle event timestamps",
                "ended before started",
            ));
        }
        if let Some(digest) = &self.diagnostics_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeDeployPermission {
    ListDeployments,
    GetDeployment,
    ListDeploymentTargets,
    MissionScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<CodeDeployPermission>,
    pub snapshot_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        revision: u64,
        permissions: BTreeSet<CodeDeployPermission>,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        validate_positive(revision, "permission revision")?;
        let snapshot_digest = Digest::from_serializable(&(revision, &permissions));
        let value = Self {
            revision,
            permissions,
            snapshot_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn read_only_default(revision: u64) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        Self::new(
            revision,
            BTreeSet::from([
                CodeDeployPermission::GetDeployment,
                CodeDeployPermission::ListDeploymentTargets,
                CodeDeployPermission::ListDeployments,
                CodeDeployPermission::MissionScope,
            ]),
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        validate_positive(self.revision, "permission revision")?;
        let required = BTreeSet::from([
            CodeDeployPermission::GetDeployment,
            CodeDeployPermission::ListDeploymentTargets,
            CodeDeployPermission::ListDeployments,
            CodeDeployPermission::MissionScope,
        ]);
        if self.permissions != required
            || self.snapshot_digest
                != Digest::from_serializable(&(self.revision, &self.permissions))
        {
            return Err(AwsCodeDeployDeploymentResultError::PermissionDrift);
        }
        self.snapshot_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployScope {
    pub account: AccountId,
    pub region: AwsRegion,
    pub application: ApplicationName,
    pub deployment_group: DeploymentGroupName,
    pub deployment: DeploymentId,
    pub revision: CodeDeployRevision,
    pub project: ProjectId,
    pub mission: MissionId,
    pub work_product: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub permissions: PermissionSnapshot,
}

impl CodeDeployScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountId,
        region: AwsRegion,
        application: ApplicationName,
        deployment_group: DeploymentGroupName,
        deployment: DeploymentId,
        revision: CodeDeployRevision,
        project: ProjectId,
        mission: MissionId,
        work_product: WorkProductId,
        mission_revision: u64,
        work_product_revision: u64,
        permissions: PermissionSnapshot,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = Self {
            account,
            region,
            application,
            deployment_group,
            deployment,
            revision,
            project,
            mission,
            work_product,
            mission_revision,
            work_product_revision,
            permissions,
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_strings(
        account: impl Into<String>,
        region: impl Into<String>,
        application: impl Into<String>,
        deployment_group: impl Into<String>,
        deployment: impl Into<String>,
        revision_id: impl Into<String>,
        revision_kind: RevisionKind,
        source_digest: Digest,
        project: impl Into<String>,
        mission: impl Into<String>,
        work_product: impl Into<String>,
        mission_revision: u64,
        work_product_revision: u64,
        permissions: PermissionSnapshot,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        Self::new(
            AccountId::aws(account)?,
            AwsRegion::aws(region)?,
            ApplicationName::new(application)?,
            DeploymentGroupName::new(deployment_group)?,
            DeploymentId::new(deployment)?,
            CodeDeployRevision::new(RevisionId::new(revision_id)?, revision_kind, source_digest)?,
            ProjectId::new(project)?,
            MissionId::new(mission)?,
            WorkProductId::new(work_product)?,
            mission_revision,
            work_product_revision,
            permissions,
        )
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.account.as_str().len() != 12
            || self
                .account
                .as_str()
                .bytes()
                .any(|byte| !byte.is_ascii_digit())
        {
            return Err(invalid(
                "AWS account id",
                "must contain exactly twelve digits",
            ));
        }
        validate_text(self.region.as_str(), "AWS region", 63)?;
        if self.region.as_str().starts_with('-') || self.region.as_str().ends_with('-') {
            return Err(invalid("AWS region", "must not start or end with a hyphen"));
        }
        validate_text(
            self.application.as_str(),
            "CodeDeploy application name",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            self.deployment_group.as_str(),
            "CodeDeploy deployment group name",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            self.deployment.as_str(),
            "CodeDeploy deployment id",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            self.project.as_str(),
            "Hartevo project id",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(self.mission.as_str(), "Mission id", MAX_IDENTIFIER_BYTES)?;
        validate_text(
            self.work_product.as_str(),
            "Work Product id",
            MAX_IDENTIFIER_BYTES,
        )?;
        self.revision.validate()?;
        self.permissions.validate()?;
        validate_positive(self.mission_revision, "mission revision")?;
        validate_positive(self.work_product_revision, "Work Product revision")
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// The only credential value crossing the registration boundary is an opaque
/// digest. The supplied host handle is hashed and immediately discarded.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretReference {
    pub reference_digest: Digest,
    pub scope_digest: Digest,
    pub credential_revision: u64,
    revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl AsRef<str>,
        scope: &CodeDeployScope,
        credential_revision: u64,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        scope.validate()?;
        Self::for_scope(opaque_handle, scope.digest(), credential_revision)
    }

    pub fn for_scope(
        opaque_handle: impl AsRef<str>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        validate_text(
            opaque_handle.as_ref(),
            "secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        if opaque_handle.as_ref().chars().any(char::is_whitespace) {
            return Err(invalid("secret reference", "must not contain whitespace"));
        }
        validate_positive(credential_revision, "credential revision")?;
        scope_digest.validate()?;
        Ok(Self {
            reference_digest: Digest::from_serializable(&(
                opaque_handle.as_ref(),
                &scope_digest,
                credential_revision,
            )),
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.reference_digest.validate()?;
        self.scope_digest.validate()?;
        validate_positive(self.credential_revision, "credential revision")
    }

    pub fn validate_for_scope(
        &self,
        scope: &CodeDeployScope,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(AwsCodeDeployDeploymentResultError::ScopeMismatch);
        }
        if self.revoked {
            return Err(AwsCodeDeployDeploymentResultError::SecretReferenceRevoked);
        }
        Ok(())
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CodeDeployRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub service_id: String,
    pub permission_digest: Digest,
    pub scope: CodeDeployScope,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference: SecretReference,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl fmt::Debug for CodeDeployRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodeDeployRegistration")
            .field("plugin_id", &self.plugin_id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("service_id", &self.service_id)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish_non_exhaustive()
    }
}

impl CodeDeployRegistration {
    pub fn new(
        scope: CodeDeployScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        Self::new_with_revision(scope, secret_reference, adapter_revision, 1)
    }

    pub fn new_with_revision(
        scope: CodeDeployScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
        registration_revision: u64,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        validate_positive(adapter_revision, "provider revision")?;
        validate_positive(registration_revision, "registration revision")?;
        let mut value = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION,
            provider_revision: format!("{API_REVISION}-a{adapter_revision}"),
            provider_digest: crate::provider_digest(),
            api_digest: crate::api_digest(),
            service_id: crate::SERVICE_ID.to_owned(),
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest(),
            evidence_digest: crate::evidence_contract_digest(&scope),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
        };
        value.registration_digest = value.computed_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.provider_digest != crate::provider_digest()
            || self.api_digest != crate::api_digest()
            || !self.provider_revision.starts_with(API_REVISION)
        {
            return Err(AwsCodeDeployDeploymentResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.contract_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.evidence_digest.validate()?;
        self.secret_reference.validate_for_scope(&self.scope)?;
        if self.contract_digest != crate::contract_digest()
            || self.permission_digest != *self.scope.permissions.digest()
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest != crate::evidence_contract_digest(&self.scope)
            || self.registration_digest != self.computed_digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::InvalidRegistration);
        }
        validate_positive(self.registration_revision, "registration revision")
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active && !self.secret_reference.is_revoked()
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!([
            &self.plugin_id,
            self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            self.provider_version,
            &self.provider_revision,
            &self.provider_digest,
            &self.api_digest,
            &self.service_id,
            &self.permission_digest,
            &self.scope_digest,
            &self.evidence_digest,
            &self.secret_reference.reference_digest,
            &self.secret_reference.scope_digest,
            self.secret_reference.credential_revision,
            self.registration_revision,
            self.status,
        ]))
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, AwsCodeDeployDeploymentResultError> {
        self.validate()?;
        if self.status != RegistrationStatus::Active {
            return Err(AwsCodeDeployDeploymentResultError::RegistrationRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(AwsCodeDeployDeploymentResultError::InvalidRegistration)?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            previous_digest,
            revoked_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: true,
        })
    }

    pub fn reissue(
        &self,
        scope: CodeDeployScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        Self::new(scope, secret_reference, adapter_revision)
    }
}

pub type CodeDeployPluginRegistration = CodeDeployRegistration;
pub type AwsAccountId = AccountId;
pub type Region = AwsRegion;
pub type CodeDeployDeploymentScope = CodeDeployScope;
pub type CodeDeployRevisionIdentity = CodeDeployRevision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub revoked_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentListFilter {
    pub statuses: BTreeSet<CodeDeployDeploymentStatus>,
    pub page_size: u16,
    pub filter_digest: Digest,
}

impl DeploymentListFilter {
    pub fn new(
        statuses: BTreeSet<CodeDeployDeploymentStatus>,
        page_size: u16,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(invalid(
                "page size",
                "must be between one and the Layer-1 maximum",
            ));
        }
        let filter_digest = Digest::from_serializable(&(statuses.clone(), page_size));
        let value = Self {
            statuses,
            page_size,
            filter_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn exact(page_size: u16) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        Self::new(BTreeSet::new(), page_size)
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(invalid("page size", "outside the bounded range"));
        }
        self.filter_digest.validate()?;
        if self.filter_digest != Digest::from_serializable(&(self.statuses.clone(), self.page_size))
        {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployReadRequest {
    pub scope: CodeDeployScope,
    pub filter: DeploymentListFilter,
    pub max_pages: usize,
    pub max_deployments: usize,
    pub max_targets: usize,
}

impl CodeDeployReadRequest {
    pub fn new(scope: CodeDeployScope) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        Self::with_bounds(scope, MAX_PAGES, MAX_DEPLOYMENTS, MAX_TARGETS)
    }

    pub fn with_bounds(
        scope: CodeDeployScope,
        max_pages: usize,
        max_deployments: usize,
        max_targets: usize,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = Self {
            scope,
            filter: DeploymentListFilter::exact(MAX_PAGE_SIZE)?,
            max_pages,
            max_deployments,
            max_targets,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.scope.validate()?;
        self.filter.validate()?;
        if self.max_pages == 0 || self.max_pages > MAX_PAGES {
            return Err(invalid("max pages", "outside the bounded range"));
        }
        if self.max_deployments == 0 || self.max_deployments > MAX_DEPLOYMENTS {
            return Err(invalid("max deployments", "outside the bounded range"));
        }
        if self.max_targets == 0 || self.max_targets > MAX_TARGETS {
            return Err(invalid("max targets", "outside the bounded range"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployDeploymentRecord {
    pub account: AccountId,
    pub region: AwsRegion,
    pub application: ApplicationName,
    pub deployment_group: DeploymentGroupName,
    pub deployment: DeploymentId,
    pub revision: CodeDeployRevision,
    pub status: CodeDeployDeploymentStatus,
    pub created_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub lifecycle_revision: u64,
    pub error_digest: Option<Digest>,
    pub provider_request_digest: Digest,
}

impl CodeDeployDeploymentRecord {
    pub fn validate_for(
        &self,
        scope: &CodeDeployScope,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.account != scope.account
            || self.region != scope.region
            || self.application != scope.application
            || self.deployment_group != scope.deployment_group
            || self.deployment != scope.deployment
        {
            return Err(AwsCodeDeployDeploymentResultError::ScopeMismatch);
        }
        if self.revision != scope.revision {
            return Err(AwsCodeDeployDeploymentResultError::RevisionMismatch);
        }
        self.revision.validate()?;
        validate_positive(self.lifecycle_revision, "deployment lifecycle revision")?;
        self.provider_request_digest.validate()?;
        if let Some(error_digest) = &self.error_digest {
            error_digest.validate()?;
        }
        if let (Some(created), Some(completed)) = (self.created_at, self.completed_at)
            && completed < created
        {
            return Err(invalid("deployment timestamps", "completed before created"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployTargetRecord {
    pub account: AccountId,
    pub region: AwsRegion,
    pub application: ApplicationName,
    pub deployment_group: DeploymentGroupName,
    pub deployment: DeploymentId,
    pub target: TargetId,
    pub kind: CodeDeployTargetKind,
    pub status: CodeDeployTargetStatus,
    pub lifecycle_events: Vec<CodeDeployLifecycleEvent>,
    pub lifecycle_revision: u64,
    pub last_updated_at: Option<u64>,
    pub provider_target_revision: u64,
}

impl CodeDeployTargetRecord {
    pub fn validate_shape(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        validate_positive(self.lifecycle_revision, "target lifecycle revision")?;
        validate_positive(self.provider_target_revision, "target revision")?;
        if self.lifecycle_events.len() > MAX_LIFECYCLE_EVENTS {
            return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
        }
        for event in &self.lifecycle_events {
            event.validate()?;
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        scope: &CodeDeployScope,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.account != scope.account
            || self.region != scope.region
            || self.application != scope.application
            || self.deployment_group != scope.deployment_group
            || self.deployment != scope.deployment
        {
            return Err(AwsCodeDeployDeploymentResultError::TargetScopeMismatch);
        }
        self.validate_shape()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployDeploymentPage {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub deployments: Vec<DeploymentId>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub truncated: bool,
    pub page_digest: Digest,
}

impl CodeDeployDeploymentPage {
    pub fn new(
        scope_digest: Digest,
        filter_digest: Digest,
        deployments: Vec<DeploymentId>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        truncated: bool,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let mut value = Self {
            scope_digest,
            filter_digest,
            deployments,
            next_cursor,
            response_bytes,
            truncated,
            page_digest: Digest::pending(),
        };
        value.page_digest = value.computed_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.scope_digest,
            &self.filter_digest,
            &self.deployments,
            &self.next_cursor,
            self.response_bytes,
            self.truncated,
        ))
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.scope_digest.validate()?;
        self.filter_digest.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsCodeDeployDeploymentResultError::ResponseTooLarge);
        }
        if self.deployments.len() > MAX_PAGE_SIZE as usize {
            return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate()?;
        }
        if self.page_digest != self.computed_digest() {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployTargetPage {
    pub scope_digest: Digest,
    pub deployment_digest: Digest,
    pub targets: Vec<CodeDeployTargetRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub truncated: bool,
    pub page_digest: Digest,
}

impl CodeDeployTargetPage {
    pub fn new(
        scope_digest: Digest,
        deployment_digest: Digest,
        targets: Vec<CodeDeployTargetRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        truncated: bool,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let mut value = Self {
            scope_digest,
            deployment_digest,
            targets,
            next_cursor,
            response_bytes,
            truncated,
            page_digest: Digest::pending(),
        };
        value.page_digest = value.computed_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.scope_digest,
            &self.deployment_digest,
            &self.targets,
            &self.next_cursor,
            self.response_bytes,
            self.truncated,
        ))
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.scope_digest.validate()?;
        self.deployment_digest.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsCodeDeployDeploymentResultError::ResponseTooLarge);
        }
        if self.targets.len() > MAX_TARGETS {
            return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
        }
        for target in &self.targets {
            target.validate_shape()?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate()?;
        }
        if self.page_digest != self.computed_digest() {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeDeployResultState {
    Created,
    Queued,
    InProgress,
    Baking,
    Ready,
    Succeeded,
    Failed,
    Stopped,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl CodeDeployResultState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Stopped
                | Self::NotFound
                | Self::AccessLoss
                | Self::Throttled
                | Self::ProviderUnknown
        )
    }

    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployDeploymentEvidence {
    pub scope: CodeDeployScope,
    pub registration_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub deployment: CodeDeployDeploymentRecord,
    pub targets: Vec<CodeDeployTargetRecord>,
    pub deployment_page_count: usize,
    pub target_page_count: usize,
    pub deployment_page_digests: Vec<Digest>,
    pub target_page_digests: Vec<Digest>,
    pub state: CodeDeployResultState,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub truncated: bool,
    pub observed_sequence: u64,
    pub evidence_digest: Digest,
}

impl CodeDeployDeploymentEvidence {
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!([
            &self.scope,
            &self.registration_digest,
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.deployment,
            &self.targets,
            self.deployment_page_count,
            self.target_page_count,
            &self.deployment_page_digests,
            &self.target_page_digests,
            self.state,
            self.provenance,
            self.native_transport,
            self.native_connected,
            self.truncated,
            self.observed_sequence,
        ]))
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.scope.validate()?;
        if self.registration_digest == Digest::pending()
            || self.plugin_version_digest != Digest::from_serializable(&PLUGIN_VERSION)
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != crate::provider_digest()
            || self.permission_digest != *self.scope.permissions.digest()
            || self.scope_digest != self.scope.digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        self.deployment.validate_for(&self.scope)?;
        if self.targets.len() > MAX_TARGETS
            || self.deployment_page_count == 0
            || self.target_page_count == 0
            || self.deployment_page_count > MAX_PAGES
            || self.target_page_count > MAX_PAGES
            || self.deployment_page_digests.len() != self.deployment_page_count
            || self.target_page_digests.len() != self.target_page_count
        {
            return Err(AwsCodeDeployDeploymentResultError::IncompleteEvidence);
        }
        let mut target_ids = BTreeSet::new();
        for target in &self.targets {
            target.validate_for(&self.scope)?;
            if !target_ids.insert(target.target.clone()) {
                return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
            }
        }
        for digest in self
            .deployment_page_digests
            .iter()
            .chain(self.target_page_digests.iter())
        {
            digest.validate()?;
        }
        let derived = derive_result_state(self.deployment.status, &self.targets);
        if self.state != derived {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        if self.provenance.is_native()
            || self.native_transport
            || self.native_connected
            || self.provenance.is_connected()
            || self.evidence_digest != self.computed_digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        validate_positive(self.observed_sequence, "evidence sequence")
    }

    pub fn is_adoptable(&self) -> bool {
        !self.truncated && self.state.is_adoptable() && !self.native_connected
    }
}

fn derive_result_state(
    deployment_status: CodeDeployDeploymentStatus,
    targets: &[CodeDeployTargetRecord],
) -> CodeDeployResultState {
    if targets
        .iter()
        .any(|target| target.status == CodeDeployTargetStatus::Failed)
    {
        return CodeDeployResultState::Failed;
    }
    if deployment_status == CodeDeployDeploymentStatus::Succeeded
        && !targets.is_empty()
        && targets.iter().all(|target| target.status.is_terminal())
        && targets
            .iter()
            .all(|target| target.status == CodeDeployTargetStatus::Succeeded)
    {
        return CodeDeployResultState::Succeeded;
    }
    match deployment_status {
        CodeDeployDeploymentStatus::Created => CodeDeployResultState::Created,
        CodeDeployDeploymentStatus::Queued => CodeDeployResultState::Queued,
        CodeDeployDeploymentStatus::InProgress => CodeDeployResultState::InProgress,
        CodeDeployDeploymentStatus::Baking => CodeDeployResultState::Baking,
        CodeDeployDeploymentStatus::Ready => CodeDeployResultState::Ready,
        CodeDeployDeploymentStatus::Succeeded => CodeDeployResultState::Partial,
        CodeDeployDeploymentStatus::Failed => CodeDeployResultState::Failed,
        CodeDeployDeploymentStatus::Stopped => CodeDeployResultState::Stopped,
        CodeDeployDeploymentStatus::Unknown => CodeDeployResultState::ProviderUnknown,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultVerificationStatus {
    Verified,
    Pending,
    Failed,
    ProviderUnknown,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProductBinding {
    pub project: ProjectId,
    pub mission: MissionId,
    pub work_product: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
}

impl MissionWorkProductBinding {
    pub fn from_scope(scope: &CodeDeployScope) -> Self {
        Self {
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            mission_revision: scope.mission_revision,
            work_product_revision: scope.work_product_revision,
        }
    }

    pub fn validate_for(
        &self,
        scope: &CodeDeployScope,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self != &Self::from_scope(scope) {
            return Err(AwsCodeDeployDeploymentResultError::ConsumerScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployDeploymentResultProposal {
    pub result_id: String,
    pub result_digest: Digest,
    pub scope: CodeDeployScope,
    pub binding: MissionWorkProductBinding,
    pub registration_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub deployment_status: CodeDeployDeploymentStatus,
    pub state: CodeDeployResultState,
    pub target_count: usize,
    pub terminal_target_count: usize,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub external_effect_performed: bool,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub verification_status: ResultVerificationStatus,
}

impl CodeDeployDeploymentResultProposal {
    pub fn from_evidence(
        evidence: &CodeDeployDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        evidence.validate()?;
        if evidence.registration_digest != registration_digest {
            return Err(AwsCodeDeployDeploymentResultError::ReceiptMismatch);
        }
        let terminal_target_count = evidence
            .targets
            .iter()
            .filter(|target| target.status.is_terminal())
            .count();
        let mut value = Self {
            result_id: format!("aws-codedeploy:{}", evidence.scope.deployment),
            result_digest: Digest::pending(),
            scope: evidence.scope.clone(),
            binding: MissionWorkProductBinding::from_scope(&evidence.scope),
            registration_digest,
            plugin_version_digest: evidence.plugin_version_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            deployment_status: evidence.deployment.status,
            state: evidence.state,
            target_count: evidence.targets.len(),
            terminal_target_count,
            provenance: evidence.provenance,
            native_transport: evidence.native_transport,
            native_connected: evidence.native_connected,
            external_effect_performed: false,
            durable_adoption: false,
            kernel_authority: false,
            verification_status: verification_for_state(evidence.state, evidence.truncated),
        };
        value.result_digest = value.computed_digest();
        value.validate_for_registration(&value.registration_digest)?;
        Ok(value)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!([
            &self.result_id,
            &self.scope,
            &self.binding,
            &self.registration_digest,
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.evidence_digest,
            self.deployment_status,
            self.state,
            self.target_count,
            self.terminal_target_count,
            self.provenance,
            self.native_transport,
            self.native_connected,
            self.external_effect_performed,
            self.durable_adoption,
            self.kernel_authority,
            self.verification_status,
        ]))
    }

    pub fn validate_for_registration(
        &self,
        registration_digest: &Digest,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.scope.validate()?;
        self.binding.validate_for(&self.scope)?;
        if &self.registration_digest != registration_digest
            || self.plugin_version_digest != Digest::from_serializable(&PLUGIN_VERSION)
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != crate::provider_digest()
            || self.permission_digest != *self.scope.permissions.digest()
            || self.scope_digest != self.scope.digest()
            || self.native_transport
            || self.native_connected
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.external_effect_performed
            || self.durable_adoption
            || self.kernel_authority
            || self.result_digest != self.computed_digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        self.evidence_digest.validate()
    }
}

fn verification_for_state(
    state: CodeDeployResultState,
    truncated: bool,
) -> ResultVerificationStatus {
    if truncated {
        return ResultVerificationStatus::Incomplete;
    }
    match state {
        CodeDeployResultState::Succeeded => ResultVerificationStatus::Verified,
        CodeDeployResultState::Created
        | CodeDeployResultState::Queued
        | CodeDeployResultState::InProgress
        | CodeDeployResultState::Baking
        | CodeDeployResultState::Ready
        | CodeDeployResultState::Partial => ResultVerificationStatus::Pending,
        CodeDeployResultState::Failed | CodeDeployResultState::Stopped => {
            ResultVerificationStatus::Failed
        }
        CodeDeployResultState::ProviderUnknown
        | CodeDeployResultState::NotFound
        | CodeDeployResultState::AccessLoss
        | CodeDeployResultState::Throttled
        | CodeDeployResultState::RegistrationRevoked => ResultVerificationStatus::ProviderUnknown,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployDeploymentReceipt {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub deployment_digest: Digest,
    pub target_digest: Digest,
    pub state: CodeDeployResultState,
    pub provenance: ProviderProvenance,
    pub truncated: bool,
    pub provider_receipt: bool,
    pub durable_readback: bool,
    pub native_connected: bool,
    pub receipt_digest: Digest,
}

impl CodeDeployDeploymentReceipt {
    pub fn from_evidence(
        evidence: &CodeDeployDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        evidence.validate()?;
        let mut value = Self {
            scope_digest: evidence.scope_digest.clone(),
            registration_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            deployment_digest: evidence.deployment.digest(),
            target_digest: Digest::from_serializable(&evidence.targets),
            state: evidence.state,
            provenance: evidence.provenance,
            truncated: evidence.truncated,
            provider_receipt: false,
            durable_readback: false,
            native_connected: false,
            receipt_digest: Digest::pending(),
        };
        value.receipt_digest = value.computed_digest();
        value.validate_against(evidence, &value.registration_digest)?;
        Ok(value)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.scope_digest,
            &self.registration_digest,
            &self.evidence_digest,
            &self.deployment_digest,
            &self.target_digest,
            self.state,
            self.provenance,
            self.truncated,
            self.provider_receipt,
            self.durable_readback,
            self.native_connected,
        ))
    }

    pub fn validate_against(
        &self,
        evidence: &CodeDeployDeploymentEvidence,
        registration_digest: &Digest,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        evidence.validate()?;
        if &self.registration_digest != registration_digest
            || self.scope_digest != evidence.scope_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.deployment_digest != evidence.deployment.digest()
            || self.target_digest != Digest::from_serializable(&evidence.targets)
            || self.state != evidence.state
            || self.truncated != evidence.truncated
            || self.provider_receipt
            || self.durable_readback
            || self.native_connected
            || self.receipt_digest != self.computed_digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::ReceiptMismatch);
        }
        Ok(())
    }
}

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{DaggerPipelineResultError, Result};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES, MAX_METADATA_ITEMS,
    MAX_RETRY_AFTER_SECONDS, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
};

pub const MAX_MEDIA_TYPE_BYTES: usize = 128;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(DaggerPipelineResultError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(DaggerPipelineResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'#')
        })
}

fn valid_commit(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
}

macro_rules! redacted_identifier {
    ($name:ident, $domain:literal, $field:literal, $validator:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err(DaggerPipelineResultError::InvalidIdentifier { field: $field })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            #[must_use]
            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if $validator(&self.0) {
                    Ok(())
                } else {
                    Err(DaggerPipelineResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.redacted())
            }
        }
    };
}

redacted_identifier!(
    DaggerModuleId,
    "dagger-module/v1",
    "module",
    valid_identifier
);
redacted_identifier!(
    DaggerPipelineId,
    "dagger-pipeline/v1",
    "pipeline",
    valid_identifier
);
redacted_identifier!(
    DaggerFunctionName,
    "dagger-function/v1",
    "function",
    valid_identifier
);
redacted_identifier!(
    DaggerContainerId,
    "dagger-container/v1",
    "container",
    valid_identifier
);
redacted_identifier!(
    DaggerExecutionId,
    "dagger-execution/v1",
    "execution",
    valid_identifier
);
redacted_identifier!(
    DaggerArtifactId,
    "dagger-artifact/v1",
    "artifact",
    valid_identifier
);
redacted_identifier!(ProjectId, "dagger-project/v1", "project", valid_identifier);
redacted_identifier!(MissionId, "dagger-mission/v1", "mission", valid_identifier);
redacted_identifier!(
    WorkProductId,
    "dagger-work-product/v1",
    "work-product",
    valid_identifier
);
redacted_identifier!(DaggerCommit, "dagger-commit/v1", "commit", valid_commit);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(DaggerPipelineResultError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type ProjectRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;
pub type ScopeRevision = Revision;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaggerRunStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaggerEvidenceState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
    AccessLoss,
    BlockedEnv,
    RegistrationRevoked,
}

impl DaggerEvidenceState {
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Failed
                | Self::Partial
                | Self::Denied
                | Self::RateLimited
                | Self::ProviderUnknown
                | Self::Tampered
                | Self::AccessLoss
                | Self::BlockedEnv
                | Self::RegistrationRevoked
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerPipelineScope {
    module: DaggerModuleId,
    pipeline: DaggerPipelineId,
    function: DaggerFunctionName,
    container: DaggerContainerId,
    commit: Option<DaggerCommit>,
    artifact: Option<DaggerArtifactId>,
    project: ProjectId,
    project_revision: ProjectRevision,
    mission: MissionId,
    mission_revision: MissionRevision,
    work_product: WorkProductId,
    work_product_revision: WorkProductRevision,
    scope_revision: ScopeRevision,
    scope_digest: Digest,
}

pub type DaggerPipelineScopeSpec = DaggerPipelineScope;

impl DaggerPipelineScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module: DaggerModuleId,
        pipeline: DaggerPipelineId,
        function: DaggerFunctionName,
        container: DaggerContainerId,
        commit: Option<DaggerCommit>,
        artifact: Option<DaggerArtifactId>,
        project: ProjectId,
        project_revision: u64,
        mission: MissionId,
        mission_revision: u64,
        work_product: WorkProductId,
        work_product_revision: u64,
        scope_revision: u64,
    ) -> Result<Self> {
        let scope = Self {
            module,
            pipeline,
            function,
            container,
            commit,
            artifact,
            project,
            project_revision: Revision::new(project_revision)?,
            mission,
            mission_revision: Revision::new(mission_revision)?,
            work_product,
            work_product_revision: Revision::new(work_product_revision)?,
            scope_revision: Revision::new(scope_revision)?,
            scope_digest: Digest::from_text("pending"),
        };
        scope.validate_fields()?;
        let scope_digest = scope.calculate_digest();
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        module: impl Into<String>,
        pipeline: impl Into<String>,
        function: impl Into<String>,
        container: impl Into<String>,
        commit: Option<String>,
        artifact: Option<String>,
        project: impl Into<String>,
        project_revision: u64,
        mission: impl Into<String>,
        mission_revision: u64,
        work_product: impl Into<String>,
        work_product_revision: u64,
        scope_revision: u64,
    ) -> Result<Self> {
        Self::new(
            DaggerModuleId::new(module)?,
            DaggerPipelineId::new(pipeline)?,
            DaggerFunctionName::new(function)?,
            DaggerContainerId::new(container)?,
            commit.map(DaggerCommit::new).transpose()?,
            artifact.map(DaggerArtifactId::new).transpose()?,
            ProjectId::new(project)?,
            project_revision,
            MissionId::new(mission)?,
            mission_revision,
            WorkProductId::new(work_product)?,
            work_product_revision,
            scope_revision,
        )
    }

    fn validate_fields(&self) -> Result<()> {
        self.module.validate()?;
        self.pipeline.validate()?;
        self.function.validate()?;
        self.container.validate()?;
        self.commit
            .as_ref()
            .map(DaggerCommit::validate)
            .transpose()?;
        self.artifact
            .as_ref()
            .map(DaggerArtifactId::validate)
            .transpose()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "dagger-scope/v1",
            &[
                ("module", self.module.digest().as_str().to_owned()),
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                ("function", self.function.digest().as_str().to_owned()),
                ("container", self.container.digest().as_str().to_owned()),
                (
                    "commit",
                    self.commit
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "artifact",
                    self.artifact
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("project", self.project.digest().as_str().to_owned()),
                ("project_revision", self.project_revision.get().to_string()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("mission_revision", self.mission_revision.get().to_string()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product_revision.get().to_string(),
                ),
                ("scope_revision", self.scope_revision.get().to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_fields()?;
        if self.scope_digest != self.calculate_digest() {
            return Err(DaggerPipelineResultError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn module(&self) -> &DaggerModuleId {
        &self.module
    }

    #[must_use]
    pub fn pipeline(&self) -> &DaggerPipelineId {
        &self.pipeline
    }

    #[must_use]
    pub fn function(&self) -> &DaggerFunctionName {
        &self.function
    }

    #[must_use]
    pub fn container(&self) -> &DaggerContainerId {
        &self.container
    }

    #[must_use]
    pub fn commit(&self) -> Option<&DaggerCommit> {
        self.commit.as_ref()
    }

    #[must_use]
    pub fn artifact(&self) -> Option<&DaggerArtifactId> {
        self.artifact.as_ref()
    }

    #[must_use]
    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    #[must_use]
    pub const fn project_revision(&self) -> ProjectRevision {
        self.project_revision
    }

    #[must_use]
    pub fn mission(&self) -> &MissionId {
        &self.mission
    }

    #[must_use]
    pub const fn mission_revision(&self) -> MissionRevision {
        self.mission_revision
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product
    }

    #[must_use]
    pub const fn work_product_revision(&self) -> WorkProductRevision {
        self.work_product_revision
    }

    #[must_use]
    pub const fn scope_revision(&self) -> ScopeRevision {
        self.scope_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
    expires_at_epoch_seconds: u64,
    revoked: bool,
}

impl ConsentScope {
    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id) {
            return Err(DaggerPipelineResultError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        let consent_digest = Digest::from_parts(
            "dagger-consent/v1",
            &[
                ("id", id),
                ("revision", revision.get().to_string()),
                ("expires_at", expires_at_epoch_seconds.to_string()),
                ("revoked", "false".to_owned()),
            ],
        );
        Ok(Self {
            consent_digest,
            revision,
            expires_at_epoch_seconds,
            revoked: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.consent_digest.clone()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn is_valid_at(&self, now_epoch_seconds: u64) -> bool {
        !self.revoked && now_epoch_seconds <= self.expires_at_epoch_seconds
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(DaggerPipelineResultError::ConsentRevoked);
        }
        self.revoked = true;
        self.consent_digest = Digest::from_parts(
            "dagger-consent-revoked/v1",
            &[
                ("previous", self.consent_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.consent_digest.validate()?;
        if self.revision.get() == 0 {
            return Err(DaggerPipelineResultError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    Token,
    Oci,
}

/// Opaque, non-serializing reference to a Layer-2 token or OCI credential.
/// The constructor accepts only a handle; no credential material is stored.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
}

impl SecretReference {
    pub fn token(
        reference_handle: impl Into<String>,
        scope: &DaggerPipelineScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(
            SecretReferenceKind::Token,
            reference_handle,
            scope,
            revision,
        )
    }

    pub fn oci(
        reference_handle: impl Into<String>,
        scope: &DaggerPipelineScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(SecretReferenceKind::Oci, reference_handle, scope, revision)
    }

    fn new(
        kind: SecretReferenceKind,
        reference_handle: impl Into<String>,
        scope: &DaggerPipelineScope,
        revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        let reference_handle = reference_handle.into();
        if !valid_text(&reference_handle, MAX_SECRET_REFERENCE_BYTES, false)
            || !reference_handle.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
            })
        {
            return Err(DaggerPipelineResultError::InvalidSecretReference);
        }
        let revision = Revision::new(revision)?;
        let kind_name = match kind {
            SecretReferenceKind::Token => "token",
            SecretReferenceKind::Oci => "oci",
        };
        Ok(Self {
            kind,
            reference_digest: Digest::from_parts(
                "dagger-secret-reference/v1",
                &[("kind", kind_name.to_owned()), ("handle", reference_handle)],
            ),
            scope_digest: scope.digest(),
            revision,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate_for_scope(&self, scope: &DaggerPipelineScope) -> Result<()> {
        scope.validate()?;
        self.reference_digest.validate()?;
        if self.scope_digest != scope.digest() || self.revision.get() == 0 {
            return Err(DaggerPipelineResultError::ScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerPermissionSnapshot {
    permissions: BTreeSet<String>,
    permission_digest: Digest,
}

impl DaggerPermissionSnapshot {
    #[must_use]
    pub fn layer_one() -> Self {
        let permissions = [
            "dagger:module:read",
            "dagger:pipeline:result:read",
            "dagger:function:metadata:read",
            "dagger:container:metadata:read",
            "dagger:artifact:metadata:read",
            "mission.scope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let permission_digest = Digest::from_parts(
            "dagger-permissions/v1",
            &permissions
                .iter()
                .enumerate()
                .map(|(index, value)| ("permission", format!("{index}:{value}")))
                .collect::<Vec<_>>(),
        );
        Self {
            permissions,
            permission_digest,
        }
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub fn validate(&self) -> Result<()> {
        if *self != Self::layer_one() {
            Err(DaggerPipelineResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerArtifactMetadata {
    pub artifact: DaggerArtifactId,
    pub kind: DaggerArtifactKind,
    pub artifact_digest: Digest,
    pub size_bytes: u64,
    pub media_type: String,
    pub created_at_epoch_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaggerArtifactKind {
    OciImage,
    Container,
    Generic,
}

impl DaggerArtifactMetadata {
    pub fn new(
        artifact: DaggerArtifactId,
        kind: DaggerArtifactKind,
        artifact_digest: impl Into<String>,
        size_bytes: u64,
        media_type: impl Into<String>,
        created_at_epoch_seconds: u64,
    ) -> Result<Self> {
        let artifact_digest = Digest::parse(artifact_digest)?;
        let media_type = media_type.into();
        if !valid_text(&media_type, MAX_MEDIA_TYPE_BYTES, false) {
            return Err(DaggerPipelineResultError::InvalidText {
                field: "media_type",
            });
        }
        Ok(Self {
            artifact,
            kind,
            artifact_digest,
            size_bytes,
            media_type,
            created_at_epoch_seconds,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.artifact.validate()?;
        self.artifact_digest.validate()?;
        if !valid_text(&self.media_type, MAX_MEDIA_TYPE_BYTES, false) {
            return Err(DaggerPipelineResultError::InvalidText {
                field: "media_type",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "dagger-artifact-metadata/v1",
            &[
                ("artifact", self.artifact.digest().as_str().to_owned()),
                ("kind", format!("{:?}", self.kind)),
                ("artifact_digest", self.artifact_digest.as_str().to_owned()),
                ("size_bytes", self.size_bytes.to_string()),
                ("media_type", self.media_type.clone()),
                ("created_at", self.created_at_epoch_seconds.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerPipelineResultMetadata {
    pub execution: DaggerExecutionId,
    pub pipeline_digest: Digest,
    pub function_digest: Digest,
    pub container_digest: Digest,
    pub commit_digest: Option<Digest>,
    pub status: DaggerRunStatus,
    pub observed_at_epoch_seconds: u64,
    pub duration_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub artifact_count: u16,
}

impl DaggerPipelineResultMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &DaggerPipelineScope,
        execution: DaggerExecutionId,
        status: DaggerRunStatus,
        observed_at_epoch_seconds: u64,
        duration_ms: Option<u64>,
        exit_code: Option<i32>,
        artifact_count: usize,
    ) -> Result<Self> {
        scope.validate()?;
        if artifact_count > MAX_METADATA_ITEMS {
            return Err(DaggerPipelineResultError::BoundsExceeded);
        }
        Ok(Self {
            execution,
            pipeline_digest: scope.pipeline().digest(),
            function_digest: scope.function().digest(),
            container_digest: scope.container().digest(),
            commit_digest: scope.commit().map(DaggerCommit::digest),
            status,
            observed_at_epoch_seconds,
            duration_ms,
            exit_code,
            artifact_count: u16::try_from(artifact_count)
                .map_err(|_| DaggerPipelineResultError::BoundsExceeded)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.execution.validate()?;
        self.pipeline_digest.validate()?;
        self.function_digest.validate()?;
        self.container_digest.validate()?;
        self.commit_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if usize::from(self.artifact_count) > MAX_METADATA_ITEMS {
            return Err(DaggerPipelineResultError::BoundsExceeded);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerBackoffHint {
    pub retry_after_seconds: Option<u32>,
    pub attempt: u8,
}

impl DaggerBackoffHint {
    pub fn new(retry_after_seconds: Option<u32>, attempt: u8) -> Result<Self> {
        if retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS) {
            return Err(DaggerPipelineResultError::BoundsExceeded);
        }
        Ok(Self {
            retry_after_seconds,
            attempt,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerFailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub diagnostic_digest: Option<Digest>,
}

impl DaggerFailureEvidence {
    pub fn new(
        category: impl Into<String>,
        status_code: Option<u16>,
        retry_after_seconds: Option<u32>,
        diagnostic: Option<&str>,
    ) -> Result<Self> {
        let category = category.into();
        if !valid_identifier(&category)
            || retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(DaggerPipelineResultError::InvalidText { field: "category" });
        }
        let diagnostic_digest = diagnostic
            .filter(|value| value.len() <= MAX_DIAGNOSTIC_BYTES)
            .map(Digest::from_text);
        Ok(Self {
            category,
            status_code,
            retry_after_seconds,
            diagnostic_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerObservationReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub transport: TransportProvenance,
    pub observed_at_epoch_seconds: u64,
    pub receipt_digest: Digest,
}

impl DaggerObservationReceipt {
    pub(crate) fn new(
        request_digest: Digest,
        response_digest: Digest,
        status_code: Option<u16>,
        transport: TransportProvenance,
        observed_at_epoch_seconds: u64,
    ) -> Self {
        let receipt_digest = Digest::from_parts(
            "dagger-observation-receipt/v1",
            &[
                ("request", request_digest.as_str().to_owned()),
                ("response", response_digest.as_str().to_owned()),
                (
                    "status_code",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                ("transport", format!("{transport:?}")),
                ("observed_at", observed_at_epoch_seconds.to_string()),
            ],
        );
        Self {
            request_digest,
            response_digest,
            status_code,
            transport,
            observed_at_epoch_seconds,
            receipt_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.request_digest.validate()?;
        self.response_digest.validate()?;
        self.receipt_digest.validate()?;
        let expected = Self::new(
            self.request_digest.clone(),
            self.response_digest.clone(),
            self.status_code,
            self.transport,
            self.observed_at_epoch_seconds,
        );
        if self.receipt_digest != expected.receipt_digest {
            return Err(DaggerPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub module_digest: Digest,
    pub pipeline_digest: Digest,
    pub function_digest: Digest,
    pub container_digest: Digest,
    pub commit_digest: Option<Digest>,
    pub execution_digest: Option<Digest>,
    pub artifact_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

impl DaggerEvidenceDigests {
    fn components_digest(&self) -> Digest {
        Digest::from_parts(
            "dagger-evidence-components/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("module", self.module_digest.as_str().to_owned()),
                ("pipeline", self.pipeline_digest.as_str().to_owned()),
                ("function", self.function_digest.as_str().to_owned()),
                ("container", self.container_digest.as_str().to_owned()),
                (
                    "commit",
                    self.commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "execution",
                    self.execution_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "artifacts",
                    self.artifact_digests
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
pub struct DaggerPipelineEvidence {
    pub state: DaggerEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub transport: TransportProvenance,
    pub result: Option<DaggerPipelineResultMetadata>,
    pub artifacts: Vec<DaggerArtifactMetadata>,
    pub failure: Option<DaggerFailureEvidence>,
    pub backoff: Option<DaggerBackoffHint>,
    pub observation_receipt: DaggerObservationReceipt,
    pub evidence_digests: DaggerEvidenceDigests,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl DaggerPipelineEvidence {
    pub(crate) fn calculate_evidence_digest(&self) -> Digest {
        let result_digest = self
            .result
            .as_ref()
            .map_or_else(String::new, |value| value.digest().as_str().to_owned());
        let artifact_digest = self
            .artifacts
            .iter()
            .map(|value| value.digest().as_str().to_owned())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts(
            "dagger-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("transport", format!("{:?}", self.transport)),
                ("result", result_digest),
                ("artifacts", artifact_digest),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        canonical_digest(value).as_str().to_owned()
                    }),
                ),
                (
                    "backoff",
                    self.backoff.as_ref().map_or_else(String::new, |value| {
                        canonical_digest(value).as_str().to_owned()
                    }),
                ),
                (
                    "receipt",
                    self.observation_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "digest_components",
                    self.evidence_digests
                        .components_digest()
                        .as_str()
                        .to_owned(),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                (
                    "durable_provider_receipt",
                    self.durable_provider_receipt.to_string(),
                ),
                ("first_party", self.first_party.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self, scope: &DaggerPipelineScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        self.request_digest.validate()?;
        self.observation_receipt.validate()?;
        if self.scope_digest != scope.digest()
            || self.connected
            || self.native
            || self.durable_provider_receipt
            || self.first_party
            || self.artifacts.len() > MAX_METADATA_ITEMS
            || self.evidence_digests.evidence_digest != self.evidence_digest
            || self.evidence_digests.scope_digest != scope.digest()
            || self.evidence_digests.module_digest != scope.module().digest()
            || self.evidence_digests.pipeline_digest != scope.pipeline().digest()
            || self.evidence_digests.function_digest != scope.function().digest()
            || self.evidence_digests.container_digest != scope.container().digest()
            || self.evidence_digests.commit_digest != scope.commit().map(DaggerCommit::digest)
            || self.evidence_digests.execution_digest
                != self.result.as_ref().map(|value| value.execution.digest())
            || self.evidence_digests.artifact_digests
                != self
                    .artifacts
                    .iter()
                    .map(DaggerArtifactMetadata::digest)
                    .collect::<Vec<_>>()
            || self.evidence_digest != self.calculate_evidence_digest()
        {
            return Err(DaggerPipelineResultError::TamperedEvidence);
        }
        if let Some(result) = &self.result {
            result.validate()?;
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerPipelineResultProposal {
    pub proposal_digest: Digest,
    pub evidence: DaggerPipelineEvidence,
    pub state: DaggerEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_revision: Revision,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl DaggerPipelineResultProposal {
    pub(crate) fn new(evidence: DaggerPipelineEvidence) -> Self {
        let proposal_revision = Revision(1);
        let proposal_digest = Digest::from_parts(
            "dagger-proposal/v1",
            &[
                ("evidence", evidence.evidence_digest.as_str().to_owned()),
                ("scope", evidence.scope_digest.as_str().to_owned()),
                (
                    "registration",
                    evidence.registration_digest.as_str().to_owned(),
                ),
                ("revision", proposal_revision.get().to_string()),
            ],
        );
        Self {
            state: evidence.state,
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence,
            proposal_digest,
            proposal_revision,
            review_only: true,
            connected: false,
            native: false,
            adopts_outcome: false,
            adopts_work_product: false,
        }
    }

    pub fn validate_integrity(&self, scope: &DaggerPipelineScope) -> Result<()> {
        self.evidence.validate_integrity(scope)?;
        if self.state != self.evidence.state
            || self.scope_digest != self.evidence.scope_digest
            || self.registration_digest != self.evidence.registration_digest
            || !self.review_only
            || self.connected
            || self.native
            || self.adopts_outcome
            || self.adopts_work_product
        {
            return Err(DaggerPipelineResultError::TamperedEvidence);
        }
        let expected = Self::new(self.evidence.clone());
        if expected.proposal_digest != self.proposal_digest
            || expected.proposal_revision != self.proposal_revision
        {
            return Err(DaggerPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerRecordingReceipt {
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
}

impl DaggerRecordingReceipt {
    pub(crate) fn new(
        idempotency_digest: Digest,
        proposal_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
        replayed: bool,
    ) -> Self {
        let recording_digest = Digest::from_parts(
            "dagger-recording/v1",
            &[
                ("idempotency", idempotency_digest.as_str().to_owned()),
                ("proposal", proposal_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            idempotency_digest,
            proposal_digest,
            scope_digest,
            registration_digest,
            recording_digest,
            replayed,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.idempotency_digest.validate()?;
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        if self.recording_digest
            != Self::new(
                self.idempotency_digest.clone(),
                self.proposal_digest.clone(),
                self.scope_digest.clone(),
                self.registration_digest.clone(),
                self.replayed,
            )
            .recording_digest
        {
            return Err(DaggerPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerPipelineRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

pub type DaggerRegistration = DaggerPipelineRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_registration_digest: Digest,
    pub new_registration_digest: Digest,
    pub registration_revision: Revision,
}

impl DaggerPipelineRegistration {
    pub(crate) fn new(
        scope: &DaggerPipelineScope,
        secret_reference: &SecretReference,
        consent: &ConsentScope,
        provider_digest: Digest,
        permission_snapshot: &DaggerPermissionSnapshot,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate_for_scope(scope)?;
        consent.validate()?;
        permission_snapshot.validate()?;
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest,
            permission_snapshot_digest: permission_snapshot.digest(),
            consent_digest: consent.digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: Revision(1),
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("pending"),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "dagger-registration/v1",
            &[
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot_digest.as_str().to_owned(),
                ),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_snapshot_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        self.registration_digest.validate()?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != PROVIDER_API_REVISION
            || self.registration_digest != self.calculate_digest()
            || self.registration_revision.get() == 0
        {
            return Err(DaggerPipelineResultError::InvalidRegistration);
        }
        Ok(())
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransitionEvidence> {
        let previous_status = self.status;
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(DaggerPipelineResultError::RevisionOverflow)?,
        );
        self.status = new_status;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            new_status,
            previous_registration_digest,
            new_registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Active {
            return Err(DaggerPipelineResultError::RegistrationInactive);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Revoked {
            return Err(DaggerPipelineResultError::RegistrationInactive);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(DaggerPipelineResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Dagger typed value serializes");
    Digest::from_bytes(&bytes)
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub const ALLOWLISTED_READ_OPERATIONS: [&str; 3] = [
    "read_module_metadata",
    "read_pipeline_result",
    "read_artifact_metadata",
];

pub const FORBIDDEN_OPERATIONS: [&str; 9] = [
    "execute_pipeline",
    "cancel_pipeline",
    "registry_mutation",
    "raw_log_read",
    "shell_output_read",
    "artifact_bytes_read",
    "secret_export",
    "external_write",
    "outcome_adoption",
];

#[allow(dead_code)]
const _MODEL_BOUNDARY_IDS: [&str; 3] = [SERVICE_ID, CONSUMER_ID, PLUGIN_VERSION];

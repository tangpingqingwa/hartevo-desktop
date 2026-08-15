use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{MeltanoPipelineResultError, Result};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, MAX_CURSOR_BYTES, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_METADATA_ITEMS, MAX_RETRY_AFTER_SECONDS, MAX_SECRET_REFERENCE_BYTES, MAX_TASKS,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
};

pub const MAX_MEDIA_TYPE_BYTES: usize = 128;

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
            Err(MeltanoPipelineResultError::InvalidDigest)
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
            Err(MeltanoPipelineResultError::InvalidDigest)
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

fn valid_secret_handle(value: &str) -> bool {
    valid_text(value, MAX_SECRET_REFERENCE_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'#' | b'%')
        })
}

fn valid_cursor_handle(value: &str) -> bool {
    valid_text(value, MAX_CURSOR_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'#' | b'%')
        })
}

macro_rules! redacted_identifier {
    ($name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(MeltanoPipelineResultError::InvalidIdentifier { field: $field })
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
                if valid_identifier(&self.0) {
                    Ok(())
                } else {
                    Err(MeltanoPipelineResultError::InvalidIdentifier { field: $field })
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

redacted_identifier!(MeltanoWorkspaceId, "meltano-workspace/v1", "workspace");
redacted_identifier!(
    MeltanoProjectId,
    "meltano-cloud-project/v1",
    "cloud-project"
);
redacted_identifier!(
    MeltanoEnvironmentId,
    "meltano-environment/v1",
    "environment"
);
redacted_identifier!(MeltanoPipelineId, "meltano-pipeline/v1", "pipeline");
redacted_identifier!(MeltanoJobId, "meltano-job/v1", "job");
redacted_identifier!(MeltanoPluginName, "meltano-plugin/v1", "plugin");
redacted_identifier!(MeltanoStateId, "meltano-state-id/v1", "state-id");
redacted_identifier!(ProjectId, "hartevo-project/v1", "project");
redacted_identifier!(MissionId, "hartevo-mission/v1", "mission");
redacted_identifier!(WorkProductId, "hartevo-work-product/v1", "work-product");

pub type WorkspaceId = MeltanoWorkspaceId;
pub type CloudProjectId = MeltanoProjectId;
pub type EnvironmentId = MeltanoEnvironmentId;
pub type PipelineId = MeltanoPipelineId;
pub type JobId = MeltanoJobId;
pub type PluginName = MeltanoPluginName;
pub type StateId = MeltanoStateId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(MeltanoPipelineResultError::InvalidRevision { field: "revision" })
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
pub type StateRevision = Revision;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeltanoPipelineStatus {
    Draft,
    Ready,
    Provisioning,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeltanoJobType {
    WorkspaceInit,
    PipelineConfig,
    PipelineVerify,
    PipelineRun,
    ProfileCollaborate,
    ProfileImport,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeltanoJobStatus {
    Queued,
    Running,
    Complete,
    Error,
    Stopped,
    Unknown,
}

impl MeltanoJobStatus {
    #[allow(non_upper_case_globals)]
    pub const Succeeded: Self = Self::Complete;
    #[allow(non_upper_case_globals)]
    pub const Failed: Self = Self::Error;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeltanoEvidenceState {
    Queued,
    Running,
    Success,
    Error,
    Stopped,
    Partial,
    RateLimited,
    Expired,
    AccessLoss,
    BlockedEnv,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

impl MeltanoEvidenceState {
    #[allow(non_upper_case_globals)]
    pub const Succeeded: Self = Self::Success;
    #[allow(non_upper_case_globals)]
    pub const Failed: Self = Self::Error;
    #[allow(non_upper_case_globals)]
    pub const Tampered: Self = Self::Tamper;
    #[allow(non_upper_case_globals)]
    pub const RegistrationRevoked: Self = Self::Revoked;

    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Error
                | Self::Stopped
                | Self::Partial
                | Self::RateLimited
                | Self::Expired
                | Self::AccessLoss
                | Self::BlockedEnv
                | Self::ProviderUnknown
                | Self::Tamper
                | Self::Stale
                | Self::Revoked
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }

    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Success)
    }

    #[must_use]
    pub const fn review_eligible(self) -> bool {
        self.is_terminal() && matches!(self, Self::Success | Self::Error | Self::Stopped)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeltanoTransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

pub type TransportProvenance = MeltanoTransportProvenance;

impl MeltanoTransportProvenance {
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
pub struct MeltanoPipelineResultScope {
    workspace: MeltanoWorkspaceId,
    cloud_project: MeltanoProjectId,
    environment: MeltanoEnvironmentId,
    pipeline: MeltanoPipelineId,
    job: Option<MeltanoJobId>,
    plugin: Option<MeltanoPluginName>,
    state_id: Option<MeltanoStateId>,
    project: ProjectId,
    project_revision: ProjectRevision,
    mission: MissionId,
    mission_revision: MissionRevision,
    work_product: WorkProductId,
    work_product_revision: WorkProductRevision,
    scope_revision: ScopeRevision,
    scope_digest: Digest,
}

pub type MeltanoScope = MeltanoPipelineResultScope;
pub type MeltanoPipelineScope = MeltanoPipelineResultScope;

impl MeltanoPipelineResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: MeltanoWorkspaceId,
        cloud_project: MeltanoProjectId,
        environment: MeltanoEnvironmentId,
        pipeline: MeltanoPipelineId,
        job: Option<MeltanoJobId>,
        plugin: Option<MeltanoPluginName>,
        state_id: Option<MeltanoStateId>,
        project: ProjectId,
        project_revision: u64,
        mission: MissionId,
        mission_revision: u64,
        work_product: WorkProductId,
        work_product_revision: u64,
        scope_revision: u64,
    ) -> Result<Self> {
        let scope = Self {
            workspace,
            cloud_project,
            environment,
            pipeline,
            job,
            plugin,
            state_id,
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
        workspace: impl Into<String>,
        cloud_project: impl Into<String>,
        environment: impl Into<String>,
        pipeline: impl Into<String>,
        job: Option<String>,
        plugin: Option<String>,
        state_id: Option<String>,
        project: impl Into<String>,
        project_revision: u64,
        mission: impl Into<String>,
        mission_revision: u64,
        work_product: impl Into<String>,
        work_product_revision: u64,
        scope_revision: u64,
    ) -> Result<Self> {
        Self::new(
            MeltanoWorkspaceId::new(workspace)?,
            MeltanoProjectId::new(cloud_project)?,
            MeltanoEnvironmentId::new(environment)?,
            MeltanoPipelineId::new(pipeline)?,
            job.map(MeltanoJobId::new).transpose()?,
            plugin.map(MeltanoPluginName::new).transpose()?,
            state_id.map(MeltanoStateId::new).transpose()?,
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
        self.workspace.validate()?;
        self.cloud_project.validate()?;
        self.environment.validate()?;
        self.pipeline.validate()?;
        self.job.as_ref().map(MeltanoJobId::validate).transpose()?;
        self.plugin
            .as_ref()
            .map(MeltanoPluginName::validate)
            .transpose()?;
        self.state_id
            .as_ref()
            .map(MeltanoStateId::validate)
            .transpose()?;
        if self.state_id.is_some() && self.plugin.is_none() {
            return Err(MeltanoPipelineResultError::InvalidScope);
        }
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-scope/v1",
            &[
                ("workspace", self.workspace.digest().as_str().to_owned()),
                (
                    "cloud_project",
                    self.cloud_project.digest().as_str().to_owned(),
                ),
                ("environment", self.environment.digest().as_str().to_owned()),
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                (
                    "job",
                    self.job
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "plugin",
                    self.plugin
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "state_id",
                    self.state_id
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
            return Err(MeltanoPipelineResultError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn workspace(&self) -> &MeltanoWorkspaceId {
        &self.workspace
    }

    #[must_use]
    pub fn cloud_project(&self) -> &MeltanoProjectId {
        &self.cloud_project
    }

    #[must_use]
    pub fn environment(&self) -> &MeltanoEnvironmentId {
        &self.environment
    }

    #[must_use]
    pub fn pipeline(&self) -> &MeltanoPipelineId {
        &self.pipeline
    }

    #[must_use]
    pub fn job(&self) -> Option<&MeltanoJobId> {
        self.job.as_ref()
    }

    #[must_use]
    pub fn plugin(&self) -> Option<&MeltanoPluginName> {
        self.plugin.as_ref()
    }

    #[must_use]
    pub fn state_id(&self) -> Option<&MeltanoStateId> {
        self.state_id.as_ref()
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SecretReferenceKind {
    ApiToken,
}

/// Opaque, non-serializing reference to a Layer-2 API token.
///
/// The constructor accepts only a handle and retains its digest, never the
/// handle or credential material itself.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
}

impl SecretReference {
    pub fn new(
        reference_handle: impl Into<String>,
        scope: &MeltanoPipelineResultScope,
        revision: u64,
    ) -> Result<Self> {
        Self::api_token(reference_handle, scope, revision)
    }

    pub fn api_token(
        reference_handle: impl Into<String>,
        scope: &MeltanoPipelineResultScope,
        revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        let reference_handle = reference_handle.into();
        if !valid_secret_handle(&reference_handle) {
            return Err(MeltanoPipelineResultError::InvalidSecretReference);
        }
        let revision = Revision::new(revision)?;
        Ok(Self {
            kind: SecretReferenceKind::ApiToken,
            reference_digest: Digest::from_parts(
                "meltano-secret-reference/v1",
                &[
                    ("kind", "api_token".to_owned()),
                    ("handle", reference_handle),
                ],
            ),
            scope_digest: scope.digest(),
            revision,
        })
    }

    pub fn token(
        reference_handle: impl Into<String>,
        scope: &MeltanoPipelineResultScope,
        revision: u64,
    ) -> Result<Self> {
        Self::api_token(reference_handle, scope, revision)
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
    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate_for_scope(&self, scope: &MeltanoPipelineResultScope) -> Result<()> {
        scope.validate()?;
        self.reference_digest.validate()?;
        if self.scope_digest != scope.digest() || self.revision.get() == 0 {
            return Err(MeltanoPipelineResultError::ScopeMismatch);
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

#[derive(Clone, Eq, PartialEq)]
pub struct MeltanoCursor {
    cursor_digest: Digest,
    scope_digest: Digest,
    page: u16,
}

impl MeltanoCursor {
    pub fn new(
        handle: impl Into<String>,
        scope: &MeltanoPipelineResultScope,
        page: u16,
    ) -> Result<Self> {
        Self::from_handle(handle, scope, page)
    }

    pub fn from_handle(
        handle: impl Into<String>,
        scope: &MeltanoPipelineResultScope,
        page: u16,
    ) -> Result<Self> {
        scope.validate()?;
        let handle = handle.into();
        if !valid_cursor_handle(&handle) || page == 0 {
            return Err(MeltanoPipelineResultError::InvalidCursor);
        }
        Ok(Self {
            cursor_digest: Digest::from_parts(
                "meltano-cursor/v1",
                &[("handle", handle), ("page", page.to_string())],
            ),
            scope_digest: scope.digest(),
            page,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.cursor_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn page(&self) -> u16 {
        self.page
    }

    pub fn validate_for_scope(&self, scope: &MeltanoPipelineResultScope) -> Result<()> {
        scope.validate()?;
        self.cursor_digest.validate()?;
        if self.scope_digest != scope.digest() || self.page == 0 {
            return Err(MeltanoPipelineResultError::ScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for MeltanoCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeltanoCursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page", &self.page)
            .finish()
    }
}

impl Serialize for MeltanoCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("cursor:{}", &self.cursor_digest.as_str()[..16]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoPermissionSnapshot {
    permissions: BTreeSet<String>,
    permission_digest: Digest,
}

impl MeltanoPermissionSnapshot {
    #[must_use]
    pub fn layer_one() -> Self {
        let permissions = [
            "meltano:pipeline:read",
            "meltano:pipeline:list",
            "meltano:job:read",
            "meltano:job:list",
            "meltano:state:read",
            "meltano:config:digest:read",
            "meltano:pagination:read",
            "mission.scope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let permission_digest = Digest::from_parts(
            "meltano-permissions/v1",
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
        if *self == Self::layer_one() {
            Ok(())
        } else {
            Err(MeltanoPipelineResultError::InvalidPermissionSnapshot)
        }
    }
}

pub type PermissionSnapshot = MeltanoPermissionSnapshot;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoConfigMetadata {
    pub config_digest: Digest,
    pub setting_count: u16,
    pub sensitive_setting_count: u16,
    pub plugin_digest: Option<Digest>,
    pub state_id_digest: Option<Digest>,
    pub updated_at_epoch_seconds: u64,
    pub metadata_digest: Digest,
}

impl MeltanoConfigMetadata {
    pub fn new(
        config_digest: Digest,
        setting_count: u16,
        sensitive_setting_count: u16,
        plugin_digest: Option<Digest>,
        state_id_digest: Option<Digest>,
        updated_at_epoch_seconds: u64,
    ) -> Result<Self> {
        if sensitive_setting_count > setting_count
            || usize::from(setting_count) > MAX_METADATA_ITEMS
        {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        config_digest.validate()?;
        if let Some(digest) = &plugin_digest {
            digest.validate()?;
        }
        if let Some(digest) = &state_id_digest {
            digest.validate()?;
        }
        let mut metadata = Self {
            config_digest,
            setting_count,
            sensitive_setting_count,
            plugin_digest,
            state_id_digest,
            updated_at_epoch_seconds,
            metadata_digest: Digest::from_text("pending"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    pub fn from_entries(
        entries: &BTreeMap<String, Digest>,
        sensitive_setting_count: u16,
        plugin_digest: Option<Digest>,
        state_id_digest: Option<Digest>,
        updated_at_epoch_seconds: u64,
    ) -> Result<Self> {
        let config_digest = config_digest_from_entries(entries)?;
        Self::new(
            config_digest,
            u16::try_from(entries.len()).map_err(|_| MeltanoPipelineResultError::BoundsExceeded)?,
            sensitive_setting_count,
            plugin_digest,
            state_id_digest,
            updated_at_epoch_seconds,
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-config-metadata/v1",
            &[
                ("config", self.config_digest.as_str().to_owned()),
                ("settings", self.setting_count.to_string()),
                ("sensitive", self.sensitive_setting_count.to_string()),
                (
                    "plugin",
                    self.plugin_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "state_id",
                    self.state_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("updated_at", self.updated_at_epoch_seconds.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.config_digest.validate()?;
        self.plugin_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.state_id_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.sensitive_setting_count > self.setting_count
            || usize::from(self.setting_count) > MAX_METADATA_ITEMS
            || self.metadata_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub fn config_digest_from_entries(entries: &BTreeMap<String, Digest>) -> Result<Digest> {
    if entries.len() > MAX_METADATA_ITEMS {
        return Err(MeltanoPipelineResultError::BoundsExceeded);
    }
    let mut fields = Vec::with_capacity(entries.len());
    for (index, (key, digest)) in entries.iter().enumerate() {
        if !valid_text(key, MAX_IDENTIFIER_BYTES, false) {
            return Err(MeltanoPipelineResultError::InvalidText {
                field: "config_key",
            });
        }
        digest.validate()?;
        fields.push(("entry", format!("{index}:{key}:{}", digest.as_str())));
    }
    Ok(Digest::from_parts("meltano-config/v1", &fields))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoStateMetadata {
    pub state_id_digest: Digest,
    pub state_digest: Digest,
    pub state_revision: StateRevision,
    pub singer_bookmark_count: u16,
    pub incremental: bool,
    pub updated_at_epoch_seconds: u64,
    pub metadata_digest: Digest,
}

impl MeltanoStateMetadata {
    pub fn new(
        state_id: &MeltanoStateId,
        state_digest: Digest,
        state_revision: u64,
        singer_bookmark_count: u16,
        incremental: bool,
        updated_at_epoch_seconds: u64,
    ) -> Result<Self> {
        state_id.validate()?;
        state_digest.validate()?;
        if usize::from(singer_bookmark_count) > MAX_METADATA_ITEMS {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        let mut metadata = Self {
            state_id_digest: state_id.digest(),
            state_digest,
            state_revision: Revision::new(state_revision)?,
            singer_bookmark_count,
            incremental,
            updated_at_epoch_seconds,
            metadata_digest: Digest::from_text("pending"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-state-metadata/v1",
            &[
                ("state_id", self.state_id_digest.as_str().to_owned()),
                ("state", self.state_digest.as_str().to_owned()),
                ("revision", self.state_revision.get().to_string()),
                ("bookmarks", self.singer_bookmark_count.to_string()),
                ("incremental", self.incremental.to_string()),
                ("updated_at", self.updated_at_epoch_seconds.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.state_id_digest.validate()?;
        self.state_digest.validate()?;
        if usize::from(self.singer_bookmark_count) > MAX_METADATA_ITEMS
            || self.metadata_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoPipelineMetadata {
    pub pipeline_digest: Digest,
    pub name_digest: Digest,
    pub status: MeltanoPipelineStatus,
    pub schedule_digest: Option<Digest>,
    pub timeout_seconds: u32,
    pub max_retries: u8,
    pub created_at_epoch_seconds: u64,
    pub last_modified_epoch_seconds: u64,
    pub data_component_count: u16,
    pub action_count: u16,
    pub config_digest: Option<Digest>,
    pub state_id_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl MeltanoPipelineMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &MeltanoPipelineResultScope,
        name_handle: impl Into<String>,
        status: MeltanoPipelineStatus,
        schedule_handle: Option<String>,
        timeout_seconds: u32,
        max_retries: u8,
        created_at_epoch_seconds: u64,
        last_modified_epoch_seconds: u64,
        data_component_count: u16,
        action_count: u16,
        config_digest: Option<Digest>,
        state_id_digest: Option<Digest>,
    ) -> Result<Self> {
        scope.validate()?;
        let name_handle = name_handle.into();
        if !valid_identifier(&name_handle)
            || usize::from(data_component_count) > MAX_METADATA_ITEMS
            || usize::from(action_count) > MAX_METADATA_ITEMS
            || max_retries > 32
        {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        let schedule_digest = schedule_handle.map(Digest::from_text);
        if let Some(digest) = &config_digest {
            digest.validate()?;
        }
        if let Some(digest) = &state_id_digest {
            digest.validate()?;
        }
        let mut metadata = Self {
            pipeline_digest: scope.pipeline.digest(),
            name_digest: Digest::from_text(name_handle),
            status,
            schedule_digest,
            timeout_seconds,
            max_retries,
            created_at_epoch_seconds,
            last_modified_epoch_seconds,
            data_component_count,
            action_count,
            config_digest,
            state_id_digest,
            metadata_digest: Digest::from_text("pending"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    pub fn for_scope(
        scope: &MeltanoPipelineResultScope,
        status: MeltanoPipelineStatus,
    ) -> Result<Self> {
        Self::new(
            scope,
            scope.pipeline.as_str(),
            status,
            None,
            300,
            0,
            0,
            0,
            0,
            0,
            None,
            scope.state_id().map(MeltanoStateId::digest),
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-pipeline-metadata/v1",
            &[
                ("pipeline", self.pipeline_digest.as_str().to_owned()),
                ("name", self.name_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "schedule",
                    self.schedule_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("timeout", self.timeout_seconds.to_string()),
                ("max_retries", self.max_retries.to_string()),
                ("created", self.created_at_epoch_seconds.to_string()),
                ("modified", self.last_modified_epoch_seconds.to_string()),
                ("components", self.data_component_count.to_string()),
                ("actions", self.action_count.to_string()),
                (
                    "config",
                    self.config_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "state_id",
                    self.state_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.pipeline_digest.validate()?;
        self.schedule_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.config_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.state_id_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if usize::from(self.data_component_count) > MAX_METADATA_ITEMS
            || usize::from(self.action_count) > MAX_METADATA_ITEMS
            || self.max_retries > 32
            || self.metadata_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoJobMetadata {
    pub job_digest: Digest,
    pub pipeline_digest: Digest,
    pub job_type: MeltanoJobType,
    pub status: MeltanoJobStatus,
    pub exit_code: Option<i32>,
    pub created_at_epoch_seconds: u64,
    pub start_time_epoch_seconds: Option<u64>,
    pub end_time_epoch_seconds: Option<u64>,
    pub attempt: u8,
    pub state_digest: Option<Digest>,
    pub config_digest: Option<Digest>,
    pub task_count: u16,
    pub metadata_digest: Digest,
}

impl MeltanoJobMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &MeltanoPipelineResultScope,
        job_type: MeltanoJobType,
        status: MeltanoJobStatus,
        exit_code: Option<i32>,
        created_at_epoch_seconds: u64,
        start_time_epoch_seconds: Option<u64>,
        end_time_epoch_seconds: Option<u64>,
        attempt: u8,
        state_digest: Option<Digest>,
        config_digest: Option<Digest>,
        task_count: u16,
    ) -> Result<Self> {
        scope.validate()?;
        let job = scope
            .job()
            .ok_or(MeltanoPipelineResultError::InvalidScope)?;
        if usize::from(task_count) > usize::from(MAX_TASKS) || attempt > 32 {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        if let Some(start) = start_time_epoch_seconds {
            if start < created_at_epoch_seconds {
                return Err(MeltanoPipelineResultError::InvalidText {
                    field: "start_time",
                });
            }
        }
        if let (Some(start), Some(end)) = (start_time_epoch_seconds, end_time_epoch_seconds) {
            if end < start {
                return Err(MeltanoPipelineResultError::InvalidText { field: "end_time" });
            }
        }
        state_digest.as_ref().map(Digest::validate).transpose()?;
        config_digest.as_ref().map(Digest::validate).transpose()?;
        let mut metadata = Self {
            job_digest: job.digest(),
            pipeline_digest: scope.pipeline.digest(),
            job_type,
            status,
            exit_code,
            created_at_epoch_seconds,
            start_time_epoch_seconds,
            end_time_epoch_seconds,
            attempt,
            state_digest,
            config_digest,
            task_count,
            metadata_digest: Digest::from_text("pending"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    pub fn for_scope(scope: &MeltanoPipelineResultScope, status: MeltanoJobStatus) -> Result<Self> {
        Self::new(
            scope,
            MeltanoJobType::PipelineRun,
            status,
            match status {
                MeltanoJobStatus::Error => Some(1),
                _ => Some(0),
            },
            0,
            Some(0),
            Some(0),
            1,
            None,
            None,
            1,
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-job-metadata/v1",
            &[
                ("job", self.job_digest.as_str().to_owned()),
                ("pipeline", self.pipeline_digest.as_str().to_owned()),
                ("type", format!("{:?}", self.job_type)),
                ("status", format!("{:?}", self.status)),
                (
                    "exit_code",
                    self.exit_code
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("created", self.created_at_epoch_seconds.to_string()),
                (
                    "start",
                    self.start_time_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "end",
                    self.end_time_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("attempt", self.attempt.to_string()),
                (
                    "state",
                    self.state_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "config",
                    self.config_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("tasks", self.task_count.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.job_digest.validate()?;
        self.pipeline_digest.validate()?;
        self.state_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.config_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if usize::from(self.task_count) > usize::from(MAX_TASKS)
            || self.attempt > 32
            || self.metadata_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoRetryReceipt {
    pub attempt: u8,
    pub max_retries: u8,
    pub retry_after_seconds: Option<u32>,
    pub retryable: bool,
    pub receipt_digest: Digest,
}

impl MeltanoRetryReceipt {
    pub fn new(
        attempt: u8,
        max_retries: u8,
        retry_after_seconds: Option<u32>,
        retryable: bool,
    ) -> Result<Self> {
        if attempt == 0
            || attempt > 32
            || max_retries > 32
            || attempt > max_retries.saturating_add(1)
        {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        if retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS) {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        let receipt_digest = Digest::from_parts(
            "meltano-retry/v1",
            &[
                ("attempt", attempt.to_string()),
                ("max_retries", max_retries.to_string()),
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
                ("retryable", retryable.to_string()),
            ],
        );
        Ok(Self {
            attempt,
            max_retries,
            retry_after_seconds,
            retryable,
            receipt_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.attempt,
            self.max_retries,
            self.retry_after_seconds,
            self.retryable,
        )?;
        if self.receipt_digest != expected.receipt_digest {
            Err(MeltanoPipelineResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoRateLimitReceipt {
    pub retry_after_seconds: Option<u32>,
    pub observed_at_epoch_seconds: u64,
    pub receipt_digest: Digest,
}

impl MeltanoRateLimitReceipt {
    pub fn new(retry_after_seconds: Option<u32>, observed_at_epoch_seconds: u64) -> Result<Self> {
        if retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS) {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        let receipt_digest = Digest::from_parts(
            "meltano-rate-limit/v1",
            &[
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
                ("observed_at", observed_at_epoch_seconds.to_string()),
            ],
        );
        Ok(Self {
            retry_after_seconds,
            observed_at_epoch_seconds,
            receipt_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.retry_after_seconds, self.observed_at_epoch_seconds)?;
        if self.receipt_digest != expected.receipt_digest {
            Err(MeltanoPipelineResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoFailureReceipt {
    pub category: String,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub retryable: bool,
}

impl MeltanoFailureReceipt {
    pub fn new(
        category: impl Into<String>,
        status_code: Option<u16>,
        diagnostic: impl AsRef<str>,
        retryable: bool,
    ) -> Result<Self> {
        let category = category.into();
        if !valid_text(&category, MAX_IDENTIFIER_BYTES, false)
            || !valid_text(diagnostic.as_ref(), MAX_DIAGNOSTIC_BYTES, true)
        {
            return Err(MeltanoPipelineResultError::InvalidText { field: "failure" });
        }
        Ok(Self {
            category,
            status_code,
            diagnostic_digest: Digest::from_text(diagnostic.as_ref()),
            retryable,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.category, MAX_IDENTIFIER_BYTES, false) {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        self.diagnostic_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoObservationReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub transport: MeltanoTransportProvenance,
    pub observed_at_epoch_seconds: u64,
    pub receipt_digest: Digest,
}

impl MeltanoObservationReceipt {
    #[must_use]
    pub fn new(
        request_digest: Digest,
        response_digest: Digest,
        status_code: Option<u16>,
        transport: MeltanoTransportProvenance,
        observed_at_epoch_seconds: u64,
    ) -> Self {
        let receipt_digest = Digest::from_parts(
            "meltano-observation/v1",
            &[
                ("request", request_digest.as_str().to_owned()),
                ("response", response_digest.as_str().to_owned()),
                (
                    "status",
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
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub pipeline_digest: Digest,
    pub job_digest: Option<Digest>,
    pub plugin_digest: Option<Digest>,
    pub state_id_digest: Option<Digest>,
    pub state_digest: Option<Digest>,
    pub config_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl MeltanoEvidenceDigests {
    fn components_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-evidence-components/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("pipeline", self.pipeline_digest.as_str().to_owned()),
                (
                    "job",
                    self.job_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "plugin",
                    self.plugin_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "state_id",
                    self.state_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "state",
                    self.state_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "config",
                    self.config_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoPipelineEvidence {
    pub state: MeltanoEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub transport: MeltanoTransportProvenance,
    pub pipeline: Option<MeltanoPipelineMetadata>,
    pub job: Option<MeltanoJobMetadata>,
    pub state_metadata: Option<MeltanoStateMetadata>,
    pub config: Option<MeltanoConfigMetadata>,
    pub next_cursor: Option<MeltanoCursor>,
    pub has_more: bool,
    pub retry: Option<MeltanoRetryReceipt>,
    pub rate_limit: Option<MeltanoRateLimitReceipt>,
    pub failure: Option<MeltanoFailureReceipt>,
    pub observation_receipt: MeltanoObservationReceipt,
    pub evidence_digests: MeltanoEvidenceDigests,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub evidence_digest: Digest,
}

impl MeltanoPipelineEvidence {
    pub(crate) fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("transport", format!("{:?}", self.transport)),
                (
                    "pipeline",
                    self.pipeline.as_ref().map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
                ),
                (
                    "job",
                    self.job.as_ref().map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
                ),
                (
                    "state_metadata",
                    self.state_metadata
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.metadata_digest.as_str().to_owned()
                        }),
                ),
                (
                    "config",
                    self.config.as_ref().map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("has_more", self.has_more.to_string()),
                (
                    "retry",
                    self.retry.as_ref().map_or_else(String::new, |value| {
                        value.receipt_digest.as_str().to_owned()
                    }),
                ),
                (
                    "rate_limit",
                    self.rate_limit.as_ref().map_or_else(String::new, |value| {
                        value.receipt_digest.as_str().to_owned()
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        canonical_digest(value).as_str().to_owned()
                    }),
                ),
                (
                    "receipt",
                    self.observation_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "components",
                    self.evidence_digests
                        .components_digest()
                        .as_str()
                        .to_owned(),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                (
                    "durable_provider_receipt",
                    self.durable_provider_receipt.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self, scope: &MeltanoPipelineResultScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        self.request_digest.validate()?;
        self.observation_receipt.validate()?;
        self.evidence_digests.plugin_version_digest.validate()?;
        self.evidence_digests.contract_digest.validate()?;
        self.evidence_digests.provider_digest.validate()?;
        self.evidence_digests.permission_digest.validate()?;
        self.evidence_digests.scope_digest.validate()?;
        self.evidence_digests.secret_reference_digest.validate()?;
        self.evidence_digests.pipeline_digest.validate()?;
        self.evidence_digests
            .job_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digests
            .plugin_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digests
            .state_id_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digests
            .state_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digests
            .config_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digests
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digests.evidence_digest.validate()?;
        if self.scope_digest != scope.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.evidence_digests.scope_digest != scope.digest()
            || self.evidence_digests.pipeline_digest != scope.pipeline.digest()
            || self.evidence_digests.job_digest != scope.job.as_ref().map(MeltanoJobId::digest)
            || self.evidence_digests.plugin_digest
                != scope.plugin.as_ref().map(MeltanoPluginName::digest)
            || self.evidence_digests.state_id_digest
                != scope.state_id.as_ref().map(MeltanoStateId::digest)
            || self.evidence_digests.evidence_digest != self.evidence_digest
            || self.evidence_digest != self.calculate_evidence_digest()
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.scope_digest != scope.digest())
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for_scope(scope)?;
        }
        if let Some(pipeline) = &self.pipeline {
            pipeline.validate()?;
            if pipeline.pipeline_digest != scope.pipeline.digest() {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        if let Some(job) = &self.job {
            job.validate()?;
            if job.pipeline_digest != scope.pipeline.digest()
                || scope.job.as_ref().map(MeltanoJobId::digest) != Some(job.job_digest.clone())
            {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        if let Some(state) = &self.state_metadata {
            state.validate()?;
            if scope.state_id.as_ref().map(MeltanoStateId::digest)
                != Some(state.state_id_digest.clone())
            {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        if let Some(config) = &self.config {
            config.validate()?;
        }
        if let Some(retry) = &self.retry {
            retry.validate()?;
        }
        if let Some(rate_limit) = &self.rate_limit {
            rate_limit.validate()?;
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        let expected_state_digest = self
            .state_metadata
            .as_ref()
            .map(|value| value.state_digest.clone())
            .or_else(|| {
                self.job
                    .as_ref()
                    .and_then(|value| value.state_digest.clone())
            });
        let expected_config_digest = self
            .config
            .as_ref()
            .map(|value| value.config_digest.clone())
            .or_else(|| {
                self.pipeline
                    .as_ref()
                    .and_then(|value| value.config_digest.clone())
            })
            .or_else(|| {
                self.job
                    .as_ref()
                    .and_then(|value| value.config_digest.clone())
            });
        let expected_cursor_digest = self.next_cursor.as_ref().map(MeltanoCursor::digest);
        if self.has_more && self.next_cursor.is_none() {
            return Err(MeltanoPipelineResultError::PartialEvidence);
        }
        if self.evidence_digests.state_digest != expected_state_digest
            || self.evidence_digests.config_digest != expected_config_digest
            || self.evidence_digests.cursor_digest != expected_cursor_digest
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoPipelineResultProposal {
    pub proposal_digest: Digest,
    pub evidence: MeltanoPipelineEvidence,
    pub state: MeltanoEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_revision: Revision,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

pub type MeltanoProposal = MeltanoPipelineResultProposal;

impl MeltanoPipelineResultProposal {
    pub(crate) fn new(evidence: MeltanoPipelineEvidence) -> Self {
        let proposal_revision = Revision(1);
        let proposal_digest = Digest::from_parts(
            "meltano-proposal/v1",
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

    pub fn validate_integrity(&self, scope: &MeltanoPipelineResultScope) -> Result<()> {
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
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        let expected = Self::new(self.evidence.clone());
        if expected.proposal_digest != self.proposal_digest
            || expected.proposal_revision != self.proposal_revision
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoRecordingReceipt {
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
}

impl MeltanoRecordingReceipt {
    pub(crate) fn new(
        idempotency_digest: Digest,
        proposal_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
        replayed: bool,
    ) -> Self {
        let recording_digest = Digest::from_parts(
            "meltano-recording/v1",
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
        let expected = Self::new(
            self.idempotency_digest.clone(),
            self.proposal_digest.clone(),
            self.scope_digest.clone(),
            self.registration_digest.clone(),
            self.replayed,
        );
        if self.recording_digest != expected.recording_digest {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
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
pub struct MeltanoRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub status: RegistrationStatus,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
}

pub type MeltanoPipelineRegistration = MeltanoRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_registration_digest: Digest,
    pub new_registration_digest: Digest,
    pub registration_revision: Revision,
}

impl MeltanoRegistration {
    pub(crate) fn new(
        scope: &MeltanoPipelineResultScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
        permission_snapshot: &MeltanoPermissionSnapshot,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate_for_scope(scope)?;
        permission_snapshot.validate()?;
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest,
            permission_snapshot_digest: permission_snapshot.digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: Revision(1),
            status: RegistrationStatus::Active,
            evidence_digest: Digest::from_text("pending"),
            registration_digest: Digest::from_text("pending"),
        };
        registration.evidence_digest = registration.calculate_evidence_digest();
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-registration-evidence/v1",
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

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "meltano-registration/v1",
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
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                ("evidence", self.evidence_digest.as_str().to_owned()),
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
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        self.evidence_digest.validate()?;
        self.registration_digest.validate()?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != PROVIDER_API_REVISION
            || self.registration_revision.get() == 0
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::InvalidRegistration);
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
                .ok_or(MeltanoPipelineResultError::RevisionOverflow)?,
        );
        self.status = new_status;
        self.evidence_digest = self.calculate_evidence_digest();
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
            return Err(MeltanoPipelineResultError::RegistrationInactive);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Revoked {
            return Err(MeltanoPipelineResultError::RegistrationInactive);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(MeltanoPipelineResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Meltano typed value serializes");
    Digest::from_bytes(&bytes)
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub const ALLOWLISTED_READ_OPERATIONS: [&str; 6] = [
    "list_pipelines",
    "read_pipeline_metadata",
    "list_jobs",
    "read_job_metadata",
    "read_state_metadata",
    "read_config_digest",
];

pub const FORBIDDEN_OPERATIONS: [&str; 13] = [
    "execute_pipeline",
    "cancel_pipeline",
    "stop_job",
    "delete_job",
    "install_plugin",
    "mutate_pipeline",
    "mutate_environment",
    "mutate_state",
    "raw_log_read",
    "raw_row_read",
    "raw_state_blob_read",
    "secret_export",
    "outcome_adoption",
];

#[allow(dead_code)]
const _MODEL_BOUNDARY_IDS: [&str; 3] = [SERVICE_ID, CONSUMER_ID, PLUGIN_VERSION];

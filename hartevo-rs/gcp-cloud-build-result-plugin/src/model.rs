//! Bounded typed models for the Google Cloud Build list/get seam.
//!
//! Provider JSON is intentionally not represented as a public model. The
//! provider parses only the allowlisted fields and turns all other input into
//! a response digest or drops it at the redaction boundary.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_CLOUD_BUILD_CONTRACT_VERSION, GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT,
    GCP_CLOUD_BUILD_PROVIDER_ID, GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT,
    GCP_CLOUD_BUILD_SCHEMA_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SOURCE_REPOSITORY_BYTES: usize = 512;
pub const MAX_OPAQUE_PAGE_TOKEN_BYTES: usize = 4_096;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_BUILDS: usize = 500;
pub const MAX_STEPS_PER_BUILD: usize = 256;
pub const MAX_ARTIFACTS_PER_BUILD: usize = 64;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// A lowercase SHA-256 digest used at every cross-boundary seam.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    #[must_use]
    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded Cloud Build value serializes");
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest { field })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        64
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains control characters or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is outside the Layer-1 bound")]
    OutsideBound { field: &'static str },
    #[error("permission scope is not exactly the read-only Cloud Build list/get scope")]
    InvalidPermission,
    #[error("consent scope is not read-only")]
    InvalidConsent,
    #[error("source scope is invalid")]
    InvalidSource,
    #[error("build timing is inconsistent")]
    InvalidTiming,
    #[error("provider payload is malformed or outside the allowlist")]
    InvalidProviderPayload,
    #[error("provider payload drifted from the bound project, location, or build")]
    ScopeDrift,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret reference is not revoked")]
    NotRevoked,
    #[error("revision overflowed")]
    RevisionOverflow,
}

fn validate_text(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'=')
    }) {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $maximum:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $maximum, false)?;
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
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

bounded_identifier!(ProjectId, "Google Cloud project id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(Location, "Google Cloud location", MAX_IDENTIFIER_BYTES);
bounded_identifier!(BuildId, "Cloud Build id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(TriggerId, "Cloud Build trigger id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(MissionId, "Mission id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WorkProductId, "Work Product id", MAX_IDENTIFIER_BYTES);

pub type GcpProjectId = ProjectId;
pub type GcpBuildId = BuildId;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceRepository(String);

impl SourceRepository {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(
            &value,
            "source repository",
            MAX_SOURCE_REPOSITORY_BYTES,
            false,
        )?;
        if value.contains('?') || value.contains('#') || value.contains('\0') {
            return Err(ModelError::InvalidSource);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for SourceRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SourceRepository")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for SourceRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceCommit(String);

impl SourceCommit {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "source commit", 128, false)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        {
            return Err(ModelError::InvalidSource);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for SourceCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SourceCommit")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for SourceCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    project_id: String,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            project_id: id.into(),
            revision: Revision::new(revision)?,
        })
        .and_then(|binding| {
            validate_identifier(&binding.project_id, "Hartevo project id")?;
            Ok(binding)
        })
    }

    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    mission_id: MissionId,
    revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            mission_id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    work_product_id: WorkProductId,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            work_product_id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceScope {
    repository: SourceRepository,
    commit: SourceCommit,
}

impl SourceScope {
    pub fn new(
        repository: impl Into<String>,
        commit: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            repository: SourceRepository::new(repository)?,
            commit: SourceCommit::new(commit)?,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_typed(repository: SourceRepository, commit: SourceCommit) -> Self {
        Self { repository, commit }
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.repository.as_str().is_empty() || self.commit.as_str().is_empty() {
            return Err(ModelError::InvalidSource);
        }
        Ok(())
    }

    #[must_use]
    pub fn repository(&self) -> &SourceRepository {
        &self.repository
    }

    #[must_use]
    pub fn commit(&self) -> &SourceCommit {
        &self.commit
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum BuildSelector {
    Any,
    Exact { build_id: BuildId },
}

impl BuildSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    #[must_use]
    pub fn exact(id: impl Into<String>) -> Self {
        Self::Exact {
            build_id: BuildId::new(id).expect("BuildSelector::exact receives a valid build id"),
        }
    }

    pub fn try_exact(id: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Exact {
            build_id: BuildId::new(id)?,
        })
    }

    #[must_use]
    pub fn build_id(&self) -> Option<&BuildId> {
        match self {
            Self::Any => None,
            Self::Exact { build_id } => Some(build_id),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn matches(&self, id: &BuildId) -> bool {
        self.build_id().is_none_or(|expected| expected == id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    BuildsList,
    BuildsGet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    actions: BTreeSet<PermissionAction>,
    digest: Digest,
}

impl PermissionScope {
    pub fn new(actions: BTreeSet<PermissionAction>) -> Result<Self, ModelError> {
        if actions.len() != 2
            || !actions.contains(&PermissionAction::BuildsList)
            || !actions.contains(&PermissionAction::BuildsGet)
        {
            return Err(ModelError::InvalidPermission);
        }
        let digest = Digest::from_serializable(&actions);
        Ok(Self { actions, digest })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new(BTreeSet::from([
            PermissionAction::BuildsGet,
            PermissionAction::BuildsList,
        ]))
        .expect("the built-in Cloud Build read scope is valid")
    }

    #[must_use]
    pub fn actions(&self) -> &BTreeSet<PermissionAction> {
        &self.actions
    }

    #[must_use]
    pub fn allows(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.actions.clone()).map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

pub type GcpCloudBuildPermission = PermissionScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    reference_digest: Digest,
    revision: Revision,
    read_only: bool,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(reference: impl AsRef<[u8]>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty() || reference.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        let reference_digest = Digest::from_bytes(reference);
        let digest = Digest::from_serializable(&(&reference_digest, revision, true));
        Ok(Self {
            reference_digest,
            revision,
            read_only: true,
            digest,
        })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new("gcp-cloud-build-read-only", 1)
            .expect("the built-in Cloud Build consent is valid")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.read_only {
            return Err(ModelError::InvalidConsent);
        }
        if !is_digest(self.reference_digest.as_str()) || !is_digest(self.digest.as_str()) {
            return Err(ModelError::InvalidConsent);
        }
        Ok(())
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

/// The only credential value the Layer-1 provider can hold is an opaque
/// handle. It is intentionally neither serializable nor deserializable.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    handle: String,
    reference_digest: Digest,
    scope_digest: Option<Digest>,
    revision: Revision,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    Opaque,
    OAuth,
    ServiceAccount,
}

impl SecretReference {
    pub fn new(handle: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::build(SecretReferenceKind::Opaque, handle.into(), revision, None)
    }

    pub fn oauth(handle: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::build(SecretReferenceKind::OAuth, handle.into(), revision, None)
    }

    pub fn service_account(handle: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::build(
            SecretReferenceKind::ServiceAccount,
            handle.into(),
            revision,
            None,
        )
    }

    pub fn for_scope(
        handle: impl Into<String>,
        revision: u64,
        scope_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::build(
            SecretReferenceKind::Opaque,
            handle.into(),
            revision,
            Some(scope_digest),
        )
    }

    fn build(
        kind: SecretReferenceKind,
        handle: String,
        revision: u64,
        scope_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        validate_text(
            &handle,
            "opaque secret reference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let revision = Revision::new(revision)?;
        let reference_digest = Digest::from_serializable(&(&kind, &handle, revision));
        Ok(Self {
            kind,
            handle,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
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
    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            return Err(ModelError::NotRevoked);
        }
        self.revoked = false;
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
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudBuildScope {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub gcp_project: ProjectId,
    pub location: Location,
    pub build_selector: BuildSelector,
    pub trigger: Option<TriggerId>,
    pub source: SourceScope,
    pub permission: PermissionScope,
    pub consent: ConsentScope,
}

impl GcpCloudBuildScope {
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        build_selector: BuildSelector,
        trigger: Option<impl Into<String>>,
        source: SourceScope,
        permission: PermissionScope,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project,
            mission,
            work_product,
            gcp_project: ProjectId::new(gcp_project)?,
            location: Location::new(location)?,
            build_selector,
            trigger: trigger.map(|value| TriggerId::new(value)).transpose()?,
            source,
            permission,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn read_only(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        build_selector: BuildSelector,
        trigger: Option<impl Into<String>>,
        source: SourceScope,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            project,
            mission,
            work_product,
            gcp_project,
            location,
            build_selector,
            trigger,
            source,
            PermissionScope::read_only(),
            consent,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permission.validate()?;
        self.consent.validate()?;
        self.source.validate()?;
        if self.project.revision().get() == 0
            || self.mission.revision().get() == 0
            || self.work_product.revision().get() == 0
        {
            return Err(ModelError::MustBePositive {
                field: "binding revision",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest()
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    #[must_use]
    pub fn source_digest(&self) -> Digest {
        self.source.digest()
    }

    #[must_use]
    pub fn trigger_digest(&self) -> Option<Digest> {
        self.trigger.as_ref().map(Digest::from_serializable)
    }

    #[must_use]
    pub fn mission_revision(&self) -> Revision {
        self.mission.revision()
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.gcp_project
    }

    #[must_use]
    pub fn build_id(&self) -> Option<&BuildId> {
        self.build_selector.build_id()
    }
}

pub type GcpCloudBuildResultScope = GcpCloudBuildScope;
pub type CloudBuildScope = GcpCloudBuildScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudBuildStatus {
    Queued,
    Working,
    Success,
    Failure,
    InternalError,
    Timeout,
    Cancelled,
    Expired,
    #[serde(other)]
    Unknown,
}

impl CloudBuildStatus {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_uppercase().as_str() {
            "QUEUED" => Self::Queued,
            "WORKING" => Self::Working,
            "SUCCESS" => Self::Success,
            "FAILURE" => Self::Failure,
            "INTERNAL_ERROR" => Self::InternalError,
            "TIMEOUT" => Self::Timeout,
            "CANCELLED" => Self::Cancelled,
            "EXPIRED" => Self::Expired,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Working | Self::Unknown)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Working => "WORKING",
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::InternalError => "INTERNAL_ERROR",
            Self::Timeout => "TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::Expired => "EXPIRED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudBuildStepStatus {
    Queued,
    Working,
    Success,
    Failure,
    InternalError,
    Timeout,
    Cancelled,
    Expired,
    #[serde(other)]
    Unknown,
}

impl CloudBuildStepStatus {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match CloudBuildStatus::parse(value) {
            CloudBuildStatus::Queued => Self::Queued,
            CloudBuildStatus::Working => Self::Working,
            CloudBuildStatus::Success => Self::Success,
            CloudBuildStatus::Failure => Self::Failure,
            CloudBuildStatus::InternalError => Self::InternalError,
            CloudBuildStatus::Timeout => Self::Timeout,
            CloudBuildStatus::Cancelled => Self::Cancelled,
            CloudBuildStatus::Expired => Self::Expired,
            CloudBuildStatus::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Stale,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

impl EvidenceState {
    #[must_use]
    pub const fn is_provider_failure(self) -> bool {
        !matches!(self, Self::Complete | Self::Partial | Self::Stale)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudBuildOperation {
    List,
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ContainerImage,
    Object,
    Generic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub kind: ArtifactKind,
    pub reference_digest: Digest,
    pub size_bytes: Option<u64>,
}

impl ArtifactMetadata {
    pub fn new(
        kind: ArtifactKind,
        reference: impl AsRef<[u8]>,
        size_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty() || reference.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::InvalidProviderPayload);
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_bytes(reference),
            size_bytes,
        })
    }

    pub fn from_digest(
        kind: ArtifactKind,
        reference_digest: Digest,
        size_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        Digest::parse(reference_digest.as_str().to_owned(), "artifact reference")?;
        Ok(Self {
            kind,
            reference_digest,
            size_bytes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildStepDigest {
    pub ordinal: u16,
    pub status: CloudBuildStepStatus,
    pub result_digest: Digest,
}

impl BuildStepDigest {
    pub fn new(
        ordinal: usize,
        status: CloudBuildStepStatus,
        result_digest: Digest,
    ) -> Result<Self, ModelError> {
        let ordinal = u16::try_from(ordinal).map_err(|_| ModelError::OutsideBound {
            field: "step ordinal",
        })?;
        Digest::parse(result_digest.as_str().to_owned(), "step result")?;
        Ok(Self {
            ordinal,
            status,
            result_digest,
        })
    }

    pub fn from_safe_fields(
        ordinal: usize,
        status: CloudBuildStepStatus,
        step_name: Option<&str>,
        result: Option<&serde_json::Value>,
    ) -> Result<Self, ModelError> {
        let name_digest = step_name.map(Digest::from_text);
        let result_digest = Digest::from_serializable(&(ordinal, status, name_digest, result));
        Self::new(ordinal, status, result_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBuildSummary {
    pub build_id: BuildId,
    pub project_id: ProjectId,
    pub location: Location,
    pub trigger_id: Option<TriggerId>,
    pub source_repository: Option<SourceRepository>,
    pub source_commit: Option<SourceCommit>,
    pub status: CloudBuildStatus,
    pub duration_seconds: Option<u64>,
    pub artifact_metadata: Vec<ArtifactMetadata>,
    pub step_digests: Vec<BuildStepDigest>,
    pub result_digest: Digest,
}

impl CloudBuildSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        build_id: BuildId,
        project_id: ProjectId,
        location: Location,
        trigger_id: Option<TriggerId>,
        source_repository: Option<SourceRepository>,
        source_commit: Option<SourceCommit>,
        status: CloudBuildStatus,
        duration_seconds: Option<u64>,
        mut artifact_metadata: Vec<ArtifactMetadata>,
        mut step_digests: Vec<BuildStepDigest>,
    ) -> Result<Self, ModelError> {
        if artifact_metadata.len() > MAX_ARTIFACTS_PER_BUILD {
            return Err(ModelError::OutsideBound {
                field: "artifacts per build",
            });
        }
        if step_digests.len() > MAX_STEPS_PER_BUILD {
            return Err(ModelError::OutsideBound {
                field: "steps per build",
            });
        }
        artifact_metadata.sort_by(|left, right| {
            left.reference_digest
                .cmp(&right.reference_digest)
                .then(left.kind.cmp(&right.kind))
        });
        step_digests.sort_by_key(|step| step.ordinal);
        if step_digests
            .windows(2)
            .any(|window| window[0].ordinal == window[1].ordinal)
        {
            return Err(ModelError::InvalidProviderPayload);
        }
        let mut summary = Self {
            build_id,
            project_id,
            location,
            trigger_id,
            source_repository,
            source_commit,
            status,
            duration_seconds,
            artifact_metadata,
            step_digests,
            result_digest: Digest::from_text("placeholder"),
        };
        summary.result_digest = summary.compute_result_digest();
        Ok(summary)
    }

    fn compute_result_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.build_id,
            &self.project_id,
            &self.location,
            &self.trigger_id,
            &self.source_repository,
            &self.source_commit,
            self.status,
            self.duration_seconds,
            &self.artifact_metadata,
            &self.step_digests,
        ))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.result_digest.clone()
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.result_digest == self.compute_result_digest()
    }

    #[must_use]
    pub fn source_matches_scope(&self, scope: &GcpCloudBuildScope) -> Option<bool> {
        match (&self.source_repository, &self.source_commit) {
            (Some(repository), Some(commit)) => {
                Some(repository == scope.source.repository() && commit == scope.source.commit())
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn matches_scope(&self, scope: &GcpCloudBuildScope) -> bool {
        self.project_id == scope.gcp_project
            && self.location == scope.location
            && scope.build_selector.matches(&self.build_id)
            && scope
                .trigger
                .as_ref()
                .is_none_or(|trigger| self.trigger_id.as_ref() == Some(trigger))
            && self.source_matches_scope(scope) == Some(true)
    }
}

pub type CloudBuildResult = CloudBuildSummary;
pub type BuildResult = CloudBuildSummary;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBuildRequestReceipt {
    pub operation: CloudBuildOperation,
    pub method: String,
    pub path: String,
    pub project_digest: Digest,
    pub location_digest: Digest,
    pub build_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBuildResponseReceipt {
    pub status_code: u16,
    pub body_digest: Digest,
    pub body_bytes: usize,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudBuildEvidence {
    pub operation: CloudBuildOperation,
    pub state: EvidenceState,
    pub builds: Vec<CloudBuildSummary>,
    pub request_receipts: Vec<CloudBuildRequestReceipt>,
    pub response_receipts: Vec<CloudBuildResponseReceipt>,
    pub next_page_token_digest: Option<Digest>,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub source_digest: Digest,
    pub trigger_digest: Option<Digest>,
    pub mission_revision: Revision,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub proposal_only: bool,
    pub digests: EvidenceDigests,
    pub evidence_digest: Digest,
}

impl GcpCloudBuildEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: CloudBuildOperation,
        state: EvidenceState,
        builds: Vec<CloudBuildSummary>,
        request_receipts: Vec<CloudBuildRequestReceipt>,
        response_receipts: Vec<CloudBuildResponseReceipt>,
        next_page_token_digest: Option<Digest>,
        registration_digest: Digest,
        scope: &GcpCloudBuildScope,
    ) -> Self {
        let provider_digest = Digest::from_serializable(&(
            GCP_CLOUD_BUILD_SCHEMA_VERSION,
            GCP_CLOUD_BUILD_PROVIDER_ID,
            GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT,
        ));
        Self::new_with_provider_digest(
            operation,
            state,
            builds,
            request_receipts,
            response_receipts,
            next_page_token_digest,
            registration_digest,
            provider_digest,
            scope,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_provider_digest(
        operation: CloudBuildOperation,
        state: EvidenceState,
        mut builds: Vec<CloudBuildSummary>,
        request_receipts: Vec<CloudBuildRequestReceipt>,
        response_receipts: Vec<CloudBuildResponseReceipt>,
        next_page_token_digest: Option<Digest>,
        registration_digest: Digest,
        provider_digest: Digest,
        scope: &GcpCloudBuildScope,
    ) -> Self {
        builds.sort_by(|left, right| left.build_id.cmp(&right.build_id));
        let request_digest = Digest::from_serializable(&request_receipts);
        let response_digest = canonical_response_digest(&response_receipts);
        let result_digest = Digest::from_serializable(&builds);
        let permission_digest = scope.permission_digest();
        let scope_digest = scope.scope_digest();
        let digests = EvidenceDigests {
            provider_digest: provider_digest.clone(),
            permission_digest: permission_digest.clone(),
            scope_digest: scope_digest.clone(),
            request_digest: request_digest.clone(),
            response_digest: response_digest.clone(),
            result_digest: result_digest.clone(),
            evidence_digest: Digest::from_text("placeholder"),
        };
        let mut evidence = Self {
            operation,
            state,
            builds,
            request_receipts,
            response_receipts,
            next_page_token_digest,
            registration_digest,
            provider_digest,
            permission_digest,
            scope_digest,
            source_digest: scope.source_digest(),
            trigger_digest: scope.trigger_digest(),
            mission_revision: scope.mission_revision(),
            native: false,
            connected: false,
            first_party: false,
            outcome_authority: false,
            work_product_adoption: false,
            proposal_only: true,
            digests,
            evidence_digest: Digest::from_text("placeholder"),
        };
        let digest = evidence.compute_evidence_digest();
        evidence.evidence_digest = digest.clone();
        evidence.digests.evidence_digest = digest;
        evidence
    }

    #[must_use]
    pub fn compute_evidence_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct EvidenceDigestInput<'a> {
            operation: CloudBuildOperation,
            state: EvidenceState,
            builds: &'a [CloudBuildSummary],
            request_receipts: &'a [CloudBuildRequestReceipt],
            response_receipts: Vec<CanonicalResponseReceipt<'a>>,
            next_page_token_digest: &'a Option<Digest>,
            registration_digest: &'a Digest,
            provider_digest: &'a Digest,
            permission_digest: &'a Digest,
            scope_digest: &'a Digest,
            source_digest: &'a Digest,
            trigger_digest: &'a Option<Digest>,
            mission_revision: Revision,
            native: bool,
            connected: bool,
            first_party: bool,
            outcome_authority: bool,
            work_product_adoption: bool,
            proposal_only: bool,
            digest_provider: &'a Digest,
            digest_permission: &'a Digest,
            digest_scope: &'a Digest,
            digest_request: &'a Digest,
            digest_response: &'a Digest,
            digest_result: &'a Digest,
        }
        Digest::from_serializable(&EvidenceDigestInput {
            operation: self.operation,
            state: self.state,
            builds: &self.builds,
            request_receipts: &self.request_receipts,
            response_receipts: canonical_response_receipts(&self.response_receipts),
            next_page_token_digest: &self.next_page_token_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            source_digest: &self.source_digest,
            trigger_digest: &self.trigger_digest,
            mission_revision: self.mission_revision,
            native: self.native,
            connected: self.connected,
            first_party: self.first_party,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
            proposal_only: self.proposal_only,
            digest_provider: &self.digests.provider_digest,
            digest_permission: &self.digests.permission_digest,
            digest_scope: &self.digests.scope_digest,
            digest_request: &self.digests.request_digest,
            digest_response: &self.digests.response_digest,
            digest_result: &self.digests.result_digest,
        })
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.builds.iter().all(CloudBuildSummary::verify_digest)
            && self.evidence_digest == self.compute_evidence_digest()
            && self.digests.evidence_digest == self.evidence_digest
            && self.digests.provider_digest == self.provider_digest
            && self.digests.permission_digest == self.permission_digest
            && self.digests.scope_digest == self.scope_digest
            && self.digests.request_digest == Digest::from_serializable(&self.request_receipts)
            && self.digests.response_digest == canonical_response_digest(&self.response_receipts)
            && self.digests.result_digest == Digest::from_serializable(&self.builds)
            && !self.native
            && !self.connected
            && !self.first_party
            && !self.outcome_authority
            && !self.work_product_adoption
            && self.proposal_only
    }
}

#[derive(Serialize)]
struct CanonicalResponseReceipt<'a> {
    status_code: u16,
    response_digest: &'a Digest,
}

fn canonical_response_receipts(
    receipts: &[CloudBuildResponseReceipt],
) -> Vec<CanonicalResponseReceipt<'_>> {
    receipts
        .iter()
        .map(|receipt| CanonicalResponseReceipt {
            status_code: receipt.status_code,
            response_digest: &receipt.response_digest,
        })
        .collect()
}

fn canonical_response_digest(receipts: &[CloudBuildResponseReceipt]) -> Digest {
    Digest::from_serializable(&canonical_response_receipts(receipts))
}

pub type GcpCloudBuildResultEvidence = GcpCloudBuildEvidence;
pub type CloudBuildEvidence = GcpCloudBuildEvidence;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBuildObservationRecord {
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub observation_revision: Revision,
    pub observation_digest: Digest,
}

impl CloudBuildObservationRecord {
    pub fn new(evidence: &GcpCloudBuildEvidence, revision: Revision) -> Self {
        let observation_digest = Digest::from_serializable(&(
            &evidence.evidence_digest,
            &evidence.registration_digest,
            revision,
        ));
        Self {
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            observation_revision: revision,
            observation_digest,
        }
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.observation_digest
            == Digest::from_serializable(&(
                &self.evidence_digest,
                &self.registration_digest,
                self.observation_revision,
            ))
    }
}

pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT)
}

pub fn contract_metadata_digest() -> Digest {
    Digest::from_serializable(&(
        GCP_CLOUD_BUILD_SCHEMA_VERSION,
        GCP_CLOUD_BUILD_CONTRACT_VERSION,
        GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT,
    ))
}

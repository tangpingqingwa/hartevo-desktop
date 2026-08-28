use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;
pub const MAX_QUERY_BYTES: usize = 512;
pub const MAX_ITEMS: usize = 100;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_BACKOFF_SECONDS: u32 = 300;
pub const MAX_ATTEMPTS: u8 = 5;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded Aha value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("Aha permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Aha API-token reference is invalid")]
    InvalidSecretReference,
    #[error("Aha scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Aha roadmap request is invalid or outside its exact scope")]
    InvalidRequest,
    #[error("Aha roadmap aggregate is invalid or exceeds the Layer-1 bound")]
    InvalidAggregate,
    #[error("Aha pagination cursor is invalid or not bound to its request")]
    InvalidCursor,
    #[error("Aha registration is already revoked")]
    AlreadyRevoked,
    #[error("Aha registration or secret is not revoked")]
    NotRevoked,
    #[error("Aha registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/$~".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_revision(value: u64, label: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_digest(value: &str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "identifier")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub(crate) fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        validate_identifier(&self.0, label)
    }
}

pub type AccountId = Identifier;
pub type WorkspaceId = Identifier;
pub type ProductLineId = Identifier;
pub type InitiativeId = Identifier;
pub type ReleaseId = Identifier;
pub type FeatureId = Identifier;
pub type RequirementId = Identifier;

pub type AhaAccountId = AccountId;
pub type AhaWorkspaceId = WorkspaceId;
pub type AhaProductLineId = ProductLineId;
pub type AhaInitiativeId = InitiativeId;
pub type AhaReleaseId = ReleaseId;
pub type AhaFeatureId = FeatureId;
pub type AhaRequirementId = RequirementId;
pub type AhaAccount = AccountId;
pub type AhaWorkspace = WorkspaceId;
pub type AhaProductLine = ProductLineId;
pub type AhaInitiative = InitiativeId;
pub type AhaRelease = ReleaseId;
pub type AhaFeature = FeatureId;
pub type AhaRequirement = RequirementId;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeBinding {
    id: Identifier,
    revision: Revision,
}

impl ScopeBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub(crate) fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        self.id.validate(label)?;
        validate_revision(self.revision.get(), label)
    }
}

pub type ProjectBinding = ScopeBinding;
pub type MissionBinding = ScopeBinding;
pub type WorkProductBinding = ScopeBinding;
pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;
pub type AhaProject = Project;
pub type AhaMission = Mission;
pub type AhaWorkProduct = WorkProduct;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AhaPermission {
    AccountRead,
    WorkspaceRead,
    ProductLineRead,
    InitiativeRead,
    ReleaseRead,
    FeatureRead,
    RequirementRead,
}

impl AhaPermission {
    #[must_use]
    pub const fn for_resource(kind: AhaResourceKind) -> Self {
        match kind {
            AhaResourceKind::Account => Self::AccountRead,
            AhaResourceKind::Workspace => Self::WorkspaceRead,
            AhaResourceKind::ProductLine => Self::ProductLineRead,
            AhaResourceKind::Initiative => Self::InitiativeRead,
            AhaResourceKind::Release => Self::ReleaseRead,
            AhaResourceKind::Feature => Self::FeatureRead,
            AhaResourceKind::Requirement => Self::RequirementRead,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaPermissionSnapshot {
    permissions: BTreeSet<AhaPermission>,
    revision: Revision,
    read_only: bool,
}

impl AhaPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = AhaPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let snapshot = Self {
            permissions: permissions.into_iter().collect(),
            revision: Revision::new(revision)?,
            read_only: true,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                AhaPermission::AccountRead,
                AhaPermission::WorkspaceRead,
                AhaPermission::ProductLineRead,
                AhaPermission::InitiativeRead,
                AhaPermission::ReleaseRead,
                AhaPermission::FeatureRead,
                AhaPermission::RequirementRead,
            ],
            revision,
        )
    }

    #[must_use]
    pub fn has(&self, permission: AhaPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<AhaPermission> {
        &self.permissions
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.read_only || self.permissions.is_empty() {
            return Err(ModelError::InvalidPermissionSnapshot);
        }
        validate_revision(self.revision.get(), "permission")
    }
}

/// A token reference stores only a digest of an external secret handle.
///
/// The API token itself is never accepted, retained, serialized, or forwarded
/// by this Layer-1 crate. Deliberately, this type has no serde implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(api_token_reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        let reference = api_token_reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_SECRET_REFERENCE_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: sha256_digest(
                format!("aha-api-token-reference/v1|{reference}").as_bytes(),
            ),
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn api_token(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        Self::new(reference, revision)
    }

    pub fn from_digest(
        reference_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_digest = reference_digest.into();
        validate_digest(&reference_digest)?;
        Ok(Self {
            reference_digest,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "aha-secret-reference/v1|{}|{}|{}",
                self.reference_digest,
                self.revision.get(),
                self.revoked
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            Err(ModelError::NotRevoked)
        } else {
            self.revoked = false;
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("api_token_reference", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AhaResourceKind {
    Account,
    Workspace,
    ProductLine,
    Initiative,
    Release,
    Feature,
    Requirement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AhaRoadmapOperation {
    AccountMetadata,
    WorkspaceMetadata,
    ProductLineMetadata,
    InitiativeMetadata,
    ReleaseMetadata,
    FeatureMetadata,
    RequirementMetadata,
    RoadmapAggregate,
}

impl AhaRoadmapOperation {
    #[must_use]
    pub const fn resource_kind(self) -> AhaResourceKind {
        match self {
            Self::AccountMetadata => AhaResourceKind::Account,
            Self::WorkspaceMetadata => AhaResourceKind::Workspace,
            Self::ProductLineMetadata => AhaResourceKind::ProductLine,
            Self::InitiativeMetadata | Self::RoadmapAggregate => AhaResourceKind::Initiative,
            Self::ReleaseMetadata => AhaResourceKind::Release,
            Self::FeatureMetadata => AhaResourceKind::Feature,
            Self::RequirementMetadata => AhaResourceKind::Requirement,
        }
    }

    #[must_use]
    pub const fn permission(self) -> AhaPermission {
        AhaPermission::for_resource(self.resource_kind())
    }

    #[must_use]
    pub const fn is_collection(self) -> bool {
        matches!(self, Self::RoadmapAggregate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapScopeSpec {
    pub account: AccountId,
    pub workspace: WorkspaceId,
    pub product_line: ProductLineId,
    pub initiative: InitiativeId,
    pub release: ReleaseId,
    pub feature: FeatureId,
    pub requirement: RequirementId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permissions: AhaPermissionSnapshot,
    pub scope_revision: Revision,
}

#[allow(clippy::too_many_arguments)]
impl AhaRoadmapScopeSpec {
    pub fn new(
        account: AccountId,
        workspace: WorkspaceId,
        product_line: ProductLineId,
        initiative: InitiativeId,
        release: ReleaseId,
        feature: FeatureId,
        requirement: RequirementId,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permissions: AhaPermissionSnapshot,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let spec = Self {
            account,
            workspace,
            product_line,
            initiative,
            release,
            feature,
            requirement,
            project,
            mission,
            work_product,
            permissions,
            scope_revision: Revision::new(scope_revision)?,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.account.validate("account")?;
        self.workspace.validate("workspace")?;
        self.product_line.validate("product line")?;
        self.initiative.validate("initiative")?;
        self.release.validate("release")?;
        self.feature.validate("feature")?;
        self.requirement.validate("requirement")?;
        self.project.validate("project")?;
        self.mission.validate("mission")?;
        self.work_product.validate("work product")?;
        self.permissions.validate()?;
        validate_revision(self.scope_revision.get(), "scope")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapScope {
    spec: AhaRoadmapScopeSpec,
    scope_digest: Digest,
    revision_digest: Digest,
}

impl AhaRoadmapScope {
    pub fn new(spec: AhaRoadmapScopeSpec) -> Result<Self, ModelError> {
        spec.validate()?;
        let scope_digest = canonical_digest(&("aha-scope/v1", &spec));
        let revision_digest = canonical_digest(&(
            "aha-revision-fence/v1",
            spec.scope_revision,
            spec.project.revision(),
            spec.mission.revision(),
            spec.work_product.revision(),
            spec.permissions.revision(),
        ));
        Ok(Self {
            spec,
            scope_digest,
            revision_digest,
        })
    }

    #[must_use]
    pub fn spec(&self) -> &AhaRoadmapScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn account(&self) -> &AccountId {
        &self.spec.account
    }

    #[must_use]
    pub fn workspace(&self) -> &WorkspaceId {
        &self.spec.workspace
    }

    #[must_use]
    pub fn product_line(&self) -> &ProductLineId {
        &self.spec.product_line
    }

    #[must_use]
    pub fn initiative(&self) -> &InitiativeId {
        &self.spec.initiative
    }

    #[must_use]
    pub fn release(&self) -> &ReleaseId {
        &self.spec.release
    }

    #[must_use]
    pub fn feature(&self) -> &FeatureId {
        &self.spec.feature
    }

    #[must_use]
    pub fn requirement(&self) -> &RequirementId {
        &self.spec.requirement
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.spec.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.spec.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.spec.work_product
    }

    #[must_use]
    pub fn permissions(&self) -> &AhaPermissionSnapshot {
        &self.spec.permissions
    }

    #[must_use]
    pub const fn scope_revision(&self) -> Revision {
        self.spec.scope_revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permissions().digest()
    }

    #[must_use]
    pub fn project_digest(&self) -> Digest {
        self.project().digest()
    }

    #[must_use]
    pub fn mission_digest(&self) -> Digest {
        self.mission().digest()
    }

    #[must_use]
    pub fn work_product_digest(&self) -> Digest {
        self.work_product().digest()
    }

    #[must_use]
    pub fn resource_digest(&self, kind: AhaResourceKind) -> Digest {
        match kind {
            AhaResourceKind::Account => self.account().digest(),
            AhaResourceKind::Workspace => self.workspace().digest(),
            AhaResourceKind::ProductLine => self.product_line().digest(),
            AhaResourceKind::Initiative => self.initiative().digest(),
            AhaResourceKind::Release => self.release().digest(),
            AhaResourceKind::Feature => self.feature().digest(),
            AhaResourceKind::Requirement => self.requirement().digest(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.spec.validate()?;
        if self.scope_digest != canonical_digest(&("aha-scope/v1", &self.spec))
            || self.revision_digest
                != canonical_digest(&(
                    "aha-revision-fence/v1",
                    self.spec.scope_revision,
                    self.spec.project.revision(),
                    self.spec.mission.revision(),
                    self.spec.work_product.revision(),
                    self.spec.permissions.revision(),
                ))
        {
            return Err(ModelError::InvalidScope("scope or revision digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdempotencyKey {
    digest: Digest,
}

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_QUERY_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            digest: sha256_digest(format!("aha-idempotency-key/v1|{value}").as_bytes()),
        })
    }

    pub fn from_digest(digest: impl Into<String>) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest).map_err(|_| ModelError::InvalidRequest)?;
        Ok(Self { digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Opaque pagination material. Only a digest and its request binding survive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaquePageToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_QUERY_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            digest: sha256_digest(format!("aha-page-token/v1|{value}").as_bytes()),
            binding_digest: None,
        })
    }

    pub fn bound(
        value: impl AsRef<str>,
        binding_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let mut token = Self::new(value)?;
        let binding_digest = binding_digest.into();
        validate_digest(&binding_digest).map_err(|_| ModelError::InvalidCursor)?;
        token.binding_digest = Some(binding_digest);
        Ok(token)
    }

    pub fn from_digest(
        digest: impl Into<String>,
        binding_digest: Option<String>,
    ) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest).map_err(|_| ModelError::InvalidCursor)?;
        if let Some(binding_digest) = &binding_digest {
            validate_digest(binding_digest).map_err(|_| ModelError::InvalidCursor)?;
        }
        Ok(Self {
            digest,
            binding_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapRequest {
    operation: AhaRoadmapOperation,
    target_id_digest: Option<Digest>,
    page_token_digest: Option<Digest>,
    cursor_binding_digest: Option<Digest>,
    page_size: u16,
    scope_digest: Digest,
    revision_digest: Digest,
    permission_digest: Digest,
    idempotency_key_digest: Digest,
}

impl AhaRoadmapRequest {
    pub fn new(
        scope: &AhaRoadmapScope,
        operation: AhaRoadmapOperation,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let target_id_digest = if operation.is_collection() {
            None
        } else {
            Some(scope.resource_digest(operation.resource_kind()))
        };
        Ok(Self {
            operation,
            target_id_digest,
            page_token_digest: None,
            cursor_binding_digest: None,
            page_size: MAX_PAGE_SIZE,
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            permission_digest: scope.permission_digest(),
            idempotency_key_digest: idempotency_key.digest().clone(),
        })
    }

    pub fn account(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, AhaRoadmapOperation::AccountMetadata, idempotency_key)
    }

    pub fn workspace(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            AhaRoadmapOperation::WorkspaceMetadata,
            idempotency_key,
        )
    }

    pub fn product_line(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            AhaRoadmapOperation::ProductLineMetadata,
            idempotency_key,
        )
    }

    pub fn initiative(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            AhaRoadmapOperation::InitiativeMetadata,
            idempotency_key,
        )
    }

    pub fn release(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, AhaRoadmapOperation::ReleaseMetadata, idempotency_key)
    }

    pub fn feature(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, AhaRoadmapOperation::FeatureMetadata, idempotency_key)
    }

    pub fn requirement(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            AhaRoadmapOperation::RequirementMetadata,
            idempotency_key,
        )
    }

    pub fn roadmap(
        scope: &AhaRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            AhaRoadmapOperation::RoadmapAggregate,
            idempotency_key,
        )
    }

    pub fn with_page_size(mut self, page_size: u16) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidRequest);
        }
        self.page_size = page_size;
        Ok(self)
    }

    #[must_use]
    pub fn with_page_token(mut self, page_token: &OpaquePageToken) -> Self {
        let binding_digest = page_token
            .binding_digest()
            .cloned()
            .unwrap_or_else(|| self.cursor_binding_digest());
        self.page_token_digest = Some(page_token.digest().clone());
        self.cursor_binding_digest = Some(binding_digest);
        self
    }

    #[must_use]
    pub const fn operation(&self) -> AhaRoadmapOperation {
        self.operation
    }

    #[must_use]
    pub fn target_id_digest(&self) -> Option<&Digest> {
        self.target_id_digest.as_ref()
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<&Digest> {
        self.page_token_digest.as_ref()
    }

    #[must_use]
    pub fn cursor_binding_digest(&self) -> Digest {
        canonical_digest(&(
            "aha-cursor-binding/v1",
            self.operation,
            &self.target_id_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.permission_digest,
            self.page_size,
        ))
    }

    #[must_use]
    pub fn cursor_binding(&self) -> Option<&Digest> {
        self.cursor_binding_digest.as_ref()
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn idempotency_key_digest(&self) -> &Digest {
        &self.idempotency_key_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self, scope: &AhaRoadmapScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || validate_digest(&self.idempotency_key_digest).is_err()
            || self
                .target_id_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
            || self
                .page_token_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(ModelError::InvalidRequest);
        }
        let expected_target = if self.operation.is_collection() {
            None
        } else {
            Some(scope.resource_digest(self.operation.resource_kind()))
        };
        if self.target_id_digest != expected_target {
            return Err(ModelError::InvalidRequest);
        }
        match (&self.page_token_digest, &self.cursor_binding_digest) {
            (None, None) => Ok(()),
            (Some(_), Some(binding)) if binding == &self.cursor_binding_digest() => Ok(()),
            _ => Err(ModelError::InvalidCursor),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapItem {
    pub kind: AhaResourceKind,
    pub id_digest: Digest,
    pub title_digest: Option<Digest>,
    pub status_digest: Option<Digest>,
    pub child_count: u16,
    pub source_revision: Revision,
}

impl AhaRoadmapItem {
    pub fn new(
        kind: AhaResourceKind,
        id_digest: Digest,
        title_digest: Option<Digest>,
        status_digest: Option<Digest>,
        child_count: u16,
        source_revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_digest(&id_digest)?;
        if title_digest
            .as_ref()
            .is_some_and(|digest| validate_digest(digest).is_err())
            || status_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(ModelError::InvalidAggregate);
        }
        validate_revision(source_revision.get(), "source")?;
        Ok(Self {
            kind,
            id_digest,
            title_digest,
            status_digest,
            child_count,
            source_revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapAggregate {
    pub operation: AhaRoadmapOperation,
    pub items: Vec<AhaRoadmapItem>,
    pub item_count: u16,
    pub total_count: u32,
    pub partial: bool,
    pub target_id_digest: Option<Digest>,
    pub next_page_token_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
}

impl AhaRoadmapAggregate {
    pub fn new(
        operation: AhaRoadmapOperation,
        mut items: Vec<AhaRoadmapItem>,
        total_count: u32,
        partial: bool,
        target_id_digest: Option<Digest>,
        next_page_token_digest: Option<Digest>,
        cursor_binding_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if items.len() > MAX_ITEMS {
            return Err(ModelError::InvalidAggregate);
        }
        if target_id_digest
            .as_ref()
            .is_some_and(|digest| validate_digest(digest).is_err())
            || next_page_token_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
            || cursor_binding_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(ModelError::InvalidAggregate);
        }
        if next_page_token_digest.is_some() != cursor_binding_digest.is_some() {
            return Err(ModelError::InvalidAggregate);
        }
        items.sort_by_key(AhaRoadmapItem::digest);
        let item_count = u16::try_from(items.len()).map_err(|_| ModelError::InvalidAggregate)?;
        if total_count < u32::from(item_count) {
            return Err(ModelError::InvalidAggregate);
        }
        Ok(Self {
            operation,
            items,
            item_count,
            total_count,
            partial,
            target_id_digest,
            next_page_token_digest,
            cursor_binding_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_response_dropped: bool,
    pub raw_api_token_dropped: bool,
    pub raw_titles_dropped: bool,
    pub raw_descriptions_dropped: bool,
    pub raw_urls_dropped: bool,
    pub raw_write_payload_dropped: bool,
}

impl RedactionSummary {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            raw_response_dropped: true,
            raw_api_token_dropped: true,
            raw_titles_dropped: true,
            raw_descriptions_dropped: true,
            raw_urls_dropped: true,
            raw_write_payload_dropped: true,
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.raw_response_dropped
            && self.raw_api_token_dropped
            && self.raw_titles_dropped
            && self.raw_descriptions_dropped
            && self.raw_urls_dropped
            && self.raw_write_payload_dropped
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub backoff_seconds: u32,
    pub attempt: u8,
    pub exhausted: bool,
}

impl Default for AhaRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: Some(MAX_REQUESTS_PER_MINUTE - 1),
            retry_after_seconds: None,
            backoff_seconds: 0,
            attempt: 1,
            exhausted: false,
        }
    }
}

impl AhaRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        backoff_seconds: u32,
        attempt: u8,
        exhausted: bool,
    ) -> Result<Self, ModelError> {
        let receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            backoff_seconds,
            attempt,
            exhausted,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || self
                .remaining
                .is_some_and(|remaining| remaining > self.limit_per_minute)
            || self
                .retry_after_seconds
                .is_some_and(|seconds| seconds > MAX_RETRY_AFTER_SECONDS)
            || self.backoff_seconds > MAX_BACKOFF_SECONDS
            || self.attempt == 0
            || self.attempt > MAX_ATTEMPTS
            || (self.exhausted && self.remaining.is_some_and(|remaining| remaining != 0))
        {
            Err(ModelError::InvalidAggregate)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AhaTransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl AhaTransportProvenance {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AhaEvidenceState {
    Complete,
    Empty,
    Partial,
    RateLimited,
    Timeout,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
    Partial,
    Empty,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

impl From<AhaTransportProvenance> for EvidenceClassification {
    fn from(value: AhaTransportProvenance) -> Self {
        match value {
            AhaTransportProvenance::Fixture => Self::Fixture,
            AhaTransportProvenance::Recording => Self::Recording,
            AhaTransportProvenance::Fake => Self::Fake,
            AhaTransportProvenance::Loopback => Self::Loopback,
            AhaTransportProvenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl AhaRegistration {
    #[must_use]
    pub fn bind(
        scope: &AhaRoadmapScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::AHA_PROVIDER_ID.to_owned(),
            provider_digest: provider_digest.clone(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            evidence_digest: canonical_digest(&(
                "aha-evidence-contract/v1",
                crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION,
                &provider_digest,
                scope.permission_digest(),
                scope.scope_digest(),
                scope.revision_digest(),
            )),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: Revision::new(1).expect("registration revision"),
            registration_digest: String::new(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "aha-registration/v1",
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.evidence_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            self.state,
            self.reversible,
            self.revocable,
        ))
    }

    pub fn validate(
        &self,
        scope: &AhaRoadmapScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        let expected_evidence_digest = canonical_digest(&(
            "aha-evidence-contract/v1",
            crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION,
            provider_digest,
            scope.permission_digest(),
            scope.scope_digest(),
            scope.revision_digest(),
        ));
        if self.plugin_version != crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::AHA_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.evidence_digest != expected_evidence_digest
            || self.secret_reference_digest != secret_reference.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if !self.revocable {
            return Err(ModelError::InvalidScope("registration is not revocable"));
        }
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.reversible {
            return Err(ModelError::InvalidScope("registration is not reversible"));
        }
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

pub type AhaProviderRegistration = AhaRegistration;
pub type AhaRoadmapScopeBinding = ScopeBinding;
pub type AhaPageToken = OpaquePageToken;

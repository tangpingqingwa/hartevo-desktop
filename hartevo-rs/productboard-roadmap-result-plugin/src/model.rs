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
    let bytes = serde_json::to_vec(value).expect("bounded Productboard value serializes");
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
    #[error("Productboard permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Productboard Public API token reference is invalid")]
    InvalidSecretReference,
    #[error("Productboard scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Productboard roadmap request is invalid or outside its exact scope")]
    InvalidRequest,
    #[error("Productboard aggregate is invalid or exceeds the Layer-1 bound")]
    InvalidAggregate,
    #[error("Productboard pagination cursor is invalid or not bound to its request")]
    InvalidCursor,
    #[error("Productboard registration is already revoked")]
    AlreadyRevoked,
    #[error("Productboard registration or secret is not revoked")]
    NotRevoked,
    #[error("Productboard registration revision overflowed")]
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

pub type WorkspaceId = Identifier;
pub type EntityId = Identifier;
pub type ConfigurationId = Identifier;
pub type EntityConfigurationId = Identifier;
pub type NoteId = Identifier;
pub type InsightId = Identifier;
pub type FeatureId = Identifier;
pub type ComponentId = Identifier;
pub type InitiativeId = Identifier;
pub type ObjectiveId = Identifier;
pub type ReleaseId = Identifier;

pub type ProductboardWorkspaceId = WorkspaceId;
pub type ProductboardEntityId = EntityId;
pub type ProductboardConfigurationId = ConfigurationId;
pub type ProductboardEntityConfigurationId = EntityConfigurationId;
pub type ProductboardNoteId = NoteId;
pub type ProductboardInsightId = InsightId;
pub type ProductboardFeatureId = FeatureId;
pub type ProductboardComponentId = ComponentId;
pub type ProductboardInitiativeId = InitiativeId;
pub type ProductboardObjectiveId = ObjectiveId;
pub type ProductboardReleaseId = ReleaseId;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
pub type ProductboardProject = Project;
pub type ProductboardMission = Mission;
pub type ProductboardWorkProduct = WorkProduct;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductboardPermission {
    WorkspaceRead,
    EntityConfigurationRead,
    NoteRead,
    InsightRead,
    FeatureRead,
    ComponentRead,
    InitiativeRead,
    ObjectiveRead,
    ReleaseRead,
    RelationshipRead,
}

impl ProductboardPermission {
    #[must_use]
    pub const fn for_resource(kind: ProductboardResourceKind) -> Self {
        match kind {
            ProductboardResourceKind::Workspace => Self::WorkspaceRead,
            ProductboardResourceKind::EntityConfiguration => Self::EntityConfigurationRead,
            ProductboardResourceKind::Note => Self::NoteRead,
            ProductboardResourceKind::Insight => Self::InsightRead,
            ProductboardResourceKind::Feature => Self::FeatureRead,
            ProductboardResourceKind::Component => Self::ComponentRead,
            ProductboardResourceKind::Initiative => Self::InitiativeRead,
            ProductboardResourceKind::Objective => Self::ObjectiveRead,
            ProductboardResourceKind::Release => Self::ReleaseRead,
            ProductboardResourceKind::Relationship => Self::RelationshipRead,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardPermissionSnapshot {
    permissions: BTreeSet<ProductboardPermission>,
    revision: Revision,
    read_only: bool,
}

impl ProductboardPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = ProductboardPermission>,
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
                ProductboardPermission::WorkspaceRead,
                ProductboardPermission::EntityConfigurationRead,
                ProductboardPermission::NoteRead,
                ProductboardPermission::InsightRead,
                ProductboardPermission::FeatureRead,
                ProductboardPermission::ComponentRead,
                ProductboardPermission::InitiativeRead,
                ProductboardPermission::ObjectiveRead,
                ProductboardPermission::ReleaseRead,
                ProductboardPermission::RelationshipRead,
            ],
            revision,
        )
    }

    #[must_use]
    pub fn has(&self, permission: ProductboardPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<ProductboardPermission> {
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

pub type PermissionSnapshot = ProductboardPermissionSnapshot;

/// A token reference stores only a digest of an external secret handle.
///
/// The Public API token itself is never accepted, retained, serialized, or
/// forwarded by this Layer-1 crate. This type intentionally has no serde
/// implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        public_api_token_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let reference = public_api_token_reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_SECRET_REFERENCE_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: sha256_digest(
                format!("productboard-public-api-token-reference/v1|{reference}").as_bytes(),
            ),
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn public_api_token(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        Self::new(reference, revision)
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
                "productboard-secret-reference/v1|{}|{}|{}",
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
            .field("public_api_token_reference", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductboardResourceKind {
    Workspace,
    EntityConfiguration,
    Note,
    Insight,
    Feature,
    Component,
    Initiative,
    Objective,
    Release,
    Relationship,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductboardRoadmapOperation {
    WorkspaceMetadata,
    EntityConfigurationMetadata,
    NoteConfigurationMetadata,
    NoteCollection,
    NoteMetadata,
    NoteRelationships,
    InsightMetadata,
    InsightRelationships,
    EntityCollection,
    FeatureMetadata,
    ComponentMetadata,
    InitiativeMetadata,
    ObjectiveMetadata,
    ReleaseMetadata,
    EntityRelationships,
    RoadmapAggregate,
}

impl ProductboardRoadmapOperation {
    #[must_use]
    pub const fn permission(self) -> ProductboardPermission {
        match self {
            Self::WorkspaceMetadata => ProductboardPermission::WorkspaceRead,
            Self::EntityConfigurationMetadata | Self::NoteConfigurationMetadata => {
                ProductboardPermission::EntityConfigurationRead
            }
            Self::NoteCollection | Self::NoteMetadata => ProductboardPermission::NoteRead,
            Self::InsightMetadata => ProductboardPermission::InsightRead,
            Self::FeatureMetadata | Self::EntityCollection | Self::RoadmapAggregate => {
                ProductboardPermission::FeatureRead
            }
            Self::ComponentMetadata => ProductboardPermission::ComponentRead,
            Self::InitiativeMetadata => ProductboardPermission::InitiativeRead,
            Self::ObjectiveMetadata => ProductboardPermission::ObjectiveRead,
            Self::ReleaseMetadata => ProductboardPermission::ReleaseRead,
            Self::NoteRelationships | Self::InsightRelationships | Self::EntityRelationships => {
                ProductboardPermission::RelationshipRead
            }
        }
    }

    #[must_use]
    pub const fn resource_kind(self) -> ProductboardResourceKind {
        match self {
            Self::WorkspaceMetadata => ProductboardResourceKind::Workspace,
            Self::EntityConfigurationMetadata | Self::NoteConfigurationMetadata => {
                ProductboardResourceKind::EntityConfiguration
            }
            Self::NoteCollection | Self::NoteMetadata | Self::NoteRelationships => {
                ProductboardResourceKind::Note
            }
            Self::InsightMetadata | Self::InsightRelationships => ProductboardResourceKind::Insight,
            Self::EntityCollection | Self::RoadmapAggregate | Self::FeatureMetadata => {
                ProductboardResourceKind::Feature
            }
            Self::ComponentMetadata => ProductboardResourceKind::Component,
            Self::InitiativeMetadata => ProductboardResourceKind::Initiative,
            Self::ObjectiveMetadata => ProductboardResourceKind::Objective,
            Self::ReleaseMetadata => ProductboardResourceKind::Release,
            Self::EntityRelationships => ProductboardResourceKind::Relationship,
        }
    }

    #[must_use]
    pub const fn target_kind(self) -> Option<ProductboardResourceKind> {
        match self {
            Self::WorkspaceMetadata => Some(ProductboardResourceKind::Workspace),
            Self::EntityConfigurationMetadata
            | Self::NoteConfigurationMetadata
            | Self::NoteCollection
            | Self::EntityCollection
            | Self::RoadmapAggregate => None,
            Self::NoteMetadata | Self::NoteRelationships => Some(ProductboardResourceKind::Note),
            Self::InsightMetadata | Self::InsightRelationships => {
                Some(ProductboardResourceKind::Insight)
            }
            Self::FeatureMetadata | Self::EntityRelationships => {
                Some(ProductboardResourceKind::Feature)
            }
            Self::ComponentMetadata => Some(ProductboardResourceKind::Component),
            Self::InitiativeMetadata => Some(ProductboardResourceKind::Initiative),
            Self::ObjectiveMetadata => Some(ProductboardResourceKind::Objective),
            Self::ReleaseMetadata => Some(ProductboardResourceKind::Release),
        }
    }

    #[must_use]
    pub const fn is_collection(self) -> bool {
        matches!(
            self,
            Self::EntityConfigurationMetadata
                | Self::NoteConfigurationMetadata
                | Self::NoteCollection
                | Self::EntityCollection
                | Self::RoadmapAggregate
                | Self::NoteRelationships
                | Self::InsightRelationships
                | Self::EntityRelationships
        )
    }
}

pub type ProductboardOperation = ProductboardRoadmapOperation;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapScopeSpec {
    pub workspace: WorkspaceId,
    pub entity_configuration: EntityConfigurationId,
    pub note: NoteId,
    pub insight: InsightId,
    pub feature: FeatureId,
    pub component: ComponentId,
    pub initiative: InitiativeId,
    pub objective: ObjectiveId,
    pub release: ReleaseId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permissions: ProductboardPermissionSnapshot,
    pub scope_revision: Revision,
}

#[allow(clippy::too_many_arguments)]
impl ProductboardRoadmapScopeSpec {
    pub fn new(
        workspace: WorkspaceId,
        entity_configuration: EntityConfigurationId,
        note: NoteId,
        insight: InsightId,
        feature: FeatureId,
        component: ComponentId,
        initiative: InitiativeId,
        objective: ObjectiveId,
        release: ReleaseId,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permissions: ProductboardPermissionSnapshot,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let spec = Self {
            workspace,
            entity_configuration,
            note,
            insight,
            feature,
            component,
            initiative,
            objective,
            release,
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
        self.workspace.validate("workspace")?;
        self.entity_configuration.validate("entity configuration")?;
        self.note.validate("note")?;
        self.insight.validate("insight")?;
        self.feature.validate("feature")?;
        self.component.validate("component")?;
        self.initiative.validate("initiative")?;
        self.objective.validate("objective")?;
        self.release.validate("release")?;
        self.project.validate("project")?;
        self.mission.validate("mission")?;
        self.work_product.validate("work product")?;
        self.permissions.validate()?;
        validate_revision(self.scope_revision.get(), "scope")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapScope {
    spec: ProductboardRoadmapScopeSpec,
    scope_digest: Digest,
    revision_digest: Digest,
}

impl ProductboardRoadmapScope {
    pub fn new(spec: ProductboardRoadmapScopeSpec) -> Result<Self, ModelError> {
        spec.validate()?;
        let scope_digest = canonical_digest(&("productboard-scope/v1", &spec));
        let revision_digest = canonical_digest(&(
            "productboard-revision-fence/v1",
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
    pub fn spec(&self) -> &ProductboardRoadmapScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn workspace(&self) -> &WorkspaceId {
        &self.spec.workspace
    }

    #[must_use]
    pub fn entity_configuration(&self) -> &EntityConfigurationId {
        &self.spec.entity_configuration
    }

    #[must_use]
    pub fn entity(&self) -> &EntityConfigurationId {
        self.entity_configuration()
    }

    #[must_use]
    pub fn configuration(&self) -> &EntityConfigurationId {
        self.entity_configuration()
    }

    #[must_use]
    pub fn note(&self) -> &NoteId {
        &self.spec.note
    }

    #[must_use]
    pub fn insight(&self) -> &InsightId {
        &self.spec.insight
    }

    #[must_use]
    pub fn feature(&self) -> &FeatureId {
        &self.spec.feature
    }

    #[must_use]
    pub fn component(&self) -> &ComponentId {
        &self.spec.component
    }

    #[must_use]
    pub fn initiative(&self) -> &InitiativeId {
        &self.spec.initiative
    }

    #[must_use]
    pub fn objective(&self) -> &ObjectiveId {
        &self.spec.objective
    }

    #[must_use]
    pub fn release(&self) -> &ReleaseId {
        &self.spec.release
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
    pub fn permissions(&self) -> &ProductboardPermissionSnapshot {
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
    pub fn resource_digest(&self, kind: ProductboardResourceKind) -> Digest {
        match kind {
            ProductboardResourceKind::Workspace => self.workspace().digest(),
            ProductboardResourceKind::EntityConfiguration => self.entity_configuration().digest(),
            ProductboardResourceKind::Note | ProductboardResourceKind::Relationship => {
                self.note().digest()
            }
            ProductboardResourceKind::Insight => self.insight().digest(),
            ProductboardResourceKind::Feature => self.feature().digest(),
            ProductboardResourceKind::Component => self.component().digest(),
            ProductboardResourceKind::Initiative => self.initiative().digest(),
            ProductboardResourceKind::Objective => self.objective().digest(),
            ProductboardResourceKind::Release => self.release().digest(),
        }
    }

    pub(crate) fn resource_id(&self, kind: ProductboardResourceKind) -> &str {
        match kind {
            ProductboardResourceKind::Workspace => self.workspace().as_str(),
            ProductboardResourceKind::EntityConfiguration => self.entity_configuration().as_str(),
            ProductboardResourceKind::Note | ProductboardResourceKind::Relationship => {
                self.note().as_str()
            }
            ProductboardResourceKind::Insight => self.insight().as_str(),
            ProductboardResourceKind::Feature => self.feature().as_str(),
            ProductboardResourceKind::Component => self.component().as_str(),
            ProductboardResourceKind::Initiative => self.initiative().as_str(),
            ProductboardResourceKind::Objective => self.objective().as_str(),
            ProductboardResourceKind::Release => self.release().as_str(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.spec.validate()?;
        if self.scope_digest != canonical_digest(&("productboard-scope/v1", &self.spec))
            || self.revision_digest
                != canonical_digest(&(
                    "productboard-revision-fence/v1",
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
            digest: sha256_digest(format!("productboard-idempotency-key/v1|{value}").as_bytes()),
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
            digest: sha256_digest(format!("productboard-page-token/v1|{value}").as_bytes()),
            binding_digest: None,
        })
    }

    pub fn bound(value: impl AsRef<str>, binding_digest: Digest) -> Result<Self, ModelError> {
        let mut token = Self::new(value)?;
        validate_digest(&binding_digest)?;
        token.binding_digest = Some(binding_digest);
        Ok(token)
    }

    pub fn from_digest(
        digest: impl Into<String>,
        binding_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest)?;
        if let Some(binding) = &binding_digest {
            validate_digest(binding)?;
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

pub type ProductboardPageToken = OpaquePageToken;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapRequest {
    pub operation: ProductboardRoadmapOperation,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub target_id_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
    pub idempotency_key_digest: Digest,
    pub field_allowlist: Vec<String>,
    pub page_size: u16,
}

impl ProductboardRoadmapRequest {
    pub fn new(
        scope: &ProductboardRoadmapScope,
        operation: ProductboardRoadmapOperation,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        let request = Self {
            operation,
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            permission_digest: scope.permission_digest(),
            target_id_digest: operation
                .target_kind()
                .map(|kind| scope.resource_digest(kind)),
            page_token_digest: None,
            cursor_binding_digest: None,
            idempotency_key_digest: idempotency_key.digest().clone(),
            field_allowlist: default_fields(operation),
            page_size: MAX_PAGE_SIZE,
        };
        request.validate(scope)?;
        Ok(request)
    }

    pub fn workspace(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::WorkspaceMetadata,
            idempotency_key,
        )
    }

    pub fn entity_configuration(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::EntityConfigurationMetadata,
            idempotency_key,
        )
    }

    pub fn note_configuration(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::NoteConfigurationMetadata,
            idempotency_key,
        )
    }

    pub fn configuration(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::entity_configuration(scope, idempotency_key)
    }

    pub fn note(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::NoteMetadata,
            idempotency_key,
        )
    }

    pub fn notes(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::NoteCollection,
            idempotency_key,
        )
    }

    pub fn note_relationships(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::NoteRelationships,
            idempotency_key,
        )
    }

    pub fn insight_relationships(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::InsightRelationships,
            idempotency_key,
        )
    }

    pub fn entity_relationships(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::EntityRelationships,
            idempotency_key,
        )
    }

    pub fn relationships(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::entity_relationships(scope, idempotency_key)
    }

    pub fn insight(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::InsightMetadata,
            idempotency_key,
        )
    }

    pub fn feature(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::FeatureMetadata,
            idempotency_key,
        )
    }

    pub fn component(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::ComponentMetadata,
            idempotency_key,
        )
    }

    pub fn initiative(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::InitiativeMetadata,
            idempotency_key,
        )
    }

    pub fn objective(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::ObjectiveMetadata,
            idempotency_key,
        )
    }

    pub fn release(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::ReleaseMetadata,
            idempotency_key,
        )
    }

    pub fn entities(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::EntityCollection,
            idempotency_key,
        )
    }

    pub fn roadmap(
        scope: &ProductboardRoadmapScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ProductboardRoadmapOperation::RoadmapAggregate,
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

    pub fn with_fields(
        mut self,
        fields: impl IntoIterator<Item = String>,
    ) -> Result<Self, ModelError> {
        let fields: Vec<String> = fields.into_iter().collect();
        if fields.is_empty()
            || fields.len() > 32
            || fields.iter().any(|field| {
                field.is_empty()
                    || field.len() > MAX_IDENTIFIER_BYTES
                    || field.trim() != field
                    || field.chars().any(char::is_control)
                    || !safe_field(field)
            })
        {
            return Err(ModelError::InvalidRequest);
        }
        self.field_allowlist = fields;
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
    pub const fn operation(&self) -> ProductboardRoadmapOperation {
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
            "productboard-cursor-binding/v1",
            self.operation,
            &self.target_id_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.permission_digest,
            &self.field_allowlist,
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

    pub fn validate(&self, scope: &ProductboardRoadmapScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.field_allowlist.is_empty()
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
        let expected_target = self
            .operation
            .target_kind()
            .map(|kind| scope.resource_digest(kind));
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

pub type ProductboardRequest = ProductboardRoadmapRequest;

fn default_fields(operation: ProductboardRoadmapOperation) -> Vec<String> {
    match operation {
        ProductboardRoadmapOperation::NoteConfigurationMetadata
        | ProductboardRoadmapOperation::EntityConfigurationMetadata => {
            vec!["type".to_owned(), "fields".to_owned(), "filters".to_owned()]
        }
        ProductboardRoadmapOperation::NoteRelationships
        | ProductboardRoadmapOperation::InsightRelationships
        | ProductboardRoadmapOperation::EntityRelationships => {
            vec!["type".to_owned(), "target".to_owned()]
        }
        _ => vec![
            "id".to_owned(),
            "type".to_owned(),
            "name".to_owned(),
            "status".to_owned(),
            "archived".to_owned(),
            "parent".to_owned(),
            "links".to_owned(),
        ],
    }
}

fn safe_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    ![
        "body",
        "content",
        "customer",
        "description",
        "email",
        "member",
        "members",
        "owner",
        "pii",
        "token",
        "url",
    ]
    .iter()
    .any(|forbidden| lower == *forbidden || lower.contains(&format!(".{forbidden}")))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapItem {
    pub kind: ProductboardResourceKind,
    pub id_digest: Digest,
    pub title_digest: Option<Digest>,
    pub status_digest: Option<Digest>,
    pub archived: bool,
    pub child_count: u16,
    pub relationship_count: u16,
    pub relationship_digest: Option<Digest>,
    pub content_digest: Option<Digest>,
    pub source_revision: Revision,
}

impl ProductboardRoadmapItem {
    pub fn new(
        kind: ProductboardResourceKind,
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
            archived: false,
            child_count,
            relationship_count: 0,
            relationship_digest: None,
            content_digest: None,
            source_revision,
        })
    }

    #[must_use]
    pub fn with_archived(mut self, archived: bool) -> Self {
        self.archived = archived;
        self
    }

    #[must_use]
    pub fn with_relationships(mut self, count: u16, digest: Option<Digest>) -> Self {
        self.relationship_count = count;
        self.relationship_digest = digest;
        self
    }

    #[must_use]
    pub fn with_content_digest(mut self, digest: Option<Digest>) -> Self {
        self.content_digest = digest;
        self
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapAggregate {
    pub operation: ProductboardRoadmapOperation,
    pub items: Vec<ProductboardRoadmapItem>,
    pub item_count: u16,
    pub total_count: u32,
    pub partial: bool,
    pub archived: bool,
    pub target_id_digest: Option<Digest>,
    pub next_page_token_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
    pub relationship_digest: Option<Digest>,
}

impl ProductboardRoadmapAggregate {
    pub fn new(
        operation: ProductboardRoadmapOperation,
        mut items: Vec<ProductboardRoadmapItem>,
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
        items.sort_by_key(ProductboardRoadmapItem::digest);
        let item_count = u16::try_from(items.len()).map_err(|_| ModelError::InvalidAggregate)?;
        if total_count < u32::from(item_count) {
            return Err(ModelError::InvalidAggregate);
        }
        let archived = !items.is_empty() && items.iter().all(|item| item.archived);
        Ok(Self {
            operation,
            items,
            item_count,
            total_count,
            partial,
            archived,
            target_id_digest,
            next_page_token_digest,
            cursor_binding_digest,
            relationship_digest: None,
        })
    }

    #[must_use]
    pub fn with_archived(mut self, archived: bool) -> Self {
        self.archived = archived;
        self
    }

    #[must_use]
    pub fn with_relationship_digest(mut self, digest: Option<Digest>) -> Self {
        self.relationship_digest = digest;
        self
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

pub type ProductboardAggregate = ProductboardRoadmapAggregate;
pub type ProductboardItem = ProductboardRoadmapItem;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_response_dropped: bool,
    pub raw_public_api_token_dropped: bool,
    pub raw_note_bodies_dropped: bool,
    pub raw_insight_content_dropped: bool,
    pub raw_member_content_dropped: bool,
    pub raw_customer_content_dropped: bool,
    pub raw_titles_dropped: bool,
    pub raw_descriptions_dropped: bool,
    pub raw_urls_dropped: bool,
    pub raw_write_payload_dropped: bool,
    pub raw_relationship_payload_dropped: bool,
}

impl RedactionSummary {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            raw_response_dropped: true,
            raw_public_api_token_dropped: true,
            raw_note_bodies_dropped: true,
            raw_insight_content_dropped: true,
            raw_member_content_dropped: true,
            raw_customer_content_dropped: true,
            raw_titles_dropped: true,
            raw_descriptions_dropped: true,
            raw_urls_dropped: true,
            raw_write_payload_dropped: true,
            raw_relationship_payload_dropped: true,
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.raw_response_dropped
            && self.raw_public_api_token_dropped
            && self.raw_note_bodies_dropped
            && self.raw_insight_content_dropped
            && self.raw_member_content_dropped
            && self.raw_customer_content_dropped
            && self.raw_titles_dropped
            && self.raw_descriptions_dropped
            && self.raw_urls_dropped
            && self.raw_write_payload_dropped
            && self.raw_relationship_payload_dropped
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub backoff_seconds: u32,
    pub attempt: u8,
    pub exhausted: bool,
}

impl Default for ProductboardRateLimitReceipt {
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

impl ProductboardRateLimitReceipt {
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

pub type ProductboardRateReceipt = ProductboardRateLimitReceipt;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductboardTransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProductboardTransportProvenance {
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
pub enum ProductboardEvidenceState {
    Present,
    Complete,
    Archived,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
    RateLimited,
    Timeout,
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
    Present,
    Archived,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
    RateLimited,
    Timeout,
}

impl From<ProductboardTransportProvenance> for EvidenceClassification {
    fn from(value: ProductboardTransportProvenance) -> Self {
        match value {
            ProductboardTransportProvenance::Fixture => Self::Fixture,
            ProductboardTransportProvenance::Recording => Self::Recording,
            ProductboardTransportProvenance::Fake => Self::Fake,
            ProductboardTransportProvenance::Loopback => Self::Loopback,
            ProductboardTransportProvenance::BlockedEnv => Self::BlockedEnv,
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
pub struct ProductboardRegistration {
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

impl ProductboardRegistration {
    #[must_use]
    pub fn bind(
        scope: &ProductboardRoadmapScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            provider_digest: provider_digest.clone(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            evidence_digest: canonical_digest(&(
                "productboard-evidence-contract/v1",
                crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION,
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
            "productboard-registration/v1",
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
        scope: &ProductboardRoadmapScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        let expected_evidence_digest = canonical_digest(&(
            "productboard-evidence-contract/v1",
            crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION,
            provider_digest,
            scope.permission_digest(),
            scope.scope_digest(),
            scope.revision_digest(),
        ));
        if self.plugin_version != crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::PRODUCTBOARD_PROVIDER_ID
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

pub type ProductboardProviderRegistration = ProductboardRegistration;
pub type ProductboardRoadmapScopeBinding = ScopeBinding;

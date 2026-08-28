use std::{fmt, fmt::Write};

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{CloudinaryAssetResultError, Result};
use crate::{MAX_COLLECTION_ITEMS, MAX_IDENTIFIER_BYTES, MAX_RESPONSE_BYTES};

/// A lowercase SHA-256 digest used for all externally meaningful bindings.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut input = Vec::new();
        append_field(&mut input, domain);
        for (name, value) in fields {
            append_field(&mut input, name);
            append_field(&mut input, value);
        }
        Self::from_bytes(input)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(CloudinaryAssetResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(CloudinaryAssetResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
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
        && !value.contains('?')
        && !value.contains('#')
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
}

macro_rules! revision_binding {
    ($name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name {
            value: String,
            revision: u64,
        }

        impl $name {
            pub fn new(value: impl Into<String>, revision: u64) -> Result<Self> {
                let value = value.into();
                if !valid_identifier(&value) || revision == 0 {
                    return Err(CloudinaryAssetResultError::InvalidScope);
                }
                Ok(Self { value, revision })
            }

            pub fn id(&self) -> &str {
                &self.value
            }

            pub fn as_str(&self) -> &str {
                self.id()
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn id_digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("cloudinary-", $field, "-id/v1"),
                    &[("id", self.value.clone())],
                )
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id_digest().as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.value) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(CloudinaryAssetResultError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id_digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

revision_binding!(CloudScope, "cloudinary-cloud/v1", "cloud");
revision_binding!(FolderScope, "cloudinary-folder/v1", "folder");
revision_binding!(AssetScope, "cloudinary-asset/v1", "asset");
revision_binding!(PublicIdScope, "cloudinary-public-id/v1", "public-id");
revision_binding!(VersionScope, "cloudinary-version/v1", "version");
revision_binding!(
    TransformationScope,
    "cloudinary-transformation/v1",
    "transformation"
);
revision_binding!(ProjectScope, "cloudinary-project/v1", "project");
revision_binding!(MissionScope, "cloudinary-mission/v1", "mission");
revision_binding!(
    WorkProductScope,
    "cloudinary-work-product/v1",
    "work-product"
);

pub type CloudName = CloudScope;
pub type CloudinaryCloudScope = CloudScope;
pub type CloudinaryFolderScope = FolderScope;
pub type CloudinaryAssetScope = AssetScope;
pub type CloudinaryPublicIdScope = PublicIdScope;
pub type CloudinaryVersionScope = VersionScope;
pub type CloudinaryTransformationScope = TransformationScope;
pub type CloudinaryProjectScope = ProjectScope;
pub type CloudinaryMissionScope = MissionScope;
pub type CloudinaryWorkProductScope = WorkProductScope;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudinarySecretKind {
    ApiKey,
    Signature,
}

pub type SecretKind = CloudinarySecretKind;

/// Opaque API-key/signature binding. The supplied handle is hashed and
/// dropped during construction; it is never serialized or emitted by Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: CloudinarySecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl Into<String>,
        kind: CloudinarySecretKind,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = opaque_reference.into();
        if !valid_text(&reference, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            reference.zeroize();
            return Err(CloudinaryAssetResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "cloudinary-opaque-secret-reference/v1",
            &[
                ("kind", format!("{kind:?}")),
                ("reference", reference.clone()),
                ("revision", revision.to_string()),
            ],
        );
        reference.zeroize();
        Ok(Self {
            kind,
            reference_digest,
            scope_digest: Digest::from_text("unbound-cloudinary-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn api_key(opaque_reference: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(opaque_reference, CloudinarySecretKind::ApiKey, revision)
    }

    pub fn signature(opaque_reference: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(opaque_reference, CloudinarySecretKind::Signature, revision)
    }

    pub fn bind_to(&mut self, scope_digest: &Digest) -> Result<()> {
        scope_digest.validate()?;
        if self.scope_digest != Digest::from_text("unbound-cloudinary-secret-scope") {
            if self.scope_digest == *scope_digest {
                return Ok(());
            }
            return Err(CloudinaryAssetResultError::InvalidSecretReference);
        }
        self.scope_digest = scope_digest.clone();
        self.reference_digest = Digest::from_parts(
            "cloudinary-opaque-secret-reference-bound/v1",
            &[
                ("reference", self.reference_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("kind", format!("{:?}", self.kind)),
                ("revision", self.revision.to_string()),
            ],
        );
        Ok(())
    }

    pub fn kind(&self) -> CloudinarySecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope_digest: &Digest) -> Result<()> {
        if self.revision == 0 || self.revoked || self.scope_digest != *scope_digest {
            return Err(CloudinaryAssetResultError::InvalidSecretReference);
        }
        self.scope_digest.validate()?;
        self.reference_digest.validate()
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
            .finish()
    }
}

pub type CloudinarySecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryType {
    Upload,
    Authenticated,
    Private,
    Fetch,
    Unknown,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeliveryScope {
    kind: DeliveryType,
    revision: u64,
}

impl DeliveryScope {
    pub fn new(kind: DeliveryType, revision: u64) -> Result<Self> {
        if matches!(kind, DeliveryType::Unknown) || revision == 0 {
            return Err(CloudinaryAssetResultError::InvalidScope);
        }
        Ok(Self { kind, revision })
    }

    pub const fn kind(&self) -> DeliveryType {
        self.kind
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-delivery-scope/v1",
            &[
                ("kind", format!("{:?}", self.kind)),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.kind, self.revision).map(|_| ())
    }
}

impl fmt::Debug for DeliveryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryScope")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .finish()
    }
}

pub type CloudinaryDeliveryScope = DeliveryScope;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudinaryScopeInput {
    pub cloud: CloudScope,
    pub folder: FolderScope,
    pub asset: AssetScope,
    pub public_id: PublicIdScope,
    pub version: VersionScope,
    pub transformation: TransformationScope,
    pub delivery: DeliveryScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub secret: SecretReference,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CloudinaryScope {
    cloud: CloudScope,
    folder: FolderScope,
    asset: AssetScope,
    public_id: PublicIdScope,
    version: VersionScope,
    transformation: TransformationScope,
    delivery: DeliveryScope,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    secret: SecretReference,
    scope_digest: Digest,
}

impl CloudinaryScope {
    pub fn new(input: CloudinaryScopeInput) -> Result<Self> {
        let mut scope = Self {
            cloud: input.cloud,
            folder: input.folder,
            asset: input.asset,
            public_id: input.public_id,
            version: input.version,
            transformation: input.transformation,
            delivery: input.delivery,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            secret: input.secret,
            scope_digest: Digest::from_text("unsealed-cloudinary-scope"),
        };
        scope.scope_digest = scope.compute_digest();
        scope.secret.bind_to(&scope.scope_digest)?;
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        cloud: CloudScope,
        folder: FolderScope,
        asset: AssetScope,
        public_id: PublicIdScope,
        version: VersionScope,
        transformation: TransformationScope,
        delivery: DeliveryScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        secret: SecretReference,
    ) -> Result<Self> {
        Self::new(CloudinaryScopeInput {
            cloud,
            folder,
            asset,
            public_id,
            version,
            transformation,
            delivery,
            project,
            mission,
            work_product,
            secret,
        })
    }

    pub fn fixture(secret: SecretReference) -> Result<Self> {
        Self::from_parts(
            CloudScope::new("demo-cloud", 1)?,
            FolderScope::new("media", 1)?,
            AssetScope::new("asset-1", 1)?,
            PublicIdScope::new("media/asset-1", 1)?,
            VersionScope::new("v1", 1)?,
            TransformationScope::new("f_auto,q_auto", 1)?,
            DeliveryScope::new(DeliveryType::Upload, 1)?,
            ProjectScope::new("project-1", 1)?,
            MissionScope::new("mission-1", 1)?,
            WorkProductScope::new("work-product-1", 1)?,
            secret,
        )
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn cloud(&self) -> &CloudScope {
        &self.cloud
    }

    pub fn folder(&self) -> &FolderScope {
        &self.folder
    }

    pub fn asset(&self) -> &AssetScope {
        &self.asset
    }

    pub fn public_id(&self) -> &PublicIdScope {
        &self.public_id
    }

    pub fn version(&self) -> &VersionScope {
        &self.version
    }

    pub fn transformation(&self) -> &TransformationScope {
        &self.transformation
    }

    pub fn delivery(&self) -> &DeliveryScope {
        &self.delivery
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn secret(&self) -> &SecretReference {
        &self.secret
    }

    pub fn cloud_digest(&self) -> Digest {
        self.cloud.digest()
    }

    pub fn folder_digest(&self) -> Digest {
        self.folder.digest()
    }

    pub fn asset_digest(&self) -> Digest {
        self.asset.digest()
    }

    pub fn public_id_digest(&self) -> Digest {
        self.public_id.digest()
    }

    pub fn version_digest(&self) -> Digest {
        self.version.digest()
    }

    pub fn transformation_digest(&self) -> Digest {
        self.transformation.digest()
    }

    pub fn delivery_digest(&self) -> Digest {
        self.delivery.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.cloud.validate()?;
        self.folder.validate()?;
        self.asset.validate()?;
        self.public_id.validate()?;
        self.version.validate()?;
        self.transformation.validate()?;
        self.delivery.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        if self.scope_digest != self.compute_digest() {
            return Err(CloudinaryAssetResultError::InvalidScope);
        }
        self.secret.validate(&self.scope_digest)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-asset-result-scope/v1",
            &[
                ("cloud", self.cloud.digest().as_str().to_owned()),
                ("folder", self.folder.digest().as_str().to_owned()),
                ("asset", self.asset.digest().as_str().to_owned()),
                ("public_id", self.public_id.digest().as_str().to_owned()),
                ("version", self.version.digest().as_str().to_owned()),
                (
                    "transformation",
                    self.transformation.digest().as_str().to_owned(),
                ),
                ("delivery", self.delivery.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }
}

impl fmt::Debug for CloudinaryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudinaryScope")
            .field("scope_digest", &self.scope_digest)
            .field("cloud", &self.cloud)
            .field("folder", &self.folder)
            .field("asset", &self.asset)
            .field("public_id", &self.public_id)
            .field("version", &self.version)
            .field("transformation", &self.transformation)
            .field("delivery", &self.delivery)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("secret", &self.secret)
            .finish()
    }
}

pub type CloudinaryAssetResultScope = CloudinaryScope;

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

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

pub type CloudinaryTransportMode = TransportProvenance;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CloudinaryOperation {
    ResourceMetadata,
    UsageMetadata,
    TransformationMetadata,
    DeliveryMetadata,
}

impl CloudinaryOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceMetadata => "ResourceMetadata",
            Self::UsageMetadata => "UsageMetadata",
            Self::TransformationMetadata => "TransformationMetadata",
            Self::DeliveryMetadata => "DeliveryMetadata",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetState {
    Present,
    Deleted,
    Invalid,
    Partial,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudinaryEvidenceState {
    Present,
    Deleted,
    Invalid,
    Partial,
    Denied,
    RateLimited,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    RegistrationRevoked,
}

impl CloudinaryEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }

    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Present | Self::Deleted | Self::Invalid)
    }
}

pub type CloudinaryAssetResultState = CloudinaryEvidenceState;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Image,
    Video,
    Raw,
    Unknown,
}

impl ResourceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::Raw => "raw",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceMetadataPayload {
    pub asset_id: String,
    pub public_id: String,
    pub folder: String,
    pub version: String,
    pub resource_type: ResourceType,
    pub status: String,
    pub bytes: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub format: String,
    pub derived_count: u16,
    pub metadata_count: u16,
}

impl ResourceMetadataPayload {
    pub fn fixture(scope: &CloudinaryScope) -> Self {
        Self {
            asset_id: scope.asset().id().to_owned(),
            public_id: scope.public_id().id().to_owned(),
            folder: scope.folder().id().to_owned(),
            version: scope.version().id().to_owned(),
            resource_type: ResourceType::Image,
            status: "present".to_owned(),
            bytes: 48_000,
            width: Some(1_920),
            height: Some(1_080),
            format: "webp".to_owned(),
            derived_count: 2,
            metadata_count: 0,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.asset_id)
            || !valid_identifier(&self.public_id)
            || !valid_identifier(&self.folder)
            || !valid_identifier(&self.version)
            || !valid_identifier(&self.format)
            || matches!(self.resource_type, ResourceType::Unknown)
            || self.derived_count as usize > MAX_COLLECTION_ITEMS
            || self.metadata_count as usize > MAX_COLLECTION_ITEMS
            || self.bytes > MAX_RESPONSE_BYTES
        {
            return Err(CloudinaryAssetResultError::InvalidEvidence);
        }
        if self.width == Some(0) || self.height == Some(0) {
            return Err(CloudinaryAssetResultError::InvalidEvidence);
        }
        Ok(())
    }

    pub(crate) fn state(&self) -> AssetState {
        match self.status.to_ascii_lowercase().as_str() {
            "present" | "uploaded" | "active" | "ready" => AssetState::Present,
            "deleted" | "destroyed" => AssetState::Deleted,
            "invalid" | "error" | "failed" => AssetState::Invalid,
            "partial" | "processing" => AssetState::Partial,
            _ => AssetState::ProviderUnknown,
        }
    }

    pub(crate) fn project(&self, scope: &CloudinaryScope) -> Result<AssetProjection> {
        self.validate()?;
        if self.asset_id != scope.asset().id()
            || self.public_id != scope.public_id().id()
            || self.folder != scope.folder().id()
            || self.version != scope.version().id()
        {
            return Err(CloudinaryAssetResultError::RevisionDrift);
        }
        let state = self.state();
        if matches!(state, AssetState::ProviderUnknown) {
            return Err(CloudinaryAssetResultError::ProviderUnknown);
        }
        let mut projection = AssetProjection {
            asset_digest: scope.asset_digest(),
            public_id_digest: scope.public_id_digest(),
            folder_digest: scope.folder_digest(),
            version_digest: scope.version_digest(),
            resource_type: self.resource_type,
            state,
            bytes: self.bytes,
            width: self.width,
            height: self.height,
            format_digest: Digest::from_parts(
                "cloudinary-format/v1",
                &[("format", self.format.clone())],
            ),
            derived_count: self.derived_count,
            metadata_count: self.metadata_count,
            projection_digest: Digest::from_text("unsealed-cloudinary-asset-projection"),
        };
        projection.projection_digest = projection.digest();
        Ok(projection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageMetadataPayload {
    pub storage_bytes: u64,
    pub bandwidth_bytes: u64,
    pub request_count: u64,
    pub transformation_count: u64,
}

impl UsageMetadataPayload {
    pub fn fixture() -> Self {
        Self {
            storage_bytes: 48_000,
            bandwidth_bytes: 128_000,
            request_count: 3,
            transformation_count: 2,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.storage_bytes > MAX_RESPONSE_BYTES * 1_024
            || self.bandwidth_bytes > MAX_RESPONSE_BYTES * 1_024
        {
            return Err(CloudinaryAssetResultError::PartialEvidence);
        }
        Ok(())
    }

    pub(crate) fn project(&self, scope: &CloudinaryScope) -> Result<UsageProjection> {
        self.validate()?;
        let mut projection = UsageProjection {
            usage_digest: Digest::from_parts(
                "cloudinary-usage/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("storage", self.storage_bytes.to_string()),
                    ("bandwidth", self.bandwidth_bytes.to_string()),
                    ("requests", self.request_count.to_string()),
                    ("transformations", self.transformation_count.to_string()),
                ],
            ),
            storage_bytes: self.storage_bytes,
            bandwidth_bytes: self.bandwidth_bytes,
            request_count: self.request_count,
            transformation_count: self.transformation_count,
            projection_digest: Digest::from_text("unsealed-cloudinary-usage-projection"),
        };
        projection.projection_digest = projection.digest();
        Ok(projection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformationMetadataPayload {
    pub transformation: String,
    pub component_count: u16,
    pub version: String,
}

impl TransformationMetadataPayload {
    pub fn fixture(scope: &CloudinaryScope) -> Self {
        Self {
            transformation: scope.transformation().id().to_owned(),
            component_count: 2,
            version: scope.version().id().to_owned(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.transformation)
            || !valid_identifier(&self.version)
            || self.component_count == 0
            || self.component_count as usize > MAX_COLLECTION_ITEMS
        {
            return Err(CloudinaryAssetResultError::InvalidEvidence);
        }
        Ok(())
    }

    pub(crate) fn project(&self, scope: &CloudinaryScope) -> Result<TransformationProjection> {
        self.validate()?;
        if self.transformation != scope.transformation().id()
            || self.version != scope.version().id()
        {
            return Err(CloudinaryAssetResultError::RevisionDrift);
        }
        let mut projection = TransformationProjection {
            transformation_digest: scope.transformation_digest(),
            component_count: self.component_count,
            version_digest: scope.version_digest(),
            metadata_digest: Digest::from_text("unsealed-cloudinary-transformation-metadata"),
        };
        projection.metadata_digest = projection.digest();
        Ok(projection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryMetadataPayload {
    pub delivery_type: DeliveryType,
    pub resource_type: ResourceType,
    pub format: String,
    pub version: String,
    reference_digest: Digest,
}

impl DeliveryMetadataPayload {
    pub fn new(
        delivery_type: DeliveryType,
        resource_type: ResourceType,
        format: impl Into<String>,
        version: impl Into<String>,
        opaque_delivery_reference: impl AsRef<str>,
    ) -> Result<Self> {
        let format = format.into();
        let version = version.into();
        let reference = opaque_delivery_reference.as_ref();
        if matches!(delivery_type, DeliveryType::Unknown)
            || matches!(resource_type, ResourceType::Unknown)
            || !valid_identifier(&format)
            || !valid_identifier(&version)
            || !valid_text(reference, MAX_IDENTIFIER_BYTES * 2, true)
        {
            return Err(CloudinaryAssetResultError::InvalidEvidence);
        }
        Ok(Self {
            delivery_type,
            resource_type,
            format,
            version,
            reference_digest: Digest::from_parts(
                "cloudinary-delivery-reference/v1",
                &[("reference", reference.to_owned())],
            ),
        })
    }

    pub fn fixture(scope: &CloudinaryScope) -> Result<Self> {
        Self::new(
            scope.delivery().kind(),
            ResourceType::Image,
            "webp",
            scope.version().id(),
            "fixture-delivery-reference",
        )
    }

    pub(crate) fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if matches!(self.delivery_type, DeliveryType::Unknown)
            || matches!(self.resource_type, ResourceType::Unknown)
            || !valid_identifier(&self.format)
            || !valid_identifier(&self.version)
        {
            return Err(CloudinaryAssetResultError::InvalidEvidence);
        }
        self.reference_digest.validate()
    }

    pub(crate) fn project(&self, scope: &CloudinaryScope) -> Result<DeliveryProjection> {
        self.validate()?;
        if self.delivery_type != scope.delivery().kind() || self.version != scope.version().id() {
            return Err(CloudinaryAssetResultError::RevisionDrift);
        }
        let mut projection = DeliveryProjection {
            delivery_digest: scope.delivery_digest(),
            delivery_type: self.delivery_type,
            resource_type: self.resource_type,
            format_digest: Digest::from_parts(
                "cloudinary-format/v1",
                &[("format", self.format.clone())],
            ),
            version_digest: scope.version_digest(),
            delivery_reference_digest: self.reference_digest.clone(),
            signed_url_execution: false,
            delivery_guarantee: false,
            projection_digest: Digest::from_text("unsealed-cloudinary-delivery-projection"),
        };
        projection.projection_digest = projection.digest();
        Ok(projection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetProjection {
    pub asset_digest: Digest,
    pub public_id_digest: Digest,
    pub folder_digest: Digest,
    pub version_digest: Digest,
    pub resource_type: ResourceType,
    pub state: AssetState,
    pub bytes: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub format_digest: Digest,
    pub derived_count: u16,
    pub metadata_count: u16,
    pub projection_digest: Digest,
}

impl AssetProjection {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-asset-projection/v1",
            &[
                ("asset", self.asset_digest.as_str().to_owned()),
                ("public_id", self.public_id_digest.as_str().to_owned()),
                ("folder", self.folder_digest.as_str().to_owned()),
                ("version", self.version_digest.as_str().to_owned()),
                ("resource_type", self.resource_type.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("bytes", self.bytes.to_string()),
                (
                    "width",
                    self.width
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "height",
                    self.height
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("format", self.format_digest.as_str().to_owned()),
                ("derived", self.derived_count.to_string()),
                ("metadata", self.metadata_count.to_string()),
            ],
        )
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        if self.projection_digest != self.digest() {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        for digest in [
            &self.asset_digest,
            &self.public_id_digest,
            &self.folder_digest,
            &self.version_digest,
            &self.format_digest,
        ] {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageProjection {
    pub usage_digest: Digest,
    pub storage_bytes: u64,
    pub bandwidth_bytes: u64,
    pub request_count: u64,
    pub transformation_count: u64,
    pub projection_digest: Digest,
}

impl UsageProjection {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-usage-projection/v1",
            &[
                ("usage", self.usage_digest.as_str().to_owned()),
                ("storage", self.storage_bytes.to_string()),
                ("bandwidth", self.bandwidth_bytes.to_string()),
                ("requests", self.request_count.to_string()),
                ("transformations", self.transformation_count.to_string()),
            ],
        )
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        if self.projection_digest != self.digest() {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        self.usage_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformationProjection {
    pub transformation_digest: Digest,
    pub component_count: u16,
    pub version_digest: Digest,
    pub metadata_digest: Digest,
}

impl TransformationProjection {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-transformation-projection/v1",
            &[
                (
                    "transformation",
                    self.transformation_digest.as_str().to_owned(),
                ),
                ("components", self.component_count.to_string()),
                ("version", self.version_digest.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        if self.metadata_digest != self.digest() {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        self.transformation_digest.validate()?;
        self.version_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryProjection {
    pub delivery_digest: Digest,
    pub delivery_type: DeliveryType,
    pub resource_type: ResourceType,
    pub format_digest: Digest,
    pub version_digest: Digest,
    pub delivery_reference_digest: Digest,
    pub signed_url_execution: bool,
    pub delivery_guarantee: bool,
    pub projection_digest: Digest,
}

impl DeliveryProjection {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-delivery-projection/v1",
            &[
                ("delivery", self.delivery_digest.as_str().to_owned()),
                ("delivery_type", format!("{:?}", self.delivery_type)),
                ("resource_type", self.resource_type.as_str().to_owned()),
                ("format", self.format_digest.as_str().to_owned()),
                ("version", self.version_digest.as_str().to_owned()),
                (
                    "reference",
                    self.delivery_reference_digest.as_str().to_owned(),
                ),
                (
                    "signed_url_execution",
                    self.signed_url_execution.to_string(),
                ),
                ("delivery_guarantee", self.delivery_guarantee.to_string()),
            ],
        )
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        if self.projection_digest != self.digest()
            || self.signed_url_execution
            || self.delivery_guarantee
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        for digest in [
            &self.delivery_digest,
            &self.format_digest,
            &self.version_digest,
            &self.delivery_reference_digest,
        ] {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: CloudinaryOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub attempts: u8,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    pub fn new(
        operation: CloudinaryOperation,
        request_digest: Digest,
        path_digest: Digest,
        scope_digest: Digest,
        attempts: u8,
    ) -> Self {
        let receipt_digest = Digest::from_parts(
            "cloudinary-request-receipt/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("request", request_digest.as_str().to_owned()),
                ("path", path_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("attempts", attempts.to_string()),
                ("redacted", "true".to_owned()),
            ],
        );
        Self {
            operation,
            request_digest,
            path_digest,
            scope_digest,
            attempts,
            redacted: true,
            receipt_digest,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted
            || self.receipt_digest
                != Digest::from_parts(
                    "cloudinary-request-receipt/v1",
                    &[
                        ("operation", self.operation.as_str().to_owned()),
                        ("request", self.request_digest.as_str().to_owned()),
                        ("path", self.path_digest.as_str().to_owned()),
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("attempts", self.attempts.to_string()),
                        ("redacted", "true".to_owned()),
                    ],
                )
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        self.scope_digest.validate()
    }

    pub const fn is_redacted(&self) -> bool {
        self.redacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: CloudinaryOperation,
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub cost_basis: String,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl CostReceipt {
    pub fn new(operation: CloudinaryOperation, response_bytes: u64) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(CloudinaryAssetResultError::PartialEvidence);
        }
        let cost_basis = "layer1_metadata_read_estimate".to_owned();
        let receipt_digest = Digest::from_parts(
            "cloudinary-cost-receipt/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("response_bytes", response_bytes.to_string()),
                ("request_units", "1".to_owned()),
                ("cost_basis", cost_basis.clone()),
                ("redacted", "true".to_owned()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units: 1,
            cost_basis,
            redacted: true,
            receipt_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.receipt_digest
                != Digest::from_parts(
                    "cloudinary-cost-receipt/v1",
                    &[
                        ("operation", self.operation.as_str().to_owned()),
                        ("response_bytes", self.response_bytes.to_string()),
                        ("request_units", self.bounded_request_units.to_string()),
                        ("cost_basis", self.cost_basis.clone()),
                        ("redacted", "true".to_owned()),
                    ],
                )
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn cost_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub const fn is_redacted(&self) -> bool {
        self.redacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub cloud_digest: Digest,
    pub folder_digest: Digest,
    pub asset_digest: Digest,
    pub public_id_digest: Digest,
    pub version_digest: Digest,
    pub transformation_digest: Digest,
    pub delivery_digest: Digest,
    pub resource_digest: Option<Digest>,
    pub usage_digest: Option<Digest>,
    pub transformation_metadata_digest: Option<Digest>,
    pub delivery_metadata_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.cloud_digest,
            &self.folder_digest,
            &self.asset_digest,
            &self.public_id_digest,
            &self.version_digest,
            &self.transformation_digest,
            &self.delivery_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        for digest in [
            &self.resource_digest,
            &self.usage_digest,
            &self.transformation_metadata_digest,
            &self.delivery_metadata_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: CloudinaryOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    pub(crate) fn from_transport(
        operation: CloudinaryOperation,
        error: &crate::error::CloudinaryTransportError,
    ) -> Self {
        let category = match error {
            crate::error::CloudinaryTransportError::BlockedEnv => "blocked_env",
            crate::error::CloudinaryTransportError::BadRequest => "invalid",
            crate::error::CloudinaryTransportError::Unauthorized
            | crate::error::CloudinaryTransportError::Forbidden => "denied",
            crate::error::CloudinaryTransportError::NotFound
            | crate::error::CloudinaryTransportError::Deleted => "deleted",
            crate::error::CloudinaryTransportError::Conflict => "conflict",
            crate::error::CloudinaryTransportError::RateLimited { .. }
            | crate::error::CloudinaryTransportError::BackoffExhausted => "rate_limited",
            crate::error::CloudinaryTransportError::ServerError { .. } => "provider_unknown",
            crate::error::CloudinaryTransportError::Timeout => "provider_unknown",
            crate::error::CloudinaryTransportError::AccessLost => "access_loss",
            crate::error::CloudinaryTransportError::Partial => "partial",
            crate::error::CloudinaryTransportError::InvalidResponse => "invalid",
            crate::error::CloudinaryTransportError::Tampered => "tampered",
            crate::error::CloudinaryTransportError::ProviderUnknown => "provider_unknown",
        }
        .to_owned();
        Self {
            operation,
            status_code: error.status_code(),
            failure_digest: Digest::from_parts(
                "cloudinary-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.clone()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |status| status.to_string()),
                    ),
                ],
            ),
            category,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub fn mission_projection(scope: &CloudinaryScope) -> MissionProjection {
    MissionProjection {
        id_digest: scope.mission().id_digest(),
        revision: scope.mission().revision(),
    }
}

pub fn project_projection(scope: &CloudinaryScope) -> ProjectProjection {
    ProjectProjection {
        id_digest: scope.project().id_digest(),
        revision: scope.project().revision(),
    }
}

pub fn work_product_projection(scope: &CloudinaryScope) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: scope.work_product().id_digest(),
        revision: scope.work_product().revision(),
    }
}

pub fn join_digests(values: impl IntoIterator<Item = Digest>) -> String {
    values
        .into_iter()
        .map(|digest| digest.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}

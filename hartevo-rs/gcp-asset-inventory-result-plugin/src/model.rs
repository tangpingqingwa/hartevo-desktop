//! Typed, bounded projections for Google Cloud Asset Inventory.
//!
//! The model stops at safe search evidence.  Resource names are accepted only
//! at an input boundary and immediately become digests.  Ancestry retains
//! resource types and name digests, while version and enrichment metadata are
//! retained as digests only.  There is deliberately no model for a Google
//! Cloud `Resource`, resource data, labels, tags, or raw response body.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_ASSET_INVENTORY_CONTRACT_VERSION, GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT,
    GCP_ASSET_INVENTORY_SCHEMA_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ASSET_TYPE_BYTES: usize = 256;
pub const MAX_ANCESTRY_ENTRIES: usize = 32;
pub const MAX_PAGES: u16 = 4;
pub const MAX_ASSETS_PER_PAGE: usize = 50;
pub const MAX_TOTAL_ASSETS: usize = 200;
pub const MAX_METADATA_BYTES: usize = 512;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("asset ancestry exceeds the Layer-1 bound")]
    AncestryTooLong,
    #[error("asset inventory bounds exceed the Layer-1 limit")]
    InvalidBounds,
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
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

/// A SHA-256 digest used as a content-free binding.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded GCP values serialize");
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest { field });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

macro_rules! bounded_text {
    ($name:ident, $field:literal, $maximum:expr, $whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $maximum, $whitespace)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
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

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_text!(
    OrganizationId,
    "organization id",
    MAX_IDENTIFIER_BYTES,
    false
);
bounded_text!(FolderId, "folder id", MAX_IDENTIFIER_BYTES, false);
bounded_text!(ProjectId, "project id", MAX_IDENTIFIER_BYTES, false);
bounded_text!(AssetType, "asset type", MAX_ASSET_TYPE_BYTES, false);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! scoped_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: String,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
                let id = id.into();
                validate_text(&id, $field, MAX_IDENTIFIER_BYTES, false)?;
                Ok(Self { id, revision })
            }
        }
    };
}

scoped_identifier!(ProjectScope, "Project id");
scoped_identifier!(MissionScope, "Mission id");
scoped_identifier!(WorkProductScope, "Work Product id");

/// The Cloud Asset Inventory `scope` parameter is one of an organization,
/// folder, or project.  The exact identifier is retained because it is the
/// read boundary, not a resource payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AssetInventorySearchScope {
    Organization { id: OrganizationId },
    Folder { id: FolderId },
    Project { id: ProjectId },
}

impl AssetInventorySearchScope {
    pub fn organization(id: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Organization {
            id: OrganizationId::new(id)?,
        })
    }

    pub fn folder(id: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Folder {
            id: FolderId::new(id)?,
        })
    }

    pub fn project(id: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Project {
            id: ProjectId::new(id)?,
        })
    }

    pub const fn kind(&self) -> AssetInventoryScopeKind {
        match self {
            Self::Organization { .. } => AssetInventoryScopeKind::Organization,
            Self::Folder { .. } => AssetInventoryScopeKind::Folder,
            Self::Project { .. } => AssetInventoryScopeKind::Project,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Organization { id } => id.as_str(),
            Self::Folder { id } => id.as_str(),
            Self::Project { id } => id.as_str(),
        }
    }

    pub fn api_scope(&self) -> String {
        let prefix = match self {
            Self::Organization { .. } => "organizations",
            Self::Folder { .. } => "folders",
            Self::Project { .. } => "projects",
        };
        format!("{prefix}/{}", self.id())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetInventoryScopeKind {
    Organization,
    Folder,
    Project,
}

/// An ancestry node contains only the type and a digest of the opaque name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AncestryNode {
    pub resource_type: AssetType,
    pub resource_name_digest: Digest,
}

impl AncestryNode {
    pub fn new(
        resource_type: impl Into<String>,
        opaque_resource_name: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let resource_type = AssetType::new(resource_type)?;
        let opaque_resource_name = opaque_resource_name.as_ref();
        validate_text(
            opaque_resource_name,
            "opaque ancestry resource name",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        Ok(Self {
            resource_name_digest: Digest::from_serializable(&(
                "hartevo:gcp-asset-inventory-resource-name:v1",
                resource_type.as_str(),
                opaque_resource_name,
            )),
            resource_type,
        })
    }
}

/// Bounded ancestry projection.  It never retains the provider's ancestry
/// names and is capped to prevent an unbounded response from becoming
/// evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceAncestry {
    pub nodes: Vec<AncestryNode>,
    pub ancestry_digest: Digest,
}

impl ResourceAncestry {
    pub fn new(nodes: Vec<AncestryNode>) -> Result<Self, ModelError> {
        if nodes.len() > MAX_ANCESTRY_ENTRIES {
            return Err(ModelError::AncestryTooLong);
        }
        let mut ancestry = Self {
            nodes,
            ancestry_digest: Digest::from_text("placeholder"),
        };
        ancestry.ancestry_digest = ancestry.compute_digest();
        Ok(ancestry)
    }

    pub fn empty() -> Self {
        Self::new(Vec::new()).expect("empty ancestry is valid")
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.nodes)
    }

    pub fn verify_digest(&self) -> bool {
        self.ancestry_digest == self.compute_digest()
    }

    pub fn digest(&self) -> Digest {
        self.ancestry_digest.clone()
    }
}

/// Resource identity is digest-only for the name and typed for the asset
/// type/ancestry.  The opaque resource name is not retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceIdentity {
    pub asset_type: AssetType,
    pub resource_name_digest: Digest,
    pub ancestry: ResourceAncestry,
}

impl ResourceIdentity {
    pub fn new(
        asset_type: AssetType,
        opaque_resource_name: impl AsRef<str>,
        ancestry: ResourceAncestry,
    ) -> Result<Self, ModelError> {
        let opaque_resource_name = opaque_resource_name.as_ref();
        validate_text(
            opaque_resource_name,
            "opaque resource name",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        if !ancestry.verify_digest() {
            return Err(ModelError::Invalid { field: "ancestry" });
        }
        Ok(Self {
            resource_name_digest: Digest::from_serializable(&(
                "hartevo:gcp-asset-inventory-resource-name:v1",
                asset_type.as_str(),
                opaque_resource_name,
            )),
            asset_type,
            ancestry,
        })
    }

    pub fn from_digest(
        asset_type: AssetType,
        resource_name_digest: Digest,
        ancestry: ResourceAncestry,
    ) -> Result<Self, ModelError> {
        if !ancestry.verify_digest() {
            return Err(ModelError::Invalid { field: "ancestry" });
        }
        Ok(Self {
            asset_type,
            resource_name_digest,
            ancestry,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    CloudAssetSearchAllResources,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionBinding {
    pub actions: Vec<PermissionAction>,
    pub resource_boundary_digest: Digest,
}

impl PermissionBinding {
    pub fn cloud_asset_search_all_resources() -> Self {
        Self {
            actions: vec![PermissionAction::CloudAssetSearchAllResources],
            resource_boundary_digest: Digest::from_text(
                "hartevo:gcp-cloud-asset-search-all-resources-boundary:v1",
            ),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Exact Project/Mission/Work Product-bound Cloud Asset Inventory scope.
/// The provider read is further bounded by a typed organization, folder, or
/// project search scope and one exact read time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAssetInventoryScope {
    pub search_scope: AssetInventorySearchScope,
    pub resource: ResourceIdentity,
    pub read_time: DateTime<Utc>,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub permission: PermissionBinding,
}

impl GcpAssetInventoryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        search_scope: AssetInventorySearchScope,
        resource: ResourceIdentity,
        read_time: DateTime<Utc>,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        permission: PermissionBinding,
    ) -> Self {
        Self {
            search_scope,
            resource,
            read_time,
            project,
            mission,
            work_product,
            permission,
        }
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn asset_type(&self) -> &AssetType {
        &self.resource.asset_type
    }

    pub fn resource_name_digest(&self) -> &Digest {
        &self.resource.resource_name_digest
    }

    pub fn ancestry(&self) -> &ResourceAncestry {
        &self.resource.ancestry
    }
}

pub type AssetInventoryScope = GcpAssetInventoryScope;

/// The auth binding is intentionally opaque and deliberately does not
/// implement `Serialize` or `Deserialize`.  Only a digest of the host-owned
/// reference is retained.  This is a binding, not live credential resolution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    ServiceAccount,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Option<Digest>,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &GcpAssetInventoryScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_scope(
            SecretReferenceKind::OAuth,
            opaque_reference,
            scope,
            revision,
        )
    }

    pub fn service_account(
        opaque_reference: impl AsRef<str>,
        scope: &GcpAssetInventoryScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_scope(
            SecretReferenceKind::ServiceAccount,
            opaque_reference,
            scope,
            revision,
        )
    }

    pub fn unbound(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::build(kind, opaque_reference.as_ref(), None, revision)
    }

    pub fn for_scope(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &GcpAssetInventoryScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::build(
            kind,
            opaque_reference.as_ref(),
            Some(scope.scope_digest()),
            revision,
        )
    }

    fn build(
        kind: SecretReferenceKind,
        opaque_reference: &str,
        scope_digest: Option<Digest>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_text(
            opaque_reference,
            "opaque OAuth or service-account SecretReference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let reference_digest = Digest::from_serializable(&(
            "hartevo:gcp-auth-secret-reference:v1",
            kind,
            opaque_reference,
            &scope_digest,
            revision,
        ));
        Ok(Self {
            kind,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
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

pub type OAuthSecretReference = SecretReference;
pub type ServiceAccountSecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SearchBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_assets: u16,
}

impl SearchBounds {
    pub fn new(max_pages: u16, page_size: u16, max_assets: u16) -> Result<Self, ModelError> {
        if !(1..=MAX_PAGES).contains(&max_pages)
            || !(1..=u16::try_from(MAX_ASSETS_PER_PAGE).expect("page bound fits u16"))
                .contains(&page_size)
            || !(1..=u16::try_from(MAX_TOTAL_ASSETS).expect("asset bound fits u16"))
                .contains(&max_assets)
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_pages,
            page_size,
            max_assets,
        })
    }
}

impl Default for SearchBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: u16::try_from(MAX_ASSETS_PER_PAGE).expect("page bound fits u16"),
            max_assets: u16::try_from(MAX_TOTAL_ASSETS).expect("asset bound fits u16"),
        }
    }
}

/// Safe query metadata. It has an exact scope binding and a digest for every
/// provider-relevant part of the request; no arbitrary Cloud Asset query
/// language is accepted in Layer 1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetInventoryQuery {
    pub scope_digest: Digest,
    pub search_scope: AssetInventorySearchScope,
    pub resource: ResourceIdentity,
    pub read_time: DateTime<Utc>,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub bounds: SearchBounds,
    pub query_digest: Digest,
}

impl AssetInventoryQuery {
    pub fn new(
        scope: &GcpAssetInventoryScope,
        permission_digest: Digest,
        secret_reference_digest: Digest,
        bounds: SearchBounds,
    ) -> Self {
        let mut query = Self {
            scope_digest: scope.scope_digest(),
            search_scope: scope.search_scope.clone(),
            resource: scope.resource.clone(),
            read_time: scope.read_time,
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            permission_digest,
            secret_reference_digest,
            bounds,
            query_digest: Digest::from_text("placeholder"),
        };
        query.query_digest = query.compute_digest();
        query
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.scope_digest,
            &self.search_scope,
            &self.resource,
            self.read_time,
            &self.project,
            &self.mission,
            &self.work_product,
            &self.permission_digest,
            &self.secret_reference_digest,
            self.bounds,
        ))
    }

    pub fn verify_digest(&self) -> bool {
        self.query_digest == self.compute_digest()
    }
}

/// Provider state is deliberately not an ownership, health, or deployability
/// claim. It only describes how the bounded provider projected the item.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedProviderState {
    Present,
    Deleted,
    Unknown,
}

/// Transient input at the redaction boundary. No serialization or Debug
/// implementation exposes the opaque version/enrichment strings.
pub struct AssetMetadataInput {
    pub version: Option<String>,
    pub enrichment: Option<String>,
    pub provider_state: RedactedProviderState,
}

impl AssetMetadataInput {
    pub fn new(
        version: Option<impl Into<String>>,
        enrichment: Option<impl Into<String>>,
        provider_state: RedactedProviderState,
    ) -> Self {
        Self {
            version: version.map(Into::into),
            enrichment: enrichment.map(Into::into),
            provider_state,
        }
    }
}

impl fmt::Debug for AssetMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssetMetadataInput")
            .field(
                "version_digest",
                &self.version.as_ref().map(Digest::from_text),
            )
            .field(
                "enrichment_digest",
                &self.enrichment.as_ref().map(Digest::from_text),
            )
            .field("provider_state", &self.provider_state)
            .finish()
    }
}

/// Only digests of provider version and enrichment material survive the
/// redaction boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestOnlyAssetMetadata {
    pub version_digest: Option<Digest>,
    pub enrichment_digest: Option<Digest>,
    pub provider_state: RedactedProviderState,
    pub metadata_digest: Digest,
}

impl DigestOnlyAssetMetadata {
    pub fn from_input(input: AssetMetadataInput) -> Result<Self, ModelError> {
        if input.version.as_deref().is_some_and(|value| {
            validate_text(value, "asset version metadata", MAX_METADATA_BYTES, true).is_err()
        }) || input.enrichment.as_deref().is_some_and(|value| {
            validate_text(value, "asset enrichment metadata", MAX_METADATA_BYTES, true).is_err()
        }) {
            return Err(ModelError::InvalidText {
                field: "asset version or enrichment metadata",
            });
        }
        let version_digest = input.version.as_ref().map(|value| {
            Digest::from_serializable(&("hartevo:gcp-asset-inventory-version:v1", value))
        });
        let enrichment_digest = input.enrichment.as_ref().map(|value| {
            Digest::from_serializable(&("hartevo:gcp-asset-inventory-enrichment:v1", value))
        });
        let metadata_digest =
            Digest::from_serializable(&(&version_digest, &enrichment_digest, input.provider_state));
        Ok(Self {
            version_digest,
            enrichment_digest,
            provider_state: input.provider_state,
            metadata_digest,
        })
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.version_digest,
            &self.enrichment_digest,
            self.provider_state,
        ))
    }

    pub fn verify_digest(&self) -> bool {
        self.metadata_digest == self.compute_digest()
    }
}

/// Transient provider input. The raw resource name and raw metadata are
/// consumed by `RedactedAsset::from_input` and are never retained.
pub struct AssetResourceInput {
    pub resource_name: String,
    pub asset_type: AssetType,
    pub ancestry: ResourceAncestry,
    pub read_time: DateTime<Utc>,
    pub metadata: AssetMetadataInput,
}

impl AssetResourceInput {
    pub fn new(
        resource_name: impl Into<String>,
        asset_type: AssetType,
        ancestry: ResourceAncestry,
        read_time: DateTime<Utc>,
        metadata: AssetMetadataInput,
    ) -> Self {
        Self {
            resource_name: resource_name.into(),
            asset_type,
            ancestry,
            read_time,
            metadata,
        }
    }
}

impl fmt::Debug for AssetResourceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssetResourceInput")
            .field(
                "resource_name_digest",
                &Digest::from_text(&self.resource_name),
            )
            .field("asset_type", &self.asset_type)
            .field("ancestry", &self.ancestry)
            .field("read_time", &self.read_time)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Safe asset projection returned in pages and evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedAsset {
    pub resource_name_digest: Digest,
    pub asset_type: AssetType,
    pub ancestry: ResourceAncestry,
    pub read_time: DateTime<Utc>,
    pub version_digest: Option<Digest>,
    pub enrichment_digest: Option<Digest>,
    pub provider_state: RedactedProviderState,
    pub asset_digest: Digest,
}

impl RedactedAsset {
    pub fn from_input(input: AssetResourceInput) -> Result<Self, ModelError> {
        let identity =
            ResourceIdentity::new(input.asset_type, &input.resource_name, input.ancestry)?;
        let metadata = DigestOnlyAssetMetadata::from_input(input.metadata)?;
        let mut asset = Self {
            resource_name_digest: identity.resource_name_digest,
            asset_type: identity.asset_type,
            ancestry: identity.ancestry,
            read_time: input.read_time,
            version_digest: metadata.version_digest,
            enrichment_digest: metadata.enrichment_digest,
            provider_state: metadata.provider_state,
            asset_digest: Digest::from_text("placeholder"),
        };
        // The provider state is an explicit safe projection. Metadata digests
        // remain content-free, and no raw metadata is available here.
        asset.asset_digest = asset.compute_digest();
        Ok(asset)
    }

    pub fn from_input_with_state(
        input: AssetResourceInput,
        provider_state: RedactedProviderState,
    ) -> Result<Self, ModelError> {
        let mut asset = Self::from_input(input)?;
        asset.provider_state = provider_state;
        asset.asset_digest = asset.compute_digest();
        Ok(asset)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.resource_name_digest,
            &self.asset_type,
            &self.ancestry,
            self.read_time,
            &self.version_digest,
            &self.enrichment_digest,
            self.provider_state,
        ))
    }

    pub fn verify_digest(&self) -> bool {
        self.ancestry.verify_digest() && self.asset_digest == self.compute_digest()
    }

    pub fn matches_scope(&self, scope: &GcpAssetInventoryScope) -> bool {
        self.resource_name_digest == scope.resource.resource_name_digest
            && self.asset_type == scope.resource.asset_type
            && self.ancestry == scope.resource.ancestry
            && self.read_time == scope.read_time
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    AssetCap,
    RateLimited,
    ProviderWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetProjection {
    Complete,
    Partial(PartialReason),
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetAnomaly {
    ReplayDetected,
    DuplicateAsset,
    OrderNormalized,
    AncestryMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectObservation {
    NoExternalEffectClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetInventoryEvidenceDigests {
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
}

/// Bounded evidence consumed by a Mission. It contains only safe resource
/// identity/type/ancestry projections and digest-only metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetInventoryEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub page_count: u16,
    pub raw_asset_count: u16,
    pub unique_asset_count: u16,
    pub duplicate_asset_count: u16,
    pub projection: AssetProjection,
    pub assets: Vec<RedactedAsset>,
    pub record_digests: Vec<Digest>,
    pub page_token_chain_digest: Digest,
    pub anomalies: Vec<AssetAnomaly>,
    pub effect_observation: EffectObservation,
    pub provider_failure_digest: Option<Digest>,
    pub digests: AssetInventoryEvidenceDigests,
}

impl AssetInventoryEvidence {
    pub fn compute_evidence_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!({
            "schemaVersion": &self.schema_version,
            "contractVersion": &self.contract_version,
            "pluginVersion": &self.plugin_version,
            "scopeDigest": &self.scope_digest,
            "registrationDigest": &self.registration_digest,
            "registrationRevision": self.registration_revision,
            "providerId": &self.provider_id,
            "providerVersion": &self.provider_version,
            "providerRevision": &self.provider_revision,
            "pageCount": self.page_count,
            "rawAssetCount": self.raw_asset_count,
            "uniqueAssetCount": self.unique_asset_count,
            "duplicateAssetCount": self.duplicate_asset_count,
            "projection": self.projection,
            "assets": &self.assets,
            "recordDigests": &self.record_digests,
            "pageTokenChainDigest": &self.page_token_chain_digest,
            "anomalies": &self.anomalies,
            "effectObservation": self.effect_observation,
            "providerFailureDigest": &self.provider_failure_digest,
        }))
    }

    pub fn verify_integrity(&self) -> bool {
        self.assets.iter().all(RedactedAsset::verify_digest)
            && self.assets.windows(2).all(|pair| {
                (&pair[0].asset_type, &pair[0].resource_name_digest)
                    <= (&pair[1].asset_type, &pair[1].resource_name_digest)
            })
            && self
                .assets
                .windows(2)
                .all(|pair| pair[0].resource_name_digest != pair[1].resource_name_digest)
            && self.digests.evidence_digest == self.compute_evidence_digest()
    }

    pub fn version_digest(&self) -> Digest {
        self.digests.version_digest.clone()
    }

    pub fn contract_digest(&self) -> Digest {
        self.digests.contract_digest.clone()
    }

    pub fn scope_digest_binding(&self) -> Digest {
        self.digests.scope_digest.clone()
    }
}

pub fn contract_version_digest() -> Digest {
    Digest::from_text(GCP_ASSET_INVENTORY_CONTRACT_VERSION)
}

pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT)
}

pub fn schema_version_digest() -> Digest {
    Digest::from_text(GCP_ASSET_INVENTORY_SCHEMA_VERSION)
}

//! Typed bounded models for the Azure Resource Graph result seam.
//!
//! Provider payloads are accepted only at the transport boundary. The
//! evidence types below retain resource identity, type, location, ancestry,
//! and SHA-256 digests of selected allowlisted properties; they never retain
//! raw resource JSON, tags, secrets, arbitrary KQL, or credential material.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AZURE_RESOURCE_GRAPH_CONTRACT_VERSION, AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT,
    AZURE_RESOURCE_GRAPH_PROVIDER_REVISION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 512;
pub const MAX_SCOPES: usize = 16;
pub const MAX_RESOURCE_TYPES: usize = 6;
pub const MAX_PROPERTIES: usize = 8;
pub const MAX_RESOURCES: usize = 256;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub type ResultDigest = Digest;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
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

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(hex::encode(Sha256::digest(bytes)))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Azure Resource Graph typed value serializes");
    sha256_digest(&bytes)
}

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ModelError::Serialization)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} is not a bounded value")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision is invalid")]
    InvalidRevision,
    #[error("inventory scope is invalid")]
    InvalidScope,
    #[error("permission snapshot does not authorize the inventory target")]
    InvalidPermission,
    #[error("query AST is invalid")]
    InvalidQuery,
    #[error("resource payload is invalid")]
    InvalidResource,
    #[error("resource type is not allowlisted")]
    UnsupportedResourceType,
    #[error("property is not allowlisted")]
    UnsupportedProperty,
    #[error("duplicate value in an allowlist")]
    Duplicate,
    #[error("continuation token is invalid")]
    InvalidContinuation,
    #[error("secret reference is already revoked")]
    AlreadyRevoked,
    #[error("secret reference is not revoked")]
    NotRevoked,
    #[error("typed value could not be serialized")]
    Serialization,
}

fn validate_text(
    value: &str,
    field: &'static str,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_revision(value: u64) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision)
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::parse(value)
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $whitespace)?;
                Ok(Self(value))
            }

            #[must_use]
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
                Self::parse(value)
            }
        }
    };
}

bounded_identifier!(TenantId, "tenant id", false);
bounded_identifier!(SubscriptionId, "subscription id", false);
bounded_identifier!(ManagementGroupId, "management group id", false);
bounded_identifier!(ResourceId, "resource id", false);
bounded_identifier!(ResourceGroupName, "resource group", false);
bounded_identifier!(ResourceLocation, "resource location", false);
bounded_identifier!(ProjectId, "Project id", false);
bounded_identifier!(MissionId, "Mission id", false);
bounded_identifier!(WorkProductId, "Work Product id", false);
bounded_identifier!(ProviderRevision, "provider revision", false);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AzureResourceType {
    MicrosoftComputeVirtualMachines,
    MicrosoftKeyVaultVaults,
    MicrosoftNetworkVirtualNetworks,
    MicrosoftResourcesResourceGroups,
    MicrosoftStorageStorageAccounts,
    MicrosoftWebSites,
}

impl AzureResourceType {
    pub const ALL: [Self; 6] = [
        Self::MicrosoftComputeVirtualMachines,
        Self::MicrosoftKeyVaultVaults,
        Self::MicrosoftNetworkVirtualNetworks,
        Self::MicrosoftResourcesResourceGroups,
        Self::MicrosoftStorageStorageAccounts,
        Self::MicrosoftWebSites,
    ];

    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref() {
            "Microsoft.Compute/virtualMachines" => Ok(Self::MicrosoftComputeVirtualMachines),
            "Microsoft.KeyVault/vaults" => Ok(Self::MicrosoftKeyVaultVaults),
            "Microsoft.Network/virtualNetworks" => Ok(Self::MicrosoftNetworkVirtualNetworks),
            "Microsoft.Resources/resourceGroups" => Ok(Self::MicrosoftResourcesResourceGroups),
            "Microsoft.Storage/storageAccounts" => Ok(Self::MicrosoftStorageStorageAccounts),
            "Microsoft.Web/sites" => Ok(Self::MicrosoftWebSites),
            _ => Err(ModelError::UnsupportedResourceType),
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MicrosoftComputeVirtualMachines => "Microsoft.Compute/virtualMachines",
            Self::MicrosoftKeyVaultVaults => "Microsoft.KeyVault/vaults",
            Self::MicrosoftNetworkVirtualNetworks => "Microsoft.Network/virtualNetworks",
            Self::MicrosoftResourcesResourceGroups => "Microsoft.Resources/resourceGroups",
            Self::MicrosoftStorageStorageAccounts => "Microsoft.Storage/storageAccounts",
            Self::MicrosoftWebSites => "Microsoft.Web/sites",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AzureResourceProperty {
    Kind,
    Location,
    PropertiesHardwareProfileVmSize,
    PropertiesProvisioningState,
    PropertiesPublicNetworkAccess,
    PropertiesSkuName,
    PropertiesStorageProfileOsDiskOsType,
    PropertiesManagedBy,
}

impl AzureResourceProperty {
    pub const ALL: [Self; 8] = [
        Self::Kind,
        Self::Location,
        Self::PropertiesHardwareProfileVmSize,
        Self::PropertiesProvisioningState,
        Self::PropertiesPublicNetworkAccess,
        Self::PropertiesSkuName,
        Self::PropertiesStorageProfileOsDiskOsType,
        Self::PropertiesManagedBy,
    ];

    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref() {
            "kind" => Ok(Self::Kind),
            "location" => Ok(Self::Location),
            "properties.hardwareProfile.vmSize" => Ok(Self::PropertiesHardwareProfileVmSize),
            "properties.provisioningState" => Ok(Self::PropertiesProvisioningState),
            "properties.publicNetworkAccess" => Ok(Self::PropertiesPublicNetworkAccess),
            "properties.sku.name" => Ok(Self::PropertiesSkuName),
            "properties.storageProfile.osDisk.osType" => {
                Ok(Self::PropertiesStorageProfileOsDiskOsType)
            }
            "properties.managedBy" => Ok(Self::PropertiesManagedBy),
            _ => Err(ModelError::UnsupportedProperty),
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Location => "location",
            Self::PropertiesHardwareProfileVmSize => "properties.hardwareProfile.vmSize",
            Self::PropertiesProvisioningState => "properties.provisioningState",
            Self::PropertiesPublicNetworkAccess => "properties.publicNetworkAccess",
            Self::PropertiesSkuName => "properties.sku.name",
            Self::PropertiesStorageProfileOsDiskOsType => "properties.storageProfile.osDisk.osType",
            Self::PropertiesManagedBy => "properties.managedBy",
        }
    }

    fn value_from(self, payload: &AzureResourceGraphResourcePayload) -> Option<&Value> {
        let path = self.code().strip_prefix("properties.")?;
        let mut segments = path.split('.');
        let first = segments.next()?;
        let mut value = payload.properties.get(first)?;
        for segment in segments {
            value = value.as_object()?.get(segment)?;
        }
        Some(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AzureResourceGraphTarget {
    Subscriptions(Vec<SubscriptionId>),
    ManagementGroups(Vec<ManagementGroupId>),
}

impl AzureResourceGraphTarget {
    pub fn subscriptions(
        values: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ModelError> {
        let ids = values
            .into_iter()
            .map(SubscriptionId::new)
            .collect::<Result<Vec<_>, _>>()?;
        Self::normalize(Self::Subscriptions(ids))
    }

    pub fn management_groups(
        values: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ModelError> {
        let ids = values
            .into_iter()
            .map(ManagementGroupId::new)
            .collect::<Result<Vec<_>, _>>()?;
        Self::normalize(Self::ManagementGroups(ids))
    }

    fn normalize(target: Self) -> Result<Self, ModelError> {
        match target {
            Self::Subscriptions(mut values) => {
                values.sort();
                if values.is_empty() || values.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(ModelError::InvalidScope);
                }
                if values.len() > MAX_SCOPES {
                    return Err(ModelError::InvalidScope);
                }
                Ok(Self::Subscriptions(values))
            }
            Self::ManagementGroups(mut values) => {
                values.sort();
                if values.is_empty() || values.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(ModelError::InvalidScope);
                }
                if values.len() > MAX_SCOPES {
                    return Err(ModelError::InvalidScope);
                }
                Ok(Self::ManagementGroups(values))
            }
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::normalize(self.clone()).map(|_| ())
    }

    #[must_use]
    pub fn is_subscription_scope(&self) -> bool {
        matches!(self, Self::Subscriptions(_))
    }

    #[must_use]
    pub fn contains_subscription(&self, value: &SubscriptionId) -> bool {
        matches!(self, Self::Subscriptions(values) if values.contains(value))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureResourceGraphPermission {
    ResourceGraphRead,
    SubscriptionRead,
    ManagementGroupRead,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<AzureResourceGraphPermission>,
    revision: Revision,
}

impl PermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = AzureResourceGraphPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let snapshot = Self {
            permissions,
            revision: Revision::new(revision)?,
        };
        if snapshot.permissions.is_empty()
            || !snapshot
                .permissions
                .contains(&AzureResourceGraphPermission::ResourceGraphRead)
        {
            return Err(ModelError::InvalidPermission);
        }
        Ok(snapshot)
    }

    pub fn for_subscriptions(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                AzureResourceGraphPermission::ResourceGraphRead,
                AzureResourceGraphPermission::SubscriptionRead,
            ],
            revision,
        )
    }

    pub fn for_management_groups(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                AzureResourceGraphPermission::ResourceGraphRead,
                AzureResourceGraphPermission::ManagementGroupRead,
            ],
            revision,
        )
    }

    pub fn validate_for(&self, target: &AzureResourceGraphTarget) -> Result<(), ModelError> {
        let required = if target.is_subscription_scope() {
            AzureResourceGraphPermission::SubscriptionRead
        } else {
            AzureResourceGraphPermission::ManagementGroupRead
        };
        if self
            .permissions
            .contains(&AzureResourceGraphPermission::ResourceGraphRead)
            && self.permissions.contains(&required)
        {
            Ok(())
        } else {
            Err(ModelError::InvalidPermission)
        }
    }

    #[must_use]
    pub fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    reference: ResourceId,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

impl ConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            reference: ResourceId::new(reference)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphQueryAst {
    pub target: AzureResourceGraphTarget,
    pub resource_types: Vec<AzureResourceType>,
    pub properties: Vec<AzureResourceProperty>,
    pub query_revision: Revision,
    pub page_size: u16,
}

impl AzureResourceGraphQueryAst {
    pub fn new(
        target: AzureResourceGraphTarget,
        resource_types: impl IntoIterator<Item = AzureResourceType>,
        properties: impl IntoIterator<Item = AzureResourceProperty>,
        query_revision: u64,
    ) -> Result<Self, ModelError> {
        let target = AzureResourceGraphTarget::normalize(target)?;
        let mut resource_types = resource_types.into_iter().collect::<Vec<_>>();
        let mut properties = properties.into_iter().collect::<Vec<_>>();
        resource_types.sort();
        properties.sort();
        if resource_types.is_empty()
            || resource_types.len() > MAX_RESOURCE_TYPES
            || resource_types.windows(2).any(|pair| pair[0] == pair[1])
            || properties.is_empty()
            || properties.len() > MAX_PROPERTIES
            || properties.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ModelError::InvalidQuery);
        }
        Ok(Self {
            target,
            resource_types,
            properties,
            query_revision: Revision::new(query_revision)?,
            page_size: PAGE_SIZE,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.target.clone(),
            self.resource_types.clone(),
            self.properties.clone(),
            self.query_revision.get(),
        )
        .map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn resource_type_codes(&self) -> Vec<String> {
        self.resource_types
            .iter()
            .map(|value| value.code().to_owned())
            .collect()
    }

    #[must_use]
    pub fn property_codes(&self) -> Vec<String> {
        self.properties
            .iter()
            .map(|value| value.code().to_owned())
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphScopeInput {
    pub tenant_id: String,
    pub target: AzureResourceGraphTarget,
    pub resource_types: Vec<AzureResourceType>,
    pub properties: Vec<AzureResourceProperty>,
    pub query_revision: u64,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionSnapshot,
    pub consent: ConsentScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphScope {
    tenant_id: TenantId,
    target: AzureResourceGraphTarget,
    resource_types: Vec<AzureResourceType>,
    properties: Vec<AzureResourceProperty>,
    query_revision: Revision,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission: PermissionSnapshot,
    consent: ConsentScope,
    scope_digest: Digest,
}

impl AzureResourceGraphScope {
    pub fn new(input: AzureResourceGraphScopeInput) -> Result<Self, ModelError> {
        let tenant_id = TenantId::new(input.tenant_id)?;
        let query = AzureResourceGraphQueryAst::new(
            input.target.clone(),
            input.resource_types.clone(),
            input.properties.clone(),
            input.query_revision,
        )?;
        input.permission.validate_for(&input.target)?;
        let mut scope = Self {
            tenant_id,
            target: query.target,
            resource_types: query.resource_types,
            properties: query.properties,
            query_revision: query.query_revision,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            permission: input.permission,
            consent: input.consent,
            scope_digest: Digest::parse("0".repeat(64))?,
        };
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.tenant_id,
            &self.target,
            &self.resource_types,
            &self.properties,
            self.query_revision,
            &self.project,
            &self.mission,
            &self.work_product,
            &self.permission,
            &self.consent,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let query = self.query_ast();
        query.validate()?;
        self.permission.validate_for(&self.target)?;
        if self.scope_digest != self.compute_digest() {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub fn target(&self) -> &AzureResourceGraphTarget {
        &self.target
    }

    #[must_use]
    pub fn resource_types(&self) -> &[AzureResourceType] {
        &self.resource_types
    }

    #[must_use]
    pub fn properties(&self) -> &[AzureResourceProperty] {
        &self.properties
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn query_revision(&self) -> Revision {
        self.query_revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn query_ast(&self) -> AzureResourceGraphQueryAst {
        AzureResourceGraphQueryAst {
            target: self.target.clone(),
            resource_types: self.resource_types.clone(),
            properties: self.properties.clone(),
            query_revision: self.query_revision,
            page_size: PAGE_SIZE,
        }
    }

    #[must_use]
    pub fn query_digest(&self) -> Digest {
        self.query_ast().digest()
    }
}

/// Opaque reference into a host-owned secret manager. The opaque identifier
/// is intentionally neither serializable nor printable; only a digest crosses
/// registration and request boundaries.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secret reference", false)?;
        Ok(Self {
            opaque_id,
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
                "azure-resource-graph-secret-reference/v1|{}|{}",
                self.opaque_id,
                self.revision.get()
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
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureResourceGraphEvidenceState {
    Complete,
    Empty,
    Partial,
    Truncated,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ProviderUnavailable,
    Timeout,
    BlockedEnv,
}

impl AzureResourceGraphEvidenceState {
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureResourceGraphResourcePayload {
    pub id: String,
    pub resource_type: String,
    pub location: Option<String>,
    pub subscription_id: Option<String>,
    pub resource_group: Option<String>,
    pub kind: Option<String>,
    pub properties: BTreeMap<String, Value>,
}

impl AzureResourceGraphResourcePayload {
    pub fn new(
        id: impl Into<String>,
        resource_type: impl Into<String>,
        location: Option<String>,
        subscription_id: Option<String>,
        resource_group: Option<String>,
        kind: Option<String>,
        properties: BTreeMap<String, Value>,
    ) -> Result<Self, ModelError> {
        let id = id.into();
        let resource_type = resource_type.into();
        validate_text(&id, "resource payload id", false)?;
        validate_text(&resource_type, "resource payload type", false)?;
        for (field, value) in [
            ("resource payload location", location.as_deref()),
            ("resource payload subscription", subscription_id.as_deref()),
            ("resource payload resource group", resource_group.as_deref()),
            ("resource payload kind", kind.as_deref()),
        ] {
            if let Some(value) = value {
                validate_text(value, field, true)?;
            }
        }
        Ok(Self {
            id,
            resource_type,
            location,
            subscription_id,
            resource_group,
            kind,
            properties,
        })
    }
}

impl fmt::Debug for AzureResourceGraphResourcePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureResourceGraphResourcePayload")
            .field("id", &self.id)
            .field("resource_type", &self.resource_type)
            .field("location", &self.location)
            .field("subscription_id", &self.subscription_id)
            .field("resource_group", &self.resource_group)
            .field("kind", &self.kind)
            .field("property_count", &self.properties.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceGraphPagePayload {
    pub resources: Vec<AzureResourceGraphResourcePayload>,
    pub partial: bool,
    pub truncated: bool,
    pub total_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphResponseReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: ProviderRevision,
    pub page: u16,
    pub continuation_digest: Option<Digest>,
    pub raw_provider_payload: bool,
    pub raw_properties: bool,
    pub raw_tags: bool,
    pub raw_secrets: bool,
    pub partial: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphDigestProperty {
    pub property: AzureResourceProperty,
    pub value_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphResource {
    pub resource_id: ResourceId,
    pub resource_type: AzureResourceType,
    pub location: Option<ResourceLocation>,
    pub subscription_id: Option<SubscriptionId>,
    pub resource_group: Option<ResourceGroupName>,
    pub kind: Option<String>,
    pub property_digests: Vec<AzureResourceGraphDigestProperty>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub query_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub provenance: TransportProvenance,
    pub state: AzureResourceGraphEvidenceState,
    pub page_count: u16,
    pub resources: Vec<AzureResourceGraphResource>,
    pub response_receipts: Vec<AzureResourceGraphResponseReceipt>,
    pub continuation_digest: Option<Digest>,
    pub usable: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub fleet_health_authority: bool,
    pub deployment_authority: bool,
    pub policy_authority: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureResourceGraphRecommendationDisposition {
    ReviewInventory,
    NeedsMoreEvidence,
    AccessLost,
    RateLimited,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphRecommendation {
    pub disposition: AzureResourceGraphRecommendationDisposition,
    pub non_mutating: bool,
    pub provider_reported_only: bool,
    pub claims_fleet_health: bool,
    pub claims_deployability: bool,
    pub claims_policy_compliance: bool,
    pub adopts_outcome: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphProposal {
    pub scope: AzureResourceGraphScope,
    pub evidence: AzureResourceGraphEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub query_digest: Digest,
    pub permission_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub recommendation: AzureResourceGraphRecommendation,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphObservationReceipt {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_provider_receipt: bool,
    pub observation_digest: Digest,
}

pub fn compute_evidence_digest(evidence: &AzureResourceGraphEvidence) -> Digest {
    canonical_digest(&serde_json::json!({
        "contractVersion": &evidence.contract_version,
        "contractDigest": &evidence.contract_digest,
        "pluginVersion": &evidence.plugin_version,
        "scopeDigest": &evidence.scope_digest,
        "registrationDigest": &evidence.registration_digest,
        "providerRevision": &evidence.provider_revision,
        "queryDigest": &evidence.query_digest,
        "permissionDigest": &evidence.permission_digest,
        "consentDigest": &evidence.consent_digest,
        "provenance": evidence.provenance,
        "state": evidence.state,
        "pageCount": evidence.page_count,
        "resources": &evidence.resources,
        "responseReceipts": &evidence.response_receipts,
        "continuationDigest": &evidence.continuation_digest,
        "usable": evidence.usable,
        "native": evidence.native,
        "connected": evidence.connected,
        "externalWrites": evidence.external_writes,
        "fleetHealthAuthority": evidence.fleet_health_authority,
        "deploymentAuthority": evidence.deployment_authority,
        "policyAuthority": evidence.policy_authority,
        "outcomeAuthority": evidence.outcome_authority,
    }))
}

pub fn compute_proposal_digest(proposal: &AzureResourceGraphProposal) -> Digest {
    canonical_digest(&(
        &proposal.scope,
        &proposal.evidence,
        &proposal.source_evidence_digest,
        &proposal.registration_digest,
        &proposal.provider_digest,
        &proposal.contract_digest,
        &proposal.query_digest,
        &proposal.permission_digest,
        proposal.proposal_only,
        proposal.native,
        proposal.connected,
        proposal.adopts_outcome,
        &proposal.recommendation,
    ))
}

impl AzureResourceGraphEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != AZURE_RESOURCE_GRAPH_CONTRACT_VERSION
            || self.plugin_version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || self.provider_revision.as_str() != AZURE_RESOURCE_GRAPH_PROVIDER_REVISION
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.native
            || self.connected
            || self.external_writes
            || self.fleet_health_authority
            || self.deployment_authority
            || self.policy_authority
            || self.outcome_authority
            || self.usable != self.state.is_usable()
            || self.resources.len() > MAX_RESOURCES
            || self.page_count == 0
            || self.page_count > MAX_PAGES
            || self.evidence_digest != compute_evidence_digest(self)
        {
            return Err(ModelError::InvalidScope);
        }
        if !self
            .resources
            .windows(2)
            .all(|pair| pair[0].resource_id <= pair[1].resource_id)
        {
            return Err(ModelError::InvalidResource);
        }
        if !self.resources.iter().all(|resource| {
            resource.property_digests.windows(2).all(|pair| {
                pair[0].property <= pair[1].property && pair[0].value_digest.as_str().len() == 64
            })
        }) {
            return Err(ModelError::InvalidResource);
        }
        if !self.state.is_usable() && !self.resources.is_empty() {
            return Err(ModelError::InvalidResource);
        }
        Ok(())
    }
}

impl AzureResourceGraphProposal {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.proposal_only
            || self.native
            || self.connected
            || self.adopts_outcome
            || self.scope.scope_digest() != &self.evidence.scope_digest
            || self.source_evidence_digest != self.evidence.evidence_digest
            || self.contract_digest.as_str().len() != 64
            || self.query_digest != self.scope.query_digest()
            || self.permission_digest != self.scope.permission().digest()
            || self.proposal_digest != compute_proposal_digest(self)
        {
            return Err(ModelError::InvalidScope);
        }
        self.scope.validate()?;
        self.evidence.validate()
    }
}

impl AzureResourceGraphObservationReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != AZURE_RESOURCE_GRAPH_CONTRACT_VERSION
            || self.consumer_id != crate::MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_ID
            || self.consumer_version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || !self.read_only
            || self.native
            || self.connected
            || self.durable_provider_receipt
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

impl AzureResourceProperty {
    #[must_use]
    pub(crate) fn digest_value(
        self,
        payload: &AzureResourceGraphResourcePayload,
    ) -> Option<Digest> {
        match self {
            Self::Kind => payload.kind.as_ref().map(canonical_digest),
            Self::Location => payload.location.as_ref().map(canonical_digest),
            _ => self.value_from(payload).map(canonical_digest),
        }
    }
}

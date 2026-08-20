//! Typed, bounded, redacted models for the Azure Cosmos DB Layer-1 seam.
//!
//! The model deliberately has no representation for keys, connection strings,
//! document payloads, account endpoints, tags, network rule bodies, managed
//! identities, partition-key paths, indexing paths, or arbitrary provider
//! properties.  Those values cannot cross this crate's public evidence
//! boundary because there is no public evidence type for them.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: usize = 12;
pub const MAX_RETRIES: u8 = 2;
pub const MAX_REGIONS: usize = 32;
pub const MAX_PROVIDER_ERRORS: usize = 12;
pub const MAX_RU_PER_SECOND: u64 = 10_000_000;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded value")]
    OutOfBounds { field: &'static str },
    #[error("{field} has too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("the opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("the opaque secret reference has been revoked")]
    SecretRevoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/@+~()".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
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

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
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

bounded_identifier!(TenantId, "tenant id");
bounded_identifier!(SubscriptionId, "subscription id");
bounded_identifier!(ResourceGroupName, "resource group name");
bounded_identifier!(AccountName, "Cosmos DB account name");
bounded_identifier!(DatabaseName, "Cosmos DB SQL database name");
bounded_identifier!(ContainerName, "Cosmos DB SQL container name");
bounded_identifier!(ApiVersion, "Azure Resource Manager API version");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(RegionName, "Azure region name");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "Azure resource id", MAX_IDENTIFIER_BYTES)?;
        if !value.starts_with("/subscriptions/") {
            return Err(ModelError::Invalid {
                field: "Azure resource id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes =
            Vec::with_capacity(tag.len() + parts.iter().map(String::len).sum::<usize>());
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    pub fn validate(&self, field: &'static str) -> Result<(), ModelError> {
        if self.0.len() != 64
            || self
                .0
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            Err(ModelError::InvalidDigest { field })
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("ProjectBinding is serializable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("MissionBinding is serializable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("WorkProductBinding is serializable")
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputTarget {
    Container,
    Database,
    ContainerOrDatabase,
}

impl ThroughputTarget {
    pub const fn allows_container(self) -> bool {
        matches!(self, Self::Container | Self::ContainerOrDatabase)
    }

    pub const fn allows_database(self) -> bool {
        matches!(self, Self::Database | Self::ContainerOrDatabase)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AzureCosmosScope {
    pub tenant_id: TenantId,
    pub subscription_id: SubscriptionId,
    pub resource_group: ResourceGroupName,
    pub account_name: AccountName,
    pub database_name: DatabaseName,
    pub container_name: ContainerName,
    pub api_version: ApiVersion,
    pub account_revision_digest: Digest,
    pub database_revision_digest: Digest,
    pub container_revision_digest: Digest,
    pub throughput_revision_digest: Option<Digest>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub provider_id: ProviderId,
    pub provider_revision: ProviderRevision,
    pub throughput_target: ThroughputTarget,
}

impl AzureCosmosScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        resource_group: ResourceGroupName,
        account_name: AccountName,
        database_name: DatabaseName,
        container_name: ContainerName,
        api_version: ApiVersion,
        account_revision_digest: Digest,
        database_revision_digest: Digest,
        container_revision_digest: Digest,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        provider_id: ProviderId,
        provider_revision: ProviderRevision,
        throughput_target: ThroughputTarget,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            tenant_id,
            subscription_id,
            resource_group,
            account_name,
            database_name,
            container_name,
            api_version,
            account_revision_digest,
            database_revision_digest,
            container_revision_digest,
            throughput_revision_digest: None,
            project,
            mission,
            work_product,
            provider_id,
            provider_revision,
            throughput_target,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_etags(
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        resource_group: ResourceGroupName,
        account_name: AccountName,
        database_name: DatabaseName,
        container_name: ContainerName,
        api_version: ApiVersion,
        account_etag: impl AsRef<str>,
        database_etag: impl AsRef<str>,
        container_etag: impl AsRef<str>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        provider_id: ProviderId,
        provider_revision: ProviderRevision,
        throughput_target: ThroughputTarget,
    ) -> Result<Self, ModelError> {
        Self::new(
            tenant_id,
            subscription_id,
            resource_group,
            account_name,
            database_name,
            container_name,
            api_version,
            Digest::from_text(account_etag.as_ref()),
            Digest::from_text(database_etag.as_ref()),
            Digest::from_text(container_etag.as_ref()),
            project,
            mission,
            work_product,
            provider_id,
            provider_revision,
            throughput_target,
        )
    }

    pub fn with_throughput_revision(mut self, revision: Digest) -> Result<Self, ModelError> {
        revision.validate("throughput revision digest")?;
        self.throughput_revision_digest = Some(revision);
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.account_revision_digest
            .validate("account revision digest")?;
        self.database_revision_digest
            .validate("database revision digest")?;
        self.container_revision_digest
            .validate("container revision digest")?;
        if let Some(revision) = &self.throughput_revision_digest {
            revision.validate("throughput revision digest")?;
        }
        if self.provider_id.as_str() != crate::AZURE_COSMOS_PROVIDER_ID {
            return Err(ModelError::ScopeMismatch {
                field: "provider id",
            });
        }
        if self.provider_revision.as_str() != crate::AZURE_COSMOS_PROVIDER_REVISION {
            return Err(ModelError::ScopeMismatch {
                field: "provider revision",
            });
        }
        if self.api_version.as_str() != crate::AZURE_COSMOS_API_VERSION {
            return Err(ModelError::ScopeMismatch {
                field: "API version",
            });
        }
        Ok(())
    }

    pub fn account_resource_id(&self) -> ResourceId {
        ResourceId::new(format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DocumentDB/databaseAccounts/{}",
            self.subscription_id, self.resource_group, self.account_name
        ))
        .expect("validated Cosmos account resource id")
    }

    pub fn database_resource_id(&self) -> ResourceId {
        ResourceId::new(format!(
            "{}/sqlDatabases/{}",
            self.account_resource_id(),
            self.database_name
        ))
        .expect("validated Cosmos database resource id")
    }

    pub fn container_resource_id(&self) -> ResourceId {
        ResourceId::new(format!(
            "{}/containers/{}",
            self.database_resource_id(),
            self.container_name
        ))
        .expect("validated Cosmos container resource id")
    }

    pub fn throughput_resource_id(&self, target: ThroughputTarget) -> ResourceId {
        let base = match target {
            ThroughputTarget::Container | ThroughputTarget::ContainerOrDatabase => {
                self.container_resource_id()
            }
            ThroughputTarget::Database => self.database_resource_id(),
        };
        ResourceId::new(format!("{base}/throughputSettings/default"))
            .expect("validated Cosmos throughput resource id")
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("AzureCosmosScope is serializable")
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }
}

pub type AzureCosmosResourceScope = AzureCosmosScope;

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    ReadDatabaseAccount,
    ReadSqlDatabase,
    ReadSqlContainer,
    ReadThroughputSettings,
}

impl PermissionAction {
    pub const fn arm_permission(self) -> &'static str {
        match self {
            Self::ReadDatabaseAccount => "Microsoft.DocumentDB/databaseAccounts/read",
            Self::ReadSqlDatabase => "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read",
            Self::ReadSqlContainer => {
                "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read"
            }
            Self::ReadThroughputSettings => {
                "Microsoft.DocumentDB/databaseAccounts/*/throughputSettings/read"
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PermissionSnapshot {
    pub authority: String,
    pub revision: Revision,
    pub actions: BTreeSet<PermissionAction>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        authority: impl Into<String>,
        revision: Revision,
        actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let authority = authority.into();
        validate_text(&authority, "permission authority", MAX_IDENTIFIER_BYTES)?;
        let actions = actions.into_iter().collect::<BTreeSet<_>>();
        if actions.is_empty() {
            return Err(ModelError::Invalid {
                field: "permission action set",
            });
        }
        let mut value = Self {
            authority,
            revision,
            actions,
            digest: Digest::zero(),
        };
        value.digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn arm_read(revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            "Microsoft.Authorization/roleAssignments/read",
            revision,
            [
                PermissionAction::ReadDatabaseAccount,
                PermissionAction::ReadSqlDatabase,
                PermissionAction::ReadSqlContainer,
                PermissionAction::ReadThroughputSettings,
            ],
        )
    }

    fn recomputed_digest(&self) -> Digest {
        digest_serializable(&(&self.authority, self.revision, &self.actions))
            .expect("PermissionSnapshot digest input is serializable")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.digest != self.recomputed_digest() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        if !self.allows_all() {
            return Err(ModelError::Unsupported {
                field: "permission action set",
            });
        }
        Ok(())
    }

    pub fn allows_all(&self) -> bool {
        [
            PermissionAction::ReadDatabaseAccount,
            PermissionAction::ReadSqlDatabase,
            PermissionAction::ReadSqlContainer,
            PermissionAction::ReadThroughputSettings,
        ]
        .into_iter()
        .all(|action| self.actions.contains(&action))
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    EntraArmRead,
}

/// An opaque host-owned Microsoft Entra reference.
///
/// The supplied handle is hashed and dropped before this value is returned.
/// The handle, token, client secret, certificate, and endpoint are not stored,
/// displayed, or serialized.  Layer 1 cannot resolve this reference.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    tenant_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl AsRef<str>,
        tenant_id: &TenantId,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let handle = opaque_handle.as_ref();
        validate_text(handle, "opaque Entra reference", MAX_IDENTIFIER_BYTES)?;
        let reference_digest = Digest::from_parts(
            "hartevo-azure-cosmosdb-entra-arm-read-reference/v1",
            &[
                handle.to_owned(),
                tenant_id.as_str().to_owned(),
                revision.get().to_string(),
            ],
        );
        Ok(Self {
            kind: SecretReferenceKind::EntraArmRead,
            reference_digest,
            tenant_digest: Digest::from_text(tenant_id.as_str()),
            revision,
            revoked: false,
        })
    }

    pub fn for_arm_read(
        opaque_handle: impl AsRef<str>,
        tenant_id: &TenantId,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, tenant_id, revision)
    }

    pub fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn tenant_digest(&self) -> &Digest {
        &self.tenant_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference", &"<opaque>")
            .field("reference_digest", &self.reference_digest)
            .field("tenant_digest", &self.tenant_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsistencyPolicy {
    Strong,
    BoundedStaleness,
    Session,
    ConsistentPrefix,
    Eventual,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupPolicy {
    Continuous,
    Periodic,
    None,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThroughputMode {
    Manual,
    Autoscale,
    SharedInherited,
    Dedicated,
    Ambiguous,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThroughputInheritance {
    Container,
    Database,
    SharedDatabase,
    Ambiguous,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndexingMode {
    Consistent,
    Lazy,
    None,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ReplicationTopologySummary {
    pub primary_location: Option<RegionName>,
    pub region_count: u16,
    pub region_set_digest: Digest,
    pub multi_region: bool,
}

impl ReplicationTopologySummary {
    pub fn new(
        primary_location: Option<RegionName>,
        regions: impl IntoIterator<Item = RegionName>,
    ) -> Result<Self, ModelError> {
        let mut regions = regions.into_iter().collect::<Vec<_>>();
        if regions.is_empty() {
            return Err(ModelError::Invalid {
                field: "replication regions",
            });
        }
        if regions.len() > MAX_REGIONS {
            return Err(ModelError::TooMany {
                field: "replication regions",
            });
        }
        regions.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        regions.dedup_by(|left, right| left == right);
        let region_set_digest = Digest::from_parts(
            "hartevo-azure-cosmosdb-replication-topology/v1",
            &regions
                .iter()
                .map(|region| region.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            primary_location,
            region_count: u16::try_from(regions.len()).expect("replication region bound fits u16"),
            region_set_digest,
            multi_region: regions.len() > 1,
        })
    }

    pub fn single(location: RegionName) -> Self {
        Self::new(Some(location.clone()), [location]).expect("one replication region is valid")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ThroughputSummary {
    pub mode: ThroughputMode,
    pub inheritance: ThroughputInheritance,
    pub min_ru_per_second: Option<u64>,
    pub max_ru_per_second: Option<u64>,
}

impl ThroughputSummary {
    pub fn unknown() -> Self {
        Self {
            mode: ThroughputMode::Unknown,
            inheritance: ThroughputInheritance::Unavailable,
            min_ru_per_second: None,
            max_ru_per_second: None,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for value in [self.min_ru_per_second, self.max_ru_per_second]
            .into_iter()
            .flatten()
        {
            if value == 0 || value > MAX_RU_PER_SECOND {
                return Err(ModelError::OutOfBounds {
                    field: "throughput RU per second",
                });
            }
        }
        if let (Some(minimum), Some(maximum)) = (self.min_ru_per_second, self.max_ru_per_second)
            && minimum > maximum
        {
            return Err(ModelError::Invalid {
                field: "throughput RU range",
            });
        }
        Ok(())
    }

    pub const fn is_degraded(&self) -> bool {
        matches!(
            self.mode,
            ThroughputMode::Ambiguous | ThroughputMode::Unknown
        ) || matches!(self.inheritance, ThroughputInheritance::Ambiguous)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ResourceDigestPair {
    pub identity_digest: Digest,
    pub revision_digest: Digest,
}

impl ResourceDigestPair {
    pub fn new(identity_digest: Digest, revision_digest: Digest) -> Result<Self, ModelError> {
        identity_digest.validate("resource identity digest")?;
        revision_digest.validate("resource revision digest")?;
        Ok(Self {
            identity_digest,
            revision_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AzureCosmosContainerPosture {
    pub account: ResourceDigestPair,
    pub database: ResourceDigestPair,
    pub container: ResourceDigestPair,
    pub throughput: Option<ResourceDigestPair>,
    pub location: Option<RegionName>,
    pub replication: ReplicationTopologySummary,
    pub consistency: ConsistencyPolicy,
    pub backup_policy: BackupPolicy,
    pub public_network_access: Option<bool>,
    pub network_filter_enabled: Option<bool>,
    pub throughput_summary: ThroughputSummary,
    pub indexing_mode: IndexingMode,
    pub partition_key_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
}

impl AzureCosmosContainerPosture {
    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(partition_key_digest) = &self.partition_key_digest {
            partition_key_digest.validate("partition key digest")?;
        }
        self.throughput_summary.validate()?;
        self.replication
            .region_set_digest
            .validate("replication digest")?;
        if self.replication.region_count == 0
            || usize::from(self.replication.region_count) > MAX_REGIONS
        {
            return Err(ModelError::OutOfBounds {
                field: "replication region count",
            });
        }
        Ok(())
    }

    pub const fn is_degraded(&self) -> bool {
        self.throughput_summary.is_degraded()
            || matches!(self.consistency, ConsistencyPolicy::Unknown)
            || matches!(self.backup_policy, BackupPolicy::Unknown)
            || matches!(self.indexing_mode, IndexingMode::Unknown)
            || self.public_network_access.is_none()
            || self.network_filter_enabled.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Present,
    DegradedConfiguration,
    Partial,
    NotFound,
    AccessLost,
    RevisionDrift,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl EvidenceState {
    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Present)
    }

    pub const fn is_terminal_failure(self) -> bool {
        matches!(self, Self::Tampered | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PartialReason {
    MissingAccount,
    MissingDatabase,
    MissingContainer,
    ThroughputUnavailable,
    ThroughputAmbiguous,
    ProviderResponseIncomplete,
    ResponseTooLarge,
    MalformedResponse,
    RetryExhausted,
    ProviderError,
    RevisionMismatch,
    ReplayDetected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    MalformedResponse,
    ResponseTooLarge,
    BlockedEnv,
    TransportUnavailable,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProviderErrorSummary {
    pub operation: String,
    pub code: ProviderErrorCode,
    pub status_code: Option<u16>,
    pub retryable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AzureCosmosEvidence {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: ProviderId,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_version: ApiVersion,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub partial_reason: Option<PartialReason>,
    pub provenance: TransportProvenance,
    pub posture: Option<AzureCosmosContainerPosture>,
    pub provider_errors: Vec<ProviderErrorSummary>,
    pub observed_at: DateTime<Utc>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub local_record_only: bool,
    pub external_write_performed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub raw_provider_payload_retained: bool,
}

impl AzureCosmosEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_version: impl Into<String>,
        contract_version: impl Into<String>,
        contract_digest: Digest,
        provider_id: ProviderId,
        provider_revision: ProviderRevision,
        provider_digest: Digest,
        api_version: ApiVersion,
        scope_digest: Digest,
        permission_digest: Digest,
        secret_reference_digest: Digest,
        request_digest: Digest,
        state: EvidenceState,
        partial_reason: Option<PartialReason>,
        provenance: TransportProvenance,
        posture: Option<AzureCosmosContainerPosture>,
        provider_errors: Vec<ProviderErrorSummary>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if provider_errors.len() > MAX_PROVIDER_ERRORS {
            return Err(ModelError::TooMany {
                field: "provider errors",
            });
        }
        for digest in [
            &contract_digest,
            &provider_digest,
            &scope_digest,
            &permission_digest,
            &secret_reference_digest,
            &request_digest,
        ] {
            digest.validate("evidence binding digest")?;
        }
        if let Some(posture) = &posture {
            posture.validate()?;
        }
        let mut evidence = Self {
            plugin_version: plugin_version.into(),
            contract_version: contract_version.into(),
            contract_digest,
            provider_id,
            provider_revision,
            provider_digest,
            api_version,
            scope_digest,
            permission_digest,
            secret_reference_digest,
            request_digest,
            evidence_digest: Digest::zero(),
            state,
            partial_reason,
            provenance,
            posture,
            provider_errors,
            observed_at,
            read_only: true,
            proposal_only: true,
            local_record_only: true,
            external_write_performed: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            raw_provider_payload_retained: false,
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        Ok(evidence)
    }

    pub fn revoked(
        scope: &AzureCosmosScope,
        permission: &PermissionSnapshot,
        secret: &SecretReference,
        provider_digest: Digest,
        request_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(
            crate::AZURE_COSMOS_PLUGIN_VERSION,
            crate::AZURE_COSMOS_CONTRACT_VERSION,
            crate::contract_digest(),
            scope.provider_id.clone(),
            scope.provider_revision.clone(),
            provider_digest,
            scope.api_version.clone(),
            scope.digest(),
            permission.digest.clone(),
            secret.reference_digest().clone(),
            request_digest,
            EvidenceState::Revoked,
            None,
            TransportProvenance::BlockedEnv,
            None,
            Vec::new(),
            observed_at,
        )
    }

    fn digest_input(&self) -> EvidenceDigestInput<'_> {
        EvidenceDigestInput {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_version: &self.api_version,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            secret_reference_digest: &self.secret_reference_digest,
            request_digest: &self.request_digest,
            state: self.state,
            partial_reason: self.partial_reason,
            provenance: self.provenance,
            posture: self.posture.as_ref(),
            provider_errors: &self.provider_errors,
            observed_at: self.observed_at,
            read_only: self.read_only,
            proposal_only: self.proposal_only,
            local_record_only: self.local_record_only,
            external_write_performed: self.external_write_performed,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            truth_authority: self.truth_authority,
            consent_authority: self.consent_authority,
            effect_authority: self.effect_authority,
            receipt_authority: self.receipt_authority,
            verification_authority: self.verification_authority,
            outcome_authority: self.outcome_authority,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
        }
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&self.digest_input()).expect("evidence digest input is serializable")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.evidence_digest != self.recomputed_digest() {
            return Err(ModelError::Invalid {
                field: "evidence digest",
            });
        }
        if !self.read_only
            || !self.proposal_only
            || !self.local_record_only
            || self.external_write_performed
            || self.connected
            || self.native
            || self.first_party
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.raw_provider_payload_retained
        {
            return Err(ModelError::Unsupported {
                field: "Layer-1 evidence authority",
            });
        }
        if self.provider_errors.len() > MAX_PROVIDER_ERRORS {
            return Err(ModelError::TooMany {
                field: "provider errors",
            });
        }
        if matches!(self.state, EvidenceState::Present) && self.posture.is_none() {
            return Err(ModelError::Invalid {
                field: "present posture",
            });
        }
        if self.posture.is_none()
            && matches!(
                self.state,
                EvidenceState::DegradedConfiguration | EvidenceState::Partial
            )
            && self.partial_reason.is_none()
        {
            return Err(ModelError::Invalid {
                field: "partial reason",
            });
        }
        if let Some(posture) = &self.posture {
            posture.validate()?;
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a ProviderId,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_version: &'a ApiVersion,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    request_digest: &'a Digest,
    state: EvidenceState,
    partial_reason: Option<PartialReason>,
    provenance: TransportProvenance,
    posture: Option<&'a AzureCosmosContainerPosture>,
    provider_errors: &'a [ProviderErrorSummary],
    observed_at: DateTime<Utc>,
    read_only: bool,
    proposal_only: bool,
    local_record_only: bool,
    external_write_performed: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    truth_authority: bool,
    consent_authority: bool,
    effect_authority: bool,
    receipt_authority: bool,
    verification_authority: bool,
    outcome_authority: bool,
    raw_provider_payload_retained: bool,
}

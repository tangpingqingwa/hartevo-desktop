//! Bounded, digest-first models for the AWS Resource Explorer Layer-1 slice.
//!
//! The model deliberately has no public representation for credentials, raw
//! Resource Explorer properties, tags, PII, raw queries, or provider tokens.
//! Constructors that accept those values immediately reduce them to digests.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::Error as SerError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_QUERY_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_RESOURCES: usize = 256;
pub const MAX_INDEXES: usize = 64;
pub const MAX_PROPERTY_DIGESTS: usize = 32;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

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
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds its bound")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} is not allowed in Layer 1")]
    Unsupported { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
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
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@*".contains(&byte)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(value: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(value.as_ref())))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    #[must_use]
    pub fn from_parts<I, S>(label: &str, parts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(label.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_ref());
        }
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded typed value serializes");
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, ModelError> {
        let value = value.into();
        validate_digest(&value, field)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn zero() -> Self {
        Self("0".repeat(64))
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
pub fn sha256_digest(value: impl AsRef<[u8]>) -> Digest {
    Digest::from_bytes(value)
}

#[must_use]
pub fn serialized_digest<T: Serialize>(value: &T) -> Digest {
    Digest::from_serialized(value)
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field, MAX_IDENTIFIER_BYTES)?;
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
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
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

impl From<MissionId> for String {
    fn from(value: MissionId) -> Self {
        value.0
    }
}

impl From<ProjectId> for String {
    fn from(value: ProjectId) -> Self {
        value.0
    }
}

impl From<WorkProductId> for String {
    fn from(value: WorkProductId) -> Self {
        value.0
    }
}

bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(IndexId, "Resource Explorer index id");
bounded_identifier!(ViewId, "Resource Explorer view id");
bounded_identifier!(ResourceType, "resource type");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
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

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
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

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

pub trait IntoRevision {
    fn into_revision(self) -> Result<Revision, ModelError>;
}

impl IntoRevision for Revision {
    fn into_revision(self) -> Result<Revision, ModelError> {
        validate_revision(self.get(), "revision")?;
        Ok(self)
    }
}

impl IntoRevision for u64 {
    fn into_revision(self) -> Result<Revision, ModelError> {
        Revision::new(self)
    }
}

pub type IndexRevision = Revision;
pub type ViewRevision = Revision;
pub type QueryRevision = Revision;
pub type ResourceRevision = Revision;
pub type MissionRevision = Revision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    id: MissionId,
    revision: MissionRevision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: impl IntoRevision) -> Result<Self, ModelError> {
        let revision = revision.into_revision()?;
        validate_revision(revision.get(), "Mission revision")?;
        Ok(Self {
            id: MissionId::new(id)?,
            revision,
        })
    }

    pub fn from_parts(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::new(id, Revision::new(revision)?)
    }

    #[must_use]
    pub fn id(&self) -> &MissionId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> MissionRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    id: ProjectId,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: impl IntoRevision) -> Result<Self, ModelError> {
        let revision = revision.into_revision()?;
        validate_revision(revision.get(), "Project revision")?;
        Ok(Self {
            id: ProjectId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: impl IntoRevision) -> Result<Self, ModelError> {
        let revision = revision.into_revision()?;
        validate_revision(revision.get(), "Work Product revision")?;
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceExplorerIndex {
    account_id: AccountId,
    region: AwsRegion,
    index_digest: Digest,
    revision: IndexRevision,
}

impl ResourceExplorerIndex {
    pub fn new(
        account_id: AccountId,
        region: AwsRegion,
        index_id: impl Into<String>,
        revision: IndexRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "index revision")?;
        let index_id = index_id.into();
        validate_identifier(&index_id, "index id", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            index_digest: Digest::from_parts(
                "aws-resource-explorer-index/v1",
                [
                    account_id.as_str().as_bytes(),
                    region.as_str().as_bytes(),
                    index_id.as_bytes(),
                ],
            ),
            account_id,
            region,
            revision,
        })
    }

    pub fn from_digest(
        account_id: AccountId,
        region: AwsRegion,
        index_digest: Digest,
        revision: IndexRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "index revision")?;
        validate_digest(index_digest.as_str(), "index digest")?;
        Ok(Self {
            account_id,
            region,
            index_digest,
            revision,
        })
    }

    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn index_digest(&self) -> &Digest {
        &self.index_digest
    }

    #[must_use]
    pub const fn revision(&self) -> IndexRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

pub type IndexBinding = ResourceExplorerIndex;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceExplorerView {
    view_digest: Digest,
    revision: ViewRevision,
}

impl ResourceExplorerView {
    pub fn new(view_id: impl Into<String>, revision: ViewRevision) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "view revision")?;
        let view_id = view_id.into();
        validate_identifier(&view_id, "view id", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            view_digest: Digest::from_parts("aws-resource-explorer-view/v1", [view_id]),
            revision,
        })
    }

    pub fn from_digest(view_digest: Digest, revision: ViewRevision) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "view revision")?;
        validate_digest(view_digest.as_str(), "view digest")?;
        Ok(Self {
            view_digest,
            revision,
        })
    }

    #[must_use]
    pub fn view_digest(&self) -> &Digest {
        &self.view_digest
    }

    #[must_use]
    pub const fn revision(&self) -> ViewRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

pub type ViewBinding = ResourceExplorerView;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceExplorerQuery {
    query_digest: Digest,
    revision: QueryRevision,
}

impl ResourceExplorerQuery {
    pub fn new(query: impl Into<String>, revision: QueryRevision) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "query revision")?;
        let query = query.into();
        if query.is_empty() {
            return Err(ModelError::Empty { field: "query" });
        }
        if query.len() > MAX_QUERY_BYTES {
            return Err(ModelError::TooLong { field: "query" });
        }
        if query.trim() != query || query.chars().any(char::is_control) {
            return Err(ModelError::ControlCharacter { field: "query" });
        }
        let lower = query.to_ascii_lowercase();
        if lower.contains("tag:")
            || lower.contains("tag.")
            || lower.contains("tag-key")
            || lower.contains("tagvalue")
        {
            return Err(ModelError::Unsupported {
                field: "query tags",
            });
        }
        if query.bytes().any(|byte| {
            !b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_:=/*()\"'."
                .contains(&byte)
        }) {
            return Err(ModelError::InvalidCharacters { field: "query" });
        }
        Ok(Self {
            query_digest: Digest::from_parts("aws-resource-explorer-query/v1", [query]),
            revision,
        })
    }

    pub fn from_digest(query_digest: Digest, revision: QueryRevision) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "query revision")?;
        validate_digest(query_digest.as_str(), "query digest")?;
        Ok(Self {
            query_digest,
            revision,
        })
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    #[must_use]
    pub const fn revision(&self) -> QueryRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

pub type Query = ResourceExplorerQuery;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceExplorerResource {
    resource_digest: Digest,
    resource_type_digest: Digest,
    region: AwsRegion,
    revision: ResourceRevision,
}

impl ResourceExplorerResource {
    pub fn new(
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        region: AwsRegion,
        revision: ResourceRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "resource revision")?;
        let resource_type = resource_type.into();
        let resource_id = resource_id.into();
        validate_identifier(&resource_type, "resource type", MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&resource_id, "resource id", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            resource_digest: Digest::from_parts(
                "aws-resource-explorer-resource/v1",
                [resource_id.as_bytes(), region.as_str().as_bytes()],
            ),
            resource_type_digest: Digest::from_text(resource_type),
            region,
            revision,
        })
    }

    pub fn from_digests(
        resource_digest: Digest,
        resource_type_digest: Digest,
        region: AwsRegion,
        revision: ResourceRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "resource revision")?;
        validate_digest(resource_digest.as_str(), "resource digest")?;
        validate_digest(resource_type_digest.as_str(), "resource type digest")?;
        Ok(Self {
            resource_digest,
            resource_type_digest,
            region,
            revision,
        })
    }

    #[must_use]
    pub fn resource_digest(&self) -> &Digest {
        &self.resource_digest
    }

    #[must_use]
    pub fn resource_type_digest(&self) -> &Digest {
        &self.resource_type_digest
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub const fn revision(&self) -> ResourceRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

pub type ResourceBinding = ResourceExplorerResource;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PropertyDigest {
    name_digest: Digest,
    value_digest: Digest,
}

impl PropertyDigest {
    pub fn new(name: impl AsRef<str>, value: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let name = name.as_ref();
        validate_identifier(name, "property name", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            name_digest: Digest::from_text(name),
            value_digest: Digest::from_bytes(value),
        })
    }

    pub fn from_digests(name_digest: Digest, value_digest: Digest) -> Result<Self, ModelError> {
        validate_digest(name_digest.as_str(), "property name digest")?;
        validate_digest(value_digest.as_str(), "property value digest")?;
        Ok(Self {
            name_digest,
            value_digest,
        })
    }

    #[must_use]
    pub fn name_digest(&self) -> &Digest {
        &self.name_digest
    }

    #[must_use]
    pub fn value_digest(&self) -> &Digest {
        &self.value_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceInventoryItem {
    resource_digest: Digest,
    resource_type_digest: Digest,
    region: AwsRegion,
    service_digest: Digest,
    property_digests: Vec<PropertyDigest>,
    revision: ResourceRevision,
}

impl ResourceInventoryItem {
    pub fn from_raw<I, N, V>(
        resource_id: impl Into<String>,
        resource_type: impl Into<String>,
        region: AwsRegion,
        service: impl Into<String>,
        properties: I,
        revision: ResourceRevision,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        let scope =
            ResourceExplorerResource::new(resource_type, resource_id, region.clone(), revision)?;
        let service = service.into();
        validate_identifier(&service, "resource service", MAX_IDENTIFIER_BYTES)?;
        let mut property_digests = properties
            .into_iter()
            .map(|(name, value)| PropertyDigest::new(name.into(), value.into()))
            .collect::<Result<Vec<_>, _>>()?;
        if property_digests.len() > MAX_PROPERTY_DIGESTS {
            return Err(ModelError::TooMany {
                field: "property digests",
            });
        }
        property_digests.sort_by(|left, right| {
            left.name_digest
                .cmp(&right.name_digest)
                .then_with(|| left.value_digest.cmp(&right.value_digest))
        });
        if property_digests
            .windows(2)
            .any(|pair| pair[0].name_digest == pair[1].name_digest)
        {
            return Err(ModelError::Duplicate {
                field: "property digest names",
            });
        }
        Ok(Self {
            resource_digest: scope.resource_digest,
            resource_type_digest: scope.resource_type_digest,
            region,
            service_digest: Digest::from_text(service),
            property_digests,
            revision,
        })
    }

    pub fn from_scope(
        scope: &ResourceExplorerResource,
        service: impl Into<String>,
        properties: impl IntoIterator<Item = PropertyDigest>,
    ) -> Result<Self, ModelError> {
        let service = service.into();
        validate_identifier(&service, "resource service", MAX_IDENTIFIER_BYTES)?;
        let mut property_digests = properties.into_iter().collect::<Vec<_>>();
        if property_digests.len() > MAX_PROPERTY_DIGESTS {
            return Err(ModelError::TooMany {
                field: "property digests",
            });
        }
        property_digests.sort_by(|left, right| left.name_digest.cmp(&right.name_digest));
        if property_digests
            .windows(2)
            .any(|pair| pair[0].name_digest == pair[1].name_digest)
        {
            return Err(ModelError::Duplicate {
                field: "property digest names",
            });
        }
        Ok(Self {
            resource_digest: scope.resource_digest.clone(),
            resource_type_digest: scope.resource_type_digest.clone(),
            region: scope.region.clone(),
            service_digest: Digest::from_text(service),
            property_digests,
            revision: scope.revision,
        })
    }

    pub fn from_digests(
        resource_digest: Digest,
        resource_type_digest: Digest,
        region: AwsRegion,
        service_digest: Digest,
        property_digests: Vec<PropertyDigest>,
        revision: ResourceRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "resource revision")?;
        validate_digest(resource_digest.as_str(), "resource digest")?;
        validate_digest(resource_type_digest.as_str(), "resource type digest")?;
        validate_digest(service_digest.as_str(), "service digest")?;
        if property_digests.len() > MAX_PROPERTY_DIGESTS {
            return Err(ModelError::TooMany {
                field: "property digests",
            });
        }
        Ok(Self {
            resource_digest,
            resource_type_digest,
            region,
            service_digest,
            property_digests,
            revision,
        })
    }

    #[must_use]
    pub fn resource_digest(&self) -> &Digest {
        &self.resource_digest
    }

    #[must_use]
    pub fn resource_type_digest(&self) -> &Digest {
        &self.resource_type_digest
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn service_digest(&self) -> &Digest {
        &self.service_digest
    }

    #[must_use]
    pub fn property_digests(&self) -> &[PropertyDigest] {
        &self.property_digests
    }

    #[must_use]
    pub const fn revision(&self) -> ResourceRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    Search,
    ListIndexes,
}

impl PermissionAction {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Search => "resource-explorer-2:Search",
            Self::ListIndexes => "resource-explorer-2:ListIndexes",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionFence {
    permissions: BTreeSet<PermissionAction>,
    revision: Revision,
}

impl PermissionFence {
    pub fn for_layer_one(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [PermissionAction::Search, PermissionAction::ListIndexes],
            Revision::new(revision)?,
        )
    }

    pub fn new(
        permissions: impl IntoIterator<Item = PermissionAction>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "permission revision")?;
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let fence = Self {
            permissions,
            revision,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permissions.len() != 2
            || !self.permissions.contains(&PermissionAction::Search)
            || !self.permissions.contains(&PermissionAction::ListIndexes)
        {
            return Err(ModelError::Unsupported {
                field: "permission fence",
            });
        }
        validate_revision(self.revision.get(), "permission revision")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<PermissionAction> {
        &self.permissions
    }

    #[must_use]
    pub fn allows(&self, permission: PermissionAction) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerScopeSpec {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub index: ResourceExplorerIndex,
    pub view: ResourceExplorerView,
    pub query: ResourceExplorerQuery,
    pub resources: Vec<ResourceExplorerResource>,
    pub mission: MissionBinding,
    pub permission: PermissionFence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerScope {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub index: ResourceExplorerIndex,
    pub view: ResourceExplorerView,
    pub query: ResourceExplorerQuery,
    pub resources: Vec<ResourceExplorerResource>,
    pub mission: MissionBinding,
    pub permission: PermissionFence,
    scope_digest: Digest,
}

impl AwsResourceExplorerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        account_id: AccountId,
        region: AwsRegion,
        index: ResourceExplorerIndex,
        view: ResourceExplorerView,
        query: ResourceExplorerQuery,
        resources: Vec<ResourceExplorerResource>,
        mission: MissionBinding,
        permission: PermissionFence,
    ) -> Result<Self, ModelError> {
        Self::new(AwsResourceExplorerScopeSpec {
            account_id,
            region,
            index,
            view,
            query,
            resources,
            mission,
            permission,
        })
    }

    pub fn new(spec: AwsResourceExplorerScopeSpec) -> Result<Self, ModelError> {
        spec.permission.validate()?;
        if spec.index.account_id != spec.account_id || spec.index.region != spec.region {
            return Err(ModelError::ScopeMismatch {
                field: "index account or region",
            });
        }
        if spec.resources.len() > MAX_RESOURCES {
            return Err(ModelError::TooMany {
                field: "resource scope",
            });
        }
        let mut resource_keys = BTreeSet::new();
        for resource in &spec.resources {
            if resource.region != spec.region {
                return Err(ModelError::ScopeMismatch {
                    field: "resource region",
                });
            }
            if !resource_keys.insert((
                resource.resource_digest.clone(),
                resource.resource_type_digest.clone(),
            )) {
                return Err(ModelError::Duplicate {
                    field: "resource scope",
                });
            }
        }
        let scope_digest = serialized_digest(&ScopeDigestMaterial {
            account_id: spec.account_id.digest(),
            region: spec.region.digest(),
            index_digest: spec.index.digest(),
            view_digest: spec.view.digest(),
            query_digest: spec.query.digest(),
            resource_digests: spec
                .resources
                .iter()
                .map(ResourceExplorerResource::digest)
                .collect(),
            mission_digest: spec.mission.digest(),
            permission_digest: spec.permission.digest(),
        });
        Ok(Self {
            account_id: spec.account_id,
            region: spec.region,
            index: spec.index,
            view: spec.view,
            query: spec.query,
            resources: spec.resources,
            mission: spec.mission,
            permission: spec.permission,
            scope_digest,
        })
    }

    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn index(&self) -> &ResourceExplorerIndex {
        &self.index
    }

    #[must_use]
    pub fn view(&self) -> &ResourceExplorerView {
        &self.view
    }

    #[must_use]
    pub fn query(&self) -> &ResourceExplorerQuery {
        &self.query
    }

    #[must_use]
    pub fn resources(&self) -> &[ResourceExplorerResource] {
        &self.resources
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        self.query.query_digest()
    }

    #[must_use]
    pub fn allows_resource(&self, resource: &ResourceInventoryItem) -> bool {
        self.resources.is_empty()
            || self.resources.iter().any(|allowed| {
                allowed.resource_digest() == resource.resource_digest()
                    && allowed.resource_type_digest() == resource.resource_type_digest()
                    && allowed.region() == resource.region()
                    && allowed.revision() == resource.revision()
            })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(AwsResourceExplorerScopeSpec {
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            index: self.index.clone(),
            view: self.view.clone(),
            query: self.query.clone(),
            resources: self.resources.clone(),
            mission: self.mission.clone(),
            permission: self.permission.clone(),
        })?;
        if rebuilt.scope_digest != self.scope_digest {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        Ok(())
    }
}

pub type ResourceExplorerScope = AwsResourceExplorerScope;

#[derive(Serialize)]
struct ScopeDigestMaterial {
    account_id: Digest,
    region: Digest,
    index_digest: Digest,
    view_digest: Digest,
    query_digest: Digest,
    resource_digests: Vec<Digest>,
    mission_digest: Digest,
    permission_digest: Digest,
}

/// A SigV4 secret reference is intentionally opaque and cannot be serialized.
/// It stores only an internal digest and binding metadata; no credential bytes
/// or keyring identifier cross the public model boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    signing_region: AwsRegion,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn for_scope(
        opaque_reference: impl Into<String>,
        scope: &AwsResourceExplorerScope,
        revision: impl IntoRevision,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.into();
        validate_identifier(
            &opaque_reference,
            "opaque secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let revision = revision.into_revision()?;
        Ok(Self {
            reference_digest: Digest::from_parts(
                "aws-resource-explorer-sigv4-secret-reference/v1",
                [
                    opaque_reference,
                    scope.scope_digest().as_str().to_owned(),
                    revision.get().to_string(),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            signing_region: scope.region().clone(),
            revision,
            revoked: false,
        })
    }

    pub fn new(
        opaque_reference: impl Into<String>,
        account_id: AccountId,
        region: AwsRegion,
        revision: impl IntoRevision,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.into();
        validate_identifier(
            &opaque_reference,
            "opaque secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let revision = revision.into_revision()?;
        let scope_digest = Digest::from_parts(
            "aws-resource-explorer-unbound-secret-scope/v1",
            [account_id.digest().as_str(), region.digest().as_str()],
        );
        Ok(Self {
            reference_digest: Digest::from_parts(
                "aws-resource-explorer-sigv4-secret-reference/v1",
                [
                    opaque_reference,
                    scope_digest.as_str().to_owned(),
                    revision.get().to_string(),
                ],
            ),
            scope_digest,
            signing_region: region,
            revision,
            revoked: false,
        })
    }

    pub fn for_resource_explorer(
        opaque_reference: impl Into<String>,
        account_id: AccountId,
        region: AwsRegion,
        revision: impl IntoRevision,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_reference, account_id, region, revision)
    }

    pub fn for_resource_explorer_scope(
        opaque_reference: impl Into<String>,
        scope: &AwsResourceExplorerScope,
        revision: impl IntoRevision,
    ) -> Result<Self, ModelError> {
        Self::for_scope(opaque_reference, scope, revision)
    }

    pub fn for_sigv4(
        opaque_reference: impl Into<String>,
        scope: &AwsResourceExplorerScope,
        revision: impl IntoRevision,
    ) -> Result<Self, ModelError> {
        Self::for_scope(opaque_reference, scope, revision)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        self.reference_digest()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn signing_service(&self) -> &'static str {
        "resource-explorer-2"
    }

    #[must_use]
    pub fn signing_region(&self) -> &AwsRegion {
        &self.signing_region
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
    pub const fn is_opaque(&self) -> bool {
        true
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
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("signing_service", &self.signing_service())
            .field("signing_region", &self.signing_region)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(S::Error::custom(
            "opaque SigV4 SecretReference is intentionally non-serializing",
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsResourceExplorerOperation {
    Search,
    ListIndexes,
}

impl AwsResourceExplorerOperation {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Search => "Search",
            Self::ListIndexes => "ListIndexes",
        }
    }

    #[must_use]
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::Search => PermissionAction::Search,
            Self::ListIndexes => PermissionAction::ListIndexes,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryState {
    Complete,
    Empty,
    Partial,
    AccessLost,
    ProviderUnknown,
}

impl InventoryState {
    #[must_use]
    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Complete | Self::Empty)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    CursorReplay,
    ScopeMismatch,
    ResponseTooLarge,
    InvalidResponse,
    ProviderFailure,
    RegistrationDrift,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexInventoryItem {
    index_digest: Digest,
    region: AwsRegion,
    state_digest: Digest,
    index_type_digest: Digest,
    revision: IndexRevision,
}

impl IndexInventoryItem {
    pub fn from_raw(
        index_id: impl Into<String>,
        region: AwsRegion,
        state: impl Into<String>,
        index_type: impl Into<String>,
        revision: IndexRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "index revision")?;
        let index_id = index_id.into();
        let state = state.into();
        let index_type = index_type.into();
        validate_identifier(&index_id, "index id", MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&state, "index state", MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&index_type, "index type", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            index_digest: Digest::from_parts(
                "aws-resource-explorer-index-inventory/v1",
                [index_id.as_bytes(), region.as_str().as_bytes()],
            ),
            region,
            state_digest: Digest::from_text(state),
            index_type_digest: Digest::from_text(index_type),
            revision,
        })
    }

    pub fn from_digests(
        index_digest: Digest,
        region: AwsRegion,
        state_digest: Digest,
        index_type_digest: Digest,
        revision: IndexRevision,
    ) -> Result<Self, ModelError> {
        validate_revision(revision.get(), "index revision")?;
        validate_digest(index_digest.as_str(), "index digest")?;
        validate_digest(state_digest.as_str(), "index state digest")?;
        validate_digest(index_type_digest.as_str(), "index type digest")?;
        Ok(Self {
            index_digest,
            region,
            state_digest,
            index_type_digest,
            revision,
        })
    }

    #[must_use]
    pub fn index_digest(&self) -> &Digest {
        &self.index_digest
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn state_digest(&self) -> &Digest {
        &self.state_digest
    }

    #[must_use]
    pub fn index_type_digest(&self) -> &Digest {
        &self.index_type_digest
    }

    #[must_use]
    pub const fn revision(&self) -> IndexRevision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerEvidence {
    pub operation: AwsResourceExplorerOperation,
    pub state: InventoryState,
    pub provenance: TransportProvenance,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub index_digest: Digest,
    pub view_digest: Digest,
    pub query_digest: Digest,
    pub indexes: Vec<IndexInventoryItem>,
    pub resources: Vec<ResourceInventoryItem>,
    pub page_count: u16,
    pub truncated: bool,
    pub partial_reason: Option<PartialReason>,
    pub provider_error_digests: Vec<Digest>,
    pub digests: EvidenceDigests,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub property_digests_only: bool,
    pub raw_properties_retained: bool,
    pub raw_tags_retained: bool,
    pub raw_pii_retained: bool,
}

impl AwsResourceExplorerEvidence {
    #[must_use]
    pub fn recomputed_evidence_digest(&self) -> Digest {
        serialized_digest(&EvidenceDigestMaterial {
            operation: self.operation,
            state: self.state,
            provenance: self.provenance,
            account_id: self.account_id.digest(),
            region: self.region.digest(),
            index_digest: self.index_digest.clone(),
            view_digest: self.view_digest.clone(),
            query_digest: self.query_digest.clone(),
            indexes: self
                .indexes
                .iter()
                .map(IndexInventoryItem::digest)
                .collect(),
            resources: self
                .resources
                .iter()
                .map(ResourceInventoryItem::digest)
                .collect(),
            page_count: self.page_count,
            truncated: self.truncated,
            partial_reason: self.partial_reason,
            provider_error_digests: self.provider_error_digests.clone(),
            version_digest: self.digests.version_digest.clone(),
            contract_digest: self.digests.contract_digest.clone(),
            provider_digest: self.digests.provider_digest.clone(),
            permission_digest: self.digests.permission_digest.clone(),
            scope_digest: self.digests.scope_digest.clone(),
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.indexes.len() > MAX_INDEXES || self.resources.len() > MAX_RESOURCES {
            return Err(ModelError::TooMany {
                field: "inventory evidence",
            });
        }
        if !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || !self.property_digests_only
            || self.raw_properties_retained
            || self.raw_tags_retained
            || self.raw_pii_retained
        {
            return Err(ModelError::Unsupported {
                field: "Layer-1 authority flags",
            });
        }
        if self.digests.evidence_digest != self.recomputed_evidence_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "evidence digest",
            });
        }
        for digest in [
            &self.digests.version_digest,
            &self.digests.contract_digest,
            &self.digests.provider_digest,
            &self.digests.permission_digest,
            &self.digests.scope_digest,
            &self.digests.query_digest,
            &self.digests.evidence_digest,
            &self.index_digest,
            &self.view_digest,
            &self.query_digest,
        ] {
            validate_digest(digest.as_str(), "evidence digest")?;
        }
        Ok(())
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    #[must_use]
    pub const fn is_reviewable(&self) -> bool {
        !self.state.is_fail_closed()
    }
}

pub type AwsResourceExplorerInventoryEvidence = AwsResourceExplorerEvidence;
pub type AwsResourceExplorerSearchEvidence = AwsResourceExplorerEvidence;
pub type AwsResourceExplorerListIndexesEvidence = AwsResourceExplorerEvidence;

#[derive(Serialize)]
struct EvidenceDigestMaterial {
    operation: AwsResourceExplorerOperation,
    state: InventoryState,
    provenance: TransportProvenance,
    account_id: Digest,
    region: Digest,
    index_digest: Digest,
    view_digest: Digest,
    query_digest: Digest,
    indexes: Vec<Digest>,
    resources: Vec<Digest>,
    page_count: u16,
    truncated: bool,
    partial_reason: Option<PartialReason>,
    provider_error_digests: Vec<Digest>,
    version_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
}

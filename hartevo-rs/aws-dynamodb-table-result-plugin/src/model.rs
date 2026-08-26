//! Typed bounded scope, posture, digest, and redaction models.
//!
//! The public posture types contain only digests, bounded enums, timestamps,
//! and counts. There is deliberately no item, key/value, stream, raw-tag, raw
//! policy, credential, or account-PII type in this module.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    LAYER1_PERMISSIONS, MAX_ARN_BYTES, MAX_IDENTIFIER_BYTES, MAX_INDEXES, MAX_REPLICAS,
    MAX_TAG_KEYS,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
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
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is stale across an eventual-consistency fence")]
    Stale { field: &'static str },
    #[error("{field} drifted during the bounded read")]
    Drift { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already reversed")]
    AlreadyReversed,
    #[error("canonical digest input could not be serialized")]
    Serialization,
}

pub type ModelResult<T> = std::result::Result<T, ModelError>;

fn validate_text(value: &str, field: &'static str, max_bytes: usize) -> ModelResult<()> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max_bytes {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> ModelResult<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_revision(value: u64, field: &'static str) -> ModelResult<()> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

/// Lower-case SHA-256 digest used as a redaction and integrity fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut input = Vec::new();
        append_digest_field(&mut input, domain);
        for (name, value) in fields {
            append_digest_field(&mut input, name);
            append_digest_field(&mut input, value);
        }
        Self::from_bytes(&input)
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
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
        self.0.fmt(formatter)
    }
}

fn append_digest_field(input: &mut Vec<u8>, field: &str) {
    input.extend_from_slice(&(field.len() as u64).to_be_bytes());
    input.extend_from_slice(field.as_bytes());
}

pub fn digest_serializable<T: Serialize>(value: &T) -> ModelResult<Digest> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::from_bytes(&bytes))
        .map_err(|_| ModelError::Serialization)
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ModelResult<Self> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-dynamodb-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> ModelResult<()> {
                validate_identifier(&self.0, $field)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
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

bounded_identifier!(MissionId, "mission-id");
bounded_identifier!(ProjectId, "project-id");
bounded_identifier!(WorkProductId, "work-product-id");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-dynamodb-account/v1", &[("account", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> ModelResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAccountId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        validate_identifier(&value, "AWS region")?;
        if value.len() > 63
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-dynamodb-region/v1", &[("region", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> ModelResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TableName(String);

impl TableName {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        validate_identifier(&value, "DynamoDB table name")?;
        if value.len() > 255
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)))
        {
            return Err(ModelError::Invalid {
                field: "DynamoDB table name",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-dynamodb-table-name/v1", &[("name", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> ModelResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for TableName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableName")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for TableName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TableArn(String);

impl TableArn {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        validate_text(&value, "DynamoDB table ARN", MAX_ARN_BYTES)?;
        if !value.starts_with("arn:aws:dynamodb:")
            || !value.contains(":table/")
            || value.chars().any(char::is_whitespace)
        {
            return Err(ModelError::Invalid {
                field: "DynamoDB table ARN",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-dynamodb-table-arn/v1", &[("arn", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> ModelResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for TableArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableArn")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for TableArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RevisionId(u64);

impl RevisionId {
    pub fn new(value: u64) -> ModelResult<Self> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: MissionId,
    revision: RevisionId,
}

impl MissionIdentity {
    pub fn new(id: MissionId, revision: RevisionId) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> RevisionId {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-mission/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> ModelResult<()> {
        self.id.validate()?;
        validate_revision(self.revision.value(), "Mission revision")
    }
}

impl fmt::Debug for MissionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: ProjectId,
    revision: RevisionId,
}

impl ProjectIdentity {
    pub fn new(id: ProjectId, revision: RevisionId) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> RevisionId {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-project/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> ModelResult<()> {
        self.id.validate()?;
        validate_revision(self.revision.value(), "Project revision")
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: WorkProductId,
    revision: RevisionId,
}

impl WorkProductIdentity {
    pub fn new(id: WorkProductId, revision: RevisionId) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> RevisionId {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-work-product/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> ModelResult<()> {
        self.id.validate()?;
        validate_revision(self.revision.value(), "Work Product revision")
    }
}

impl fmt::Debug for WorkProductIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TableAllowlist {
    names: Vec<TableName>,
    allowlist_digest: Digest,
}

impl TableAllowlist {
    pub fn new(mut names: Vec<TableName>) -> ModelResult<Self> {
        if names.is_empty() || names.len() > 16 {
            return Err(ModelError::TooMany {
                field: "DynamoDB table allowlist",
            });
        }
        names.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        for pair in names.windows(2) {
            if pair[0] == pair[1] {
                return Err(ModelError::Duplicate {
                    field: "DynamoDB table allowlist",
                });
            }
        }
        let digest = Digest::from_parts(
            "aws-dynamodb-table-allowlist/v1",
            &[(
                "names",
                names
                    .iter()
                    .map(|name| name.digest().as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        Ok(Self {
            names,
            allowlist_digest: digest,
        })
    }

    pub fn single(name: TableName) -> ModelResult<Self> {
        Self::new(vec![name])
    }

    pub fn names(&self) -> &[TableName] {
        &self.names
    }

    pub fn contains(&self, name: &TableName) -> bool {
        self.names.binary_search(name).is_ok()
    }

    pub fn digest(&self) -> &Digest {
        &self.allowlist_digest
    }

    fn validate(&self) -> ModelResult<()> {
        Self::new(self.names.clone()).map(|_| ())
    }
}

impl fmt::Debug for TableAllowlist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableAllowlist")
            .field("allowlist_digest", &self.allowlist_digest)
            .field("count", &self.names.len())
            .finish_non_exhaustive()
    }
}

/// The exact account/region/table/Mission scope accepted by a registration.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsDynamoDbTableScope {
    account: AwsAccountId,
    region: AwsRegion,
    table_arn: TableArn,
    table_name: TableName,
    allowlist: TableAllowlist,
    table_revision: RevisionId,
    schema_digest: Digest,
    index_digest: Digest,
    replica_digest: Digest,
    backup_digest: Digest,
    ttl_digest: Digest,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsDynamoDbTableScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        table_arn: TableArn,
        table_name: TableName,
        table_revision: RevisionId,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> ModelResult<Self> {
        Self::with_allowlist(
            account,
            region,
            table_arn,
            TableAllowlist::single(table_name.clone())?,
            table_name,
            table_revision,
            mission,
            project,
            work_product,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_allowlist(
        account: AwsAccountId,
        region: AwsRegion,
        table_arn: TableArn,
        allowlist: TableAllowlist,
        table_name: TableName,
        table_revision: RevisionId,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> ModelResult<Self> {
        let unset = Digest::from_text("aws-dynamodb-scope-fence-unset/v1");
        let scope = Self {
            account,
            region,
            table_arn,
            table_name,
            allowlist,
            table_revision,
            schema_digest: unset.clone(),
            index_digest: unset.clone(),
            replica_digest: unset.clone(),
            backup_digest: unset.clone(),
            ttl_digest: unset,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_fences(
        account: AwsAccountId,
        region: AwsRegion,
        table_arn: TableArn,
        table_name: TableName,
        table_revision: RevisionId,
        schema_digest: Digest,
        index_digest: Digest,
        replica_digest: Digest,
        backup_digest: Digest,
        ttl_digest: Digest,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> ModelResult<Self> {
        let mut scope = Self::new(
            account,
            region,
            table_arn,
            table_name,
            table_revision,
            mission,
            project,
            work_product,
        )?;
        scope.schema_digest = schema_digest;
        scope.index_digest = index_digest;
        scope.replica_digest = replica_digest;
        scope.backup_digest = backup_digest;
        scope.ttl_digest = ttl_digest;
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn table_arn(&self) -> &TableArn {
        &self.table_arn
    }

    pub fn table_name(&self) -> &TableName {
        &self.table_name
    }

    pub fn allowlist(&self) -> &TableAllowlist {
        &self.allowlist
    }

    pub const fn table_revision(&self) -> RevisionId {
        self.table_revision
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    pub fn index_digest(&self) -> &Digest {
        &self.index_digest
    }

    pub fn replica_digest(&self) -> &Digest {
        &self.replica_digest
    }

    pub fn backup_digest(&self) -> &Digest {
        &self.backup_digest
    }

    pub fn ttl_digest(&self) -> &Digest {
        &self.ttl_digest
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn table_digest(&self) -> Digest {
        self.table_arn.digest()
    }

    pub fn allowlist_digest(&self) -> &Digest {
        self.allowlist.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-table-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("table", self.table_digest().as_str().to_owned()),
                ("table_name", self.table_name.digest().as_str().to_owned()),
                ("allowlist", self.allowlist.digest().as_str().to_owned()),
                ("table_revision", self.table_revision.value().to_string()),
                ("schema", self.schema_digest.as_str().to_owned()),
                ("index", self.index_digest.as_str().to_owned()),
                ("replica", self.replica_digest.as_str().to_owned()),
                ("backup", self.backup_digest.as_str().to_owned()),
                ("ttl", self.ttl_digest.as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> ModelResult<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.table_arn.validate()?;
        self.table_name.validate()?;
        self.allowlist.validate()?;
        if !self.allowlist.contains(&self.table_name)
            || !self
                .table_arn
                .as_str()
                .ends_with(&format!("/{}", self.table_name.as_str()))
            || self.table_arn.as_str()
                != format!(
                    "arn:aws:dynamodb:{}:{}:table/{}",
                    self.region.as_str(),
                    self.account.as_str(),
                    self.table_name.as_str()
                )
        {
            return Err(ModelError::ScopeMismatch {
                field: "DynamoDB table allowlist/ARN",
            });
        }
        validate_revision(self.table_revision.value(), "table revision")?;
        for digest in [
            &self.schema_digest,
            &self.index_digest,
            &self.replica_digest,
            &self.backup_digest,
            &self.ttl_digest,
        ] {
            digest.validate()?;
        }
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsDynamoDbTableScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDynamoDbTableScope")
            .field("scope_digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("table_digest", &self.table_digest())
            .field("table_name", &self.table_name)
            .field("allowlist", &self.allowlist)
            .field("table_revision", &self.table_revision)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller handle is immediately hashed and
/// zeroized; no Serialize/Deserialize implementation exists for this type.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

pub type SigV4SecretReference = SecretReference;

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> ModelResult<Self> {
        let mut handle = opaque_handle.into();
        if validate_identifier(&handle, "SigV4 secret reference").is_err() || revision == 0 {
            handle.zeroize();
            return Err(ModelError::Invalid {
                field: "SigV4 secret reference",
            });
        }
        let reference_digest = Digest::from_parts(
            "aws-dynamodb-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-dynamodb-secret-scope/v1"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsDynamoDbTableScope,
        revision: u64,
    ) -> ModelResult<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-dynamodb-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &AwsDynamoDbTableScope,
        revision: u64,
    ) -> ModelResult<Self> {
        Self::sigv4(opaque_handle, scope, revision)
    }

    pub fn kind(&self) -> SecretKind {
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

    pub(crate) fn validate(&self, scope: &AwsDynamoDbTableScope) -> ModelResult<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "opaque SigV4 SecretReference",
            });
        }
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: Vec<String>,
    permission_digest: Digest,
}

pub type PermissionFence = PermissionSnapshot;

impl PermissionSnapshot {
    pub fn layer1() -> Self {
        Self::new(LAYER1_PERMISSIONS.iter().map(ToString::to_string).collect())
    }

    pub fn new(mut permissions: Vec<String>) -> Self {
        permissions.sort();
        permissions.dedup();
        let permission_digest = Digest::from_parts(
            "aws-dynamodb-permission-snapshot/v1",
            &[("permissions", permissions.join("\n"))],
        );
        Self {
            permissions,
            permission_digest,
        }
    }

    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub fn validate(&self) -> ModelResult<()> {
        let mut expected = LAYER1_PERMISSIONS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        expected.sort();
        if self.permissions != expected {
            return Err(ModelError::Invalid {
                field: "Layer-1 DynamoDB permission allowlist",
            });
        }
        if self.permission_digest
            != Digest::from_parts(
                "aws-dynamodb-permission-snapshot/v1",
                &[("permissions", self.permissions.join("\n"))],
            )
        {
            return Err(ModelError::Drift {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentBinding {
    permission_digest: Digest,
    consent_digest: Digest,
}

pub type ConsentScope = ConsentBinding;

impl ConsentBinding {
    pub fn layer1() -> Self {
        Self::for_permissions(&PermissionSnapshot::layer1())
    }

    pub fn for_permissions(permissions: &PermissionSnapshot) -> Self {
        let permission_digest = permissions.digest();
        let consent_digest = Digest::from_parts(
            "aws-dynamodb-consent/v1",
            &[("permission", permission_digest.as_str().to_owned())],
        );
        Self {
            permission_digest,
            consent_digest,
        }
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn digest(&self) -> Digest {
        self.consent_digest.clone()
    }

    pub fn validate_against(&self, permissions: &PermissionSnapshot) -> ModelResult<()> {
        if self.permission_digest != permissions.digest()
            || self.consent_digest
                != Digest::from_parts(
                    "aws-dynamodb-consent/v1",
                    &[("permission", self.permission_digest.as_str().to_owned())],
                )
        {
            return Err(ModelError::ScopeMismatch {
                field: "consent binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableStatus {
    Creating,
    Updating,
    Active,
    Deleting,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    Partition,
    Sort,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    String,
    Number,
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyComponent {
    pub name_digest: Digest,
    pub role: KeyRole,
    pub attribute_type: AttributeType,
}

impl KeyComponent {
    pub fn new(
        attribute_name: impl Into<String>,
        role: KeyRole,
        attribute_type: AttributeType,
    ) -> ModelResult<Self> {
        let name = attribute_name.into();
        validate_identifier(&name, "DynamoDB key attribute name")?;
        Ok(Self {
            name_digest: Digest::from_parts("aws-dynamodb-key-attribute/v1", &[("name", name)]),
            role,
            attribute_type,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.name_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableSchemaPosture {
    pub components: Vec<KeyComponent>,
    pub schema_digest: Digest,
}

impl TableSchemaPosture {
    pub fn new(mut components: Vec<KeyComponent>) -> ModelResult<Self> {
        if components.is_empty() || components.len() > 2 {
            return Err(ModelError::Invalid {
                field: "DynamoDB table key schema",
            });
        }
        if !components
            .iter()
            .any(|component| component.role == KeyRole::Partition)
            || components
                .iter()
                .filter(|component| component.role == KeyRole::Partition)
                .count()
                != 1
            || components
                .iter()
                .filter(|component| component.role == KeyRole::Sort)
                .count()
                > 1
        {
            return Err(ModelError::Invalid {
                field: "DynamoDB table key roles",
            });
        }
        for component in &components {
            component.validate()?;
        }
        components.sort_by_key(|component| component.role);
        let schema_digest = digest_serializable(&components)?;
        Ok(Self {
            components,
            schema_digest,
        })
    }

    pub fn partition_key(&self) -> &KeyComponent {
        self.components
            .iter()
            .find(|component| component.role == KeyRole::Partition)
            .expect("validated schema has a partition key")
    }

    pub fn sort_key(&self) -> Option<&KeyComponent> {
        self.components
            .iter()
            .find(|component| component.role == KeyRole::Sort)
    }

    pub fn digest(&self) -> &Digest {
        &self.schema_digest
    }

    pub fn validate(&self) -> ModelResult<()> {
        let rebuilt = Self::new(self.components.clone())?;
        if rebuilt.schema_digest != self.schema_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB schema digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexKind {
    GlobalSecondary,
    LocalSecondary,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexProjection {
    All,
    KeysOnly,
    Include,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexPosture {
    pub name_digest: Digest,
    pub kind: IndexKind,
    pub projection: IndexProjection,
    pub key_schema_digest: Digest,
    pub index_digest: Digest,
}

impl IndexPosture {
    pub fn new(
        name: impl Into<String>,
        kind: IndexKind,
        projection: IndexProjection,
        key_schema_digest: Digest,
    ) -> ModelResult<Self> {
        let name = name.into();
        validate_identifier(&name, "DynamoDB index name")?;
        key_schema_digest.validate()?;
        let name_digest = Digest::from_parts("aws-dynamodb-index-name/v1", &[("name", name)]);
        let index_digest = Digest::from_parts(
            "aws-dynamodb-index/v1",
            &[
                ("name", name_digest.as_str().to_owned()),
                ("kind", format!("{kind:?}")),
                ("projection", format!("{projection:?}")),
                ("schema", key_schema_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            name_digest,
            kind,
            projection,
            key_schema_digest,
            index_digest,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.name_digest.validate()?;
        self.key_schema_digest.validate()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-index/v1",
            &[
                ("name", self.name_digest.as_str().to_owned()),
                ("kind", format!("{:?}", self.kind)),
                ("projection", format!("{:?}", self.projection)),
                ("schema", self.key_schema_digest.as_str().to_owned()),
            ],
        );
        if expected != self.index_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB index digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaStatus {
    Creating,
    Updating,
    Active,
    Deleting,
    InaccessibleEncryptionCredentials,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplicaPosture {
    pub region_digest: Digest,
    pub status: ReplicaStatus,
    pub encryption_key_digest: Option<Digest>,
    pub revision: RevisionId,
    pub replica_digest: Digest,
}

impl ReplicaPosture {
    pub fn new(
        region: impl Into<String>,
        status: ReplicaStatus,
        encryption_key_arn: Option<impl AsRef<str>>,
        revision: RevisionId,
    ) -> ModelResult<Self> {
        let region = region.into();
        let region_value = AwsRegion::new(region)?;
        let encryption_key_digest = encryption_key_arn
            .map(|arn| {
                let value = arn.as_ref();
                validate_text(value, "DynamoDB replica encryption key", MAX_ARN_BYTES)?;
                Ok(Digest::from_parts(
                    "aws-dynamodb-replica-kms-key/v1",
                    &[("key", value.to_owned())],
                ))
            })
            .transpose()?;
        let replica_digest = Digest::from_parts(
            "aws-dynamodb-replica/v1",
            &[
                ("region", region_value.digest().as_str().to_owned()),
                ("status", format!("{status:?}")),
                (
                    "key",
                    encryption_key_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", revision.value().to_string()),
            ],
        );
        Ok(Self {
            region_digest: region_value.digest(),
            status,
            encryption_key_digest,
            revision,
            replica_digest,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.region_digest.validate()?;
        self.encryption_key_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-replica/v1",
            &[
                ("region", self.region_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "key",
                    self.encryption_key_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", self.revision.value().to_string()),
            ],
        );
        if expected != self.replica_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB replica digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionKeyType {
    AwsOwned,
    AwsManaged,
    CustomerManaged,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptionPosture {
    pub enabled: bool,
    pub key_type: EncryptionKeyType,
    pub key_reference_digest: Option<Digest>,
    pub encryption_digest: Digest,
}

impl EncryptionPosture {
    pub fn new(
        enabled: bool,
        key_type: EncryptionKeyType,
        key_reference_arn: Option<impl AsRef<str>>,
    ) -> ModelResult<Self> {
        let key_reference_digest = key_reference_arn
            .map(|arn| {
                let value = arn.as_ref();
                validate_text(value, "DynamoDB encryption key", MAX_ARN_BYTES)?;
                Ok(Digest::from_parts(
                    "aws-dynamodb-encryption-key/v1",
                    &[("key", value.to_owned())],
                ))
            })
            .transpose()?;
        let encryption_digest = Digest::from_parts(
            "aws-dynamodb-encryption/v1",
            &[
                ("enabled", enabled.to_string()),
                ("key_type", format!("{key_type:?}")),
                (
                    "key",
                    key_reference_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            enabled,
            key_type,
            key_reference_digest,
            encryption_digest,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.key_reference_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-encryption/v1",
            &[
                ("enabled", self.enabled.to_string()),
                ("key_type", format!("{:?}", self.key_type)),
                (
                    "key",
                    self.key_reference_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        if expected != self.encryption_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB encryption digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TablePosture {
    pub table_digest: Digest,
    pub table_id_digest: Digest,
    pub status: TableStatus,
    pub schema: TableSchemaPosture,
    pub indexes: Vec<IndexPosture>,
    pub replicas: Vec<ReplicaPosture>,
    pub encryption: EncryptionPosture,
    pub revision: RevisionId,
    pub observed_at: DateTime<Utc>,
    pub posture_digest: Digest,
}

impl TablePosture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsDynamoDbTableScope,
        table_id: impl Into<String>,
        status: TableStatus,
        schema: TableSchemaPosture,
        mut indexes: Vec<IndexPosture>,
        mut replicas: Vec<ReplicaPosture>,
        encryption: EncryptionPosture,
        revision: RevisionId,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        scope.validate()?;
        let table_id = table_id.into();
        validate_identifier(&table_id, "DynamoDB table id")?;
        schema.validate()?;
        if indexes.len() > MAX_INDEXES {
            return Err(ModelError::TooMany {
                field: "DynamoDB indexes",
            });
        }
        if replicas.len() > MAX_REPLICAS {
            return Err(ModelError::TooMany {
                field: "DynamoDB replicas",
            });
        }
        for index in &indexes {
            index.validate()?;
        }
        for replica in &replicas {
            replica.validate()?;
        }
        encryption.validate()?;
        if revision != scope.table_revision() {
            return Err(ModelError::Stale {
                field: "table revision",
            });
        }
        indexes.sort_by(|left, right| left.index_digest.cmp(&right.index_digest));
        replicas.sort_by(|left, right| left.replica_digest.cmp(&right.replica_digest));
        if indexes
            .windows(2)
            .any(|pair| pair[0].index_digest == pair[1].index_digest)
            || replicas
                .windows(2)
                .any(|pair| pair[0].replica_digest == pair[1].replica_digest)
        {
            return Err(ModelError::Duplicate {
                field: "DynamoDB table posture entries",
            });
        }
        let table_digest = scope.table_digest();
        let table_id_digest = Digest::from_parts("aws-dynamodb-table-id/v1", &[("id", table_id)]);
        let index_digest = digest_serializable(&indexes)?;
        let replica_digest = digest_serializable(&replicas)?;
        if !is_unset_fence(scope.schema_digest()) && scope.schema_digest() != schema.digest()
            || !is_unset_fence(scope.index_digest()) && scope.index_digest() != &index_digest
            || !is_unset_fence(scope.replica_digest()) && scope.replica_digest() != &replica_digest
        {
            return Err(ModelError::Drift {
                field: "DynamoDB schema/index/replica fence",
            });
        }
        let posture_digest = Digest::from_parts(
            "aws-dynamodb-table-posture/v1",
            &[
                ("table", table_digest.as_str().to_owned()),
                ("table_id", table_id_digest.as_str().to_owned()),
                ("status", format!("{status:?}")),
                ("schema", schema.digest().as_str().to_owned()),
                ("index", index_digest.as_str().to_owned()),
                ("replica", replica_digest.as_str().to_owned()),
                (
                    "encryption",
                    encryption.encryption_digest.as_str().to_owned(),
                ),
                ("revision", revision.value().to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            table_digest,
            table_id_digest,
            status,
            schema,
            indexes,
            replicas,
            encryption,
            revision,
            observed_at,
            posture_digest,
        })
    }

    pub fn fixture(scope: &AwsDynamoDbTableScope, observed_at: DateTime<Utc>) -> ModelResult<Self> {
        let schema = TableSchemaPosture::new(vec![KeyComponent::new(
            "pk",
            KeyRole::Partition,
            AttributeType::String,
        )?])?;
        Self::new(
            scope,
            "fixture-table-id",
            TableStatus::Active,
            schema,
            Vec::new(),
            Vec::new(),
            EncryptionPosture::new(true, EncryptionKeyType::AwsOwned, None::<&str>)?,
            scope.table_revision(),
            observed_at,
        )
    }

    pub fn schema_digest(&self) -> &Digest {
        self.schema.digest()
    }

    pub fn index_digest(&self) -> ModelResult<Digest> {
        digest_serializable(&self.indexes)
    }

    pub fn replica_digest(&self) -> ModelResult<Digest> {
        digest_serializable(&self.replicas)
    }

    pub fn digest(&self) -> &Digest {
        &self.posture_digest
    }

    pub fn validate_against(&self, scope: &AwsDynamoDbTableScope) -> ModelResult<()> {
        if self.table_digest != scope.table_digest()
            || self.revision != scope.table_revision()
            || self.observed_at.timestamp() < 0
        {
            return Err(ModelError::ScopeMismatch {
                field: "DynamoDB table posture scope",
            });
        }
        self.schema.validate()?;
        for index in &self.indexes {
            index.validate()?;
        }
        for replica in &self.replicas {
            replica.validate()?;
        }
        self.encryption.validate()?;
        let index_digest = self.index_digest()?;
        let replica_digest = self.replica_digest()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-table-posture/v1",
            &[
                ("table", self.table_digest.as_str().to_owned()),
                ("table_id", self.table_id_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("schema", self.schema.digest().as_str().to_owned()),
                ("index", index_digest.as_str().to_owned()),
                ("replica", replica_digest.as_str().to_owned()),
                (
                    "encryption",
                    self.encryption.encryption_digest.as_str().to_owned(),
                ),
                ("revision", self.revision.value().to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.posture_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB table posture digest",
            });
        }
        if !is_unset_fence(scope.schema_digest()) && scope.schema_digest() != self.schema.digest()
            || !is_unset_fence(scope.index_digest()) && scope.index_digest() != &index_digest
            || !is_unset_fence(scope.replica_digest()) && scope.replica_digest() != &replica_digest
        {
            return Err(ModelError::Drift {
                field: "DynamoDB table schema/index/replica",
            });
        }
        Ok(())
    }
}

fn is_unset_fence(digest: &Digest) -> bool {
    *digest == Digest::from_text("aws-dynamodb-scope-fence-unset/v1")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableSummary {
    pub table_digest: Digest,
    pub table_name_digest: Digest,
    pub table_id_digest: Digest,
    pub table_revision: RevisionId,
    pub schema_digest: Digest,
    pub index_digest: Digest,
    pub replica_digest: Digest,
    pub summary_digest: Digest,
}

impl TableSummary {
    pub fn from_posture(
        scope: &AwsDynamoDbTableScope,
        posture: &TablePosture,
    ) -> ModelResult<Self> {
        posture.validate_against(scope)?;
        let index_digest = posture.index_digest()?;
        let replica_digest = posture.replica_digest()?;
        let summary_digest = Digest::from_parts(
            "aws-dynamodb-table-summary/v1",
            &[
                ("table", scope.table_digest().as_str().to_owned()),
                ("name", scope.table_name().digest().as_str().to_owned()),
                ("id", posture.table_id_digest.as_str().to_owned()),
                ("revision", posture.revision.value().to_string()),
                ("schema", posture.schema_digest().as_str().to_owned()),
                ("index", index_digest.as_str().to_owned()),
                ("replica", replica_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            table_digest: scope.table_digest(),
            table_name_digest: scope.table_name().digest(),
            table_id_digest: posture.table_id_digest.clone(),
            table_revision: posture.revision,
            schema_digest: posture.schema_digest().clone(),
            index_digest,
            replica_digest,
            summary_digest,
        })
    }

    pub fn validate_against(&self, scope: &AwsDynamoDbTableScope) -> ModelResult<()> {
        if self.table_digest != scope.table_digest()
            || self.table_name_digest != scope.table_name().digest()
            || self.table_revision != scope.table_revision()
        {
            return Err(ModelError::ScopeMismatch {
                field: "DynamoDB table summary",
            });
        }
        for digest in [
            &self.table_digest,
            &self.table_name_digest,
            &self.table_id_digest,
            &self.schema_digest,
            &self.index_digest,
            &self.replica_digest,
        ] {
            digest.validate()?;
        }
        let expected = Digest::from_parts(
            "aws-dynamodb-table-summary/v1",
            &[
                ("table", self.table_digest.as_str().to_owned()),
                ("name", self.table_name_digest.as_str().to_owned()),
                ("id", self.table_id_digest.as_str().to_owned()),
                ("revision", self.table_revision.value().to_string()),
                ("schema", self.schema_digest.as_str().to_owned()),
                ("index", self.index_digest.as_str().to_owned()),
                ("replica", self.replica_digest.as_str().to_owned()),
            ],
        );
        if expected != self.summary_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB table summary digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointInTimeRecoveryStatus {
    Enabled,
    Disabled,
    Enabling,
    Disabling,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupPosture {
    pub table_digest: Digest,
    pub status: PointInTimeRecoveryStatus,
    pub recovery_window_digest: Option<Digest>,
    pub latest_restorable_time_digest: Option<Digest>,
    pub revision: RevisionId,
    pub observed_at: DateTime<Utc>,
    pub backup_digest: Digest,
}

impl BackupPosture {
    pub fn new(
        scope: &AwsDynamoDbTableScope,
        status: PointInTimeRecoveryStatus,
        recovery_window_start: Option<DateTime<Utc>>,
        latest_restorable_time: Option<DateTime<Utc>>,
        revision: RevisionId,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        if revision != scope.table_revision() {
            return Err(ModelError::Stale {
                field: "DynamoDB backup revision",
            });
        }
        let recovery_window_digest = recovery_window_start.map(|time| {
            Digest::from_parts(
                "aws-dynamodb-recovery-window/v1",
                &[("time", time.to_rfc3339())],
            )
        });
        let latest_restorable_time_digest = latest_restorable_time.map(|time| {
            Digest::from_parts(
                "aws-dynamodb-latest-restorable-time/v1",
                &[("time", time.to_rfc3339())],
            )
        });
        let backup_digest = Digest::from_parts(
            "aws-dynamodb-backup-posture/v1",
            &[
                ("table", scope.table_digest().as_str().to_owned()),
                ("status", format!("{status:?}")),
                (
                    "window",
                    recovery_window_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "latest",
                    latest_restorable_time_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", revision.value().to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            table_digest: scope.table_digest(),
            status,
            recovery_window_digest,
            latest_restorable_time_digest,
            revision,
            observed_at,
            backup_digest,
        })
    }

    pub fn fixture(scope: &AwsDynamoDbTableScope, observed_at: DateTime<Utc>) -> ModelResult<Self> {
        Self::new(
            scope,
            PointInTimeRecoveryStatus::Enabled,
            Some(observed_at),
            Some(observed_at),
            scope.table_revision(),
            observed_at,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.backup_digest
    }

    pub fn validate_against(
        &self,
        scope: &AwsDynamoDbTableScope,
        fence: &EventualConsistencyFence,
    ) -> ModelResult<()> {
        if self.table_digest != scope.table_digest()
            || self.revision != scope.table_revision()
            || self.observed_at < fence.observed_at_floor
        {
            return Err(ModelError::Stale {
                field: "DynamoDB backup posture",
            });
        }
        self.recovery_window_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.latest_restorable_time_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-backup-posture/v1",
            &[
                ("table", self.table_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "window",
                    self.recovery_window_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "latest",
                    self.latest_restorable_time_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", self.revision.value().to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.backup_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB backup posture digest",
            });
        }
        if !is_unset_fence(scope.backup_digest()) && scope.backup_digest() != &self.backup_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB backup fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlStatus {
    Enabled,
    Disabled,
    Enabling,
    Disabling,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TtlPosture {
    pub table_digest: Digest,
    pub status: TtlStatus,
    pub attribute_name_digest: Option<Digest>,
    pub revision: RevisionId,
    pub observed_at: DateTime<Utc>,
    pub ttl_digest: Digest,
}

impl TtlPosture {
    pub fn new(
        scope: &AwsDynamoDbTableScope,
        status: TtlStatus,
        attribute_name: Option<impl AsRef<str>>,
        revision: RevisionId,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        if revision != scope.table_revision() {
            return Err(ModelError::Stale {
                field: "DynamoDB TTL revision",
            });
        }
        let attribute_name_digest = attribute_name
            .map(|name| {
                let value = name.as_ref();
                validate_identifier(value, "DynamoDB TTL attribute name")?;
                Ok(Digest::from_parts(
                    "aws-dynamodb-ttl-attribute/v1",
                    &[("name", value.to_owned())],
                ))
            })
            .transpose()?;
        let ttl_digest = Digest::from_parts(
            "aws-dynamodb-ttl-posture/v1",
            &[
                ("table", scope.table_digest().as_str().to_owned()),
                ("status", format!("{status:?}")),
                (
                    "attribute",
                    attribute_name_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", revision.value().to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            table_digest: scope.table_digest(),
            status,
            attribute_name_digest,
            revision,
            observed_at,
            ttl_digest,
        })
    }

    pub fn fixture(scope: &AwsDynamoDbTableScope, observed_at: DateTime<Utc>) -> ModelResult<Self> {
        Self::new(
            scope,
            TtlStatus::Enabled,
            Some("expires_at"),
            scope.table_revision(),
            observed_at,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.ttl_digest
    }

    pub fn validate_against(
        &self,
        scope: &AwsDynamoDbTableScope,
        fence: &EventualConsistencyFence,
    ) -> ModelResult<()> {
        if self.table_digest != scope.table_digest()
            || self.revision != scope.table_revision()
            || self.observed_at < fence.observed_at_floor
        {
            return Err(ModelError::Stale {
                field: "DynamoDB TTL posture",
            });
        }
        self.attribute_name_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-ttl-posture/v1",
            &[
                ("table", self.table_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "attribute",
                    self.attribute_name_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", self.revision.value().to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.ttl_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB TTL posture digest",
            });
        }
        if !is_unset_fence(scope.ttl_digest()) && scope.ttl_digest() != &self.ttl_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB TTL fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TagKeyPosture {
    pub table_digest: Digest,
    pub tag_key_digests: Vec<Digest>,
    pub observed_at: DateTime<Utc>,
    pub tags_digest: Digest,
}

impl TagKeyPosture {
    pub fn new(
        scope: &AwsDynamoDbTableScope,
        tag_keys: Vec<String>,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        if tag_keys.len() > MAX_TAG_KEYS {
            return Err(ModelError::TooMany {
                field: "DynamoDB tag keys",
            });
        }
        let mut tag_key_digests = Vec::with_capacity(tag_keys.len());
        for mut tag_key in tag_keys {
            validate_text(&tag_key, "DynamoDB tag key", MAX_IDENTIFIER_BYTES)?;
            tag_key_digests.push(Digest::from_parts(
                "aws-dynamodb-tag-key/v1",
                &[("key", tag_key.clone())],
            ));
            tag_key.zeroize();
        }
        tag_key_digests.sort();
        if tag_key_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::Duplicate {
                field: "DynamoDB tag keys",
            });
        }
        let tags_digest = Digest::from_parts(
            "aws-dynamodb-tags/v1",
            &[(
                "keys",
                tag_key_digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        Ok(Self {
            table_digest: scope.table_digest(),
            tag_key_digests,
            observed_at,
            tags_digest,
        })
    }

    pub fn fixture(scope: &AwsDynamoDbTableScope, observed_at: DateTime<Utc>) -> ModelResult<Self> {
        Self::new(scope, vec!["environment".to_owned()], observed_at)
    }

    pub fn digest(&self) -> &Digest {
        &self.tags_digest
    }

    pub fn validate_against(
        &self,
        scope: &AwsDynamoDbTableScope,
        fence: &EventualConsistencyFence,
    ) -> ModelResult<()> {
        if self.table_digest != scope.table_digest() || self.observed_at < fence.observed_at_floor {
            return Err(ModelError::Stale {
                field: "DynamoDB tag posture",
            });
        }
        if self.tag_key_digests.len() > MAX_TAG_KEYS
            || self
                .tag_key_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ModelError::Invalid {
                field: "DynamoDB tag key digest ordering",
            });
        }
        for digest in &self.tag_key_digests {
            digest.validate()?;
        }
        let expected = Digest::from_parts(
            "aws-dynamodb-tags/v1",
            &[(
                "keys",
                self.tag_key_digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        if expected != self.tags_digest {
            return Err(ModelError::Drift {
                field: "DynamoDB tag posture digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventualConsistencyFence {
    pub table_digest: Digest,
    pub table_revision: RevisionId,
    pub observed_at_floor: DateTime<Utc>,
    pub fence_digest: Digest,
}

impl EventualConsistencyFence {
    pub fn new(scope: &AwsDynamoDbTableScope, observed_at_floor: DateTime<Utc>) -> Self {
        let table_digest = scope.table_digest();
        let fence_digest = Digest::from_parts(
            "aws-dynamodb-eventual-consistency-fence/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("table", table_digest.as_str().to_owned()),
                ("revision", scope.table_revision().value().to_string()),
                ("observed_at", observed_at_floor.to_rfc3339()),
            ],
        );
        Self {
            table_digest,
            table_revision: scope.table_revision(),
            observed_at_floor,
            fence_digest,
        }
    }

    pub fn validate(&self, scope: &AwsDynamoDbTableScope) -> ModelResult<()> {
        if self.table_digest != scope.table_digest()
            || self.table_revision != scope.table_revision()
        {
            return Err(ModelError::ScopeMismatch {
                field: "eventual-consistency fence",
            });
        }
        let expected = Self::new(scope, self.observed_at_floor).fence_digest;
        if expected != self.fence_digest {
            return Err(ModelError::Drift {
                field: "eventual-consistency fence digest",
            });
        }
        Ok(())
    }

    pub fn check_common(
        &self,
        scope: &AwsDynamoDbTableScope,
        table_digest: &Digest,
        revision: RevisionId,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<()> {
        self.validate(scope)?;
        if table_digest != &self.table_digest || revision != self.table_revision {
            return Err(ModelError::Stale {
                field: "DynamoDB table replacement/revision",
            });
        }
        if observed_at < self.observed_at_floor {
            return Err(ModelError::Stale {
                field: "DynamoDB metadata timestamp",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.fence_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    token_digest: Digest,
    scope_digest: Digest,
    allowlist_digest: Digest,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        raw_token: impl Into<String>,
        scope: &AwsDynamoDbTableScope,
        page_number: u16,
    ) -> ModelResult<Self> {
        let mut raw_token = raw_token.into();
        if raw_token.is_empty() || raw_token.len() > 512 || page_number == 0 {
            raw_token.zeroize();
            return Err(ModelError::InvalidCursor {
                field: "DynamoDB next token",
            });
        }
        let token_digest = Digest::from_parts(
            "aws-dynamodb-opaque-next-token/v1",
            &[
                ("token", raw_token.clone()),
                ("scope", scope.digest().as_str().to_owned()),
                ("allowlist", scope.allowlist_digest().as_str().to_owned()),
                ("page", page_number.to_string()),
            ],
        );
        raw_token.zeroize();
        Ok(Self {
            token_digest,
            scope_digest: scope.digest(),
            allowlist_digest: scope.allowlist_digest().clone(),
            page_number,
        })
    }

    pub fn from_digest(
        token_digest: Digest,
        scope: &AwsDynamoDbTableScope,
        page_number: u16,
    ) -> ModelResult<Self> {
        token_digest.validate()?;
        if page_number == 0 {
            return Err(ModelError::InvalidCursor {
                field: "DynamoDB page number",
            });
        }
        Ok(Self {
            token_digest,
            scope_digest: scope.digest(),
            allowlist_digest: scope.allowlist_digest().clone(),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn allowlist_digest(&self) -> &Digest {
        &self.allowlist_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AwsDynamoDbTableScope,
        expected_page: u16,
    ) -> ModelResult<()> {
        if self.scope_digest != scope.digest()
            || self.allowlist_digest != *scope.allowlist_digest()
            || self.page_number != expected_page
        {
            return Err(ModelError::ScopeMismatch {
                field: "DynamoDB opaque pagination cursor",
            });
        }
        self.token_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Completed,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    TableReplaced,
    SchemaDrift,
    IndexDrift,
    StaleMetadata,
    RegistrationRevoked,
}

pub type AwsDynamoDbEvidenceState = EvidenceState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: RevisionId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: RevisionId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: RevisionId,
}

pub fn mission_projection(scope: &AwsDynamoDbTableScope) -> MissionProjection {
    MissionProjection {
        id_digest: scope.mission().id().digest(),
        revision: scope.mission().revision(),
    }
}

pub fn project_projection(scope: &AwsDynamoDbTableScope) -> ProjectProjection {
    ProjectProjection {
        id_digest: scope.project().id().digest(),
        revision: scope.project().revision(),
    }
}

pub fn work_product_projection(scope: &AwsDynamoDbTableScope) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: scope.work_product().id().digest(),
        revision: scope.work_product().revision(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_response_bytes: u64,
}

impl ReadBounds {
    pub const fn layer1() -> Self {
        Self {
            max_pages: crate::MAX_PAGES,
            page_size: crate::MAX_PAGE_SIZE,
            max_response_bytes: crate::MAX_RESPONSE_BYTES,
        }
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.max_pages == 0 || self.max_pages > crate::MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "DynamoDB maximum pages",
            });
        }
        if self.page_size == 0 || self.page_size > crate::MAX_PAGE_SIZE {
            return Err(ModelError::Invalid {
                field: "DynamoDB page size",
            });
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "DynamoDB response byte budget",
            });
        }
        Ok(())
    }
}

pub fn sorted_unique_digests(values: impl IntoIterator<Item = Digest>) -> ModelResult<Vec<Digest>> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ModelError::Duplicate {
            field: "digest list",
        });
    }
    Ok(values)
}

pub fn validate_digest_set(values: &BTreeSet<Digest>) -> ModelResult<()> {
    for digest in values {
        digest.validate()?;
    }
    Ok(())
}

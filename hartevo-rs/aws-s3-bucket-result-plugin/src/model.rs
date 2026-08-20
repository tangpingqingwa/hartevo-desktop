//! Typed, bounded and redacted AWS S3 bucket result models.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AwsS3BucketError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_ALLOWLISTED_BUCKETS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES,
};

pub const MAX_BUCKET_NAME_BYTES: usize = 63;
pub const MAX_REGION_BYTES: usize = 63;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;

fn invalid(field: &'static str) -> AwsS3BucketError {
    AwsS3BucketError::InvalidModel(field.to_owned())
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn valid_identifier(value: &str, max: usize) -> bool {
    valid_text(value, max)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_bucket_name(value: &str) -> bool {
    valid_text(value, MAX_BUCKET_NAME_BYTES)
        && (3..=MAX_BUCKET_NAME_BYTES).contains(&value.len())
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value.parse::<std::net::Ipv4Addr>().is_err()
}

fn append_part(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
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

    pub fn from_parts(domain: &str, values: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_part(&mut bytes, domain);
        for (name, value) in values {
            append_part(&mut bytes, name);
            append_part(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(invalid("digest"))
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err(invalid("digest"))
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
        formatter.write_str(&self.0)
    }
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("bounded S3 model serializes"))
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, $max) {
                    Ok(Self(value))
                } else {
                    Err(invalid($field))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-s3-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0, $max) {
                    Ok(())
                } else {
                    Err(invalid($field))
                }
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
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(MissionId, "mission_id", MAX_IDENTIFIER_BYTES);
identifier_type!(ProjectId, "project_id", MAX_IDENTIFIER_BYTES);
identifier_type!(WorkProductId, "work_product_id", MAX_IDENTIFIER_BYTES);
identifier_type!(PermissionId, "permission_id", MAX_IDENTIFIER_BYTES);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(invalid("aws_account_id"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-s3-account/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&self.digest())
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_text(&value, MAX_REGION_BYTES)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-')
        {
            Ok(Self(value))
        } else {
            Err(invalid("aws_region"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-s3-region/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
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
        formatter.write_str(&self.0)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, serde::Deserialize, Eq, Ord, PartialEq, PartialOrd, serde::Serialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(invalid("revision"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum AwsS3Operation {
    GetBucketVersioning,
    GetBucketEncryption,
    GetBucketLifecycleConfiguration,
    GetBucketReplication,
    GetBucketLocation,
}

impl AwsS3Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetBucketVersioning => "GetBucketVersioning",
            Self::GetBucketEncryption => "GetBucketEncryption",
            Self::GetBucketLifecycleConfiguration => "GetBucketLifecycleConfiguration",
            Self::GetBucketReplication => "GetBucketReplication",
            Self::GetBucketLocation => "GetBucketLocation",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::GetBucketVersioning => "s3:GetBucketVersioning",
            Self::GetBucketEncryption => "s3:GetBucketEncryption",
            Self::GetBucketLifecycleConfiguration => "s3:GetBucketLifecycleConfiguration",
            Self::GetBucketReplication => "s3:GetBucketReplication",
            Self::GetBucketLocation => "s3:GetBucketLocation",
        }
    }

    pub const fn all() -> [Self; 5] {
        [
            Self::GetBucketVersioning,
            Self::GetBucketEncryption,
            Self::GetBucketLifecycleConfiguration,
            Self::GetBucketReplication,
            Self::GetBucketLocation,
        ]
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct BucketName(String);

impl BucketName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_bucket_name(&value) {
            Ok(Self(value))
        } else {
            Err(invalid("bucket_name"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-s3-bucket/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_bucket_name(&self.0) {
            Ok(())
        } else {
            Err(invalid("bucket_name"))
        }
    }
}

impl fmt::Debug for BucketName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BucketName")
            .field(&self.digest())
            .finish()
    }
}

impl fmt::Display for BucketName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub type AwsS3BucketName = BucketName;
pub type ResourceId = BucketName;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    id: MissionId,
    revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-mission-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            Err(invalid("mission_revision"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    id: ProjectId,
    revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-project-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            Err(invalid("project_revision"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-work-product-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            Err(invalid("work_product_revision"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    revision: Revision,
    permissions: BTreeSet<String>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = Revision::new(revision)?;
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let expected = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if permissions != expected {
            return Err(invalid("permission_snapshot"));
        }
        let digest = Self::compute_digest(revision, &permissions);
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn layer_one(revision: u64) -> Result<Self> {
        Self::new(revision, LAYER1_PERMISSIONS)
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if self.permissions != expected
            || self.digest != Self::compute_digest(self.revision, &self.permissions)
        {
            Err(invalid("permission_snapshot"))
        } else {
            Ok(())
        }
    }

    fn compute_digest(revision: Revision, permissions: &BTreeSet<String>) -> Digest {
        Digest::from_parts(
            "aws-s3-permission-snapshot/v1",
            &[
                ("revision", revision.get().to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsS3ProviderScope {
    account: AwsAccountId,
    region: AwsRegion,
    allowlisted_buckets: BTreeSet<BucketName>,
    target_bucket: BucketName,
    resource_revision: Revision,
    provider_scope_digest: Digest,
}

impl AwsS3ProviderScope {
    pub fn new<I>(
        account: AwsAccountId,
        region: AwsRegion,
        allowlisted_buckets: I,
        target_bucket: BucketName,
        resource_revision: Revision,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = BucketName>,
    {
        let allowlisted_buckets = allowlisted_buckets.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_buckets.is_empty()
            || allowlisted_buckets.len() > MAX_ALLOWLISTED_BUCKETS
            || !allowlisted_buckets.contains(&target_bucket)
        {
            return Err(invalid("bucket_allowlist"));
        }
        account.validate()?;
        region.validate()?;
        target_bucket.validate()?;
        let provider_scope_digest = Self::compute_digest(
            &account,
            &region,
            &allowlisted_buckets,
            &target_bucket,
            resource_revision,
        );
        Ok(Self {
            account,
            region,
            allowlisted_buckets,
            target_bucket,
            resource_revision,
            provider_scope_digest,
        })
    }

    pub fn for_bucket(
        account: AwsAccountId,
        region: AwsRegion,
        target_bucket: BucketName,
        resource_revision: Revision,
    ) -> Result<Self> {
        Self::new(
            account,
            region,
            std::iter::once(target_bucket.clone()),
            target_bucket,
            resource_revision,
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn allowlisted_buckets(&self) -> &BTreeSet<BucketName> {
        &self.allowlisted_buckets
    }

    pub fn target_bucket(&self) -> &BucketName {
        &self.target_bucket
    }

    pub const fn resource_revision(&self) -> Revision {
        self.resource_revision
    }

    pub const fn bucket_revision(&self) -> Revision {
        self.resource_revision
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_scope_digest
    }

    pub fn bucket_digest(&self) -> Digest {
        self.target_bucket.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.target_bucket.validate()?;
        if self.allowlisted_buckets.is_empty()
            || self.allowlisted_buckets.len() > MAX_ALLOWLISTED_BUCKETS
            || !self.allowlisted_buckets.contains(&self.target_bucket)
        {
            return Err(invalid("bucket_allowlist"));
        }
        let recomputed = Self::new(
            self.account.clone(),
            self.region.clone(),
            self.allowlisted_buckets.clone(),
            self.target_bucket.clone(),
            self.resource_revision,
        )?;
        if recomputed.provider_scope_digest != self.provider_scope_digest {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn compute_digest(
        account: &AwsAccountId,
        region: &AwsRegion,
        allowlisted_buckets: &BTreeSet<BucketName>,
        target_bucket: &BucketName,
        resource_revision: Revision,
    ) -> Digest {
        Digest::from_parts(
            "aws-s3-provider-scope/v1",
            &[
                ("account", account.digest().to_string()),
                ("region", region.digest().to_string()),
                (
                    "allowlist",
                    allowlisted_buckets
                        .iter()
                        .map(BucketName::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("target", target_bucket.digest().to_string()),
                ("resource_revision", resource_revision.get().to_string()),
            ],
        )
    }
}

impl fmt::Debug for AwsS3ProviderScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsS3ProviderScope")
            .field("account_digest", &self.account.digest())
            .field("region", &self.region)
            .field(
                "allowlist_digest",
                &digest_serialized(&self.allowlisted_buckets),
            )
            .field("target_bucket_digest", &self.target_bucket.digest())
            .field("resource_revision", &self.resource_revision)
            .field("provider_scope_digest", &self.provider_scope_digest)
            .finish()
    }
}

impl Serialize for AwsS3ProviderScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AwsS3ProviderScope", 6)?;
        value.serialize_field("accountDigest", &self.account.digest())?;
        value.serialize_field("region", &self.region)?;
        value.serialize_field(
            "allowlistDigest",
            &digest_serialized(&self.allowlisted_buckets),
        )?;
        value.serialize_field("targetBucketDigest", &self.target_bucket.digest())?;
        value.serialize_field("resourceRevision", &self.resource_revision)?;
        value.serialize_field("providerScopeDigest", &self.provider_scope_digest)?;
        value.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsS3BucketScope {
    provider_scope: AwsS3ProviderScope,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
    permission_snapshot: PermissionSnapshot,
    scope_digest: Digest,
}

impl AwsS3BucketScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        allowlisted_buckets: impl IntoIterator<Item = BucketName>,
        target_bucket: BucketName,
        resource_revision: Revision,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self> {
        let provider_scope = AwsS3ProviderScope::new(
            account,
            region,
            allowlisted_buckets,
            target_bucket,
            resource_revision,
        )?;
        Self::from_provider_scope(
            provider_scope,
            mission,
            project,
            work_product,
            permission_snapshot,
        )
    }

    pub fn for_bucket(
        provider_scope: AwsS3ProviderScope,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self> {
        Self::from_provider_scope(
            provider_scope,
            mission,
            project,
            work_product,
            permission_snapshot,
        )
    }

    pub fn from_provider_scope(
        provider_scope: AwsS3ProviderScope,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self> {
        provider_scope.validate()?;
        permission_snapshot.validate()?;
        let scope_digest = Self::compute_digest(
            &provider_scope,
            &mission,
            &project,
            &work_product,
            &permission_snapshot,
        );
        Ok(Self {
            provider_scope,
            mission,
            project,
            work_product,
            permission_snapshot,
            scope_digest,
        })
    }

    pub fn provider_scope(&self) -> &AwsS3ProviderScope {
        &self.provider_scope
    }

    pub fn account(&self) -> &AwsAccountId {
        self.provider_scope.account()
    }

    pub fn region(&self) -> &AwsRegion {
        self.provider_scope.region()
    }

    pub fn target_bucket(&self) -> &BucketName {
        self.provider_scope.target_bucket()
    }

    pub fn bucket(&self) -> &BucketName {
        self.target_bucket()
    }

    pub const fn resource_revision(&self) -> Revision {
        self.provider_scope.resource_revision()
    }

    pub const fn bucket_revision(&self) -> Revision {
        self.provider_scope.resource_revision()
    }

    pub fn bucket_digest(&self) -> Digest {
        self.provider_scope.bucket_digest()
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

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.provider_scope.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.permission_snapshot.validate()?;
        let recomputed = Self::from_provider_scope(
            self.provider_scope.clone(),
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
            self.permission_snapshot.clone(),
        )?;
        if recomputed.scope_digest != self.scope_digest {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn compute_digest(
        provider_scope: &AwsS3ProviderScope,
        mission: &MissionIdentity,
        project: &ProjectIdentity,
        work_product: &WorkProductIdentity,
        permission_snapshot: &PermissionSnapshot,
    ) -> Digest {
        Digest::from_parts(
            "aws-s3-bucket-scope/v1",
            &[
                ("provider_scope", provider_scope.digest().to_string()),
                ("mission", mission.digest().to_string()),
                ("project", project.digest().to_string()),
                ("work_product", work_product.digest().to_string()),
                ("permission", permission_snapshot.digest().to_string()),
            ],
        )
    }
}

impl fmt::Debug for AwsS3BucketScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsS3BucketScope")
            .field("provider_scope_digest", self.provider_scope.digest())
            .field("mission_digest", &self.mission.digest())
            .field("project_digest", &self.project.digest())
            .field("work_product_digest", &self.work_product.digest())
            .field("permission_digest", self.permission_snapshot.digest())
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl Serialize for AwsS3BucketScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AwsS3BucketScope", 6)?;
        value.serialize_field("providerScopeDigest", self.provider_scope.digest())?;
        value.serialize_field("missionDigest", &self.mission.digest())?;
        value.serialize_field("projectDigest", &self.project.digest())?;
        value.serialize_field("workProductDigest", &self.work_product.digest())?;
        value.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScheme {
    Sigv4,
}

/// Opaque host-owned reference to SigV4 credentials.
///
/// The supplied handle is used only to derive `reference_digest`; it is not
/// retained, serialized, deserialized, or printed. Layer 2 owns resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    scheme: SecretScheme,
    revoked: bool,
}

pub type SigV4SecretReference = SecretReference;

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &AwsS3BucketScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::sigv4(reference_id, scope, credential_revision)
    }

    pub fn sigv4(
        reference_id: impl AsRef<str>,
        scope: &AwsS3BucketScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let reference_id = reference_id.as_ref();
        if !valid_text(reference_id, MAX_SECRET_REFERENCE_BYTES) {
            return Err(AwsS3BucketError::InvalidSecretReference);
        }
        scope.validate()?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = Digest::from_parts(
            "aws-s3-secret-reference/v1",
            &[
                ("reference", reference_id.to_owned()),
                ("scope", scope_digest.to_string()),
                ("revision", credential_revision.get().to_string()),
                ("scheme", "sigv4".to_owned()),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            scheme: SecretScheme::Sigv4,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn scheme(&self) -> SecretScheme {
        self.scheme
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(AwsS3BucketError::InvalidSecretReference)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("scheme", &self.scheme)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_non_native(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(identity: &MissionIdentity) -> Self {
        Self {
            id_digest: identity.id.digest(),
            revision: identity.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(identity: &ProjectIdentity) -> Self {
        Self {
            id_digest: identity.id.digest(),
            revision: identity.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(identity: &WorkProductIdentity) -> Self {
        Self {
            id_digest: identity.id.digest(),
            revision: identity.revision,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum VersioningPosture {
    Enabled,
    Suspended,
    NeverEnabled,
    Unknown,
}

impl VersioningPosture {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPosture {
    Encrypted,
    Unencrypted,
    Unknown,
}

impl EncryptionPosture {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionAlgorithm {
    Aes256,
    AwsKms,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePosture {
    Configured,
    NotConfigured,
    Unknown,
}

impl LifecyclePosture {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationPosture {
    Configured,
    NotConfigured,
    Unknown,
}

impl ReplicationPosture {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketVersioningObservation {
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub posture: VersioningPosture,
    pub configuration_digest: Digest,
}

impl BucketVersioningObservation {
    pub fn new(
        bucket_digest: Digest,
        resource_revision: Revision,
        posture: VersioningPosture,
    ) -> Result<Self> {
        bucket_digest.validate()?;
        let configuration_digest = Digest::from_parts(
            "aws-s3-versioning-configuration/v1",
            &[
                ("bucket", bucket_digest.to_string()),
                ("revision", resource_revision.get().to_string()),
                ("posture", format!("{posture:?}")),
            ],
        );
        Ok(Self {
            bucket_digest,
            resource_revision,
            posture,
            configuration_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-versioning-observation/v1",
            &[
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("posture", format!("{:?}", self.posture)),
                ("configuration", self.configuration_digest.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        if self.bucket_digest != scope.bucket_digest()
            || self.resource_revision != scope.resource_revision()
            || self.configuration_digest
                != Digest::from_parts(
                    "aws-s3-versioning-configuration/v1",
                    &[
                        ("bucket", self.bucket_digest.to_string()),
                        ("revision", self.resource_revision.get().to_string()),
                        ("posture", format!("{:?}", self.posture)),
                    ],
                )
        {
            Err(AwsS3BucketError::ScopeMismatch(
                "versioning bucket or resource revision".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketEncryptionObservation {
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub posture: EncryptionPosture,
    pub algorithm: EncryptionAlgorithm,
    pub rule_count: u16,
    pub configuration_digest: Digest,
}

impl BucketEncryptionObservation {
    pub fn new(
        bucket_digest: Digest,
        resource_revision: Revision,
        posture: EncryptionPosture,
        algorithm: EncryptionAlgorithm,
        rule_count: u16,
    ) -> Result<Self> {
        bucket_digest.validate()?;
        let configuration_digest = Digest::from_parts(
            "aws-s3-encryption-configuration/v1",
            &[
                ("bucket", bucket_digest.to_string()),
                ("revision", resource_revision.get().to_string()),
                ("posture", format!("{posture:?}")),
                ("algorithm", format!("{algorithm:?}")),
                ("rule_count", rule_count.to_string()),
            ],
        );
        Ok(Self {
            bucket_digest,
            resource_revision,
            posture,
            algorithm,
            rule_count,
            configuration_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-encryption-observation/v1",
            &[
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("posture", format!("{:?}", self.posture)),
                ("algorithm", format!("{:?}", self.algorithm)),
                ("rule_count", self.rule_count.to_string()),
                ("configuration", self.configuration_digest.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        let expected = Self::new(
            self.bucket_digest.clone(),
            self.resource_revision,
            self.posture,
            self.algorithm,
            self.rule_count,
        )?;
        if self.bucket_digest != scope.bucket_digest()
            || self.resource_revision != scope.resource_revision()
            || self.configuration_digest != expected.configuration_digest
        {
            Err(AwsS3BucketError::ScopeMismatch(
                "encryption bucket or resource revision".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketLifecycleObservation {
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub posture: LifecyclePosture,
    pub rule_count: u16,
    pub enabled_rule_count: u16,
    pub configuration_digest: Digest,
}

impl BucketLifecycleObservation {
    pub fn new(
        bucket_digest: Digest,
        resource_revision: Revision,
        posture: LifecyclePosture,
        rule_count: u16,
        enabled_rule_count: u16,
    ) -> Result<Self> {
        if enabled_rule_count > rule_count {
            return Err(invalid("lifecycle rule counts"));
        }
        bucket_digest.validate()?;
        let configuration_digest = Digest::from_parts(
            "aws-s3-lifecycle-configuration/v1",
            &[
                ("bucket", bucket_digest.to_string()),
                ("revision", resource_revision.get().to_string()),
                ("posture", format!("{posture:?}")),
                ("rule_count", rule_count.to_string()),
                ("enabled_rule_count", enabled_rule_count.to_string()),
            ],
        );
        Ok(Self {
            bucket_digest,
            resource_revision,
            posture,
            rule_count,
            enabled_rule_count,
            configuration_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-lifecycle-observation/v1",
            &[
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("posture", format!("{:?}", self.posture)),
                ("rule_count", self.rule_count.to_string()),
                ("enabled_rule_count", self.enabled_rule_count.to_string()),
                ("configuration", self.configuration_digest.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        let expected = Self::new(
            self.bucket_digest.clone(),
            self.resource_revision,
            self.posture,
            self.rule_count,
            self.enabled_rule_count,
        )?;
        if self.bucket_digest != scope.bucket_digest()
            || self.resource_revision != scope.resource_revision()
            || self.configuration_digest != expected.configuration_digest
        {
            Err(AwsS3BucketError::ScopeMismatch(
                "lifecycle bucket or resource revision".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketReplicationObservation {
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub posture: ReplicationPosture,
    pub rule_count: u16,
    pub enabled_rule_count: u16,
    pub configuration_digest: Digest,
}

impl BucketReplicationObservation {
    pub fn new(
        bucket_digest: Digest,
        resource_revision: Revision,
        posture: ReplicationPosture,
        rule_count: u16,
        enabled_rule_count: u16,
    ) -> Result<Self> {
        if enabled_rule_count > rule_count {
            return Err(invalid("replication rule counts"));
        }
        bucket_digest.validate()?;
        let configuration_digest = Digest::from_parts(
            "aws-s3-replication-configuration/v1",
            &[
                ("bucket", bucket_digest.to_string()),
                ("revision", resource_revision.get().to_string()),
                ("posture", format!("{posture:?}")),
                ("rule_count", rule_count.to_string()),
                ("enabled_rule_count", enabled_rule_count.to_string()),
            ],
        );
        Ok(Self {
            bucket_digest,
            resource_revision,
            posture,
            rule_count,
            enabled_rule_count,
            configuration_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-replication-observation/v1",
            &[
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("posture", format!("{:?}", self.posture)),
                ("rule_count", self.rule_count.to_string()),
                ("enabled_rule_count", self.enabled_rule_count.to_string()),
                ("configuration", self.configuration_digest.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        let expected = Self::new(
            self.bucket_digest.clone(),
            self.resource_revision,
            self.posture,
            self.rule_count,
            self.enabled_rule_count,
        )?;
        if self.bucket_digest != scope.bucket_digest()
            || self.resource_revision != scope.resource_revision()
            || self.configuration_digest != expected.configuration_digest
        {
            Err(AwsS3BucketError::ScopeMismatch(
                "replication bucket or resource revision".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketLocationObservation {
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub observed_region: AwsRegion,
    pub matches_scope_region: bool,
    pub configuration_digest: Digest,
}

impl BucketLocationObservation {
    pub fn new(
        bucket_digest: Digest,
        resource_revision: Revision,
        observed_region: AwsRegion,
        scope_region: &AwsRegion,
    ) -> Result<Self> {
        bucket_digest.validate()?;
        observed_region.validate()?;
        let matches_scope_region = observed_region == *scope_region;
        let configuration_digest = Digest::from_parts(
            "aws-s3-location-configuration/v1",
            &[
                ("bucket", bucket_digest.to_string()),
                ("revision", resource_revision.get().to_string()),
                ("observed_region", observed_region.digest().to_string()),
                ("matches_scope_region", matches_scope_region.to_string()),
            ],
        );
        Ok(Self {
            bucket_digest,
            resource_revision,
            observed_region,
            matches_scope_region,
            configuration_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-location-observation/v1",
            &[
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("region", self.observed_region.digest().to_string()),
                ("matches", self.matches_scope_region.to_string()),
                ("configuration", self.configuration_digest.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        let expected = Self::new(
            self.bucket_digest.clone(),
            self.resource_revision,
            self.observed_region.clone(),
            scope.region(),
        )?;
        if self.bucket_digest != scope.bucket_digest()
            || self.resource_revision != scope.resource_revision()
            || self.configuration_digest != expected.configuration_digest
        {
            Err(AwsS3BucketError::ScopeMismatch(
                "location bucket or resource revision".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "operation", content = "observation", rename_all = "camelCase")]
pub enum AwsS3Observation {
    GetBucketVersioning(BucketVersioningObservation),
    GetBucketEncryption(BucketEncryptionObservation),
    GetBucketLifecycleConfiguration(BucketLifecycleObservation),
    GetBucketReplication(BucketReplicationObservation),
    GetBucketLocation(BucketLocationObservation),
}

impl AwsS3Observation {
    pub const fn operation(&self) -> AwsS3Operation {
        match self {
            Self::GetBucketVersioning(_) => AwsS3Operation::GetBucketVersioning,
            Self::GetBucketEncryption(_) => AwsS3Operation::GetBucketEncryption,
            Self::GetBucketLifecycleConfiguration(_) => {
                AwsS3Operation::GetBucketLifecycleConfiguration
            }
            Self::GetBucketReplication(_) => AwsS3Operation::GetBucketReplication,
            Self::GetBucketLocation(_) => AwsS3Operation::GetBucketLocation,
        }
    }

    pub fn digest(&self) -> Digest {
        match self {
            Self::GetBucketVersioning(value) => value.digest(),
            Self::GetBucketEncryption(value) => value.digest(),
            Self::GetBucketLifecycleConfiguration(value) => value.digest(),
            Self::GetBucketReplication(value) => value.digest(),
            Self::GetBucketLocation(value) => value.digest(),
        }
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        match self {
            Self::GetBucketVersioning(value) => value.validate_against(scope),
            Self::GetBucketEncryption(value) => value.validate_against(scope),
            Self::GetBucketLifecycleConfiguration(value) => value.validate_against(scope),
            Self::GetBucketReplication(value) => value.validate_against(scope),
            Self::GetBucketLocation(value) => value.validate_against(scope),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketDurabilityPosture {
    pub versioning: Option<BucketVersioningObservation>,
    pub encryption: Option<BucketEncryptionObservation>,
    pub lifecycle: Option<BucketLifecycleObservation>,
    pub replication: Option<BucketReplicationObservation>,
    pub location: Option<BucketLocationObservation>,
    pub posture_digest: Digest,
}

impl BucketDurabilityPosture {
    pub fn empty() -> Self {
        let mut value = Self {
            versioning: None,
            encryption: None,
            lifecycle: None,
            replication: None,
            location: None,
            posture_digest: Digest::zero(),
        };
        value.posture_digest = value.recomputed_digest();
        value
    }

    pub fn from_observations(
        observations: impl IntoIterator<Item = AwsS3Observation>,
    ) -> Result<Self> {
        let mut value = Self::empty();
        for observation in observations {
            match observation {
                AwsS3Observation::GetBucketVersioning(observation) => {
                    value.versioning = Some(observation);
                }
                AwsS3Observation::GetBucketEncryption(observation) => {
                    value.encryption = Some(observation);
                }
                AwsS3Observation::GetBucketLifecycleConfiguration(observation) => {
                    value.lifecycle = Some(observation);
                }
                AwsS3Observation::GetBucketReplication(observation) => {
                    value.replication = Some(observation);
                }
                AwsS3Observation::GetBucketLocation(observation) => {
                    value.location = Some(observation);
                }
            }
        }
        value.posture_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn observations(&self) -> Vec<AwsS3Observation> {
        let mut values = Vec::new();
        if let Some(observation) = &self.versioning {
            values.push(AwsS3Observation::GetBucketVersioning(observation.clone()));
        }
        if let Some(observation) = &self.encryption {
            values.push(AwsS3Observation::GetBucketEncryption(observation.clone()));
        }
        if let Some(observation) = &self.lifecycle {
            values.push(AwsS3Observation::GetBucketLifecycleConfiguration(
                observation.clone(),
            ));
        }
        if let Some(observation) = &self.replication {
            values.push(AwsS3Observation::GetBucketReplication(observation.clone()));
        }
        if let Some(observation) = &self.location {
            values.push(AwsS3Observation::GetBucketLocation(observation.clone()));
        }
        values
    }

    pub fn is_complete(&self) -> bool {
        self.versioning
            .as_ref()
            .is_some_and(|value| value.posture.is_known())
            && self
                .encryption
                .as_ref()
                .is_some_and(|value| value.posture.is_known())
            && self
                .lifecycle
                .as_ref()
                .is_some_and(|value| value.posture.is_known())
            && self
                .replication
                .as_ref()
                .is_some_and(|value| value.posture.is_known())
            && self
                .location
                .as_ref()
                .is_some_and(|value| value.matches_scope_region)
    }

    pub fn has_unknown_configuration(&self) -> bool {
        self.versioning
            .as_ref()
            .is_some_and(|value| !value.posture.is_known())
            || self
                .encryption
                .as_ref()
                .is_some_and(|value| !value.posture.is_known())
            || self
                .lifecycle
                .as_ref()
                .is_some_and(|value| !value.posture.is_known())
            || self
                .replication
                .as_ref()
                .is_some_and(|value| !value.posture.is_known())
    }

    pub fn has_region_drift(&self) -> bool {
        self.location
            .as_ref()
            .is_some_and(|value| !value.matches_scope_region)
    }

    pub fn validate_against(&self, scope: &AwsS3ProviderScope) -> Result<()> {
        for observation in self.observations() {
            observation.validate_against(scope)?;
        }
        if self.posture_digest != self.recomputed_digest() {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.posture_digest
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-bucket-durability-posture/v1",
            &[
                (
                    "versioning",
                    self.versioning
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                (
                    "encryption",
                    self.encryption
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                (
                    "lifecycle",
                    self.lifecycle
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                (
                    "replication",
                    self.replication
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                (
                    "location",
                    self.location
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
            ],
        )
    }
}

pub type AwsS3BucketDurabilityPosture = BucketDurabilityPosture;
pub type VersioningObservation = BucketVersioningObservation;
pub type EncryptionObservation = BucketEncryptionObservation;
pub type LifecycleObservation = BucketLifecycleObservation;
pub type ReplicationObservation = BucketReplicationObservation;
pub type LocationObservation = BucketLocationObservation;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3ReadRequest {
    scope: AwsS3BucketScope,
    operations: Vec<AwsS3Operation>,
    pub max_page_size: u16,
    pub max_pages: u16,
    pub max_requests: u16,
    pub max_response_bytes: u64,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_digest: Digest,
}

pub type AwsS3ReadPlan = AwsS3ReadRequest;

impl AwsS3ReadRequest {
    pub fn new(
        scope: &AwsS3BucketScope,
        operations: impl IntoIterator<Item = AwsS3Operation>,
        max_pages: u16,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let mut operations = operations.into_iter().collect::<Vec<_>>();
        operations.sort_unstable();
        operations.dedup();
        if operations.is_empty() || operations.len() > AwsS3Operation::all().len() {
            return Err(invalid("S3 operation set"));
        }
        if max_pages == 0 || max_pages > MAX_PAGES || expires_at <= observed_at {
            return Err(AwsS3BucketError::InvalidRequest(
                "read page budget or expiry".to_owned(),
            ));
        }
        let mut request = Self {
            scope: scope.clone(),
            operations,
            max_page_size: MAX_PAGE_SIZE,
            max_pages,
            max_requests: MAX_REQUESTS_PER_READ,
            max_response_bytes: MAX_RESPONSE_BYTES,
            observed_at,
            expires_at,
            request_digest: Digest::zero(),
        };
        request.request_digest = request.recomputed_request_digest();
        Ok(request)
    }

    pub fn all_posture(
        scope: &AwsS3BucketScope,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            scope,
            AwsS3Operation::all(),
            MAX_PAGES,
            observed_at,
            expires_at,
        )
    }

    pub fn for_operation(
        scope: &AwsS3BucketScope,
        operation: AwsS3Operation,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(scope, [operation], MAX_PAGES, observed_at, expires_at)
    }

    pub fn versioning(
        scope: &AwsS3BucketScope,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::for_operation(
            scope,
            AwsS3Operation::GetBucketVersioning,
            observed_at,
            expires_at,
        )
    }

    pub fn encryption(
        scope: &AwsS3BucketScope,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::for_operation(
            scope,
            AwsS3Operation::GetBucketEncryption,
            observed_at,
            expires_at,
        )
    }

    pub fn lifecycle(
        scope: &AwsS3BucketScope,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::for_operation(
            scope,
            AwsS3Operation::GetBucketLifecycleConfiguration,
            observed_at,
            expires_at,
        )
    }

    pub fn replication(
        scope: &AwsS3BucketScope,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::for_operation(
            scope,
            AwsS3Operation::GetBucketReplication,
            observed_at,
            expires_at,
        )
    }

    pub fn location(
        scope: &AwsS3BucketScope,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::for_operation(
            scope,
            AwsS3Operation::GetBucketLocation,
            observed_at,
            expires_at,
        )
    }

    pub fn scope(&self) -> &AwsS3BucketScope {
        &self.scope
    }

    pub fn operations(&self) -> &[AwsS3Operation] {
        &self.operations
    }

    pub fn operation(&self) -> Option<AwsS3Operation> {
        (self.operations.len() == 1).then_some(self.operations[0])
    }

    pub fn scope_digest(&self) -> &Digest {
        self.scope.digest()
    }

    pub fn query_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-read-query/v1",
            &[
                ("scope", self.scope.digest().to_string()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("page_size", self.max_page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("max_requests", self.max_requests.to_string()),
                ("max_response_bytes", self.max_response_bytes.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("expires_at", self.expires_at.to_rfc3339()),
            ],
        )
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn with_bounds(
        &self,
        max_pages: u16,
        max_requests: u16,
        max_response_bytes: u64,
    ) -> Result<Self> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_requests == 0
            || max_requests > MAX_REQUESTS_PER_READ
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsS3BucketError::InvalidRequest("read bounds".to_owned()));
        }
        let mut request = self.clone();
        request.max_pages = max_pages;
        request.max_requests = max_requests;
        request.max_response_bytes = max_response_bytes;
        request.request_digest = request.recomputed_request_digest();
        Ok(request)
    }

    pub fn validate_against(&self, scope: &AwsS3BucketScope) -> Result<()> {
        self.scope.validate()?;
        scope.validate()?;
        if self.scope.digest() != scope.digest()
            || self.max_page_size == 0
            || self.max_page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_requests == 0
            || self.max_requests > MAX_REQUESTS_PER_READ
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.expires_at <= self.observed_at
            || self.request_digest != self.recomputed_request_digest()
        {
            return Err(AwsS3BucketError::ScopeMismatch(
                "read request scope, bounds or digest".to_owned(),
            ));
        }
        Ok(())
    }

    fn recomputed_request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-read-request/v1",
            &[("query", self.query_digest().to_string())],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: String,
    pub operation: AwsS3Operation,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn from_transport(
        operation: AwsS3Operation,
        error: &crate::error::AwsS3TransportError,
    ) -> Self {
        let kind = error.kind().to_owned();
        let status_code = error.status_code();
        let retry_after_seconds = match error {
            crate::error::AwsS3TransportError::Throttled {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        };
        let error_digest = Digest::from_parts(
            "aws-s3-provider-error/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("kind", kind.clone()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            kind,
            operation,
            status_code,
            retry_after_seconds,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedResponseReceipt {
    pub response_bytes: u64,
    pub page_digests: Vec<Digest>,
    pub marker_digests: Vec<Digest>,
    pub raw_marker_retained: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_object_keys_retained: bool,
    pub raw_object_bytes_retained: bool,
    pub raw_bucket_policy_retained: bool,
    pub raw_kms_material_retained: bool,
    pub raw_replication_role_arns_retained: bool,
    pub receipt_digest: Digest,
}

impl RedactedResponseReceipt {
    pub fn new(
        response_bytes: u64,
        page_digests: Vec<Digest>,
        marker_digests: Vec<Digest>,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsS3BucketError::PartialEvidence);
        }
        let mut receipt = Self {
            response_bytes,
            page_digests,
            marker_digests,
            raw_marker_retained: false,
            raw_provider_payload_retained: false,
            raw_object_keys_retained: false,
            raw_object_bytes_retained: false,
            raw_bucket_policy_retained: false,
            raw_kms_material_retained: false,
            raw_replication_role_arns_retained: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<()> {
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.raw_marker_retained
            || self.raw_provider_payload_retained
            || self.raw_object_keys_retained
            || self.raw_object_bytes_retained
            || self.raw_bucket_policy_retained
            || self.raw_kms_material_retained
            || self.raw_replication_role_arns_retained
            || self.receipt_digest != self.recomputed_digest()
        {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-redacted-response/v1",
            &[
                ("bytes", self.response_bytes.to_string()),
                (
                    "pages",
                    self.page_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "markers",
                    self.marker_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

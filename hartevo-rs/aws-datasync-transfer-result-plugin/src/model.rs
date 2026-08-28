use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsDataSyncTransferError, Result};
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_COUNTER_VALUE, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE,
    MAX_PAGES,
};

pub const MAX_STATUS_MESSAGE_BYTES: usize = 2_048;
pub const MAX_REPORT_FORMAT_BYTES: usize = 64;

#[derive(Clone, serde::Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsDataSyncTransferError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsDataSyncTransferError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
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
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, 2_048, false) && value.starts_with("arn:")
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else if value.is_empty() {
                    Err(AwsDataSyncTransferError::Empty { field: $field })
                } else if value.len() > MAX_IDENTIFIER_BYTES {
                    Err(AwsDataSyncTransferError::TooLong { field: $field })
                } else if value.chars().any(char::is_control) {
                    Err(AwsDataSyncTransferError::ControlCharacter { field: $field })
                } else {
                    Err(AwsDataSyncTransferError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-datasync-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsDataSyncTransferError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

redacted_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_text!(DataSyncTaskArn, "task-arn", valid_arn);
redacted_text!(DataSyncExecutionArn, "execution-arn", valid_arn);
redacted_text!(DataSyncLocationArn, "location-arn", valid_arn);
redacted_text!(MissionId, "mission", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
redacted_text!(ProjectId, "project", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
redacted_text!(WorkProductId, "work-product", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionIdentity {
    id: MissionId,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AwsDataSyncTransferError::MustBePositive {
                field: "mission revision",
            });
        }
        Ok(Self {
            id: MissionId::new(id)?,
            revision,
        })
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-mission/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision == 0 {
            return Err(AwsDataSyncTransferError::MustBePositive {
                field: "mission revision",
            });
        }
        Ok(())
    }
}

impl Serialize for MissionIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MissionIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: ProjectId,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AwsDataSyncTransferError::MustBePositive {
                field: "project revision",
            });
        }
        Ok(Self {
            id: ProjectId::new(id)?,
            revision,
        })
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-project/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision == 0 {
            return Err(AwsDataSyncTransferError::MustBePositive {
                field: "project revision",
            });
        }
        Ok(())
    }
}

impl Serialize for ProjectIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ProjectIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: WorkProductId,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AwsDataSyncTransferError::MustBePositive {
                field: "work product revision",
            });
        }
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision,
        })
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-work-product/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision == 0 {
            return Err(AwsDataSyncTransferError::MustBePositive {
                field: "work product revision",
            });
        }
        Ok(())
    }
}

impl Serialize for WorkProductIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("WorkProductIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    S3,
    Efs,
    FsxWindows,
    FsxLustre,
    Nfs,
    Smb,
    Hdfs,
    ObjectStorage,
    Unknown,
}

impl LocationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Efs => "efs",
            Self::FsxWindows => "fsx_windows",
            Self::FsxLustre => "fsx_lustre",
            Self::Nfs => "nfs",
            Self::Smb => "smb",
            Self::Hdfs => "hdfs",
            Self::ObjectStorage => "object_storage",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataSyncLocationIdentity {
    arn: DataSyncLocationArn,
    kind: LocationKind,
}

impl DataSyncLocationIdentity {
    pub fn new(arn: impl Into<String>, kind: LocationKind) -> Result<Self> {
        Ok(Self {
            arn: DataSyncLocationArn::new(arn)?,
            kind,
        })
    }

    pub fn kind(&self) -> LocationKind {
        self.kind
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-location/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("kind", self.kind.as_str().to_owned()),
            ],
        )
    }

    pub fn arn_digest(&self) -> Digest {
        self.arn.digest()
    }

    fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl Serialize for DataSyncLocationIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DataSyncLocationIdentity", 2)?;
        state.serialize_field("locationDigest", &self.digest())?;
        state.serialize_field("kind", &self.kind)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataSyncTaskIdentity {
    arn: DataSyncTaskArn,
}

impl DataSyncTaskIdentity {
    pub fn new(arn: impl Into<String>) -> Result<Self> {
        Ok(Self {
            arn: DataSyncTaskArn::new(arn)?,
        })
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub fn arn_digest(&self) -> Digest {
        self.arn.digest()
    }

    fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl Serialize for DataSyncTaskIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DataSyncTaskIdentity", 1)?;
        state.serialize_field("taskDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsDataSyncScopeInput {
    pub account: String,
    pub region: String,
    pub task_arn: String,
    pub source_location_arn: String,
    pub source_location_kind: LocationKind,
    pub destination_location_arn: String,
    pub destination_location_kind: LocationKind,
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

impl fmt::Debug for AwsDataSyncScopeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataSyncScopeInput")
            .field("account_digest", &Digest::from_text(&self.account))
            .field("region_digest", &Digest::from_text(&self.region))
            .field("task_digest", &Digest::from_text(&self.task_arn))
            .field(
                "source_location_digest",
                &Digest::from_text(&self.source_location_arn),
            )
            .field("source_location_kind", &self.source_location_kind)
            .field(
                "destination_location_digest",
                &Digest::from_text(&self.destination_location_arn),
            )
            .field("destination_location_kind", &self.destination_location_kind)
            .field("mission_digest", &Digest::from_text(&self.mission_id))
            .field("mission_revision", &self.mission_revision)
            .field("project_digest", &Digest::from_text(&self.project_id))
            .field("project_revision", &self.project_revision)
            .field(
                "work_product_digest",
                &Digest::from_text(&self.work_product_id),
            )
            .field("work_product_revision", &self.work_product_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDataSyncScope {
    account: AwsAccountId,
    region: AwsRegion,
    task: DataSyncTaskIdentity,
    source: DataSyncLocationIdentity,
    destination: DataSyncLocationIdentity,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsDataSyncScope {
    pub fn new(input: AwsDataSyncScopeInput) -> Result<Self> {
        let scope = Self {
            account: AwsAccountId::new(input.account)?,
            region: AwsRegion::new(input.region)?,
            task: DataSyncTaskIdentity::new(input.task_arn)?,
            source: DataSyncLocationIdentity::new(
                input.source_location_arn,
                input.source_location_kind,
            )?,
            destination: DataSyncLocationIdentity::new(
                input.destination_location_arn,
                input.destination_location_kind,
            )?,
            mission: MissionIdentity::new(input.mission_id, input.mission_revision)?,
            project: ProjectIdentity::new(input.project_id, input.project_revision)?,
            work_product: WorkProductIdentity::new(
                input.work_product_id,
                input.work_product_revision,
            )?,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn task(&self) -> &DataSyncTaskIdentity {
        &self.task
    }

    pub fn source(&self) -> &DataSyncLocationIdentity {
        &self.source
    }

    pub fn destination(&self) -> &DataSyncLocationIdentity {
        &self.destination
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

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("task", self.task.digest().as_str().to_owned()),
                ("source", self.source.digest().as_str().to_owned()),
                ("destination", self.destination.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.task.validate()?;
        self.source.validate()?;
        self.destination.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.source.digest() == self.destination.digest() {
            return Err(AwsDataSyncTransferError::InvalidScope);
        }
        Ok(())
    }
}

impl Serialize for AwsDataSyncScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsDataSyncScope", 8)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("task", &self.task)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("destination", &self.destination)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The supplied host handle is hashed and dropped;
/// the type intentionally has no serialization implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsDataSyncTransferError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-datasync-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-datasync-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsDataSyncScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.bind_to(scope)?;
        Ok(reference)
    }

    pub fn bind_to(&mut self, scope: &AwsDataSyncScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest = scope.digest();
        self.reference_digest = Digest::from_parts(
            "aws-datasync-opaque-sigv4-reference-bound/v1",
            &[
                ("reference", self.reference_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        );
        Ok(())
    }

    pub const fn kind(&self) -> SecretKind {
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

    pub fn validate(&self, scope: &AwsDataSyncScope) -> Result<()> {
        if self.kind != SecretKind::Sigv4Credential
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsDataSyncTransferError::InvalidSecretReference);
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

pub type Sigv4SecretReference = SecretReference;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(AwsDataSyncTransferError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let consent = Self {
            id: id.into(),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-consent/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(AwsDataSyncTransferError::InvalidConsent);
        }
        Ok(())
    }

    fn permission_digest(&self) -> Digest {
        Digest::from_text(
            self.permissions
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("revision", &self.revision)
            .field("permission_digest", &self.permission_digest())
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for ConsentScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConsentScope", 5)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

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
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataSyncTaskStatus {
    Available,
    Creating,
    Pending,
    Running,
    Unavailable,
    Error,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferExecutionState {
    Queued,
    Launching,
    Preparing,
    Transferring,
    Verifying,
    Success,
    Error,
    Cancelling,
}

impl TransferExecutionState {
    pub const ALL: [Self; 8] = [
        Self::Queued,
        Self::Launching,
        Self::Preparing,
        Self::Transferring,
        Self::Verifying,
        Self::Success,
        Self::Error,
        Self::Cancelling,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Launching => "LAUNCHING",
            Self::Preparing => "PREPARING",
            Self::Transferring => "TRANSFERRING",
            Self::Verifying => "VERIFYING",
            Self::Success => "SUCCESS",
            Self::Error => "ERROR",
            Self::Cancelling => "CANCELLING",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Success | Self::Error | Self::Cancelling)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        match self {
            Self::Queued => matches!(next, Self::Launching | Self::Error | Self::Cancelling),
            Self::Launching => matches!(next, Self::Preparing | Self::Error | Self::Cancelling),
            Self::Preparing => matches!(next, Self::Transferring | Self::Error | Self::Cancelling),
            Self::Transferring => matches!(next, Self::Verifying | Self::Error | Self::Cancelling),
            Self::Verifying => matches!(next, Self::Success | Self::Error | Self::Cancelling),
            Self::Success | Self::Error | Self::Cancelling => false,
        }
    }

    pub fn validate_sequence(states: &[Self]) -> Result<()> {
        if states.is_empty()
            || states
                .windows(2)
                .any(|window| !window[0].can_transition_to(window[1]))
        {
            return Err(AwsDataSyncTransferError::InvalidStateTransition);
        }
        Ok(())
    }
}

pub type AwsDataSyncExecutionState = TransferExecutionState;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    CounterTruncated,
    ExecutionInProgress,
    MissingExecution,
    ResponseCap,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferEvidenceState {
    Complete,
    Partial(PartialReason),
    ProviderUnknown,
    AccessLoss,
    NotFound,
    Conflict,
    Throttled,
    InvalidRequest,
    Timeout,
}

impl TransferEvidenceState {
    pub const fn is_review_eligible(self) -> bool {
        matches!(self, Self::Complete | Self::Partial(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedCounter {
    pub value: u64,
    pub truncated: bool,
}

impl BoundedCounter {
    pub fn from_raw(value: u64) -> Self {
        Self {
            value: value.min(MAX_COUNTER_VALUE),
            truncated: value > MAX_COUNTER_VALUE,
        }
    }

    pub const fn is_truncated(self) -> bool {
        self.truncated
    }

    pub fn validate(self) -> Result<()> {
        if self.value > MAX_COUNTER_VALUE || (self.truncated && self.value != MAX_COUNTER_VALUE) {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCountersInput {
    pub bytes_to_transfer: u64,
    pub bytes_transferred: u64,
    pub bytes_verified: u64,
    pub bytes_deleted: u64,
    pub files_to_transfer: u64,
    pub files_transferred: u64,
    pub files_verified: u64,
    pub files_deleted: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCounters {
    pub bytes_to_transfer: BoundedCounter,
    pub bytes_transferred: BoundedCounter,
    pub bytes_verified: BoundedCounter,
    pub bytes_deleted: BoundedCounter,
    pub files_to_transfer: BoundedCounter,
    pub files_transferred: BoundedCounter,
    pub files_verified: BoundedCounter,
    pub files_deleted: BoundedCounter,
    pub errors: BoundedCounter,
}

impl From<TransferCountersInput> for TransferCounters {
    fn from(input: TransferCountersInput) -> Self {
        Self {
            bytes_to_transfer: BoundedCounter::from_raw(input.bytes_to_transfer),
            bytes_transferred: BoundedCounter::from_raw(input.bytes_transferred),
            bytes_verified: BoundedCounter::from_raw(input.bytes_verified),
            bytes_deleted: BoundedCounter::from_raw(input.bytes_deleted),
            files_to_transfer: BoundedCounter::from_raw(input.files_to_transfer),
            files_transferred: BoundedCounter::from_raw(input.files_transferred),
            files_verified: BoundedCounter::from_raw(input.files_verified),
            files_deleted: BoundedCounter::from_raw(input.files_deleted),
            errors: BoundedCounter::from_raw(input.errors),
        }
    }
}

impl TransferCounters {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-transfer-counters/v1",
            &[
                (
                    "bytes_to_transfer",
                    self.bytes_to_transfer.value.to_string(),
                ),
                (
                    "bytes_transferred",
                    self.bytes_transferred.value.to_string(),
                ),
                ("bytes_verified", self.bytes_verified.value.to_string()),
                ("bytes_deleted", self.bytes_deleted.value.to_string()),
                (
                    "files_to_transfer",
                    self.files_to_transfer.value.to_string(),
                ),
                (
                    "files_transferred",
                    self.files_transferred.value.to_string(),
                ),
                ("files_verified", self.files_verified.value.to_string()),
                ("files_deleted", self.files_deleted.value.to_string()),
                ("errors", self.errors.value.to_string()),
                ("truncated", self.is_truncated().to_string()),
            ],
        )
    }

    pub const fn is_truncated(&self) -> bool {
        self.bytes_to_transfer.truncated
            || self.bytes_transferred.truncated
            || self.bytes_verified.truncated
            || self.bytes_deleted.truncated
            || self.files_to_transfer.truncated
            || self.files_transferred.truncated
            || self.files_verified.truncated
            || self.files_deleted.truncated
            || self.errors.truncated
    }

    pub fn validate(&self) -> Result<()> {
        self.bytes_to_transfer.validate()?;
        self.bytes_transferred.validate()?;
        self.bytes_verified.validate()?;
        self.bytes_deleted.validate()?;
        self.files_to_transfer.validate()?;
        self.files_transferred.validate()?;
        self.files_verified.validate()?;
        self.files_deleted.validate()?;
        self.errors.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransferReportMetadataInput {
    pub report_identifier: Option<String>,
    pub report_format: Option<String>,
    pub report_size_bytes: Option<u64>,
}

impl fmt::Debug for TransferReportMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferReportMetadataInput")
            .field(
                "report_identifier_present",
                &self.report_identifier.is_some(),
            )
            .field("report_format_present", &self.report_format.is_some())
            .field("report_size_bytes", &self.report_size_bytes)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferReportMetadata {
    pub report_digest: Option<Digest>,
    pub format_digest: Option<Digest>,
    pub size_bytes: Option<BoundedCounter>,
}

impl TransferReportMetadata {
    pub fn from_input(input: TransferReportMetadataInput) -> Result<Option<Self>> {
        if input.report_identifier.is_none()
            && input.report_format.is_none()
            && input.report_size_bytes.is_none()
        {
            return Ok(None);
        }
        if let Some(identifier) = &input.report_identifier
            && !valid_text(identifier, MAX_IDENTIFIER_BYTES, true)
        {
            return Err(AwsDataSyncTransferError::InvalidIdentifier {
                field: "transfer report identifier",
            });
        }
        if let Some(format) = &input.report_format {
            if !valid_text(format, MAX_REPORT_FORMAT_BYTES, false) {
                return Err(AwsDataSyncTransferError::InvalidIdentifier {
                    field: "transfer report format",
                });
            }
        }
        let report_digest = input.report_identifier.map(|identifier| {
            Digest::from_parts(
                "aws-datasync-transfer-report-reference/v1",
                &[("identifier", identifier)],
            )
        });
        let format_digest = input.report_format.map(|format| {
            Digest::from_parts(
                "aws-datasync-transfer-report-format/v1",
                &[("format", format)],
            )
        });
        Ok(Some(Self {
            report_digest,
            format_digest,
            size_bytes: input.report_size_bytes.map(BoundedCounter::from_raw),
        }))
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-transfer-report-metadata/v1",
            &[
                (
                    "report",
                    self.report_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "format",
                    self.format_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "size",
                    self.size_bytes.map_or_else(String::new, |counter| {
                        format!("{}:{}", counter.value, counter.truncated)
                    }),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.report_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.format_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if let Some(size) = self.size_bytes {
            size.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TaskMetadataInput {
    pub task_arn: String,
    pub status: DataSyncTaskStatus,
    pub source_location_arn: String,
    pub source_location_kind: LocationKind,
    pub destination_location_arn: String,
    pub destination_location_kind: LocationKind,
}

impl fmt::Debug for TaskMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskMetadataInput")
            .field("task_digest", &Digest::from_text(&self.task_arn))
            .field("status", &self.status)
            .field(
                "source_location_digest",
                &Digest::from_text(&self.source_location_arn),
            )
            .field("source_location_kind", &self.source_location_kind)
            .field(
                "destination_location_digest",
                &Digest::from_text(&self.destination_location_arn),
            )
            .field("destination_location_kind", &self.destination_location_kind)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskProjection {
    pub task_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub source_location_digest: Digest,
    pub destination_location_digest: Digest,
    pub source_location_kind: LocationKind,
    pub destination_location_kind: LocationKind,
    pub status: DataSyncTaskStatus,
}

impl TaskProjection {
    pub fn from_input(scope: &AwsDataSyncScope, input: TaskMetadataInput) -> Result<Self> {
        let task = DataSyncTaskIdentity::new(input.task_arn)?;
        let source =
            DataSyncLocationIdentity::new(input.source_location_arn, input.source_location_kind)?;
        let destination = DataSyncLocationIdentity::new(
            input.destination_location_arn,
            input.destination_location_kind,
        )?;
        let projection = Self {
            task_digest: task.digest(),
            account_digest: scope.account.digest(),
            region_digest: scope.region.digest(),
            source_location_digest: source.digest(),
            destination_location_digest: destination.digest(),
            source_location_kind: source.kind(),
            destination_location_kind: destination.kind(),
            status: input.status,
        };
        projection.validate_against(scope)?;
        Ok(projection)
    }

    pub fn for_scope(scope: &AwsDataSyncScope, status: DataSyncTaskStatus) -> Self {
        Self {
            task_digest: scope.task.digest(),
            account_digest: scope.account.digest(),
            region_digest: scope.region.digest(),
            source_location_digest: scope.source.digest(),
            destination_location_digest: scope.destination.digest(),
            source_location_kind: scope.source.kind(),
            destination_location_kind: scope.destination.kind(),
            status,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-task-projection/v1",
            &[
                ("task", self.task_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("source", self.source_location_digest.as_str().to_owned()),
                (
                    "destination",
                    self.destination_location_digest.as_str().to_owned(),
                ),
                ("source_kind", self.source_location_kind.as_str().to_owned()),
                (
                    "destination_kind",
                    self.destination_location_kind.as_str().to_owned(),
                ),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsDataSyncScope) -> Result<()> {
        self.task_digest.validate()?;
        self.account_digest.validate()?;
        self.region_digest.validate()?;
        self.source_location_digest.validate()?;
        self.destination_location_digest.validate()?;
        if self.task_digest != scope.task.digest()
            || self.account_digest != scope.account.digest()
            || self.region_digest != scope.region.digest()
            || self.source_location_digest != scope.source.digest()
            || self.destination_location_digest != scope.destination.digest()
            || self.source_location_kind != scope.source.kind()
            || self.destination_location_kind != scope.destination.kind()
        {
            return Err(AwsDataSyncTransferError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionMetadataInput {
    pub execution_arn: String,
    pub task_arn: String,
    pub status: TransferExecutionState,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub counters: TransferCountersInput,
    pub transfer_report: TransferReportMetadataInput,
    pub error_message: Option<String>,
}

impl fmt::Debug for ExecutionMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionMetadataInput")
            .field("execution_digest", &Digest::from_text(&self.execution_arn))
            .field("task_digest", &Digest::from_text(&self.task_arn))
            .field("status", &self.status)
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .field("counters", &self.counters)
            .field("transfer_report", &self.transfer_report)
            .field("error_message_present", &self.error_message.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionProjection {
    pub execution_digest: Digest,
    pub task_digest: Digest,
    pub status: TransferExecutionState,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub counters: TransferCounters,
    pub transfer_report: Option<TransferReportMetadata>,
    pub error_digest: Option<Digest>,
}

impl ExecutionProjection {
    pub fn from_input(scope: &AwsDataSyncScope, input: ExecutionMetadataInput) -> Result<Self> {
        if let Some(message) = &input.error_message
            && !valid_text(message, MAX_STATUS_MESSAGE_BYTES, true)
        {
            return Err(AwsDataSyncTransferError::InvalidIdentifier {
                field: "provider error message",
            });
        }
        let execution = DataSyncExecutionArn::new(input.execution_arn)?;
        execution.validate()?;
        let task = DataSyncTaskIdentity::new(input.task_arn)?;
        let projection = Self {
            execution_digest: execution.digest(),
            task_digest: task.digest(),
            status: input.status,
            started_at: input.started_at,
            ended_at: input.ended_at,
            counters: input.counters.into(),
            transfer_report: TransferReportMetadata::from_input(input.transfer_report)?,
            error_digest: input.error_message.map(|message| {
                Digest::from_parts(
                    "aws-datasync-provider-error-message/v1",
                    &[("message", message)],
                )
            }),
        };
        projection.validate_against(scope)?;
        Ok(projection)
    }

    pub fn for_scope(
        scope: &AwsDataSyncScope,
        execution_arn: impl Into<String>,
        status: TransferExecutionState,
        counters: TransferCountersInput,
    ) -> Result<Self> {
        Self::from_input(
            scope,
            ExecutionMetadataInput {
                execution_arn: execution_arn.into(),
                task_arn: scope.task.arn.as_str().to_owned(),
                status,
                started_at: None,
                ended_at: None,
                counters,
                transfer_report: TransferReportMetadataInput {
                    report_identifier: None,
                    report_format: None,
                    report_size_bytes: None,
                },
                error_message: None,
            },
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-execution-projection/v1",
            &[
                ("execution", self.execution_digest.as_str().to_owned()),
                ("task", self.task_digest.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                (
                    "started",
                    self.started_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "ended",
                    self.ended_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("counters", self.counters.digest().as_str().to_owned()),
                (
                    "report",
                    self.transfer_report
                        .as_ref()
                        .map_or_else(String::new, |report| report.digest().as_str().to_owned()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsDataSyncScope) -> Result<()> {
        self.task_digest.validate()?;
        if self.task_digest != scope.task.digest() {
            return Err(AwsDataSyncTransferError::TaskMismatch);
        }
        if let (Some(started), Some(ended)) = (self.started_at, self.ended_at)
            && ended < started
        {
            return Err(AwsDataSyncTransferError::InvalidResponse);
        }
        self.execution_digest.validate()?;
        self.counters.validate()?;
        if let Some(report) = &self.transfer_report {
            report.validate()?;
        }
        if let Some(error_digest) = &self.error_digest {
            error_digest.validate()?;
        }
        Ok(())
    }
}

pub trait CursorBinding {
    fn binding_digest(&self) -> Digest;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskListFilter {
    pub scope_digest: Digest,
    pub page_size: u16,
}

impl TaskListFilter {
    pub fn for_scope(scope: &AwsDataSyncScope, page_size: u16) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(AwsDataSyncTransferError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            page_size,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-list-tasks-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
            ],
        )
    }
}

impl CursorBinding for TaskListFilter {
    fn binding_digest(&self) -> Digest {
        self.digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionListFilter {
    pub scope_digest: Digest,
    pub task_digest: Digest,
    pub page_size: u16,
}

impl ExecutionListFilter {
    pub fn for_scope(scope: &AwsDataSyncScope, page_size: u16) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(AwsDataSyncTransferError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            task_digest: scope.task.digest(),
            page_size,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-list-task-executions-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("task", self.task_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
            ],
        )
    }
}

impl CursorBinding for ExecutionListFilter {
    fn binding_digest(&self) -> Digest {
        self.digest()
    }
}

impl CursorBinding for Digest {
    fn binding_digest(&self) -> Digest {
        self.clone()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    token_digest: Digest,
    scope_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new<B: CursorBinding>(
        opaque_token: impl AsRef<str>,
        scope: &AwsDataSyncScope,
        binding: &B,
        page_number: u16,
    ) -> Result<Self> {
        let token = opaque_token.as_ref();
        if !valid_text(token, 4_096, true)
            || page_number == 0
            || page_number > MAX_PAGES.saturating_add(1)
        {
            return Err(AwsDataSyncTransferError::InvalidRequest);
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-datasync-opaque-cursor/v1",
                &[("token", token.to_owned())],
            ),
            scope_digest: scope.digest(),
            binding_digest: binding.binding_digest(),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against<B: CursorBinding>(
        &self,
        scope: &AwsDataSyncScope,
        binding: &B,
        expected_page: u16,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.binding_digest != binding.binding_digest()
            || self.page_number != expected_page
        {
            return Err(AwsDataSyncTransferError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Cursor", 4)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub path_digest: Digest,
    pub status: u16,
    pub response_bytes: u64,
    pub provider_revision: u64,
    pub provenance: TransportProvenance,
    pub raw_payload_retained: bool,
    pub raw_report_retained: bool,
    pub raw_logs_retained: bool,
    pub credential_material_retained: bool,
    pub observed_at: DateTime<Utc>,
}

impl ResponseReceipt {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.operation.as_str(),
            "DescribeTask" | "DescribeTaskExecution" | "ListTasks" | "ListTaskExecutions"
        ) || !valid_text(&self.operation, MAX_IDENTIFIER_BYTES, false)
            || self.status == 0
            || self.status != 200
            || self.provider_revision == 0
            || self.raw_payload_retained
            || self.raw_report_retained
            || self.raw_logs_retained
            || self.credential_material_retained
            || self.provenance.is_native()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        validate_response_bytes(self.response_bytes)?;
        self.request_digest.validate()?;
        self.response_digest.validate()?;
        self.path_digest.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-response-receipt/v1",
            &[
                ("operation", self.operation.clone()),
                ("request", self.request_digest.as_str().to_owned()),
                ("response", self.response_digest.as_str().to_owned()),
                ("path", self.path_digest.as_str().to_owned()),
                ("status", self.status.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

pub fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > crate::MAX_RESPONSE_BYTES {
        Err(AwsDataSyncTransferError::ResponseTooLarge)
    } else {
        Ok(())
    }
}

pub fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(AwsDataSyncTransferError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub fn validate_page_count(page_count: u16) -> Result<()> {
    if page_count == 0 || page_count > MAX_PAGES {
        Err(AwsDataSyncTransferError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub fn contract_version_digest() -> Digest {
    Digest::from_text(CONTRACT_VERSION)
}

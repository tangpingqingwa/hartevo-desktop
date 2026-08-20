//! Typed, bounded, redacted AWS License Manager models.
//!
//! The provider-facing constructors may briefly accept provider identifiers or
//! text so they can be converted to digests. The stored projections and their
//! `Debug`/`Serialize` implementations expose only typed metadata and digests;
//! raw resource inventory, license text, rules, and secret material never cross
//! the Layer-1 evidence boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AwsLicenseManagerError, Result};
use crate::{
    AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES, AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS,
    AWS_LICENSE_MANAGER_MAX_USAGE_WINDOW_DAYS, AWS_LICENSE_MANAGER_PERMISSIONS,
};

pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_RESOURCE_TYPE_BYTES: usize = 64;
pub const MAX_LICENSE_TYPE_BYTES: usize = 64;

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

    pub fn from_fields<T: AsRef<str>>(domain: &str, fields: &[T]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field.as_ref());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsLicenseManagerError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.bytes().all(|byte| byte == b'0')
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsLicenseManagerError::InvalidDigest)
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
    if !valid_text(value, MAX_ARN_BYTES, false) || value.contains(['*', '?', '\\', '\n', '\r']) {
        return false;
    }
    let mut parts = value.splitn(6, ':');
    matches!(parts.next(), Some("arn"))
        && matches!(parts.next(), Some("aws" | "aws-us-gov" | "aws-cn"))
        && parts.next().is_some_and(|service| !service.is_empty())
        && parts
            .next()
            .is_some_and(|region| !region.is_empty() || value.contains(":aws:iam:"))
        && parts.next().is_some_and(|account| account.len() <= 64)
        && parts.next().is_some_and(|resource| !resource.is_empty())
}

fn arn_parts(value: &str) -> Option<Vec<&str>> {
    if !valid_arn(value) {
        return None;
    }
    Some(value.splitn(6, ':').collect())
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
                } else {
                    Err(AwsLicenseManagerError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields(concat!("aws-license-manager-", $field, "/v1"), &[&self.0])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsLicenseManagerError::InvalidIdentifier { field: $field })
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
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.redacted())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.redacted().fmt(formatter)
            }
        }
    };
}

redacted_text!(AwsAccountId, "account", |value: &str| {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
});
redacted_text!(AwsRegion, "region", |value: &str| {
    valid_identifier(value, 64)
});
redacted_text!(
    LicenseConfigurationId,
    "license-configuration-id",
    |value: &str| {
        value.len() <= AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES
            && value.starts_with("lic-")
            && valid_identifier(value, AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES)
    }
);
redacted_text!(ResourceArn, "managed-resource-arn", valid_arn);
redacted_text!(ProjectId, "project", |value: &str| {
    valid_identifier(value, AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES)
});
redacted_text!(MissionId, "mission", |value: &str| {
    valid_identifier(value, AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES)
});
redacted_text!(WorkProductId, "work-product", |value: &str| {
    valid_identifier(value, AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES)
});

pub type AccountId = AwsAccountId;
pub type Region = AwsRegion;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsLicenseManagerError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LicenseConfigurationIdentity {
    id: LicenseConfigurationId,
    arn_digest: Digest,
}

pub type LicenseConfiguration = LicenseConfigurationIdentity;

impl LicenseConfigurationIdentity {
    pub fn new(id: LicenseConfigurationId, arn: Option<impl Into<String>>) -> Result<Self> {
        let arn_digest = arn
            .map(Into::into)
            .map(|value| {
                let parts = arn_parts(&value).ok_or(AwsLicenseManagerError::InvalidIdentifier {
                    field: "license-configuration-arn",
                })?;
                if parts.get(2) != Some(&"license-manager")
                    || !parts[5].contains("license-configuration")
                    || !parts[5].contains(id.as_str())
                {
                    return Err(AwsLicenseManagerError::InvalidIdentifier {
                        field: "license-configuration-arn",
                    });
                }
                Ok(Digest::from_fields(
                    "aws-license-manager-configuration-arn/v1",
                    &[value],
                ))
            })
            .transpose()?
            .unwrap_or_else(|| id.digest());
        let identity = Self { id, arn_digest };
        identity.validate()?;
        Ok(identity)
    }

    pub fn from_id(id: LicenseConfigurationId) -> Result<Self> {
        Self::new(id, None::<String>)
    }

    pub fn id(&self) -> &LicenseConfigurationId {
        &self.id
    }

    pub fn arn_digest(&self) -> &Digest {
        &self.arn_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-configuration/v1",
            &[self.id.digest().to_string(), self.arn_digest.to_string()],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn_digest.validate()
    }
}

impl Serialize for LicenseConfigurationIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LicenseConfigurationIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("arnDigest", &self.arn_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceType(String);

impl ResourceType {
    pub const ALLOWLIST: [&'static str; 16] = [
        "EC2",
        "EC2_INSTANCE",
        "EC2_HOST",
        "EC2_AMI",
        "RDS",
        "RDS_INSTANCE",
        "RDS_CLUSTER",
        "SSM_MANAGED_INSTANCE",
        "DMS",
        "S3",
        "DYNAMODB",
        "DOCDB",
        "ELASTICACHE",
        "WORKSPACES",
        "APPSTREAM",
        "APPLICATION",
    ];

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if Self::ALLOWLIST.contains(&value.as_str()) && value.len() <= MAX_RESOURCE_TYPE_BYTES {
            Ok(Self(value))
        } else {
            Err(AwsLicenseManagerError::InvalidIdentifier {
                field: "managed-resource-type",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields("aws-license-manager-resource-type/v1", &[&self.0])
    }

    pub fn is_allowlisted(value: &str) -> bool {
        Self::ALLOWLIST.contains(&value)
    }
}

impl fmt::Debug for ResourceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceType")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ResourceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for ResourceType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedResourceIdentity {
    arn: ResourceArn,
    resource_type: ResourceType,
}

pub type ManagedResource = ManagedResourceIdentity;

impl ManagedResourceIdentity {
    pub fn new(arn: ResourceArn, resource_type: ResourceType) -> Result<Self> {
        let identity = Self { arn, resource_type };
        identity.validate()?;
        Ok(identity)
    }

    pub fn from_values(arn: impl Into<String>, resource_type: impl Into<String>) -> Result<Self> {
        Self::new(ResourceArn::new(arn)?, ResourceType::new(resource_type)?)
    }

    pub fn arn(&self) -> &ResourceArn {
        &self.arn
    }

    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-managed-resource/v1",
            &[
                self.arn.digest().to_string(),
                self.resource_type.digest().to_string(),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        if !ResourceType::is_allowlisted(self.resource_type.as_str()) {
            return Err(AwsLicenseManagerError::InvalidIdentifier {
                field: "managed-resource-type",
            });
        }
        Ok(())
    }
}

impl Serialize for ManagedResourceIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ManagedResourceIdentity", 2)?;
        state.serialize_field("resourceDigest", &self.digest())?;
        state.serialize_field("resourceType", &self.resource_type)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub window_digest: Digest,
}

pub type AwsLicenseManagerUsageWindow = UsageWindow;

impl UsageWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        if end <= start || end - start > Duration::days(AWS_LICENSE_MANAGER_MAX_USAGE_WINDOW_DAYS) {
            return Err(AwsLicenseManagerError::InvalidScope);
        }
        let window_digest = Digest::from_fields(
            "aws-license-manager-usage-window/v1",
            &[start.to_rfc3339(), end.to_rfc3339()],
        );
        Ok(Self {
            start,
            end,
            window_digest,
        })
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    pub fn digest(&self) -> &Digest {
        &self.window_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.end <= self.start
            || self.end - self.start > Duration::days(AWS_LICENSE_MANAGER_MAX_USAGE_WINDOW_DAYS)
            || self.window_digest
                != Digest::from_fields(
                    "aws-license-manager-usage-window/v1",
                    &[self.start.to_rfc3339(), self.end.to_rfc3339()],
                )
        {
            return Err(AwsLicenseManagerError::UsageWindowDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionIdentity {
    id: MissionId,
    revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: MissionId, revision: impl Into<Revision>) -> Result<Self> {
        let value = Self {
            id,
            revision: revision.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-mission/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            return Err(AwsLicenseManagerError::InvalidScope);
        }
        Ok(())
    }
}

impl Serialize for MissionIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MissionIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: ProjectId,
    revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: ProjectId, revision: impl Into<Revision>) -> Result<Self> {
        let value = Self {
            id,
            revision: revision.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-project/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            return Err(AwsLicenseManagerError::InvalidScope);
        }
        Ok(())
    }
}

impl Serialize for ProjectIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ProjectIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductIdentity {
    pub fn new(id: WorkProductId, revision: impl Into<Revision>) -> Result<Self> {
        let value = Self {
            id,
            revision: revision.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-work-product/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            return Err(AwsLicenseManagerError::InvalidScope);
        }
        Ok(())
    }
}

impl Serialize for WorkProductIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("WorkProductIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsLicenseManagerScope {
    account_id: AwsAccountId,
    region: AwsRegion,
    license_configuration: LicenseConfigurationIdentity,
    managed_resource: ManagedResourceIdentity,
    usage_window: UsageWindow,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsLicenseManagerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        license_configuration: LicenseConfigurationIdentity,
        managed_resource: ManagedResourceIdentity,
        usage_window: UsageWindow,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let value = Self {
            account_id,
            region,
            license_configuration,
            managed_resource,
            usage_window,
            mission,
            project,
            work_product,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn account_id(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn account(&self) -> &AwsAccountId {
        self.account_id()
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn license_configuration(&self) -> &LicenseConfigurationIdentity {
        &self.license_configuration
    }

    pub fn configuration(&self) -> &LicenseConfigurationIdentity {
        self.license_configuration()
    }

    pub fn managed_resource(&self) -> &ManagedResourceIdentity {
        &self.managed_resource
    }

    pub fn usage_window(&self) -> &UsageWindow {
        &self.usage_window
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
        Digest::from_fields(
            "aws-license-manager-scope/v1",
            &[
                self.account_id.digest().to_string(),
                self.region.digest().to_string(),
                self.license_configuration.digest().to_string(),
                self.managed_resource.digest().to_string(),
                self.usage_window.digest().to_string(),
                self.mission.digest().to_string(),
                self.project.digest().to_string(),
                self.work_product.digest().to_string(),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.license_configuration.validate()?;
        self.managed_resource.validate()?;
        self.usage_window.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        let parts = arn_parts(self.managed_resource.arn().as_str())
            .ok_or(AwsLicenseManagerError::InvalidScope)?;
        if parts[3] != self.region.as_str()
            || (!parts[4].is_empty() && parts[4] != self.account_id.as_str())
        {
            return Err(AwsLicenseManagerError::InvalidScope);
        }
        Ok(())
    }
}

impl Serialize for AwsLicenseManagerScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsLicenseManagerScope", 8)?;
        state.serialize_field("accountDigest", &self.account_id.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field(
            "licenseConfigurationDigest",
            &self.license_configuration.digest(),
        )?;
        state.serialize_field("managedResourceDigest", &self.managed_resource.digest())?;
        state.serialize_field("usageWindow", &self.usage_window)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSnapshot {
    revision: Revision,
    permissions: BTreeSet<String>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(revision: Revision, permissions: impl IntoIterator<Item = String>) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let value = Self {
            revision,
            permissions,
            digest: Digest::zero(),
        };
        value.validate_values()?;
        let mut value = value;
        value.digest = value.calculate_digest();
        Ok(value)
    }

    pub fn readonly(revision: Revision) -> Result<Self> {
        Self::new(revision, AWS_LICENSE_MANAGER_PERMISSIONS.map(str::to_owned))
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-permission-snapshot/v1",
            &[
                self.revision.get().to_string(),
                self.permissions
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            ],
        )
    }

    fn validate_values(&self) -> Result<()> {
        if self.revision.get() == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !AWS_LICENSE_MANAGER_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsLicenseManagerError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_values()?;
        self.digest.validate()?;
        if self.digest != self.calculate_digest() {
            return Err(AwsLicenseManagerError::PermissionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

pub type TransportProvenance = ProviderProvenance;

#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    material: Zeroizing<String>,
    scope_digest: Digest,
    credential_revision: Revision,
    reference_digest: Digest,
}

pub type SecretReference = SigV4SecretReference;

impl SigV4SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AwsLicenseManagerScope,
        credential_revision: impl Into<Revision>,
    ) -> Result<Self> {
        scope.validate()?;
        let credential_revision = credential_revision.into();
        let material = opaque_handle.into();
        if credential_revision.get() == 0
            || !valid_text(&material, AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES, false)
        {
            return Err(AwsLicenseManagerError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "aws-license-manager-sigv4-secret-reference/v1",
            &[
                scope_digest.to_string(),
                credential_revision.get().to_string(),
                material.clone(),
            ],
        );
        Ok(Self {
            material: Zeroizing::new(material),
            scope_digest,
            credential_revision,
            reference_digest,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsLicenseManagerScope,
        credential_revision: impl Into<Revision>,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, credential_revision)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn ensure_bound(&self, scope: &AwsLicenseManagerScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            Err(AwsLicenseManagerError::ScopeMismatch)
        } else {
            self.validate()
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.credential_revision.get() == 0
            || !valid_text(
                &self.material,
                AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES,
                false,
            )
            || self.reference_digest
                != Digest::from_fields(
                    "aws-license-manager-sigv4-secret-reference/v1",
                    &[
                        self.scope_digest.to_string(),
                        self.credential_revision.get().to_string(),
                        self.material.to_string(),
                    ],
                )
        {
            return Err(AwsLicenseManagerError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("reference_digest", &self.reference_digest)
            .field("opaque", &true)
            .finish()
    }
}

impl Serialize for SigV4SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SigV4SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl fmt::Display for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("opaque-sigv4-secret-reference")
    }
}

#[derive(Clone, Debug, Eq, PartialOrd, Ord, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseType {
    LicenseIncluded,
    BringYourOwnLicense,
    Subscription,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseConfigurationStatus {
    Active,
    Disabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedResourceStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaState {
    WithinLimit,
    AtLimit,
    Exceeded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    QuotaExceeded,
    Drifted,
    AccessLoss,
    NotFound,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_failure(self) -> bool {
        !self.review_eligible()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LicenseConfigurationMetadata {
    identity: LicenseConfigurationIdentity,
    license_type: LicenseType,
    license_count: u64,
    license_count_hard_limit: bool,
    status: LicenseConfigurationStatus,
    resource_type: ResourceType,
    discovery_timestamp: DateTime<Utc>,
    license_rules_digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct LicenseConfigurationMetadataInput {
    pub identity: LicenseConfigurationIdentity,
    pub license_type: LicenseType,
    pub license_count: u64,
    pub license_count_hard_limit: bool,
    pub status: LicenseConfigurationStatus,
    pub resource_type: ResourceType,
    pub discovery_timestamp: DateTime<Utc>,
    pub license_rules: Option<String>,
}

impl fmt::Debug for LicenseConfigurationMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LicenseConfigurationMetadataInput")
            .field("identity", &self.identity)
            .field("license_type", &self.license_type)
            .field("license_count", &self.license_count)
            .field("license_count_hard_limit", &self.license_count_hard_limit)
            .field("status", &self.status)
            .field("resource_type", &self.resource_type)
            .field("discovery_timestamp", &self.discovery_timestamp)
            .field("license_rules_present", &self.license_rules.is_some())
            .field(
                "license_rules_digest",
                &self.license_rules.as_ref().map(|rules| {
                    Digest::from_fields("aws-license-manager-license-rules/v1", &[rules])
                }),
            )
            .finish()
    }
}

impl LicenseConfigurationMetadata {
    pub fn new(
        scope: &AwsLicenseManagerScope,
        input: LicenseConfigurationMetadataInput,
    ) -> Result<Self> {
        if input.identity.digest() != scope.license_configuration.digest()
            || !ResourceType::is_allowlisted(input.resource_type.as_str())
        {
            return Err(AwsLicenseManagerError::ConfigurationDrift);
        }
        let license_rules_digest = input
            .license_rules
            .map(|rules| Digest::from_fields("aws-license-manager-license-rules/v1", &[rules]));
        let value = Self {
            identity: input.identity,
            license_type: input.license_type,
            license_count: input.license_count,
            license_count_hard_limit: input.license_count_hard_limit,
            status: input.status,
            resource_type: input.resource_type,
            discovery_timestamp: input.discovery_timestamp,
            license_rules_digest,
        };
        value.validate_for(scope)?;
        Ok(value)
    }

    pub fn fixture(scope: &AwsLicenseManagerScope, discovered_at: DateTime<Utc>) -> Result<Self> {
        Self::new(
            scope,
            LicenseConfigurationMetadataInput {
                identity: scope.license_configuration.clone(),
                license_type: LicenseType::BringYourOwnLicense,
                license_count: 8,
                license_count_hard_limit: true,
                status: LicenseConfigurationStatus::Active,
                resource_type: scope.managed_resource.resource_type.clone(),
                discovery_timestamp: discovered_at,
                license_rules: Some("bounded-rule-digest-input".to_owned()),
            },
        )
    }

    pub fn identity(&self) -> &LicenseConfigurationIdentity {
        &self.identity
    }

    pub fn license_type(&self) -> &LicenseType {
        &self.license_type
    }

    pub const fn license_count(&self) -> u64 {
        self.license_count
    }

    pub const fn license_count_hard_limit(&self) -> bool {
        self.license_count_hard_limit
    }

    pub const fn status(&self) -> LicenseConfigurationStatus {
        self.status
    }

    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    pub const fn discovery_timestamp(&self) -> DateTime<Utc> {
        self.discovery_timestamp
    }

    pub fn license_rules_digest(&self) -> Option<&Digest> {
        self.license_rules_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-configuration-metadata/v1",
            &[
                self.identity.digest().to_string(),
                format!("{:?}", self.license_type),
                self.license_count.to_string(),
                self.license_count_hard_limit.to_string(),
                format!("{:?}", self.status),
                self.resource_type.digest().to_string(),
                self.discovery_timestamp.to_rfc3339(),
                self.license_rules_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
            ],
        )
    }

    pub(crate) fn validate_for(&self, scope: &AwsLicenseManagerScope) -> Result<()> {
        self.identity.validate()?;
        if self.identity.digest() != scope.license_configuration.digest()
            || !ResourceType::is_allowlisted(self.resource_type.as_str())
            || self.resource_type != *scope.managed_resource.resource_type()
            || self
                .license_rules_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(AwsLicenseManagerError::ConfigurationDrift);
        }
        Ok(())
    }
}

impl Serialize for LicenseConfigurationMetadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LicenseConfigurationMetadata", 9)?;
        state.serialize_field("configurationDigest", &self.identity.digest())?;
        state.serialize_field("licenseType", &self.license_type)?;
        state.serialize_field("licenseCount", &self.license_count)?;
        state.serialize_field("licenseCountHardLimit", &self.license_count_hard_limit)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("resourceType", &self.resource_type)?;
        state.serialize_field("discoveryTimestamp", &self.discovery_timestamp)?;
        state.serialize_field("licenseRulesDigest", &self.license_rules_digest)?;
        state.serialize_field("metadataDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LicenseUsageItem {
    resource: ManagedResourceIdentity,
    association_time: DateTime<Utc>,
    consumed_licenses: u64,
    status: ManagedResourceStatus,
}

impl LicenseUsageItem {
    pub fn new(
        scope: &AwsLicenseManagerScope,
        association_time: DateTime<Utc>,
        consumed_licenses: u64,
        status: ManagedResourceStatus,
    ) -> Result<Self> {
        Self::for_resource(
            scope,
            scope.managed_resource.clone(),
            association_time,
            consumed_licenses,
            status,
        )
    }

    pub fn for_resource(
        scope: &AwsLicenseManagerScope,
        resource: ManagedResourceIdentity,
        association_time: DateTime<Utc>,
        consumed_licenses: u64,
        status: ManagedResourceStatus,
    ) -> Result<Self> {
        resource.validate()?;
        if resource.digest() != scope.managed_resource.digest() {
            return Err(AwsLicenseManagerError::ResourceDrift);
        }
        Ok(Self {
            resource,
            association_time,
            consumed_licenses,
            status,
        })
    }

    pub fn resource(&self) -> &ManagedResourceIdentity {
        &self.resource
    }

    pub const fn association_time(&self) -> DateTime<Utc> {
        self.association_time
    }

    pub const fn consumed_licenses(&self) -> u64 {
        self.consumed_licenses
    }

    pub const fn status(&self) -> ManagedResourceStatus {
        self.status
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-usage-item/v1",
            &[
                self.resource.digest().to_string(),
                self.association_time.to_rfc3339(),
                self.consumed_licenses.to_string(),
                format!("{:?}", self.status),
            ],
        )
    }

    pub(crate) fn validate_for(&self, scope: &AwsLicenseManagerScope) -> Result<()> {
        if self.resource.digest() != scope.managed_resource.digest() {
            return Err(AwsLicenseManagerError::ResourceDrift);
        }
        self.resource.validate()
    }
}

impl Serialize for LicenseUsageItem {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LicenseUsageItem", 5)?;
        state.serialize_field("resourceDigest", &self.resource.digest())?;
        state.serialize_field("associationTime", &self.association_time)?;
        state.serialize_field("consumedLicenses", &self.consumed_licenses)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("usageItemDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationProjection {
    pub configuration_digest: Digest,
    pub license_type: LicenseType,
    pub license_count: u64,
    pub license_count_hard_limit: bool,
    pub status: LicenseConfigurationStatus,
    pub resource_type: ResourceType,
    pub discovery_timestamp: DateTime<Utc>,
    pub license_rules_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl From<&LicenseConfigurationMetadata> for ConfigurationProjection {
    fn from(value: &LicenseConfigurationMetadata) -> Self {
        Self {
            configuration_digest: value.identity.digest(),
            license_type: value.license_type.clone(),
            license_count: value.license_count,
            license_count_hard_limit: value.license_count_hard_limit,
            status: value.status,
            resource_type: value.resource_type.clone(),
            discovery_timestamp: value.discovery_timestamp,
            license_rules_digest: value.license_rules_digest.clone(),
            metadata_digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageProjection {
    pub usage_window: UsageWindow,
    pub usage_item_count: u32,
    pub consumed_licenses: u64,
    pub resource_status: ManagedResourceStatus,
    pub resource_digests: Vec<Digest>,
    pub usage_digest: Digest,
    pub quota_state: QuotaState,
}

impl UsageProjection {
    pub fn empty(scope: &AwsLicenseManagerScope) -> Self {
        Self {
            usage_window: scope.usage_window.clone(),
            usage_item_count: 0,
            consumed_licenses: 0,
            resource_status: ManagedResourceStatus::Unknown,
            resource_digests: Vec::new(),
            usage_digest: Digest::from_text("aws-license-manager-empty-usage"),
            quota_state: QuotaState::Unknown,
        }
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

// Keep the constants used by downstream callers discoverable from the model
// module as well as from the crate root.
pub const MAX_USAGE_ITEMS: usize = AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS;

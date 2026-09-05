//! Redacted, bounded data model for the AWS Resource Access Manager Layer-1 seam.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_ARN_LENGTH: usize = 2_048;
pub const MAX_PAGE_TOKEN_LENGTH: usize = 100_000;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_ITEMS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RETRIES: u8 = 2;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a valid digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid AWS account identifier")]
    InvalidAccount { field: &'static str },
    #[error("{field} is not a valid AWS ARN")]
    InvalidArn { field: &'static str },
    #[error("{field} is not a valid AWS region")]
    InvalidRegion { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("page size must be between one and one hundred")]
    InvalidPageSize,
    #[error("page count is outside the bounded read window")]
    InvalidPageCount,
    #[error("opaque page token is invalid")]
    InvalidPageToken,
    #[error("registration or secret reference is revoked")]
    Revoked,
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
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_LENGTH)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

/// A lower-case SHA-256 digest used as a redacted evidence handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(value)))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn from_parts(label: &str, parts: &[String]) -> Self {
        let mut input = String::from(label);
        for part in parts {
            input.push('|');
            input.push_str(part);
        }
        Self::from_text(&input)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

fn serialize_redacted<S>(digest: Digest, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut object = serializer.serialize_struct("RedactedIdentifier", 1)?;
    object.serialize_field("digest", &digest)?;
    object.end()
}

macro_rules! sensitive_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_ARN_LENGTH)?;
                if value.chars().any(char::is_whitespace) {
                    return Err(ModelError::Invalid { field: $field });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
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

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serialize_redacted(self.digest(), serializer)
            }
        }
    };
}

sensitive_identifier!(ResourceShareArn, "resource share ARN");
sensitive_identifier!(ResourceArn, "resource ARN");
sensitive_identifier!(PrincipalId, "principal identifier");
sensitive_identifier!(PermissionArn, "permission ARN");
sensitive_identifier!(InvitationArn, "invitation ARN");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS account id", 12)?;
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::InvalidAccount {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
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

impl Serialize for AwsAccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_redacted(self.digest(), serializer)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OrganizationId(String);

impl OrganizationId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "organization id")?;
        let suffix = value.strip_prefix("o-").ok_or(ModelError::Invalid {
            field: "organization id",
        })?;
        if !(10..=32).contains(&suffix.len())
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(ModelError::Invalid {
                field: "organization id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Debug for OrganizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrganizationId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for OrganizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for OrganizationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_redacted(self.digest(), serializer)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "AWS region")?;
        if value != "global"
            && (value.len() > 32
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        {
            return Err(ModelError::InvalidRegion {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MissionId(String);

impl MissionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "Mission id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MissionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProjectId(String);

impl ProjectId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "Project id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkProductId(String);

impl WorkProductId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "Work Product id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkProductId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            return Err(ModelError::Invalid { field: "revision" });
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum RamOperation {
    GetResourceShares,
    ListResources,
    ListPrincipals,
    ListResourceSharePermissions,
    GetResourceShareInvitations,
}

impl RamOperation {
    pub const ALL: [Self; 5] = [
        Self::GetResourceShares,
        Self::ListResources,
        Self::ListPrincipals,
        Self::ListResourceSharePermissions,
        Self::GetResourceShareInvitations,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetResourceShares => "GetResourceShares",
            Self::ListResources => "ListResources",
            Self::ListPrincipals => "ListPrincipals",
            Self::ListResourceSharePermissions => "ListResourceSharePermissions",
            Self::GetResourceShareInvitations => "GetResourceShareInvitations",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceOwner {
    SelfAccount,
    OtherAccounts,
}

impl ResourceOwner {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelfAccount => "SELF",
            Self::OtherAccounts => "OTHER-ACCOUNTS",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceRegionScope {
    All,
    Regional,
    Global,
}

impl ResourceRegionScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::Regional => "REGIONAL",
            Self::Global => "GLOBAL",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceShareStatus {
    Pending,
    Active,
    Failed,
    Deleting,
    Deleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Declined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssociationStatus {
    Associated,
    Disassociated,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceType(String);

impl ResourceType {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "resource type")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Display for ResourceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for ResourceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_redacted(self.digest(), serializer)
    }
}

#[derive(Clone, Eq, PartialOrd, Ord, PartialEq)]
pub struct ShareName(String);

impl ShareName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "resource share name", MAX_IDENTIFIER_LENGTH)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Debug for ShareName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareName")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamReadFilter {
    pub resource_owner: ResourceOwner,
    pub share_status: Option<ResourceShareStatus>,
    pub resource_region_scope: Option<ResourceRegionScope>,
    pub resource_type: Option<ResourceType>,
    pub resource_share_arn: Option<ResourceShareArn>,
    pub resource_arn: Option<ResourceArn>,
    pub principal: Option<PrincipalId>,
    pub permission_arn: Option<PermissionArn>,
    pub permission_version: Option<u32>,
    pub invitation_status: Option<InvitationStatus>,
}

impl RamReadFilter {
    pub fn new(resource_owner: ResourceOwner) -> Self {
        Self {
            resource_owner,
            share_status: None,
            resource_region_scope: None,
            resource_type: None,
            resource_share_arn: None,
            resource_arn: None,
            principal: None,
            permission_arn: None,
            permission_version: None,
            invitation_status: None,
        }
    }

    pub fn for_operation(operation: RamOperation) -> Self {
        let mut filter = Self::new(ResourceOwner::SelfAccount);
        if matches!(operation, RamOperation::GetResourceShareInvitations) {
            filter.resource_owner = ResourceOwner::OtherAccounts;
        }
        filter
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_version == Some(0) {
            return Err(ModelError::Invalid {
                field: "permission version",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        let parts = vec![
            self.resource_owner.as_str().to_owned(),
            self.share_status
                .map_or_else(String::new, |value| format!("{value:?}")),
            self.resource_region_scope
                .map_or_else(String::new, |value| format!("{value:?}")),
            self.resource_type
                .as_ref()
                .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            self.resource_share_arn
                .as_ref()
                .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            self.resource_arn
                .as_ref()
                .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            self.principal
                .as_ref()
                .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            self.permission_arn
                .as_ref()
                .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            self.permission_version
                .map_or_else(String::new, |value| value.to_string()),
            self.invitation_status
                .map_or_else(String::new, |value| format!("{value:?}")),
        ];
        Digest::from_parts("aws-ram-filter/v1", &parts)
    }
}

/// An opaque provider cursor. Its token is retained only inside the transport
/// seam and is never serialised or included in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token: Zeroizing<String>,
    token_digest: Digest,
    binding_digest: Option<Digest>,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "opaque page token", MAX_PAGE_TOKEN_LENGTH)?;
        Ok(Self {
            token_digest: Digest::from_text(&value),
            token: Zeroizing::new(value),
            binding_digest: None,
            page_number: 0,
        })
    }

    pub fn bound(
        value: impl Into<String>,
        binding_digest: Digest,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        if page_number == 0 {
            return Err(ModelError::InvalidPageToken);
        }
        let mut token = Self::new(value)?;
        token.binding_digest = Some(binding_digest);
        token.page_number = page_number;
        Ok(token)
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn bind_for_request(&self, binding: &Digest, page_number: u16) -> Self {
        let mut value = self.clone();
        value.binding_digest = Some(binding.clone());
        value.page_number = page_number;
        value
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("OpaquePageToken", 1)?;
        object.serialize_field("opaque", &true)?;
        object.end()
    }
}

#[derive(Eq, PartialEq)]
pub struct SecretReference {
    handle: Zeroizing<String>,
    region: AwsRegion,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn sigv4(
        handle: impl Into<String>,
        scope: &AwsRamScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let handle = handle.into();
        validate_text(
            &handle,
            "opaque SigV4 secret reference",
            MAX_IDENTIFIER_LENGTH,
        )?;
        Ok(Self {
            handle: Zeroizing::new(handle),
            region: scope.region.clone(),
            scope_digest: scope.scope_digest.clone(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ram-secret-reference/v1",
            &[
                self.handle.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.credential_revision.value().to_string(),
            ],
        )
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self, scope: &AwsRamScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.scope_digest || self.revoked {
            return Err(ModelError::Revoked);
        }
        Ok(())
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            handle: Zeroizing::new(self.handle.as_str().to_owned()),
            region: self.region.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("SecretReference", 1)?;
        object.serialize_field("opaque", &true)?;
        object.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub operations: BTreeSet<RamOperation>,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        revision: Revision,
        operations: impl IntoIterator<Item = RamOperation>,
    ) -> Result<Self, ModelError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty()
            || operations
                .iter()
                .any(|operation| !RamOperation::ALL.contains(operation))
        {
            return Err(ModelError::Invalid {
                field: "RAM permission snapshot",
            });
        }
        let permission_digest = digest_serializable(&(revision, &operations))?;
        Ok(Self {
            revision,
            operations,
            permission_digest,
        })
    }

    pub fn read_only(revision: Revision) -> Result<Self, ModelError> {
        Self::new(revision, RamOperation::ALL)
    }

    pub fn contains(&self, operation: RamOperation) -> bool {
        self.operations.contains(&operation)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest != digest_serializable(&(self.revision, &self.operations))? {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsRamScope {
    pub account: AwsAccountId,
    pub region: AwsRegion,
    pub organization: OrganizationId,
    pub resource_share_arns: Vec<ResourceShareArn>,
    pub resource_arns: Vec<ResourceArn>,
    pub principals: Vec<PrincipalId>,
    pub permission_arns: Vec<PermissionArn>,
    pub invitation_arns: Vec<InvitationArn>,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub association_revision: Revision,
    pub scope_digest: Digest,
}

impl AwsRamScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        organization: OrganizationId,
        resource_share_arns: impl IntoIterator<Item = ResourceShareArn>,
        resource_arns: impl IntoIterator<Item = ResourceArn>,
        principals: impl IntoIterator<Item = PrincipalId>,
        permission_arns: impl IntoIterator<Item = PermissionArn>,
        invitation_arns: impl IntoIterator<Item = InvitationArn>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        association_revision: Revision,
    ) -> Result<Self, ModelError> {
        let resource_share_arns = unique(resource_share_arns, "resource-share scope")?;
        let resource_arns = unique(resource_arns, "resource scope")?;
        let principals = unique(principals, "principal scope")?;
        let permission_arns = unique(permission_arns, "permission scope")?;
        let invitation_arns = unique(invitation_arns, "invitation scope")?;
        if resource_share_arns.is_empty()
            && resource_arns.is_empty()
            && principals.is_empty()
            && permission_arns.is_empty()
            && invitation_arns.is_empty()
        {
            return Err(ModelError::Invalid {
                field: "RAM target scope",
            });
        }
        let mut scope = Self {
            account,
            region,
            organization,
            resource_share_arns,
            resource_arns,
            principals,
            permission_arns,
            invitation_arns,
            mission,
            project,
            work_product,
            association_revision,
            scope_digest: Digest::from_text("unsealed-aws-ram-scope"),
        };
        scope.scope_digest = scope.calculate_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn single(
        account: AwsAccountId,
        region: AwsRegion,
        organization: OrganizationId,
        resource_share: ResourceShareArn,
        resource: ResourceArn,
        principal: PrincipalId,
        permission: PermissionArn,
        invitation: InvitationArn,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        association_revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            account,
            region,
            organization,
            [resource_share],
            [resource],
            [principal],
            [permission],
            [invitation],
            mission,
            project,
            work_product,
            association_revision,
        )
    }

    fn calculate_digest(&self) -> Digest {
        let parts = vec![
            self.account.digest().as_str().to_owned(),
            self.region.as_str().to_owned(),
            self.organization.digest().as_str().to_owned(),
            digest_list(&self.resource_share_arns).as_str().to_owned(),
            digest_list(&self.resource_arns).as_str().to_owned(),
            digest_list(&self.principals).as_str().to_owned(),
            digest_list(&self.permission_arns).as_str().to_owned(),
            digest_list(&self.invitation_arns).as_str().to_owned(),
            self.mission.id.as_str().to_owned(),
            self.mission.revision.value().to_string(),
            self.project.id.as_str().to_owned(),
            self.project.revision.value().to_string(),
            self.work_product.id.as_str().to_owned(),
            self.work_product.revision.value().to_string(),
            self.association_revision.value().to_string(),
        ];
        Digest::from_parts("aws-ram-scope/v1", &parts)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.scope_digest != self.calculate_digest() {
            return Err(ModelError::Invalid {
                field: "scope digest",
            });
        }
        Ok(())
    }

    pub fn contains_resource_share(&self, value: &ResourceShareArn) -> bool {
        self.resource_share_arns.contains(value)
    }

    pub fn contains_resource(&self, value: &ResourceArn) -> bool {
        self.resource_arns.contains(value)
    }

    pub fn contains_principal(&self, value: &PrincipalId) -> bool {
        self.principals.contains(value)
    }

    pub fn contains_permission(&self, value: &PermissionArn) -> bool {
        self.permission_arns.contains(value)
    }

    pub fn contains_invitation(&self, value: &InvitationArn) -> bool {
        self.invitation_arns.contains(value)
    }
}

impl fmt::Debug for AwsRamScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRamScope")
            .field("account_digest", &self.account.digest())
            .field("region", &self.region)
            .field("organization_digest", &self.organization.digest())
            .field("resource_share_count", &self.resource_share_arns.len())
            .field("resource_count", &self.resource_arns.len())
            .field("principal_count", &self.principals.len())
            .field("permission_count", &self.permission_arns.len())
            .field("invitation_count", &self.invitation_arns.len())
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("association_revision", &self.association_revision)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl Serialize for AwsRamScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("AwsRamScope", 12)?;
        object.serialize_field("accountDigest", &self.account.digest())?;
        object.serialize_field("region", &self.region)?;
        object.serialize_field("organizationDigest", &self.organization.digest())?;
        object.serialize_field("resourceShareCount", &self.resource_share_arns.len())?;
        object.serialize_field("resourceCount", &self.resource_arns.len())?;
        object.serialize_field("principalCount", &self.principals.len())?;
        object.serialize_field("permissionCount", &self.permission_arns.len())?;
        object.serialize_field("invitationCount", &self.invitation_arns.len())?;
        object.serialize_field("mission", &self.mission)?;
        object.serialize_field("project", &self.project)?;
        object.serialize_field("workProduct", &self.work_product)?;
        object.serialize_field("associationRevision", &self.association_revision)?;
        object.serialize_field("scopeDigest", &self.scope_digest)?;
        object.end()
    }
}

fn unique<T>(values: impl IntoIterator<Item = T>, field: &'static str) -> Result<Vec<T>, ModelError>
where
    T: Ord,
{
    let mut set = BTreeSet::new();
    for value in values {
        if !set.insert(value) {
            return Err(ModelError::Duplicate { field });
        }
    }
    Ok(set.into_iter().collect())
}

fn digest_list<T>(values: &[T]) -> Digest
where
    T: fmt::Display,
{
    let values = values.iter().map(ToString::to_string).collect::<Vec<_>>();
    Digest::from_parts("aws-ram-scope-list/v1", &values)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceShareMetadata {
    pub resource_share_arn: ResourceShareArn,
    pub name: ShareName,
    pub owning_account: AwsAccountId,
    pub status: ResourceShareStatus,
    pub allow_external_principals: bool,
    pub feature_set: Option<String>,
    pub creation_time: i64,
    pub last_updated_time: i64,
    pub retain_sharing_on_account_leave_organization: bool,
    pub association_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceMetadata {
    pub arn: ResourceArn,
    pub resource_share_arn: ResourceShareArn,
    pub resource_type: ResourceType,
    pub resource_region_scope: ResourceRegionScope,
    pub status: AssociationStatus,
    pub resource_group_arn: Option<ResourceArn>,
    pub creation_time: i64,
    pub last_updated_time: i64,
    pub association_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalMetadata {
    pub id: PrincipalId,
    pub resource_share_arn: ResourceShareArn,
    pub external: bool,
    pub creation_time: i64,
    pub last_updated_time: i64,
    pub association_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionMetadata {
    pub permission_arn: PermissionArn,
    pub version: u32,
    pub default_version: bool,
    pub resource_type: ResourceType,
    pub customer_managed: bool,
    pub association_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationMetadata {
    pub invitation_arn: InvitationArn,
    pub resource_share_arn: ResourceShareArn,
    pub sender_account: AwsAccountId,
    pub receiver_account: AwsAccountId,
    pub status: InvitationStatus,
    pub creation_time: i64,
    pub expiration_time: Option<i64>,
    pub association_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssociationState {
    Present,
    Absent,
    Pending,
    Accepted,
    Declined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RamEvidenceState {
    Present,
    Absent,
    Pending,
    Accepted,
    Declined,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

impl RamEvidenceState {
    pub const fn can_be_reviewed(self) -> bool {
        matches!(
            self,
            Self::Present | Self::Absent | Self::Pending | Self::Accepted | Self::Declined
        )
    }
}

pub type EvidenceState = RamEvidenceState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceShareProjection {
    pub resource_share_arn_digest: Digest,
    pub name_digest: Digest,
    pub owning_account_digest: Digest,
    pub status: ResourceShareStatus,
    pub allow_external_principals: bool,
    pub feature_set_digest: Option<Digest>,
    pub creation_time: i64,
    pub last_updated_time: i64,
    pub retain_sharing_on_account_leave_organization: bool,
    pub association_revision: Revision,
    pub state: AssociationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceProjection {
    pub resource_arn_digest: Digest,
    pub resource_share_arn_digest: Digest,
    pub resource_type_digest: Digest,
    pub resource_region_scope: ResourceRegionScope,
    pub status: AssociationStatus,
    pub resource_group_arn_digest: Option<Digest>,
    pub creation_time: i64,
    pub last_updated_time: i64,
    pub association_revision: Revision,
    pub state: AssociationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrincipalProjection {
    pub principal_digest: Digest,
    pub resource_share_arn_digest: Digest,
    pub external: bool,
    pub creation_time: i64,
    pub last_updated_time: i64,
    pub association_revision: Revision,
    pub state: AssociationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionProjection {
    pub permission_arn_digest: Digest,
    pub version: u32,
    pub default_version: bool,
    pub resource_type_digest: Digest,
    pub customer_managed: bool,
    pub association_revision: Revision,
    pub state: AssociationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvitationProjection {
    pub invitation_arn_digest: Digest,
    pub resource_share_arn_digest: Digest,
    pub sender_account_digest: Digest,
    pub receiver_account_digest: Digest,
    pub status: InvitationStatus,
    pub creation_time: i64,
    pub expiration_time: Option<i64>,
    pub association_revision: Revision,
    pub state: AssociationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub share_digest: Digest,
    pub resource_digest: Digest,
    pub principal_digest: Digest,
    pub permission_metadata_digest: Digest,
    pub invitation_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub filter_digest: Digest,
    pub loop_rejected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryRateReceipt {
    pub attempts: u8,
    pub rate_limited: bool,
    pub retry_after_seconds: Option<u32>,
    pub receipt_digest: Digest,
}

impl RetryRateReceipt {
    pub fn new(
        attempts: u8,
        rate_limited: bool,
        retry_after_seconds: Option<u32>,
    ) -> Result<Self, ModelError> {
        if attempts == 0 || attempts > MAX_RETRIES.saturating_add(1) {
            return Err(ModelError::Invalid { field: "attempts" });
        }
        let receipt_digest = digest_serializable(&(attempts, rate_limited, retry_after_seconds))?;
        Ok(Self {
            attempts,
            rate_limited,
            retry_after_seconds,
            receipt_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestReceipt {
    pub operation: RamOperation,
    pub request_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub response_bytes: usize,
    pub retry: RetryRateReceipt,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    pub fn new(
        request: &RamReadRequest,
        response_bytes: usize,
        retry: RetryRateReceipt,
    ) -> Result<Self, ModelError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::BoundExceeded {
                field: "response bytes",
            });
        }
        let receipt_digest = digest_serializable(&(
            request.operation,
            &request.request_digest,
            &request.filter.digest(),
            &request.cursor_digest(),
            response_bytes,
            &retry.receipt_digest,
        ))?;
        Ok(Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            filter_digest: request.filter.digest(),
            cursor_digest: request.cursor_digest(),
            response_bytes,
            retry,
            redacted: true,
            receipt_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RamPageItems {
    ResourceShares(Vec<ResourceShareMetadata>),
    Resources(Vec<ResourceMetadata>),
    Principals(Vec<PrincipalMetadata>),
    Permissions(Vec<PermissionMetadata>),
    Invitations(Vec<InvitationMetadata>),
}

impl RamPageItems {
    pub fn operation(&self) -> RamOperation {
        match self {
            Self::ResourceShares(_) => RamOperation::GetResourceShares,
            Self::Resources(_) => RamOperation::ListResources,
            Self::Principals(_) => RamOperation::ListPrincipals,
            Self::Permissions(_) => RamOperation::ListResourceSharePermissions,
            Self::Invitations(_) => RamOperation::GetResourceShareInvitations,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::ResourceShares(values) => values.len(),
            Self::Resources(values) => values.len(),
            Self::Principals(values) => values.len(),
            Self::Permissions(values) => values.len(),
            Self::Invitations(values) => values.len(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            Self::ResourceShares(values) => values.is_empty(),
            Self::Resources(values) => values.is_empty(),
            Self::Principals(values) => values.is_empty(),
            Self::Permissions(values) => values.is_empty(),
            Self::Invitations(values) => values.is_empty(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamReadPage {
    pub operation: RamOperation,
    pub request_digest: Digest,
    pub page_number: u16,
    pub items: RamPageItems,
    pub next_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub association_revision: Revision,
    pub provider_revision: String,
    pub retry: RetryRateReceipt,
}

impl RamReadPage {
    pub fn new(
        request: &RamReadRequest,
        items: RamPageItems,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
        association_revision: Revision,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if items.operation() != request.operation {
            return Err(ModelError::Invalid {
                field: "page operation",
            });
        }
        if items.len() > request.max_results as usize || items.len() > MAX_ITEMS {
            return Err(ModelError::BoundExceeded {
                field: "page items",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::BoundExceeded {
                field: "response bytes",
            });
        }
        let page_number = request.page_number;
        let next_token = next_token.map(|token| {
            token.bind_for_request(&request.query_digest(), page_number.saturating_add(1))
        });
        Ok(Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            page_number,
            items,
            next_token,
            response_bytes,
            association_revision,
            provider_revision: provider_revision.into(),
            retry: RetryRateReceipt::new(1, false, None)?,
        })
    }

    pub fn with_retry(mut self, retry: RetryRateReceipt) -> Self {
        self.retry = retry;
        self
    }

    pub fn validate_for(
        &self,
        request: &RamReadRequest,
        provider_revision: &str,
    ) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.page_number != request.page_number
            || self.provider_revision != provider_revision
            || self.items.operation() != request.operation
            || self.items.len() > request.max_results as usize
            || self.items.len() > MAX_ITEMS
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::Invalid {
                field: "provider page binding",
            });
        }
        if let Some(token) = &self.next_token
            && (token.binding_digest() != Some(&request.query_digest())
                || token.page_number() != request.page_number.saturating_add(1))
        {
            return Err(ModelError::Invalid {
                field: "provider cursor binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamReadRequest {
    pub operation: RamOperation,
    pub scope: AwsRamScope,
    pub filter: RamReadFilter,
    pub cursor: Option<OpaquePageToken>,
    pub page_number: u16,
    pub max_results: u16,
    pub request_digest: Digest,
}

impl RamReadRequest {
    pub fn new(
        scope: AwsRamScope,
        operation: RamOperation,
        filter: RamReadFilter,
        max_results: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        filter.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&max_results) {
            return Err(ModelError::InvalidPageSize);
        }
        let page_number = cursor.as_ref().map_or(1, |token| {
            if token.page_number() == 0 {
                1
            } else {
                token.page_number()
            }
        });
        if !(1..=MAX_PAGES).contains(&page_number) {
            return Err(ModelError::InvalidPageCount);
        }
        let mut request = Self {
            operation,
            scope,
            filter,
            cursor,
            page_number,
            max_results,
            request_digest: Digest::from_text("unsealed-aws-ram-request"),
        };
        request.request_digest = request.calculate_digest();
        request.validate()?;
        Ok(request)
    }

    pub fn get_resource_shares(
        scope: AwsRamScope,
        filter: RamReadFilter,
        max_results: u16,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            RamOperation::GetResourceShares,
            filter,
            max_results,
            None,
        )
    }

    pub fn list_resources(
        scope: AwsRamScope,
        filter: RamReadFilter,
        max_results: u16,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            RamOperation::ListResources,
            filter,
            max_results,
            None,
        )
    }

    pub fn list_principals(
        scope: AwsRamScope,
        filter: RamReadFilter,
        max_results: u16,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            RamOperation::ListPrincipals,
            filter,
            max_results,
            None,
        )
    }

    pub fn list_resource_share_permissions(
        scope: AwsRamScope,
        filter: RamReadFilter,
        max_results: u16,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            RamOperation::ListResourceSharePermissions,
            filter,
            max_results,
            None,
        )
    }

    pub fn get_resource_share_invitations(
        scope: AwsRamScope,
        filter: RamReadFilter,
        max_results: u16,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            RamOperation::GetResourceShareInvitations,
            filter,
            max_results,
            None,
        )
    }

    pub fn with_cursor(&self, cursor: OpaquePageToken) -> Result<Self, ModelError> {
        let page_number = if cursor.page_number() == 0 {
            self.page_number.saturating_add(1)
        } else {
            cursor.page_number()
        };
        if page_number != self.page_number.saturating_add(1) || page_number > MAX_PAGES {
            return Err(ModelError::InvalidPageCount);
        }
        if let Some(binding) = cursor.binding_digest()
            && binding != &self.query_digest()
        {
            return Err(ModelError::Invalid {
                field: "cursor filter binding",
            });
        }
        let cursor = cursor.bind_for_request(&self.query_digest(), page_number);
        Self::new(
            self.scope.clone(),
            self.operation,
            self.filter.clone(),
            self.max_results,
            Some(cursor),
        )
    }

    pub fn query_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ram-query/v1",
            &[
                self.operation.as_str().to_owned(),
                self.scope.scope_digest.as_str().to_owned(),
                self.filter.digest().as_str().to_owned(),
                self.max_results.to_string(),
            ],
        )
    }

    pub fn cursor_digest(&self) -> Option<Digest> {
        self.cursor
            .as_ref()
            .map(|cursor| cursor.token_digest().clone())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ram-request/v1",
            &[
                self.query_digest().as_str().to_owned(),
                self.cursor_digest()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.page_number.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.request_digest != self.calculate_digest()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            return Err(ModelError::Invalid {
                field: "request digest",
            });
        }
        if let Some(cursor) = &self.cursor
            && (cursor.binding_digest() != Some(&self.query_digest())
                || cursor.page_number() != self.page_number)
        {
            return Err(ModelError::Invalid {
                field: "request cursor",
            });
        }
        Ok(())
    }
}

impl Serialize for RamReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("RamReadRequest", 7)?;
        object.serialize_field("operation", &self.operation)?;
        object.serialize_field("scopeDigest", &self.scope.scope_digest)?;
        object.serialize_field("filterDigest", &self.filter.digest())?;
        object.serialize_field("cursor", &self.cursor)?;
        object.serialize_field("pageNumber", &self.page_number)?;
        object.serialize_field("maxResults", &self.max_results)?;
        object.serialize_field("requestDigest", &self.request_digest)?;
        object.end()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("access loss")]
    AccessLoss,
    #[error("unauthorized")]
    Unauthorized,
    #[error("rate limited")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("provider unavailable")]
    Unavailable,
    #[error("blocked environment")]
    BlockedEnvironment,
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("invalid provider request")]
    InvalidRequest,
    #[error("provider returned an unknown condition")]
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RamFailureCategory {
    AccessLoss,
    RateLimited,
    BlockedEnv,
    Unavailable,
    Malformed,
    InvalidRequest,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RamProviderFailure {
    pub category: RamFailureCategory,
    pub retry_after_seconds: Option<u32>,
    pub failure_digest: Digest,
}

impl RamProviderFailure {
    pub fn from_transport(error: &TransportError) -> Self {
        let (category, retry_after_seconds) = match error {
            TransportError::AccessLoss | TransportError::Unauthorized => {
                (RamFailureCategory::AccessLoss, None)
            }
            TransportError::RateLimited {
                retry_after_seconds,
            } => (RamFailureCategory::RateLimited, *retry_after_seconds),
            TransportError::BlockedEnvironment => (RamFailureCategory::BlockedEnv, None),
            TransportError::Unavailable => (RamFailureCategory::Unavailable, None),
            TransportError::MalformedResponse => (RamFailureCategory::Malformed, None),
            TransportError::InvalidRequest => (RamFailureCategory::InvalidRequest, None),
            TransportError::ProviderUnknown => (RamFailureCategory::ProviderUnknown, None),
        };
        let failure_digest = Digest::from_parts(
            "aws-ram-provider-failure/v1",
            &[
                format!("{category:?}"),
                retry_after_seconds.unwrap_or_default().to_string(),
            ],
        );
        Self {
            category,
            retry_after_seconds,
            failure_digest,
        }
    }
}

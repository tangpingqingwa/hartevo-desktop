//! Typed, bounded, and redacted AWS Control Tower Layer-1 model values.
//!
//! The model deliberately contains no AWS SDK, signer, HTTP client, raw
//! manifest, or mutation operation.  Values that could be useful to an
//! adapter are kept behind typed constructors and are serialized as digests
//! whenever they cross the evidence boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{MAX_ITEMS, MAX_PAGE_SIZE, MAX_PAGES, OPERATION_RETENTION_DAYS};

pub const MAX_IDENTIFIER_BYTES: usize = 2_048;
pub const MAX_REVISION_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
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
    #[error("{field} is not a valid AWS account id")]
    InvalidAccount { field: &'static str },
    #[error("{field} is not a valid AWS region")]
    InvalidRegion { field: &'static str },
    #[error("{field} is not a valid AWS Control Tower ARN")]
    InvalidArn { field: &'static str },
    #[error("{field} is not a valid digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid UUID operation identifier")]
    InvalidOperation { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is outside its bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} is outside the exact scope")]
    OutOfScope { field: &'static str },
    #[error("{field} does not match the home region")]
    RegionMismatch { field: &'static str },
    #[error("{field} does not match the account")]
    AccountMismatch { field: &'static str },
    #[error("the opaque cursor is invalid")]
    InvalidCursor,
    #[error("the permission scope is empty")]
    EmptyPermissionScope,
    #[error("the secret reference is invalid or revoked")]
    InvalidSecretReference,
    #[error("the secret reference is already revoked")]
    SecretAlreadyRevoked,
    #[error("the operation detail is older than the 90-day retention window")]
    OperationRetentionExpired,
}

pub type Result<T> = std::result::Result<T, ModelError>;

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<()> {
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

fn validate_safe_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    validate_text(value, field, max)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@#?%".contains(&byte)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<()> {
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

/// A lower-case SHA-256 digest used as an evidence handle and fence.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, parts: &[String]) -> Self {
        let mut input = Vec::new();
        append_length_prefixed(&mut input, domain);
        for part in parts {
            append_length_prefixed(&mut input, part);
        }
        Self::from_bytes(&input)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub const fn zero() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<()> {
        validate_digest(&self.0, field)
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

fn append_length_prefixed(input: &mut Vec<u8>, value: &str) {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
}

macro_rules! digest_identifier {
    ($name:ident, $field:literal, $domain:literal, $max:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_safe_text(&value, $field, $max)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, std::slice::from_ref(&self.0))
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

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

digest_identifier!(ProjectId, "project id", "aws-control-tower-project/v1", 256);
digest_identifier!(MissionId, "mission id", "aws-control-tower-mission/v1", 256);
digest_identifier!(
    WorkProductId,
    "work product id",
    "aws-control-tower-work-product/v1",
    256
);
digest_identifier!(
    RevisionId,
    "revision id",
    "aws-control-tower-revision/v1",
    MAX_REVISION_BYTES
);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::InvalidAccount {
                field: "account id",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-account/v1",
            std::slice::from_ref(&self.0),
        )
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

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "home region", 64)?;
        if value.len() < 3
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
            || value.starts_with('-')
            || value.ends_with('-')
        {
            return Err(ModelError::InvalidRegion {
                field: "home region",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-home-region/v1",
            std::slice::from_ref(&self.0),
        )
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

impl Serialize for AwsRegion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LandingZoneId(String);

impl LandingZoneId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "landing zone identifier", MAX_IDENTIFIER_BYTES)?;
        if value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte)))
        {
            return Err(ModelError::InvalidCharacters {
                field: "landing zone identifier",
            });
        }
        if value.starts_with("arn:") {
            let parts = value.split(':').collect::<Vec<_>>();
            if parts.len() != 6
                || parts[0] != "arn"
                || parts[2] != "controltower"
                || parts[3].is_empty()
                || parts[4].len() != 12
                || parts[4].bytes().any(|byte| !byte.is_ascii_digit())
                || !parts[5].starts_with("landingzone/")
            {
                return Err(ModelError::InvalidArn {
                    field: "landing zone identifier",
                });
            }
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-landing-zone/v1",
            std::slice::from_ref(&self.0),
        )
    }

    pub fn arn_account_region(&self) -> Option<(AccountId, AwsRegion)> {
        let parts = self.0.split(':').collect::<Vec<_>>();
        if parts.len() != 6 || parts[0] != "arn" {
            return None;
        }
        Some((
            AccountId::new(parts[4].to_owned()).ok()?,
            AwsRegion::new(parts[3].to_owned()).ok()?,
        ))
    }
}

impl fmt::Debug for LandingZoneId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LandingZoneId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for LandingZoneId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for LandingZoneId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

pub type LandingZoneIdentifier = LandingZoneId;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BaselineId(String);

impl BaselineId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_safe_text(&value, "baseline identifier", MAX_IDENTIFIER_BYTES)?;
        if value.starts_with("arn:") {
            let parts = value.split(':').collect::<Vec<_>>();
            if parts.len() != 6
                || parts[0] != "arn"
                || parts[2] != "controltower"
                || !parts[5].starts_with("baseline/")
            {
                return Err(ModelError::InvalidArn {
                    field: "baseline identifier",
                });
            }
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-baseline/v1",
            std::slice::from_ref(&self.0),
        )
    }

    pub fn arn_account_region(&self) -> Option<(AccountId, AwsRegion)> {
        let parts = self.0.split(':').collect::<Vec<_>>();
        if parts.len() != 6 || parts[0] != "arn" {
            return None;
        }
        Some((
            AccountId::new(parts[4].to_owned()).ok()?,
            AwsRegion::new(parts[3].to_owned()).ok()?,
        ))
    }
}

impl fmt::Debug for BaselineId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaselineId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for BaselineId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for BaselineId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

pub type BaselineIdentifier = BaselineId;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetId(String);

impl TargetId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_safe_text(&value, "target identifier", MAX_IDENTIFIER_BYTES)?;
        if value.starts_with("arn:") {
            let parts = value.split(':').collect::<Vec<_>>();
            if parts.len() != 6
                || parts[0] != "arn"
                || parts[2] != "organizations"
                || !(parts[5].starts_with("account/")
                    || parts[5].starts_with("ou/")
                    || parts[5].starts_with("root/"))
            {
                return Err(ModelError::InvalidArn {
                    field: "target identifier",
                });
            }
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-control-tower-target/v1", std::slice::from_ref(&self.0))
    }

    pub fn kind(&self) -> TargetKind {
        let resource = self.0.split(':').nth(5).unwrap_or(self.0.as_str());
        if resource.starts_with("account/") || self.0.len() == 12 {
            TargetKind::Account
        } else if resource.starts_with("ou/") || self.0.starts_with("ou-") {
            TargetKind::OrganizationalUnit
        } else if resource.starts_with("root/") || self.0.starts_with("r-") {
            TargetKind::Root
        } else {
            TargetKind::Unknown
        }
    }

    pub fn account_id(&self) -> Option<AccountId> {
        if self.0.len() == 12 && self.0.bytes().all(|byte| byte.is_ascii_digit()) {
            return AccountId::new(self.0.clone()).ok();
        }
        let parts = self.0.split(':').collect::<Vec<_>>();
        if parts.len() == 6 && parts[2] == "organizations" {
            if let Ok(account) = AccountId::new(parts[4].to_owned()) {
                return Some(account);
            }
            let resource = parts[5];
            let account = resource
                .strip_prefix("account/")
                .or_else(|| resource.split('/').next_back())?;
            return AccountId::new(account.to_owned()).ok();
        }
        None
    }
}

impl fmt::Debug for TargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for TargetId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetKind {
    Root,
    OrganizationalUnit,
    Account,
    Unknown,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(String);

impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = value.len() == 36
            && value.as_bytes().iter().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
                }
            });
        if !valid {
            return Err(ModelError::InvalidOperation {
                field: "operation identifier",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-operation/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for OperationId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Version(String);

impl Version {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_safe_text(&value, "version", 128)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-version/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Version")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LandingZoneIdentity {
    pub id: LandingZoneId,
    pub arn: LandingZoneId,
}

impl LandingZoneIdentity {
    pub fn new(arn: impl Into<String>) -> Result<Self> {
        let arn = LandingZoneId::new(arn)?;
        if !arn.as_str().starts_with("arn:") {
            return Err(ModelError::InvalidArn {
                field: "landing zone ARN",
            });
        }
        Ok(Self {
            id: arn.clone(),
            arn,
        })
    }

    pub fn from_id(id: LandingZoneId) -> Result<Self> {
        Self::new(id.as_str().to_owned())
    }

    pub fn account_id(&self) -> Option<AccountId> {
        self.arn.arn_account_region().map(|value| value.0)
    }

    pub fn region(&self) -> Option<AwsRegion> {
        self.arn.arn_account_region().map(|value| value.1)
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub fn verify_against(&self, account: &AccountId, region: &AwsRegion) -> Result<()> {
        if self.account_id().as_ref() != Some(account) {
            return Err(ModelError::AccountMismatch {
                field: "landing zone account",
            });
        }
        if self.region().as_ref() != Some(region) {
            return Err(ModelError::RegionMismatch {
                field: "landing zone home region",
            });
        }
        Ok(())
    }
}

impl Serialize for LandingZoneIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

impl fmt::Debug for LandingZoneIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LandingZoneIdentity")
            .field("arn_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetReference {
    pub target_id: TargetId,
    pub kind: TargetKind,
}

impl TargetReference {
    pub fn new(identifier: impl Into<String>) -> Result<Self> {
        let target_id = TargetId::new(identifier)?;
        Ok(Self {
            kind: target_id.kind(),
            target_id,
        })
    }

    pub fn from_parts(target_id: TargetId, kind: TargetKind) -> Result<Self> {
        if kind != target_id.kind() && target_id.kind() != TargetKind::Unknown {
            return Err(ModelError::Invalid {
                field: "target kind",
            });
        }
        Ok(Self { target_id, kind })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-target-reference/v1",
            &[
                self.target_id.digest().to_string(),
                format!("{:?}", self.kind),
            ],
        )
    }

    pub fn account_id(&self) -> Option<AccountId> {
        self.target_id.account_id()
    }
}

impl fmt::Debug for TargetReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetReference")
            .field("target_id", &self.target_id)
            .field("digest", &self.digest())
            .field("kind", &self.kind)
            .finish()
    }
}

impl Serialize for TargetReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TargetReference", 2)?;
        state.serialize_field("targetDigest", &self.digest())?;
        state.serialize_field("kind", &self.kind)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadOperation {
    ListLandingZones,
    GetLandingZone,
    GetLandingZoneOperation,
    ListEnabledBaselines,
}

impl ReadOperation {
    pub const ALL: [Self; 4] = [
        Self::ListLandingZones,
        Self::GetLandingZone,
        Self::GetLandingZoneOperation,
        Self::ListEnabledBaselines,
    ];

    pub const fn api_name(&self) -> &'static str {
        match self {
            Self::ListLandingZones => "ListLandingZones",
            Self::GetLandingZone => "GetLandingZone",
            Self::GetLandingZoneOperation => "GetLandingZoneOperation",
            Self::ListEnabledBaselines => "ListEnabledBaselines",
        }
    }
}

impl Ord for ReadOperation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.api_name().cmp(other.api_name())
    }
}

impl PartialOrd for ReadOperation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for ReadOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.api_name().hash(state);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub allowed_operations: BTreeSet<ReadOperation>,
    pub permission_revision: RevisionId,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        allowed_operations: impl IntoIterator<Item = ReadOperation>,
        permission_revision: RevisionId,
    ) -> Result<Self> {
        let mut operation_set = BTreeSet::new();
        for operation in allowed_operations {
            if !operation_set.insert(operation) {
                return Err(ModelError::Duplicate {
                    field: "permission operation",
                });
            }
        }
        let allowed_operations = operation_set;
        if allowed_operations.is_empty() {
            return Err(ModelError::EmptyPermissionScope);
        }
        let material = allowed_operations
            .iter()
            .map(ReadOperation::api_name)
            .map(str::to_owned)
            .chain([permission_revision.as_str().to_owned()])
            .collect::<Vec<_>>();
        let permission_digest = Digest::from_parts("aws-control-tower-permission/v1", &material);
        Ok(Self {
            allowed_operations,
            permission_revision,
            permission_digest,
        })
    }

    pub fn all(permission_revision: RevisionId) -> Result<Self> {
        Self::new(ReadOperation::ALL, permission_revision)
    }

    pub fn read_only(permission_revision: RevisionId) -> Result<Self> {
        Self::all(permission_revision)
    }

    pub fn allows(&self, operation: &ReadOperation) -> bool {
        self.allowed_operations.contains(operation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: RevisionId,
}

impl MissionBinding {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        mission_revision: RevisionId,
    ) -> Self {
        Self {
            project_id,
            mission_id,
            work_product_id,
            mission_revision,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-mission-binding/v1",
            &[
                self.project_id.digest().to_string(),
                self.mission_id.digest().to_string(),
                self.work_product_id.digest().to_string(),
                self.mission_revision.digest().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub page_size: u16,
    pub max_pages: u16,
    pub max_items: usize,
}

impl ReadBounds {
    pub fn new(max_pages: u16, page_size: u16, max_items: usize) -> Result<Self> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::BoundExceeded { field: "max pages" });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::BoundExceeded { field: "page size" });
        }
        if max_items == 0 || max_items > MAX_ITEMS {
            return Err(ModelError::BoundExceeded { field: "max items" });
        }
        Ok(Self {
            page_size,
            max_pages,
            max_items,
        })
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_items: MAX_ITEMS,
        }
    }
}

/// A provider continuation token.  The token can be forwarded only inside a
/// typed transport request; serialization and debug output expose its digest.
#[derive(Eq, PartialEq)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "opaque cursor", MAX_CURSOR_BYTES)?;
        if value.trim().is_empty() {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self(value))
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-opaque-cursor/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl Clone for OpaqueCursor {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 2)?;
        state.serialize_field("opaque", &true)?;
        state.serialize_field("digest", &self.digest())?;
        state.end()
    }
}

impl Drop for OpaqueCursor {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub type OpaquePageToken = OpaqueCursor;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LandingZoneStatus {
    Active,
    Creating,
    Updating,
    Failed,
    Deleting,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftStatus {
    InSync,
    Drifted,
    NotChecked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    InProgress,
    Succeeded,
    Failed,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    Setup,
    Update,
    Reset,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    Enabled,
    Enabling,
    Updating,
    Disabling,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    ProviderUnknown,
    AccessLoss,
    NotFound,
    Conflict,
    Throttled,
    RetentionExpired,
    ScopeDrift,
    RegionMismatch,
    PaginationIncomplete,
    BlockedEnv,
    Partial,
}

impl EvidenceStatus {
    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Complete | Self::Partial)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LandingZoneSummary {
    pub landing_zone: LandingZoneIdentity,
    pub status: LandingZoneStatus,
    pub version: Version,
    pub observed_at: DateTime<Utc>,
    pub arn_digest: Digest,
    pub status_digest: Digest,
    pub version_digest: Digest,
    pub timestamp_digest: Digest,
}

impl LandingZoneSummary {
    pub fn new(
        landing_zone: LandingZoneIdentity,
        status: LandingZoneStatus,
        version: Version,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let arn_digest = landing_zone.digest();
        let status_digest = Digest::from_text(format!("{status:?}"));
        let version_digest = version.digest();
        let timestamp_digest = Digest::from_text(observed_at.to_rfc3339());
        Self {
            landing_zone,
            status,
            version,
            observed_at,
            arn_digest,
            status_digest,
            version_digest,
            timestamp_digest,
        }
    }

    pub fn verify(&self) -> Result<()> {
        let rebuilt = Self::new(
            self.landing_zone.clone(),
            self.status,
            self.version.clone(),
            self.observed_at,
        );
        if rebuilt.arn_digest != self.arn_digest
            || rebuilt.status_digest != self.status_digest
            || rebuilt.version_digest != self.version_digest
            || rebuilt.timestamp_digest != self.timestamp_digest
        {
            return Err(ModelError::Invalid {
                field: "landing zone summary digest",
            });
        }
        Ok(())
    }
}

impl Serialize for LandingZoneSummary {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LandingZoneSummary", 5)?;
        state.serialize_field("arnDigest", &self.arn_digest)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("timestampDigest", &self.timestamp_digest)?;
        state.serialize_field("status", &self.status)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LandingZoneDetail {
    pub landing_zone: LandingZoneIdentity,
    pub status: LandingZoneStatus,
    pub drift_status: DriftStatus,
    pub version: Version,
    pub latest_available_version: Option<Version>,
    pub manifest_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub arn_digest: Digest,
    pub status_digest: Digest,
    pub drift_status_digest: Digest,
    pub version_digest: Digest,
    pub latest_available_version_digest: Option<Digest>,
    pub timestamp_digest: Digest,
}

impl LandingZoneDetail {
    pub fn new(
        landing_zone: LandingZoneIdentity,
        status: LandingZoneStatus,
        drift_status: DriftStatus,
        version: Version,
        latest_available_version: Option<Version>,
        manifest_digest: Option<Digest>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let latest_available_version_digest =
            latest_available_version.as_ref().map(Version::digest);
        Self {
            arn_digest: landing_zone.digest(),
            status_digest: Digest::from_text(format!("{status:?}")),
            drift_status_digest: Digest::from_text(format!("{drift_status:?}")),
            version_digest: version.digest(),
            timestamp_digest: Digest::from_text(observed_at.to_rfc3339()),
            landing_zone,
            status,
            drift_status,
            version,
            latest_available_version,
            manifest_digest,
            observed_at,
            latest_available_version_digest,
        }
    }

    pub fn verify(&self) -> Result<()> {
        if let Some(manifest_digest) = &self.manifest_digest {
            manifest_digest.validate("manifest digest")?;
        }
        let rebuilt = Self::new(
            self.landing_zone.clone(),
            self.status,
            self.drift_status,
            self.version.clone(),
            self.latest_available_version.clone(),
            self.manifest_digest.clone(),
            self.observed_at,
        );
        if rebuilt.arn_digest != self.arn_digest
            || rebuilt.status_digest != self.status_digest
            || rebuilt.drift_status_digest != self.drift_status_digest
            || rebuilt.version_digest != self.version_digest
            || rebuilt.latest_available_version_digest != self.latest_available_version_digest
            || rebuilt.timestamp_digest != self.timestamp_digest
        {
            return Err(ModelError::Invalid {
                field: "landing zone detail digest",
            });
        }
        Ok(())
    }
}

impl Serialize for LandingZoneDetail {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LandingZoneDetail", 8)?;
        state.serialize_field("arnDigest", &self.arn_digest)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.serialize_field("driftStatusDigest", &self.drift_status_digest)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field(
            "latestAvailableVersionDigest",
            &self.latest_available_version_digest,
        )?;
        state.serialize_field("manifestDigest", &self.manifest_digest)?;
        state.serialize_field("timestampDigest", &self.timestamp_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LandingZoneOperation {
    pub operation_id: OperationId,
    pub landing_zone: LandingZoneIdentity,
    pub operation_type: OperationType,
    pub status: OperationStatus,
    pub status_message_digest: Option<Digest>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub operation_identifier_digest: Digest,
    pub status_digest: Digest,
    pub start_timestamp_digest: Digest,
    pub end_timestamp_digest: Option<Digest>,
}

impl LandingZoneOperation {
    pub fn new(
        operation_id: OperationId,
        landing_zone: LandingZoneIdentity,
        operation_type: OperationType,
        status: OperationStatus,
        status_message: Option<&str>,
        started_at: DateTime<Utc>,
        ended_at: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        if let Some(end) = ended_at
            && end < started_at
        {
            return Err(ModelError::Invalid {
                field: "operation end time",
            });
        }
        if let Some(message) = status_message {
            validate_text(message, "operation status message", 4_096)?;
        }
        let status_message_digest = status_message.map(Digest::from_text);
        let operation_identifier_digest = operation_id.digest();
        let status_digest = Digest::from_text(format!("{status:?}"));
        let start_timestamp_digest = Digest::from_text(started_at.to_rfc3339());
        let end_timestamp_digest = ended_at.map(|value| Digest::from_text(value.to_rfc3339()));
        Ok(Self {
            operation_id,
            landing_zone,
            operation_type,
            status,
            status_message_digest,
            started_at,
            ended_at,
            operation_identifier_digest,
            status_digest,
            start_timestamp_digest,
            end_timestamp_digest,
        })
    }

    pub fn verify_retention(&self, observed_at: DateTime<Utc>) -> Result<()> {
        if self.started_at > observed_at
            || observed_at
                .signed_duration_since(self.started_at)
                .num_days()
                >= OPERATION_RETENTION_DAYS
        {
            return Err(ModelError::OperationRetentionExpired);
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        if let Some(status_message_digest) = &self.status_message_digest {
            status_message_digest.validate("status message digest")?;
        }
        let status_message = None;
        let rebuilt = Self::new(
            self.operation_id.clone(),
            self.landing_zone.clone(),
            self.operation_type,
            self.status,
            status_message,
            self.started_at,
            self.ended_at,
        )?;
        if rebuilt.operation_identifier_digest != self.operation_identifier_digest
            || rebuilt.status_digest != self.status_digest
            || rebuilt.start_timestamp_digest != self.start_timestamp_digest
            || rebuilt.end_timestamp_digest != self.end_timestamp_digest
        {
            return Err(ModelError::Invalid {
                field: "operation digest",
            });
        }
        Ok(())
    }
}

impl Serialize for LandingZoneOperation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LandingZoneOperation", 8)?;
        state.serialize_field(
            "operationIdentifierDigest",
            &self.operation_identifier_digest,
        )?;
        state.serialize_field("landingZoneDigest", &self.landing_zone.digest())?;
        state.serialize_field("operationType", &self.operation_type)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.serialize_field("statusMessageDigest", &self.status_message_digest)?;
        state.serialize_field("startTimestampDigest", &self.start_timestamp_digest)?;
        state.serialize_field("endTimestampDigest", &self.end_timestamp_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnabledBaselineSummary {
    pub baseline_id: BaselineId,
    pub target: TargetReference,
    pub parent_target: Option<TargetReference>,
    pub baseline_version: Version,
    pub status: BaselineStatus,
    pub drift_status: DriftStatus,
    pub last_operation_id: Option<OperationId>,
    pub is_child: bool,
    pub observed_at: DateTime<Utc>,
    pub baseline_identifier_digest: Digest,
    pub target_identifier_digest: Digest,
    pub parent_identifier_digest: Option<Digest>,
    pub baseline_version_digest: Digest,
    pub status_digest: Digest,
    pub drift_status_digest: Digest,
    pub last_operation_identifier_digest: Option<Digest>,
    pub timestamp_digest: Digest,
}

impl EnabledBaselineSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        baseline_id: BaselineId,
        target: TargetReference,
        parent_target: Option<TargetReference>,
        baseline_version: Version,
        status: BaselineStatus,
        drift_status: DriftStatus,
        last_operation_id: Option<OperationId>,
        is_child: bool,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let baseline_identifier_digest = baseline_id.digest();
        let target_identifier_digest = target.digest();
        let parent_identifier_digest = parent_target.as_ref().map(TargetReference::digest);
        let baseline_version_digest = baseline_version.digest();
        let status_digest = Digest::from_text(format!("{status:?}"));
        let drift_status_digest = Digest::from_text(format!("{drift_status:?}"));
        let last_operation_identifier_digest = last_operation_id.as_ref().map(OperationId::digest);
        let timestamp_digest = Digest::from_text(observed_at.to_rfc3339());
        Self {
            baseline_id,
            target,
            parent_target,
            baseline_version,
            status,
            drift_status,
            last_operation_id,
            is_child,
            observed_at,
            baseline_identifier_digest,
            target_identifier_digest,
            parent_identifier_digest,
            baseline_version_digest,
            status_digest,
            drift_status_digest,
            last_operation_identifier_digest,
            timestamp_digest,
        }
    }

    pub fn verify(&self) -> Result<()> {
        let rebuilt = Self::new(
            self.baseline_id.clone(),
            self.target.clone(),
            self.parent_target.clone(),
            self.baseline_version.clone(),
            self.status,
            self.drift_status,
            self.last_operation_id.clone(),
            self.is_child,
            self.observed_at,
        );
        if rebuilt.baseline_identifier_digest != self.baseline_identifier_digest
            || rebuilt.target_identifier_digest != self.target_identifier_digest
            || rebuilt.parent_identifier_digest != self.parent_identifier_digest
            || rebuilt.baseline_version_digest != self.baseline_version_digest
            || rebuilt.status_digest != self.status_digest
            || rebuilt.drift_status_digest != self.drift_status_digest
            || rebuilt.last_operation_identifier_digest != self.last_operation_identifier_digest
            || rebuilt.timestamp_digest != self.timestamp_digest
        {
            return Err(ModelError::Invalid {
                field: "enabled baseline digest",
            });
        }
        Ok(())
    }
}

impl Serialize for EnabledBaselineSummary {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EnabledBaselineSummary", 10)?;
        state.serialize_field("baselineIdentifierDigest", &self.baseline_identifier_digest)?;
        state.serialize_field("targetIdentifierDigest", &self.target_identifier_digest)?;
        state.serialize_field("parentIdentifierDigest", &self.parent_identifier_digest)?;
        state.serialize_field("baselineVersionDigest", &self.baseline_version_digest)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.serialize_field("driftStatusDigest", &self.drift_status_digest)?;
        state.serialize_field(
            "lastOperationIdentifierDigest",
            &self.last_operation_identifier_digest,
        )?;
        state.serialize_field("isChild", &self.is_child)?;
        state.serialize_field("timestampDigest", &self.timestamp_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsControlTowerScope {
    pub account_id: AccountId,
    pub home_region: AwsRegion,
    pub landing_zone: LandingZoneIdentity,
    pub baseline_ids: BTreeSet<BaselineId>,
    pub target_ids: BTreeSet<TargetReference>,
    pub operation_ids: BTreeSet<OperationId>,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission: MissionBinding,
    pub permission: PermissionScope,
    pub scope_digest: Digest,
}

impl AwsControlTowerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        home_region: AwsRegion,
        landing_zone: LandingZoneIdentity,
        baseline_ids: impl IntoIterator<Item = BaselineId>,
        target_ids: impl IntoIterator<Item = TargetReference>,
        operation_ids: impl IntoIterator<Item = OperationId>,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        permission: PermissionScope,
    ) -> Result<Self> {
        landing_zone.verify_against(&account_id, &home_region)?;
        let baseline_ids = collect_unique(baseline_ids, "baseline scope")?;
        let target_ids = collect_unique(target_ids, "target scope")?;
        let operation_ids = collect_unique(operation_ids, "operation scope")?;
        if baseline_ids.is_empty() {
            return Err(ModelError::Empty {
                field: "baseline scope",
            });
        }
        if target_ids.is_empty() {
            return Err(ModelError::Empty {
                field: "target scope",
            });
        }
        if operation_ids.is_empty() {
            return Err(ModelError::Empty {
                field: "operation scope",
            });
        }
        if target_ids.iter().any(|target| {
            target
                .account_id()
                .as_ref()
                .is_some_and(|id| id != &account_id)
        }) {
            return Err(ModelError::AccountMismatch {
                field: "target scope account",
            });
        }
        if baseline_ids.iter().any(|baseline| {
            baseline
                .arn_account_region()
                .is_some_and(|(account, _)| account != account_id)
        }) {
            return Err(ModelError::AccountMismatch {
                field: "baseline scope account",
            });
        }
        if baseline_ids.iter().any(|baseline| {
            baseline
                .arn_account_region()
                .is_some_and(|(_, region)| region != home_region)
        }) {
            return Err(ModelError::RegionMismatch {
                field: "baseline scope home region",
            });
        }
        if permission.allowed_operations.is_empty() {
            return Err(ModelError::EmptyPermissionScope);
        }
        let mission = MissionBinding::new(
            project_id.clone(),
            mission_id.clone(),
            work_product_id.clone(),
            RevisionId::new("mission-revision-1")?,
        );
        let scope_digest = Self::compute_digest(
            &account_id,
            &home_region,
            &landing_zone,
            &baseline_ids,
            &target_ids,
            &operation_ids,
            &mission,
            &permission,
        );
        Ok(Self {
            account_id,
            home_region,
            landing_zone,
            baseline_ids,
            target_ids,
            operation_ids,
            project_id,
            mission_id,
            work_product_id,
            mission,
            permission,
            scope_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_mission_revision(
        account_id: AccountId,
        home_region: AwsRegion,
        landing_zone: LandingZoneIdentity,
        baseline_ids: impl IntoIterator<Item = BaselineId>,
        target_ids: impl IntoIterator<Item = TargetReference>,
        operation_ids: impl IntoIterator<Item = OperationId>,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        mission_revision: RevisionId,
        permission: PermissionScope,
    ) -> Result<Self> {
        let mut scope = Self::new(
            account_id,
            home_region,
            landing_zone,
            baseline_ids,
            target_ids,
            operation_ids,
            project_id,
            mission_id,
            work_product_id,
            permission,
        )?;
        scope.mission.mission_revision = mission_revision;
        scope.scope_digest = Self::compute_digest(
            &scope.account_id,
            &scope.home_region,
            &scope.landing_zone,
            &scope.baseline_ids,
            &scope.target_ids,
            &scope.operation_ids,
            &scope.mission,
            &scope.permission,
        );
        Ok(scope)
    }

    fn compute_digest(
        account_id: &AccountId,
        home_region: &AwsRegion,
        landing_zone: &LandingZoneIdentity,
        baseline_ids: &BTreeSet<BaselineId>,
        target_ids: &BTreeSet<TargetReference>,
        operation_ids: &BTreeSet<OperationId>,
        mission: &MissionBinding,
        permission: &PermissionScope,
    ) -> Digest {
        let mut parts = vec![
            account_id.digest().to_string(),
            home_region.digest().to_string(),
            landing_zone.digest().to_string(),
            mission.digest().to_string(),
            permission.permission_digest.to_string(),
        ];
        parts.extend(
            baseline_ids
                .iter()
                .map(BaselineId::digest)
                .map(|value| value.to_string()),
        );
        parts.extend(
            target_ids
                .iter()
                .map(TargetReference::digest)
                .map(|value| value.to_string()),
        );
        parts.extend(
            operation_ids
                .iter()
                .map(OperationId::digest)
                .map(|value| value.to_string()),
        );
        Digest::from_parts("aws-control-tower-scope/v1", &parts)
    }

    pub fn verify(&self) -> Result<()> {
        self.landing_zone
            .verify_against(&self.account_id, &self.home_region)?;
        if self.scope_digest
            != Self::compute_digest(
                &self.account_id,
                &self.home_region,
                &self.landing_zone,
                &self.baseline_ids,
                &self.target_ids,
                &self.operation_ids,
                &self.mission,
                &self.permission,
            )
        {
            return Err(ModelError::Invalid {
                field: "scope digest",
            });
        }
        Ok(())
    }

    pub fn allows_baseline(&self, baseline: &BaselineId) -> bool {
        self.baseline_ids.contains(baseline)
    }

    pub fn allows_target(&self, target: &TargetReference) -> bool {
        self.target_ids.contains(target)
    }

    pub fn allows_operation(&self, operation: &OperationId) -> bool {
        self.operation_ids.contains(operation)
    }

    pub fn target_scope_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-target-scope/v1",
            &self
                .target_ids
                .iter()
                .map(TargetReference::digest)
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    pub fn baseline_scope_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-baseline-scope/v1",
            &self
                .baseline_ids
                .iter()
                .map(BaselineId::digest)
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }
}

pub type ControlTowerScope = AwsControlTowerScope;

fn collect_unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<BTreeSet<T>> {
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value) {
            return Err(ModelError::Duplicate { field });
        }
    }
    Ok(result)
}

/// A SigV4 credential handle.  It intentionally has no `Serialize`
/// implementation: only its digest is allowed in registration/evidence.
pub struct SigV4SecretReference {
    handle: String,
    account_id: AccountId,
    home_region: AwsRegion,
    scope_digest: Digest,
    credential_revision: RevisionId,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl Clone for SigV4SecretReference {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            account_id: self.account_id.clone(),
            home_region: self.home_region.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision.clone(),
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("handle_digest", &Digest::from_text(self.handle.as_bytes()))
            .field("reference_digest", &self.digest())
            .field("account_digest", &self.account_id.digest())
            .field("home_region_digest", &self.home_region.digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision.digest())
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SigV4SecretReference {
    pub fn new(
        handle: impl Into<String>,
        account_id: AccountId,
        home_region: AwsRegion,
        scope_digest: Digest,
        credential_revision: RevisionId,
    ) -> Result<Self> {
        let handle = handle.into();
        validate_safe_text(&handle, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        scope_digest.validate("secret scope digest")?;
        Ok(Self {
            handle,
            account_id,
            home_region,
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn for_scope(handle: impl Into<String>, scope: &AwsControlTowerScope) -> Result<Self> {
        Self::new(
            handle,
            scope.account_id.clone(),
            scope.home_region.clone(),
            scope.scope_digest.clone(),
            RevisionId::new("credential-revision-1")?,
        )
    }

    pub fn for_sigv4(handle: impl Into<String>, scope: &AwsControlTowerScope) -> Result<Self> {
        Self::for_scope(handle, scope)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-sigv4-secret-reference/v1",
            &[
                Digest::from_text(self.handle.as_bytes()).to_string(),
                self.account_id.digest().to_string(),
                self.home_region.digest().to_string(),
                self.scope_digest.to_string(),
                self.credential_revision.digest().to_string(),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn home_region(&self) -> &AwsRegion {
        &self.home_region
    }

    pub fn credential_revision(&self) -> &RevisionId {
        &self.credential_revision
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<()> {
        if self.revoked {
            Err(ModelError::InvalidSecretReference)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(ModelError::SecretAlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.handle.zeroize();
    }
}

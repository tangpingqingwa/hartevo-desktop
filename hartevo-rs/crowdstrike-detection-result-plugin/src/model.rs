//! Bounded Falcon scope, redacted projections, receipts, and evidence types.
//!
//! The model is deliberately provider-shaped but not provider-payload-shaped.
//! Raw process/device/technique values may be supplied to constructors, where
//! they are immediately reduced to SHA-256 digests. They are never retained by
//! a projection, receipt, registration, proposal, or evidence value.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_FQL_BYTES: usize = 2_048;
pub const MAX_WINDOW_DAYS: i64 = 31;
pub const MAX_HOST_IDS: usize = 128;
pub const MAX_GROUP_IDS: usize = 128;
pub const MAX_DETECTION_IDS: usize = 128;
pub const MAX_ALERT_IDS: usize = 128;
pub const MAX_DETECTIONS_PER_PAGE: usize = 100;
pub const MAX_TOTAL_DETECTIONS: usize = 800;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_OFFSET: u32 = 100_000;
pub const MAX_RETRIES: u8 = 3;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_TECHNIQUES_PER_DETECTION: usize = 32;

pub type ProjectRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;
pub type EvidenceRevision = Revision;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum size")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains a character outside its allowlist")]
    InvalidCharacter { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("FQL filter is outside the allowlisted grammar")]
    InvalidFql,
    #[error("time window is invalid or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its Layer-1 bound")]
    BoundExceeded { field: &'static str },
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("read bounds are invalid")]
    InvalidBounds,
    #[error("provider response is invalid or outside its declared bounds")]
    InvalidResponse,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is reversed and cannot be restored")]
    AlreadyReversed,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("the typed value cannot be used after revocation")]
    Revoked,
    #[error("canonical digest input could not be serialized")]
    DigestSerialization,
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
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

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::from_bytes(&bytes))
        .map_err(|_| ModelError::DigestSerialization)
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(ModelError::InvalidCharacter { field });
    }
    Ok(())
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
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

bounded_identifier!(CustomerId, "customer id");
bounded_identifier!(Cid, "cid");
bounded_identifier!(HostId, "host id");
bounded_identifier!(GroupId, "group id");
bounded_identifier!(DetectionId, "detection id");
bounded_identifier!(AlertId, "alert id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");

pub type CrowdStrikeCustomerId = CustomerId;
pub type CrowdStrikeCid = Cid;
pub type FalconHostId = HostId;
pub type FalconGroupId = GroupId;
pub type FalconDetectionId = DetectionId;
pub type FalconAlertId = AlertId;

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::parse(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("ProjectScope is serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::parse(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("MissionScope is serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::parse(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("WorkProductScope is serializable")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FalconCloud {
    Us1,
    Us2,
    Eu1,
    Gov1,
}

impl FalconCloud {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "us-1" | "us1" => Ok(Self::Us1),
            "us-2" | "us2" => Ok(Self::Us2),
            "eu-1" | "eu1" => Ok(Self::Eu1),
            "gov-1" | "gov1" => Ok(Self::Gov1),
            _ => Err(ModelError::InvalidScope("Falcon cloud")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Us1 => "us-1",
            Self::Us2 => "us-2",
            Self::Eu1 => "eu-1",
            Self::Gov1 => "gov-1",
        }
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FalconRegion(String);

impl FalconRegion {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        validate_identifier(&value, "Falcon region")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FalconRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FalconRegion")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for FalconRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// An opaque handle to a host-owned Falcon OAuth client secret.
///
/// The input is immediately hashed. The raw handle is not stored, serialized,
/// formatted with `Debug`, or exposed through any accessor. The reference is
/// bound to its Falcon region/cloud and the canonical Alerts READ permission.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    region: FalconRegion,
    cloud: FalconCloud,
    permission_digest: Digest,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        region: FalconRegion,
        cloud: FalconCloud,
    ) -> Result<Self, ModelError> {
        let reference = opaque_reference.as_ref();
        validate_text(
            reference,
            "opaque Falcon OAuth client reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let permission_digest = Digest::from_text(crate::FALCON_ALERTS_READ_PERMISSION);
        Ok(Self {
            reference_digest: Digest::from_text(reference),
            region,
            cloud,
            permission_digest,
        })
    }

    pub fn for_alerts_read(
        opaque_reference: impl AsRef<str>,
        region: FalconRegion,
        cloud: FalconCloud,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_reference, region, cloud)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn region(&self) -> &FalconRegion {
        &self.region
    }

    #[must_use]
    pub const fn cloud(&self) -> FalconCloud {
        self.cloud
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest != Digest::from_text(crate::FALCON_ALERTS_READ_PERMISSION) {
            return Err(ModelError::InvalidScope(
                "SecretReference permission binding",
            ));
        }
        validate_text(self.region.as_str(), "Falcon region", MAX_IDENTIFIER_BYTES)
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("region", &self.region)
            .field("cloud", &self.cloud)
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

pub type FalconOAuthClientSecretReference = SecretReference;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: Vec<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut normalized = permissions
            .into_iter()
            .map(Into::into)
            .map(
                |permission| match permission.to_ascii_lowercase().as_str() {
                    "alerts: read" | "alerts:read" | "alerts.read" => {
                        crate::FALCON_ALERTS_READ_PERMISSION.to_owned()
                    }
                    _ => permission,
                },
            )
            .collect::<Vec<_>>();
        normalized.sort();
        normalized.dedup();
        let snapshot = Self {
            permissions: normalized,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn alerts_read() -> Self {
        Self {
            permissions: vec![crate::FALCON_ALERTS_READ_PERMISSION.to_owned()],
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permissions != [crate::FALCON_ALERTS_READ_PERMISSION.to_owned()] {
            return Err(ModelError::InvalidScope(
                "least-privilege Falcon Alerts READ permission",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("PermissionSnapshot is serializable")
    }
}

pub type CrowdStrikePermissionSnapshot = PermissionSnapshot;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FalconHostGroupScope {
    pub host_ids: Vec<HostId>,
    pub group_ids: Vec<GroupId>,
}

impl FalconHostGroupScope {
    pub fn new(host_ids: Vec<HostId>, group_ids: Vec<GroupId>) -> Result<Self, ModelError> {
        if host_ids.len() > MAX_HOST_IDS || group_ids.len() > MAX_GROUP_IDS {
            return Err(ModelError::BoundExceeded {
                field: "host/group ids",
            });
        }
        if host_ids.is_empty() && group_ids.is_empty() {
            return Err(ModelError::InvalidScope(
                "at least one host or group is required",
            ));
        }
        if has_duplicate(&host_ids) || has_duplicate(&group_ids) {
            return Err(ModelError::Duplicate {
                field: "host/group ids",
            });
        }
        Ok(Self {
            host_ids,
            group_ids,
        })
    }

    pub fn from_values<H, G>(host_ids: H, group_ids: G) -> Result<Self, ModelError>
    where
        H: IntoIterator,
        H::Item: Into<String>,
        G: IntoIterator,
        G::Item: Into<String>,
    {
        let hosts = host_ids
            .into_iter()
            .map(|value| HostId::parse(value.into()))
            .collect::<Result<Vec<_>, _>>()?;
        let groups = group_ids
            .into_iter()
            .map(|value| GroupId::parse(value.into()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(hosts, groups)
    }

    pub fn for_host(host_id: impl Into<String>) -> Result<Self, ModelError> {
        Self::from_values([host_id.into()], std::iter::empty::<String>())
    }

    pub fn for_group(group_id: impl Into<String>) -> Result<Self, ModelError> {
        Self::from_values(std::iter::empty::<String>(), [group_id.into()])
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("FalconHostGroupScope is serializable")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.host_ids.clone(), self.group_ids.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FalconDetectionAlertScope {
    pub detection_ids: Vec<DetectionId>,
    pub alert_ids: Vec<AlertId>,
}

pub type HostGroupScope = FalconHostGroupScope;
pub type DetectionAlertScope = FalconDetectionAlertScope;

impl FalconDetectionAlertScope {
    pub fn new(
        detection_ids: Vec<DetectionId>,
        alert_ids: Vec<AlertId>,
    ) -> Result<Self, ModelError> {
        if detection_ids.len() > MAX_DETECTION_IDS || alert_ids.len() > MAX_ALERT_IDS {
            return Err(ModelError::BoundExceeded {
                field: "detection/alert ids",
            });
        }
        if has_duplicate(&detection_ids) || has_duplicate(&alert_ids) {
            return Err(ModelError::Duplicate {
                field: "detection/alert ids",
            });
        }
        Ok(Self {
            detection_ids,
            alert_ids,
        })
    }

    pub fn from_values<D, A>(detection_ids: D, alert_ids: A) -> Result<Self, ModelError>
    where
        D: IntoIterator,
        D::Item: Into<String>,
        A: IntoIterator,
        A::Item: Into<String>,
    {
        let detections = detection_ids
            .into_iter()
            .map(|value| DetectionId::parse(value.into()))
            .collect::<Result<Vec<_>, _>>()?;
        let alerts = alert_ids
            .into_iter()
            .map(|value| AlertId::parse(value.into()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(detections, alerts)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("FalconDetectionAlertScope is serializable")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.detection_ids.clone(), self.alert_ids.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FalconSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl FalconSeverity {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "informational" | "info" => Self::Informational,
            "low" => Self::Low,
            "medium" | "moderate" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

pub type DetectionSeverity = FalconSeverity;
pub type CrowdStrikeSeverity = FalconSeverity;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FalconDetectionStatus {
    New,
    InProgress,
    Reopened,
    Closed,
    Suppressed,
    Unknown,
}

impl FalconDetectionStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "new" => Self::New,
            "in_progress" | "in-progress" | "in progress" => Self::InProgress,
            "reopened" | "re-opened" => Self::Reopened,
            "closed" => Self::Closed,
            "suppressed" => Self::Suppressed,
            _ => Self::Unknown,
        }
    }
}

pub type DetectionStatus = FalconDetectionStatus;
pub type CrowdStrikeDetectionStatus = FalconDetectionStatus;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FqlFilter(String);

impl FqlFilter {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_fql(&value)?;
        Ok(Self(value))
    }

    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::parse(value)
    }

    pub fn exact(field: &str, value: &str) -> Result<Self, ModelError> {
        if !is_allowed_fql_field(field) {
            return Err(ModelError::InvalidFql);
        }
        validate_text(value, "FQL literal", MAX_IDENTIFIER_BYTES)?;
        let escaped = escape_fql_literal(value)?;
        Self::parse(format!("{field}:'{escaped}'"))
    }

    pub fn all(parts: &[FqlFilter]) -> Result<Self, ModelError> {
        if parts.is_empty() {
            return Err(ModelError::InvalidFql);
        }
        Self::parse(
            parts
                .iter()
                .map(Self::as_str)
                .map(|part| format!("({part})"))
                .collect::<Vec<_>>()
                .join("+"),
        )
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::parse(self.0.clone()).map(|_| ())
    }
}

fn escape_fql_literal(value: &str) -> Result<String, ModelError> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            return Err(ModelError::InvalidFql);
        }
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\'' => escaped.push_str("\\'"),
            _ => escaped.push(character),
        }
    }
    Ok(escaped)
}

fn is_allowed_fql_field(field: &str) -> bool {
    matches!(
        field,
        "cid"
            | "customer_id"
            | "detection_id"
            | "device.device_id"
            | "device.group_ids"
            | "device.platform_name"
            | "status"
            | "severity"
            | "created_timestamp"
            | "updated_timestamp"
            | "behaviors.tactic"
            | "behaviors.technique"
            | "host_id"
    )
}

fn validate_fql(value: &str) -> Result<(), ModelError> {
    validate_text(value, "FQL filter", MAX_FQL_BYTES)?;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let mut parentheses = 0_i32;
    let mut brackets = 0_i32;
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if escaped {
                if byte != b'\\' && byte != active_quote {
                    return Err(ModelError::InvalidFql);
                }
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => parentheses += 1,
            b')' => {
                parentheses -= 1;
                if parentheses < 0 {
                    return Err(ModelError::InvalidFql);
                }
            }
            b'[' => brackets += 1,
            b']' => {
                brackets -= 1;
                if brackets < 0 {
                    return Err(ModelError::InvalidFql);
                }
            }
            b';' | b'|' | b'&' | b'{' | b'}' | b'`' | b'$' | b'\n' | b'\r' => {
                return Err(ModelError::InvalidFql);
            }
            _ => {}
        }
        index += 1;
    }
    if quote.is_some() || escaped || parentheses != 0 || brackets != 0 {
        return Err(ModelError::InvalidFql);
    }

    let mut token_start = None;
    index = 0;
    while index <= bytes.len() {
        let is_token = index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric()
                || bytes[index] == b'_'
                || bytes[index] == b'.');
        if is_token && token_start.is_none() {
            token_start = Some(index);
        }
        if (!is_token || index == bytes.len()) && token_start.is_some() {
            let start = token_start.take().expect("token start exists");
            let token = &value[start..index];
            let mut next = index;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len()
                && (bytes[next] == b':'
                    || bytes[next] == b'='
                    || bytes[next] == b'!'
                    || bytes[next] == b'<'
                    || bytes[next] == b'>')
                && !is_allowed_fql_field(token)
            {
                return Err(ModelError::InvalidFql);
            }
        }
        index += 1;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionTimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub revision: Revision,
}

impl DetectionTimeWindow {
    pub fn new(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let value = Self {
            start,
            end,
            revision: Revision::new(revision)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn parse(start: &str, end: &str, revision: u64) -> Result<Self, ModelError> {
        let start = start
            .parse::<DateTime<Utc>>()
            .map_err(|_| ModelError::InvalidTimeWindow)?;
        let end = end
            .parse::<DateTime<Utc>>()
            .map_err(|_| ModelError::InvalidTimeWindow)?;
        Self::new(start, end, revision)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.start > self.end
            || self.end - self.start > Duration::days(MAX_WINDOW_DAYS)
            || self.revision.get() == 0
        {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("DetectionTimeWindow is serializable")
    }
}

pub type TimeWindow = DetectionTimeWindow;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeDetectionScope {
    pub customer_id: CustomerId,
    pub cid: Cid,
    pub host_group: FalconHostGroupScope,
    pub detection_alert: FalconDetectionAlertScope,
    pub severity: Option<FalconSeverity>,
    pub status: Option<FalconDetectionStatus>,
    pub fql_filter: FqlFilter,
    pub time_window: DetectionTimeWindow,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub scope_revision: Revision,
}

impl CrowdStrikeDetectionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        customer_id: impl Into<String>,
        cid: impl Into<String>,
        host_group: FalconHostGroupScope,
        detection_alert: FalconDetectionAlertScope,
        severity: Option<FalconSeverity>,
        status: Option<FalconDetectionStatus>,
        fql_filter: FqlFilter,
        time_window: DetectionTimeWindow,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let value = Self {
            customer_id: CustomerId::parse(customer_id)?,
            cid: Cid::parse(cid)?,
            host_group,
            detection_alert,
            severity,
            status,
            fql_filter,
            time_window,
            project,
            mission,
            work_product,
            scope_revision: Revision::new(scope_revision)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.host_group.validate()?;
        self.detection_alert.validate()?;
        self.fql_filter.validate()?;
        self.time_window.validate()?;
        if self.scope_revision.get() == 0 {
            return Err(ModelError::InvalidScope("scope revision"));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("CrowdStrikeDetectionScope is serializable")
    }

    #[must_use]
    pub fn project_revision(&self) -> Revision {
        self.project.revision
    }

    #[must_use]
    pub fn mission_revision(&self) -> Revision {
        self.mission.revision
    }

    #[must_use]
    pub fn work_product_revision(&self) -> Revision {
        self.work_product.revision
    }
}

pub type FalconDetectionScope = CrowdStrikeDetectionScope;

fn has_duplicate<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformClass {
    Macos,
    Windows,
    Linux,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedProcessFields {
    pub image_digest: Option<Digest>,
    pub command_line_digest: Option<Digest>,
    pub parent_image_digest: Option<Digest>,
}

impl RedactedProcessFields {
    pub fn from_sensitive(
        image: Option<&str>,
        command_line: Option<&str>,
        parent_image: Option<&str>,
    ) -> Self {
        Self {
            image_digest: image
                .filter(|value| !value.is_empty())
                .map(Digest::from_text),
            command_line_digest: command_line
                .filter(|value| !value.is_empty())
                .map(Digest::from_text),
            parent_image_digest: parent_image
                .filter(|value| !value.is_empty())
                .map(Digest::from_text),
        }
    }

    #[must_use]
    pub fn is_redacted(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedDeviceFields {
    pub device_id_digest: Digest,
    pub hostname_digest: Option<Digest>,
    pub group_id_digests: Vec<Digest>,
    pub platform: PlatformClass,
}

impl RedactedDeviceFields {
    pub fn from_sensitive(
        device_id: &str,
        hostname: Option<&str>,
        group_ids: &[&str],
        platform: PlatformClass,
    ) -> Result<Self, ModelError> {
        validate_text(device_id, "device id", MAX_IDENTIFIER_BYTES)?;
        if group_ids.len() > MAX_GROUP_IDS {
            return Err(ModelError::BoundExceeded {
                field: "device groups",
            });
        }
        Ok(Self {
            device_id_digest: Digest::from_text(device_id),
            hostname_digest: hostname
                .filter(|value| !value.is_empty())
                .map(Digest::from_text),
            group_id_digests: group_ids
                .iter()
                .map(|value| Digest::from_text(value))
                .collect(),
            platform,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedTechniqueFields {
    pub tactic_digest: Digest,
    pub technique_digest: Digest,
}

impl RedactedTechniqueFields {
    pub fn from_sensitive(tactic: &str, technique: &str) -> Result<Self, ModelError> {
        validate_text(tactic, "tactic", MAX_IDENTIFIER_BYTES)?;
        validate_text(technique, "technique", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            tactic_digest: Digest::from_text(tactic),
            technique_digest: Digest::from_text(technique),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionProjection {
    pub detection_id: DetectionId,
    pub alert_id: Option<AlertId>,
    pub severity: FalconSeverity,
    pub status: FalconDetectionStatus,
    pub device: RedactedDeviceFields,
    pub process: Option<RedactedProcessFields>,
    pub techniques: Vec<RedactedTechniqueFields>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub evidence_revision: Revision,
    pub detection_digest: Digest,
}

impl DetectionProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn from_sensitive(
        detection_id: impl Into<String>,
        alert_id: Option<String>,
        severity: FalconSeverity,
        status: FalconDetectionStatus,
        device: RedactedDeviceFields,
        process: Option<RedactedProcessFields>,
        techniques: Vec<RedactedTechniqueFields>,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        evidence_revision: u64,
    ) -> Result<Self, ModelError> {
        let value = Self {
            detection_id: DetectionId::parse(detection_id)?,
            alert_id: alert_id.map(AlertId::parse).transpose()?,
            severity,
            status,
            device,
            process,
            techniques,
            first_seen,
            last_seen,
            evidence_revision: Revision::new(evidence_revision)?,
            detection_digest: Digest::from_text("unsealed-crowdstrike-detection"),
        };
        value.validate_shape()?;
        let mut sealed = value;
        sealed.detection_digest = sealed.calculate_digest()?;
        Ok(sealed)
    }

    pub fn validate_shape(&self) -> Result<(), ModelError> {
        if self.first_seen > self.last_seen
            || self.evidence_revision.get() == 0
            || self.techniques.len() > MAX_TECHNIQUES_PER_DETECTION
        {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.detection_id,
            &self.alert_id,
            &self.severity,
            &self.status,
            &self.device,
            &self.process,
            &self.techniques,
            self.first_seen,
            self.last_seen,
            self.evidence_revision,
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.detection_digest != self.calculate_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "detection digest",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.detection_digest = digest;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionSummary {
    pub total: u64,
    pub severity_counts: BTreeMap<FalconSeverity, u64>,
    pub status_counts: BTreeMap<FalconDetectionStatus, u64>,
    pub summary_digest: Digest,
}

impl DetectionSummary {
    pub fn from_detections(detections: &[DetectionProjection]) -> Result<Self, ModelError> {
        let mut severity_counts = BTreeMap::new();
        let mut status_counts = BTreeMap::new();
        for detection in detections {
            *severity_counts
                .entry(detection.severity.clone())
                .or_insert(0) += 1;
            *status_counts.entry(detection.status.clone()).or_insert(0) += 1;
        }
        let mut value = Self {
            total: detections.len() as u64,
            severity_counts,
            status_counts,
            summary_digest: Digest::from_text("unsealed-crowdstrike-summary"),
        };
        value.summary_digest = value.calculate_digest()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(&self.total, &self.severity_counts, &self.status_counts))
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.summary_digest != self.calculate_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "summary digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum FalconOperation {
    QueryDetects,
    GetDetectSummaries,
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
    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitReceipt {
    pub limit_per_minute: u32,
    pub remaining: Option<u32>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl RateLimitReceipt {
    pub fn new(
        limit_per_minute: u32,
        remaining: Option<u32>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, ModelError> {
        let value = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute > 10_000
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || self.throttled != self.retry_after_seconds.is_some_and(|value| value > 0)
        {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryReceipt {
    pub operation: FalconOperation,
    pub attempts: u8,
    pub retries: u8,
    pub max_retries: u8,
    pub exhausted: bool,
}

impl RetryReceipt {
    pub fn new(
        operation: FalconOperation,
        attempts: u8,
        max_retries: u8,
        exhausted: bool,
    ) -> Result<Self, ModelError> {
        if attempts == 0 || max_retries > MAX_RETRIES || attempts - 1 > max_retries {
            return Err(ModelError::InvalidResponse);
        }
        Ok(Self {
            operation,
            attempts,
            retries: attempts - 1,
            max_retries,
            exhausted,
        })
    }

    #[must_use]
    pub fn first_attempt(operation: FalconOperation, max_retries: u8) -> Self {
        Self {
            operation,
            attempts: 1,
            retries: 0,
            max_retries,
            exhausted: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureReceipt {
    pub operation: FalconOperation,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retry: RetryReceipt,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
}

impl FailureReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.rate_limit.validate()?;
        self.retry
            .operation
            .eq(&self.operation)
            .then_some(())
            .ok_or(ModelError::InvalidResponse)?;
        if self.error_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "failure error digest",
            });
        }
        Ok(())
    }
}

pub type FalconFailureReceipt = FailureReceipt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadReceipt {
    pub operation: FalconOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub retry: RetryReceipt,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
}

impl ReadReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.rate_limit.validate()?;
        if self.request_digest.as_str().len() != 64 || self.response_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "read receipt digest",
            });
        }
        if self.retry.operation != self.operation {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionQueryResult {
    pub offset: u32,
    pub page_size: u16,
    pub next_offset: Option<u32>,
    pub complete: bool,
    pub detections: Vec<DetectionProjection>,
    pub receipt: ReadReceipt,
    pub page_digest: Digest,
}

impl DetectionQueryResult {
    pub fn new(
        offset: u32,
        page_size: u16,
        next_offset: Option<u32>,
        detections: Vec<DetectionProjection>,
        receipt: ReadReceipt,
    ) -> Result<Self, ModelError> {
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || offset > MAX_OFFSET
            || detections.len() > usize::from(page_size)
            || next_offset.is_some_and(|next| next <= offset || next > MAX_OFFSET)
        {
            return Err(ModelError::InvalidResponse);
        }
        receipt.validate()?;
        for detection in &detections {
            detection.validate_integrity()?;
        }
        let complete = next_offset.is_none();
        let page_digest = digest_serializable(&(
            offset,
            page_size,
            next_offset,
            complete,
            &detections,
            &receipt.response_digest,
        ))?;
        Ok(Self {
            offset,
            page_size,
            next_offset,
            complete,
            detections,
            receipt,
            page_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.offset,
            self.page_size,
            self.next_offset,
            self.detections.clone(),
            self.receipt.clone(),
        )?;
        if rebuilt.page_digest != self.page_digest {
            return Err(ModelError::InvalidDigest {
                field: "detection page digest",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.page_digest = digest;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionSummaryResult {
    pub offset: u32,
    pub page_size: u16,
    pub summary: DetectionSummary,
    pub receipt: ReadReceipt,
    pub summary_result_digest: Digest,
}

impl DetectionSummaryResult {
    pub fn new(
        offset: u32,
        page_size: u16,
        summary: DetectionSummary,
        receipt: ReadReceipt,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || offset > MAX_OFFSET {
            return Err(ModelError::InvalidResponse);
        }
        summary.validate_integrity()?;
        receipt.validate()?;
        let summary_result_digest =
            digest_serializable(&(offset, page_size, &summary, &receipt.response_digest))?;
        Ok(Self {
            offset,
            page_size,
            summary,
            receipt,
            summary_result_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.offset,
            self.page_size,
            self.summary.clone(),
            self.receipt.clone(),
        )?;
        if rebuilt.summary_result_digest != self.summary_result_digest {
            return Err(ModelError::InvalidDigest {
                field: "summary result digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionEvidenceState {
    Present,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Stale,
    Revoked,
}

impl DetectionEvidenceState {
    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Present)
    }

    #[must_use]
    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Present | Self::Empty)
    }
}

pub type CrowdStrikeDetectionEvidenceState = DetectionEvidenceState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeDetectionEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: Revision,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub evidence_revision: Revision,
    pub state: DetectionEvidenceState,
    pub provenance: TransportProvenance,
    pub query_pages: Vec<DetectionQueryResult>,
    pub summary: Option<DetectionSummaryResult>,
    pub failure: Option<FailureReceipt>,
    pub detections: Vec<DetectionProjection>,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl CrowdStrikeDetectionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_version: impl Into<String>,
        contract_digest: Digest,
        provider_id: impl Into<String>,
        provider_revision: Revision,
        permission_digest: Digest,
        scope_digest: Digest,
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
        evidence_revision: Revision,
        state: DetectionEvidenceState,
        provenance: TransportProvenance,
        query_pages: Vec<DetectionQueryResult>,
        summary: Option<DetectionSummaryResult>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new_with_failure(
            contract_version,
            contract_digest,
            provider_id,
            provider_revision,
            permission_digest,
            scope_digest,
            project_revision,
            mission_revision,
            work_product_revision,
            evidence_revision,
            state,
            provenance,
            query_pages,
            summary,
            observed_at,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_failure(
        contract_version: impl Into<String>,
        contract_digest: Digest,
        provider_id: impl Into<String>,
        provider_revision: Revision,
        permission_digest: Digest,
        scope_digest: Digest,
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
        evidence_revision: Revision,
        state: DetectionEvidenceState,
        provenance: TransportProvenance,
        query_pages: Vec<DetectionQueryResult>,
        summary: Option<DetectionSummaryResult>,
        observed_at: DateTime<Utc>,
        failure: Option<FailureReceipt>,
    ) -> Result<Self, ModelError> {
        if query_pages.len() > usize::from(MAX_PAGES) {
            return Err(ModelError::BoundExceeded {
                field: "query pages",
            });
        }
        let mut detections = Vec::new();
        let mut seen = BTreeSet::new();
        for page in &query_pages {
            page.validate_integrity()?;
            for detection in &page.detections {
                detection.validate_integrity()?;
                if !seen.insert(detection.detection_id.clone()) {
                    return Err(ModelError::Duplicate {
                        field: "detection id across pages",
                    });
                }
                detections.push(detection.clone());
            }
        }
        if detections.len() > MAX_TOTAL_DETECTIONS {
            return Err(ModelError::BoundExceeded {
                field: "total detections",
            });
        }
        if let Some(summary) = &summary {
            summary.validate_integrity()?;
        }
        if let Some(failure) = &failure {
            failure.validate()?;
        }
        let response_digest = digest_serializable(&(
            query_pages
                .iter()
                .map(|page| &page.page_digest)
                .collect::<Vec<_>>(),
            summary.as_ref().map(|value| &value.summary_result_digest),
            detections
                .iter()
                .map(|value| &value.detection_digest)
                .collect::<Vec<_>>(),
            failure.as_ref().map(|value| &value.error_digest),
        ))?;
        let mut value = Self {
            contract_version: contract_version.into(),
            contract_digest,
            provider_id: provider_id.into(),
            provider_revision,
            permission_digest,
            scope_digest,
            project_revision,
            mission_revision,
            work_product_revision,
            evidence_revision,
            state,
            provenance,
            query_pages,
            summary,
            failure,
            detections,
            response_digest,
            evidence_digest: Digest::from_text("unsealed-crowdstrike-evidence"),
            observed_at,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            kernel_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        value.evidence_digest = value.calculate_evidence_digest()?;
        value.validate_integrity()?;
        Ok(value)
    }

    fn calculate_evidence_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&serde_json::json!({
            "contractVersion": &self.contract_version,
            "contractDigest": &self.contract_digest,
            "providerId": &self.provider_id,
            "providerRevision": self.provider_revision,
            "permissionDigest": &self.permission_digest,
            "scopeDigest": &self.scope_digest,
            "projectRevision": self.project_revision,
            "missionRevision": self.mission_revision,
            "workProductRevision": self.work_product_revision,
            "evidenceRevision": self.evidence_revision,
            "state": self.state,
            "provenance": self.provenance,
            "responseDigest": &self.response_digest,
            "failure": &self.failure,
            "observedAt": self.observed_at,
            "reviewOnly": self.review_only,
            "connected": self.connected,
            "native": self.native,
            "firstParty": self.first_party,
            "durableProviderReceipt": self.durable_provider_receipt,
            "kernelAuthority": self.kernel_authority,
            "outcomeAdopted": self.outcome_adopted,
            "workProductAdopted": self.work_product_adopted,
        }))
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.kernel_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provider_revision.get() == 0
            || self.evidence_revision.get() == 0
            || self.query_pages.len() > usize::from(MAX_PAGES)
        {
            return Err(ModelError::InvalidResponse);
        }
        if self.state == DetectionEvidenceState::Present && self.detections.is_empty() {
            return Err(ModelError::InvalidResponse);
        }
        if self.state == DetectionEvidenceState::Empty && !self.detections.is_empty() {
            return Err(ModelError::InvalidResponse);
        }
        if self.state == DetectionEvidenceState::Partial
            && self.query_pages.last().is_some_and(|page| page.complete)
        {
            return Err(ModelError::InvalidResponse);
        }
        for detection in &self.detections {
            detection.validate_integrity()?;
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        let rebuilt_response = digest_serializable(&(
            self.query_pages
                .iter()
                .map(|page| &page.page_digest)
                .collect::<Vec<_>>(),
            self.summary
                .as_ref()
                .map(|value| &value.summary_result_digest),
            self.detections
                .iter()
                .map(|value| &value.detection_digest)
                .collect::<Vec<_>>(),
            self.failure.as_ref().map(|value| &value.error_digest),
        ))?;
        if rebuilt_response != self.response_digest
            || self.calculate_evidence_digest()? != self.evidence_digest
        {
            return Err(ModelError::InvalidDigest {
                field: "evidence digest",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn is_non_adoptable(&self) -> bool {
        self.state.is_non_adoptable()
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        self.state.review_eligible() && self.validate_integrity().is_ok()
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }
}

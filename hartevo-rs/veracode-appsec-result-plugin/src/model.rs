//! Typed bounded scope, redacted Veracode projections, and local receipts.
//!
//! Constructors that accept provider-shaped strings immediately reduce
//! sensitive names, categories, source locations, and package coordinates to
//! SHA-256 digests. The raw values are not retained in any projection,
//! receipt, registration, proposal, or evidence value.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_FINDING_IDS: usize = 256;
pub const MAX_APPLICATIONS: usize = 64;
pub const MAX_BUILDS: usize = 256;
pub const MAX_SCANS: usize = 256;
pub const MAX_FINDINGS: usize = 1_024;
pub const MAX_POLICIES: usize = 64;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RETRIES: u8 = 3;
pub const MAX_TOTAL_RECORDS: usize = 2_048;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

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

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

bounded_identifier!(ApplicationId, "application id");
bounded_identifier!(BuildId, "build id");
bounded_identifier!(ScanId, "scan id");
bounded_identifier!(FindingId, "finding id");
bounded_identifier!(PolicyId, "policy id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");

pub type ApplicationGuid = ApplicationId;
pub type VeracodeApplicationId = ApplicationId;
pub type VeracodeBuildId = BuildId;
pub type VeracodeScanId = ScanId;
pub type VeracodeFindingId = FindingId;
pub type VeracodePolicyId = PolicyId;

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
pub enum VeracodeRegion {
    Commercial,
    Europe,
    Federal,
}

impl VeracodeRegion {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "commercial" | "api.veracode.com" | "us" => Ok(Self::Commercial),
            "europe" | "eu" | "api.veracode.eu" => Ok(Self::Europe),
            "federal" | "fed" | "api.veracode.us" => Ok(Self::Federal),
            _ => Err(ModelError::InvalidScope("Veracode region")),
        }
    }

    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::Commercial => "api.veracode.com",
            Self::Europe => "api.veracode.eu",
            Self::Federal => "api.veracode.us",
        }
    }
}

/// An opaque host-owned Veracode API credential reference.
///
/// The raw handle is hashed at construction and is never serialized, exposed
/// through an accessor, or included in a `Debug` representation. Only the
/// reference digest, region binding, and permission binding survive.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    region: VeracodeRegion,
    permission_digest: Digest,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        region: VeracodeRegion,
    ) -> Result<Self, ModelError> {
        let reference = opaque_reference.as_ref();
        validate_text(
            reference,
            "opaque Veracode API credential reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        Ok(Self {
            reference_digest: Digest::from_text(reference),
            region,
            permission_digest: Digest::from_text(crate::VERACODE_RESULTS_READ_PERMISSION),
        })
    }

    pub fn for_results_read(
        opaque_reference: impl AsRef<str>,
        region: VeracodeRegion,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_reference, region)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub const fn region(&self) -> VeracodeRegion {
        self.region
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest != Digest::from_text(crate::VERACODE_RESULTS_READ_PERMISSION) {
            return Err(ModelError::InvalidScope(
                "SecretReference permission binding",
            ));
        }
        if !self.reference_digest.is_valid() {
            return Err(ModelError::InvalidDigest {
                field: "secret reference digest",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("region", &self.region)
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

pub type VeracodeApiSecretReference = SecretReference;
pub type VeracodeCredentialReference = SecretReference;

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
        let mut permissions = permissions
            .into_iter()
            .map(Into::into)
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "results.read" | "results:read" | "results_read" => {
                    crate::VERACODE_RESULTS_READ_PERMISSION.to_owned()
                }
                _ => value,
            })
            .collect::<Vec<_>>();
        permissions.sort();
        permissions.dedup();
        let value = Self { permissions };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn results_read() -> Self {
        Self {
            permissions: vec![crate::VERACODE_RESULTS_READ_PERMISSION.to_owned()],
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permissions != [crate::VERACODE_RESULTS_READ_PERMISSION.to_owned()] {
            return Err(ModelError::InvalidScope(
                "least-privilege Veracode Results READ permission",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("PermissionSnapshot is serializable")
    }
}

pub type VeracodePermissionSnapshot = PermissionSnapshot;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Static,
    Dynamic,
    Manual,
    Sca,
    Unknown,
}

impl ScanType {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "static" => Self::Static,
            "dynamic" => Self::Dynamic,
            "manual" | "manual_penetration_testing" => Self::Manual,
            "sca" | "software_composition_analysis" => Self::Sca,
            _ => Self::Unknown,
        }
    }
}

pub type VeracodeScanType = ScanType;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "0" | "informational" | "info" | "very_low" | "very low" => Self::Informational,
            "1" | "2" | "low" => Self::Low,
            "3" | "medium" | "moderate" => Self::Medium,
            "4" | "high" => Self::High,
            "5" | "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

pub type VeracodeSeverity = Severity;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Fixed,
    Mitigated,
    Accepted,
    Unknown,
}

impl FindingStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "open" | "new" | "unresolved" => Self::Open,
            "fixed" | "closed" | "resolved" => Self::Fixed,
            "mitigated" | "remediated" => Self::Mitigated,
            "accepted" | "dismissed" => Self::Accepted,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Fixed => "fixed",
            Self::Mitigated => "mitigated",
            Self::Accepted => "accepted",
            Self::Unknown => "unknown",
        }
    }
}

pub type VeracodeFindingStatus = FindingStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Violating,
    Passing,
    Unknown,
}

impl PolicyStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "violating" | "did_not_pass" | "did not pass" | "fail" | "failed" => Self::Violating,
            "passing" | "passed" | "did_pass" | "did pass" => Self::Passing,
            _ => Self::Unknown,
        }
    }
}

pub type VeracodePolicyStatus = PolicyStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildStatus {
    InProgress,
    Published,
    Failed,
    Unknown,
}

impl BuildStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "in_progress" | "in-progress" | "scanning" => Self::InProgress,
            "published" | "complete" | "completed" => Self::Published,
            "failed" | "error" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Running,
    Published,
    Failed,
    Unknown,
}

impl ScanStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "running" | "in_progress" | "scanning" => Self::Running,
            "published" | "complete" | "completed" => Self::Published,
            "failed" | "error" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessCriticality {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeScope {
    pub region: VeracodeRegion,
    pub application_id: ApplicationId,
    pub build_id: Option<BuildId>,
    pub scan_id: Option<ScanId>,
    pub finding_ids: Vec<FindingId>,
    pub policy_id: Option<PolicyId>,
    pub application_revision: Revision,
    pub build_revision: Option<Revision>,
    pub scan_revision: Option<Revision>,
    pub policy_revision: Option<Revision>,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub scope_revision: Revision,
}

impl VeracodeScope {
    pub fn new(
        application_id: impl Into<String>,
        region: VeracodeRegion,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let value = Self {
            region,
            application_id: ApplicationId::parse(application_id)?,
            build_id: None,
            scan_id: None,
            finding_ids: Vec::new(),
            policy_id: None,
            application_revision: Revision::new(1)?,
            build_revision: None,
            scan_revision: None,
            policy_revision: None,
            project,
            mission,
            work_product,
            scope_revision: Revision::new(scope_revision)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn for_application(
        application_id: impl Into<String>,
        region: VeracodeRegion,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            application_id,
            region,
            project,
            mission,
            work_product,
            scope_revision,
        )
    }

    pub fn with_build(
        mut self,
        build_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        self.build_id = Some(BuildId::parse(build_id)?);
        self.build_revision = Some(Revision::new(revision)?);
        self.validate()?;
        Ok(self)
    }

    pub fn with_scan(
        mut self,
        scan_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        self.scan_id = Some(ScanId::parse(scan_id)?);
        self.scan_revision = Some(Revision::new(revision)?);
        self.validate()?;
        Ok(self)
    }

    pub fn with_findings<I, S>(mut self, finding_ids: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.finding_ids = finding_ids
            .into_iter()
            .map(|id| FindingId::parse(id.into()))
            .collect::<Result<Vec<_>, _>>()?;
        self.validate()?;
        Ok(self)
    }

    pub fn with_policy(
        mut self,
        policy_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        self.policy_id = Some(PolicyId::parse(policy_id)?);
        self.policy_revision = Some(Revision::new(revision)?);
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.finding_ids.len() > MAX_FINDING_IDS {
            return Err(ModelError::BoundExceeded {
                field: "finding ids",
            });
        }
        if has_duplicate(&self.finding_ids) {
            return Err(ModelError::Duplicate {
                field: "finding ids",
            });
        }
        if self.application_revision.get() == 0
            || self.scope_revision.get() == 0
            || self.build_id.is_some() != self.build_revision.is_some()
            || self.scan_id.is_some() != self.scan_revision.is_some()
            || self.policy_id.is_some() != self.policy_revision.is_some()
        {
            return Err(ModelError::InvalidScope("resource revision fence"));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("VeracodeScope is serializable")
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

pub type VeracodeApplicationScope = VeracodeScope;
pub type ApplicationSecurityScope = VeracodeScope;

fn has_duplicate<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn optional_digest(value: Option<&str>) -> Option<Digest> {
    value
        .filter(|value| !value.is_empty())
        .map(Digest::from_text)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationProjection {
    pub application_id: ApplicationId,
    pub name_digest: Digest,
    pub business_criticality: BusinessCriticality,
    pub last_completed_scan: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub policy_id: Option<PolicyId>,
    pub policy_status: PolicyStatus,
    pub evidence_revision: Revision,
    pub application_digest: Digest,
}

impl ApplicationProjection {
    pub fn from_sensitive(
        application_id: impl Into<String>,
        name: &str,
        business_criticality: BusinessCriticality,
        last_completed_scan: Option<DateTime<Utc>>,
        modified_at: Option<DateTime<Utc>>,
        policy_id: Option<String>,
        policy_status: PolicyStatus,
        evidence_revision: u64,
    ) -> Result<Self, ModelError> {
        validate_text(name, "application name", MAX_IDENTIFIER_BYTES)?;
        let value = Self {
            application_id: ApplicationId::parse(application_id)?,
            name_digest: Digest::from_text(name),
            business_criticality,
            last_completed_scan,
            modified_at,
            policy_id: policy_id.map(PolicyId::parse).transpose()?,
            policy_status,
            evidence_revision: Revision::new(evidence_revision)?,
            application_digest: Digest::from_text("unsealed-veracode-application"),
        };
        value.seal()
    }

    fn seal(mut self) -> Result<Self, ModelError> {
        self.application_digest = digest_serializable(&(
            self.application_id.digest(),
            &self.name_digest,
            self.business_criticality,
            self.last_completed_scan,
            self.modified_at,
            self.policy_id.as_ref().map(PolicyId::digest),
            self.policy_status,
            self.evidence_revision,
        ))?;
        self.validate_integrity()?;
        Ok(self)
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if !self.name_digest.is_valid()
            || self.evidence_revision.get() == 0
            || self.application_digest
                != digest_serializable(&(
                    self.application_id.digest(),
                    &self.name_digest,
                    self.business_criticality,
                    self.last_completed_scan,
                    self.modified_at,
                    self.policy_id.as_ref().map(PolicyId::digest),
                    self.policy_status,
                    self.evidence_revision,
                ))?
        {
            return Err(ModelError::InvalidDigest {
                field: "application digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildProjection {
    pub build_id: BuildId,
    pub version_digest: Option<Digest>,
    pub status: BuildStatus,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub evidence_revision: Revision,
    pub build_digest: Digest,
}

impl BuildProjection {
    pub fn from_sensitive(
        build_id: impl Into<String>,
        version: Option<&str>,
        status: BuildStatus,
        created_at: Option<DateTime<Utc>>,
        modified_at: Option<DateTime<Utc>>,
        evidence_revision: u64,
    ) -> Result<Self, ModelError> {
        let value = Self {
            build_id: BuildId::parse(build_id)?,
            version_digest: optional_digest(version),
            status,
            created_at,
            modified_at,
            evidence_revision: Revision::new(evidence_revision)?,
            build_digest: Digest::from_text("unsealed-veracode-build"),
        };
        value.seal()
    }

    fn seal(mut self) -> Result<Self, ModelError> {
        self.build_digest = digest_serializable(&(
            self.build_id.digest(),
            &self.version_digest,
            self.status,
            self.created_at,
            self.modified_at,
            self.evidence_revision,
        ))?;
        self.validate_integrity()?;
        Ok(self)
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self
            .version_digest
            .as_ref()
            .is_some_and(|value| !value.is_valid())
            || self.evidence_revision.get() == 0
            || self.build_digest
                != digest_serializable(&(
                    self.build_id.digest(),
                    &self.version_digest,
                    self.status,
                    self.created_at,
                    self.modified_at,
                    self.evidence_revision,
                ))?
        {
            return Err(ModelError::InvalidDigest {
                field: "build digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanProjection {
    pub scan_id: ScanId,
    pub scan_type: ScanType,
    pub status: ScanStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub finding_count: u32,
    pub evidence_revision: Revision,
    pub scan_digest: Digest,
}

impl ScanProjection {
    pub fn from_values(
        scan_id: impl Into<String>,
        scan_type: ScanType,
        status: ScanStatus,
        started_at: Option<DateTime<Utc>>,
        completed_at: Option<DateTime<Utc>>,
        finding_count: u32,
        evidence_revision: u64,
    ) -> Result<Self, ModelError> {
        let value = Self {
            scan_id: ScanId::parse(scan_id)?,
            scan_type,
            status,
            started_at,
            completed_at,
            finding_count,
            evidence_revision: Revision::new(evidence_revision)?,
            scan_digest: Digest::from_text("unsealed-veracode-scan"),
        };
        value.seal()
    }

    fn seal(mut self) -> Result<Self, ModelError> {
        self.scan_digest = digest_serializable(&(
            self.scan_id.digest(),
            self.scan_type,
            self.status,
            self.started_at,
            self.completed_at,
            self.finding_count,
            self.evidence_revision,
        ))?;
        self.validate_integrity()?;
        Ok(self)
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.evidence_revision.get() == 0
            || self.scan_digest
                != digest_serializable(&(
                    self.scan_id.digest(),
                    self.scan_type,
                    self.status,
                    self.started_at,
                    self.completed_at,
                    self.finding_count,
                    self.evidence_revision,
                ))?
        {
            return Err(ModelError::InvalidDigest {
                field: "scan digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingProjection {
    pub finding_id: FindingId,
    pub severity: Severity,
    pub severity_digest: Digest,
    pub status: FindingStatus,
    pub status_digest: Digest,
    pub category_digest: Digest,
    pub scan_type: ScanType,
    pub violates_policy: bool,
    pub first_found_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub source_location_digest: Option<Digest>,
    pub package_coordinate_digest: Option<Digest>,
    pub count: u32,
    pub evidence_revision: Revision,
    pub finding_digest: Digest,
}

impl FindingProjection {
    pub fn from_sensitive(
        finding_id: impl Into<String>,
        severity: Severity,
        status: FindingStatus,
        category: &str,
        scan_type: ScanType,
        violates_policy: bool,
        first_found_at: Option<DateTime<Utc>>,
        last_seen_at: Option<DateTime<Utc>>,
        source_location: Option<&str>,
        package_coordinate: Option<&str>,
        count: u32,
        evidence_revision: u64,
    ) -> Result<Self, ModelError> {
        validate_text(category, "finding category", MAX_IDENTIFIER_BYTES)?;
        let value = Self {
            finding_id: FindingId::parse(finding_id)?,
            severity,
            severity_digest: Digest::from_text(severity.as_str()),
            status,
            status_digest: Digest::from_text(status.as_str()),
            category_digest: Digest::from_text(category),
            scan_type,
            violates_policy,
            first_found_at,
            last_seen_at,
            source_location_digest: optional_digest(source_location),
            package_coordinate_digest: optional_digest(package_coordinate),
            count,
            evidence_revision: Revision::new(evidence_revision)?,
            finding_digest: Digest::from_text("unsealed-veracode-finding"),
        };
        value.seal()
    }

    #[must_use]
    pub fn state(&self) -> FindingStatus {
        self.status
    }

    fn seal(mut self) -> Result<Self, ModelError> {
        self.finding_digest = digest_serializable(&(
            self.finding_id.digest(),
            self.severity,
            &self.severity_digest,
            self.status,
            &self.status_digest,
            &self.category_digest,
            self.scan_type,
            self.violates_policy,
            self.first_found_at,
            self.last_seen_at,
            &self.source_location_digest,
            &self.package_coordinate_digest,
            self.count,
            self.evidence_revision,
        ))?;
        self.validate_integrity()?;
        Ok(self)
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if !self.severity_digest.is_valid()
            || !self.status_digest.is_valid()
            || !self.category_digest.is_valid()
            || self
                .source_location_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid())
            || self
                .package_coordinate_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid())
            || self.evidence_revision.get() == 0
            || self.finding_digest
                != digest_serializable(&(
                    self.finding_id.digest(),
                    self.severity,
                    &self.severity_digest,
                    self.status,
                    &self.status_digest,
                    &self.category_digest,
                    self.scan_type,
                    self.violates_policy,
                    self.first_found_at,
                    self.last_seen_at,
                    &self.source_location_digest,
                    &self.package_coordinate_digest,
                    self.count,
                    self.evidence_revision,
                ))?
        {
            return Err(ModelError::InvalidDigest {
                field: "finding digest",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.finding_digest = digest;
        self
    }
}

pub type FindingEvidence = FindingProjection;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyProjection {
    pub policy_id: PolicyId,
    pub name_digest: Digest,
    pub status: PolicyStatus,
    pub maximum_severity: Option<Severity>,
    pub violating_finding_count: u32,
    pub policy_digest: Digest,
    pub evidence_revision: Revision,
}

impl PolicyProjection {
    pub fn from_sensitive(
        policy_id: impl Into<String>,
        name: &str,
        status: PolicyStatus,
        maximum_severity: Option<Severity>,
        violating_finding_count: u32,
        evidence_revision: u64,
    ) -> Result<Self, ModelError> {
        validate_text(name, "policy name", MAX_IDENTIFIER_BYTES)?;
        let value = Self {
            policy_id: PolicyId::parse(policy_id)?,
            name_digest: Digest::from_text(name),
            status,
            maximum_severity,
            violating_finding_count,
            policy_digest: Digest::from_text("unsealed-veracode-policy"),
            evidence_revision: Revision::new(evidence_revision)?,
        };
        value.seal()
    }

    fn seal(mut self) -> Result<Self, ModelError> {
        self.policy_digest = digest_serializable(&(
            self.policy_id.digest(),
            &self.name_digest,
            self.status,
            self.maximum_severity,
            self.violating_finding_count,
            self.evidence_revision,
        ))?;
        self.validate_integrity()?;
        Ok(self)
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if !self.name_digest.is_valid()
            || self.evidence_revision.get() == 0
            || self.policy_digest
                != digest_serializable(&(
                    self.policy_id.digest(),
                    &self.name_digest,
                    self.status,
                    self.maximum_severity,
                    self.violating_finding_count,
                    self.evidence_revision,
                ))?
        {
            return Err(ModelError::InvalidDigest {
                field: "policy digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum VeracodeOperation {
    GetApplications,
    GetBuilds,
    GetScans,
    GetFindings,
    GetPolicies,
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
                .remaining
                .is_some_and(|remaining| remaining > self.limit_per_minute)
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
    pub operation: VeracodeOperation,
    pub attempts: u8,
    pub retries: u8,
    pub max_retries: u8,
    pub exhausted: bool,
}

impl RetryReceipt {
    pub fn new(
        operation: VeracodeOperation,
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
    pub fn first_attempt(operation: VeracodeOperation, max_retries: u8) -> Self {
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
pub struct ReadReceipt {
    pub operation: VeracodeOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub next_cursor_digest: Option<Digest>,
    pub retry: RetryReceipt,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
}

impl ReadReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.rate_limit.validate()?;
        if !self.request_digest.is_valid()
            || !self.response_digest.is_valid()
            || self
                .cursor_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid())
            || self
                .next_cursor_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid())
            || self.retry.operation != self.operation
        {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureReceipt {
    pub operation: VeracodeOperation,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retry: RetryReceipt,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
}

impl FailureReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.rate_limit.validate()?;
        if !self.error_digest.is_valid() || self.retry.operation != self.operation {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }
}

pub type VeracodeFailureReceipt = FailureReceipt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeReadPage {
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
    pub next_cursor_digest: Option<Digest>,
    pub applications: Vec<ApplicationProjection>,
    pub builds: Vec<BuildProjection>,
    pub scans: Vec<ScanProjection>,
    pub findings: Vec<FindingProjection>,
    pub policies: Vec<PolicyProjection>,
    pub receipt: ReadReceipt,
    pub page_digest: Digest,
}

impl VeracodeReadPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        page_number: u16,
        cursor_digest: Option<Digest>,
        next_cursor_digest: Option<Digest>,
        applications: Vec<ApplicationProjection>,
        builds: Vec<BuildProjection>,
        scans: Vec<ScanProjection>,
        findings: Vec<FindingProjection>,
        policies: Vec<PolicyProjection>,
        receipt: ReadReceipt,
    ) -> Result<Self, ModelError> {
        if page_number == 0
            || page_number > MAX_PAGES
            || applications.len() > MAX_APPLICATIONS
            || builds.len() > MAX_BUILDS
            || scans.len() > MAX_SCANS
            || findings.len() > MAX_FINDINGS
            || policies.len() > MAX_POLICIES
            || cursor_digest != receipt.cursor_digest
            || next_cursor_digest != receipt.next_cursor_digest
        {
            return Err(ModelError::InvalidResponse);
        }
        receipt.validate()?;
        for value in &applications {
            value.validate_integrity()?;
        }
        for value in &builds {
            value.validate_integrity()?;
        }
        for value in &scans {
            value.validate_integrity()?;
        }
        for value in &findings {
            value.validate_integrity()?;
        }
        for value in &policies {
            value.validate_integrity()?;
        }
        let page_digest = digest_serializable(&(
            page_number,
            &cursor_digest,
            &next_cursor_digest,
            applications
                .iter()
                .map(|value| &value.application_digest)
                .collect::<Vec<_>>(),
            builds
                .iter()
                .map(|value| &value.build_digest)
                .collect::<Vec<_>>(),
            scans
                .iter()
                .map(|value| &value.scan_digest)
                .collect::<Vec<_>>(),
            findings
                .iter()
                .map(|value| &value.finding_digest)
                .collect::<Vec<_>>(),
            policies
                .iter()
                .map(|value| &value.policy_digest)
                .collect::<Vec<_>>(),
            &receipt,
        ))?;
        Ok(Self {
            page_number,
            cursor_digest,
            next_cursor_digest,
            applications,
            builds,
            scans,
            findings,
            policies,
            receipt,
            page_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.page_number,
            self.cursor_digest.clone(),
            self.next_cursor_digest.clone(),
            self.applications.clone(),
            self.builds.clone(),
            self.scans.clone(),
            self.findings.clone(),
            self.policies.clone(),
            self.receipt.clone(),
        )?;
        if rebuilt.page_digest != self.page_digest {
            return Err(ModelError::InvalidDigest {
                field: "Veracode page digest",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.applications.len()
            + self.builds.len()
            + self.scans.len()
            + self.findings.len()
            + self.policies.len()
    }

    #[must_use]
    pub fn complete(&self) -> bool {
        self.next_cursor_digest.is_none()
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.page_digest = digest;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeRead {
    pub pages: Vec<VeracodeReadPage>,
    pub complete: bool,
    pub observed_at: DateTime<Utc>,
}

impl VeracodeRead {
    pub fn new(
        pages: Vec<VeracodeReadPage>,
        complete: bool,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if pages.is_empty() || pages.len() > usize::from(MAX_PAGES) {
            return Err(ModelError::InvalidResponse);
        }
        for page in &pages {
            page.validate_integrity()?;
        }
        if complete != pages.last().is_some_and(VeracodeReadPage::complete) {
            return Err(ModelError::InvalidResponse);
        }
        Ok(Self {
            pages,
            complete,
            observed_at,
        })
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.pages.iter().map(VeracodeReadPage::record_count).sum()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.pages
            .first()
            .map_or(TransportProvenance::BlockedEnv, |page| {
                page.receipt.provenance
            })
    }

    #[must_use]
    pub fn applications(&self) -> Vec<ApplicationProjection> {
        self.pages
            .iter()
            .flat_map(|page| page.applications.iter().cloned())
            .collect()
    }

    #[must_use]
    pub fn builds(&self) -> Vec<BuildProjection> {
        self.pages
            .iter()
            .flat_map(|page| page.builds.iter().cloned())
            .collect()
    }

    #[must_use]
    pub fn scans(&self) -> Vec<ScanProjection> {
        self.pages
            .iter()
            .flat_map(|page| page.scans.iter().cloned())
            .collect()
    }

    #[must_use]
    pub fn findings(&self) -> Vec<FindingProjection> {
        self.pages
            .iter()
            .flat_map(|page| page.findings.iter().cloned())
            .collect()
    }

    #[must_use]
    pub fn policies(&self) -> Vec<PolicyProjection> {
        self.pages
            .iter()
            .flat_map(|page| page.policies.iter().cloned())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Present,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    #[serde(rename = "tamper", alias = "tampered")]
    Tampered,
    Stale,
    Revoked,
}

impl EvidenceState {
    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Present | Self::Empty)
    }

    #[must_use]
    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Present | Self::Empty)
    }
}

pub type VeracodeEvidenceState = EvidenceState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionCounts {
    pub applications: u32,
    pub builds: u32,
    pub scans: u32,
    pub findings: u32,
    pub policies: u32,
    pub finding_statuses: BTreeMap<FindingStatus, u32>,
    pub policy_statuses: BTreeMap<PolicyStatus, u32>,
}

impl ProjectionCounts {
    pub fn from_pages(pages: &[VeracodeReadPage]) -> Self {
        let mut finding_statuses = BTreeMap::new();
        let mut policy_statuses = BTreeMap::new();
        let mut value = Self {
            applications: 0,
            builds: 0,
            scans: 0,
            findings: 0,
            policies: 0,
            finding_statuses: BTreeMap::new(),
            policy_statuses: BTreeMap::new(),
        };
        for page in pages {
            value.applications += page.applications.len() as u32;
            value.builds += page.builds.len() as u32;
            value.scans += page.scans.len() as u32;
            value.findings += page.findings.len() as u32;
            value.policies += page.policies.len() as u32;
            for finding in &page.findings {
                *finding_statuses.entry(finding.status).or_insert(0) += 1;
            }
            for policy in &page.policies {
                *policy_statuses.entry(policy.status).or_insert(0) += 1;
            }
        }
        value.finding_statuses = finding_statuses;
        value.policy_statuses = policy_statuses;
        value
    }
}

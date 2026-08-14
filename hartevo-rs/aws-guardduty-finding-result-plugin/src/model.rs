//! Typed, bounded GuardDuty scope, query, projection, and evidence models.
//!
//! No type in this module represents a raw GuardDuty payload. Resource
//! references are accepted only to compute a digest and are never stored.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::provider::RequestReceipt;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_CRITERION_VALUES: usize = 32;
pub const MAX_DETECTORS: usize = 8;
pub const MAX_LIST_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_FINDINGS: usize = 200;
pub const MAX_GET_BATCH: usize = 50;
pub const MAX_STATISTICS_BUCKETS: usize = 16;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains control characters or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not an allowlisted value")]
    InvalidValue { field: &'static str },
    #[error("{field} exceeds its configured bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains a duplicate value")]
    Duplicate { field: &'static str },
    #[error("{field} does not match its digest")]
    MismatchedDigest { field: &'static str },
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidValue { field });
    }
    Ok(())
}

macro_rules! bounded_text {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_text!(AwsAccountId, "AWS account id");
bounded_text!(AwsRegion, "AWS region");
bounded_text!(DetectorId, "GuardDuty detector id");
bounded_text!(FindingId, "GuardDuty finding id");
bounded_text!(FindingType, "GuardDuty finding type");
bounded_text!(MissionId, "mission id");
bounded_text!(ProjectId, "project id");
bounded_text!(WorkProductId, "work product id");

pub type AccountId = AwsAccountId;
pub type Region = AwsRegion;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
        Self(hex::encode(Sha256::digest(value)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields<T: AsRef<str>>(namespace: &str, fields: &[T]) -> Self {
        let mut canonical = format!("{namespace}\0");
        for field in fields {
            let value = field.as_ref();
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\0');
        }
        Self::from_text(canonical)
    }

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

pub fn sha256_digest(value: &[u8]) -> Digest {
    Digest::from_bytes(value)
}

pub fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("bounded values serialize"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidValue { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES {
            return if value.is_empty() {
                Err(ModelError::Empty { field: "timestamp" })
            } else {
                Err(ModelError::TooLong { field: "timestamp" })
            };
        }
        if value.trim() != value || value.chars().any(char::is_control) {
            return Err(ModelError::InvalidText { field: "timestamp" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.0.is_empty() || self.0.len() > MAX_TIMESTAMP_BYTES {
            return Err(if self.0.is_empty() {
                ModelError::Empty { field: "timestamp" }
            } else {
                ModelError::TooLong { field: "timestamp" }
            });
        }
        if self.0.trim() != self.0 || self.0.chars().any(char::is_control) {
            return Err(ModelError::InvalidText { field: "timestamp" });
        }
        Ok(())
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Timestamp").field(&self.0).finish()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
    ProviderUnknown,
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Ec2Instance,
    S3Bucket,
    S3Object,
    AccessKey,
    Container,
    EcsCluster,
    EksCluster,
    KubernetesPod,
    RdsDbInstance,
    LambdaFunction,
    Other,
    Unknown,
}

impl ResourceKind {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl FindingSeverity {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
            Self::Unknown => 0,
        }
    }

    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
    Unknown,
}

impl ConfidenceBand {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Unknown => 0,
        }
    }

    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Active,
    Archived,
    Stale,
    Unknown,
}

impl FindingStatus {
    pub const fn is_non_adoptable(self) -> bool {
        matches!(self, Self::Archived | Self::Stale | Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionabilityLabel {
    Actionable,
    ReviewRequired,
    Informational,
    NotActionable,
    Unknown,
}

impl ActionabilityLabel {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsGuardDutyFinding {
    pub finding_id: FindingId,
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub confidence: ConfidenceBand,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub resource_kind: ResourceKind,
    pub status: FindingStatus,
    pub actionability_labels: Vec<ActionabilityLabel>,
    pub resource_digest: Digest,
    pub finding_digest: Digest,
}

impl AwsGuardDutyFinding {
    /// Construct a projection from a provider resource reference. The
    /// reference is immediately digested and never retained.
    pub fn new(
        finding_id: FindingId,
        finding_type: FindingType,
        severity: FindingSeverity,
        confidence: ConfidenceBand,
        created_at: Timestamp,
        updated_at: Timestamp,
        resource_kind: ResourceKind,
        status: FindingStatus,
        mut actionability_labels: Vec<ActionabilityLabel>,
        resource_reference: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        if actionability_labels.len() > 8 {
            return Err(ModelError::BoundExceeded {
                field: "actionability labels",
            });
        }
        actionability_labels.sort_unstable();
        for pair in actionability_labels.windows(2) {
            if pair[0] == pair[1] {
                return Err(ModelError::Duplicate {
                    field: "actionability labels",
                });
            }
        }
        if resource_reference.as_ref().is_empty() {
            return Err(ModelError::InvalidValue {
                field: "resource reference",
            });
        }
        let resource_digest = Digest::from_text(resource_reference);
        let mut finding = Self {
            finding_id,
            finding_type,
            severity,
            confidence,
            created_at,
            updated_at,
            resource_kind,
            status,
            actionability_labels,
            resource_digest,
            finding_digest: Digest::from_text("pending-finding-digest"),
        };
        finding.finding_digest = finding.compute_digest();
        Ok(finding)
    }

    /// Construct a projection when only a previously computed resource digest
    /// is available. No resource identifier crosses this API.
    pub fn from_resource_digest(
        finding_id: FindingId,
        finding_type: FindingType,
        severity: FindingSeverity,
        confidence: ConfidenceBand,
        created_at: Timestamp,
        updated_at: Timestamp,
        resource_kind: ResourceKind,
        status: FindingStatus,
        mut actionability_labels: Vec<ActionabilityLabel>,
        resource_digest: Digest,
    ) -> Result<Self, ModelError> {
        if actionability_labels.len() > 8 {
            return Err(ModelError::BoundExceeded {
                field: "actionability labels",
            });
        }
        actionability_labels.sort_unstable();
        for pair in actionability_labels.windows(2) {
            if pair[0] == pair[1] {
                return Err(ModelError::Duplicate {
                    field: "actionability labels",
                });
            }
        }
        let mut finding = Self {
            finding_id,
            finding_type,
            severity,
            confidence,
            created_at,
            updated_at,
            resource_kind,
            status,
            actionability_labels,
            resource_digest,
            finding_digest: Digest::from_text("pending-finding-digest"),
        };
        finding.finding_digest = finding.compute_digest();
        Ok(finding)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-guardduty-finding/v1",
            &[
                self.finding_id.as_str().to_owned(),
                self.finding_type.as_str().to_owned(),
                serde_json::to_string(&self.severity).expect("severity serializes"),
                serde_json::to_string(&self.confidence).expect("confidence serializes"),
                self.created_at.as_str().to_owned(),
                self.updated_at.as_str().to_owned(),
                serde_json::to_string(&self.resource_kind).expect("resource kind serializes"),
                serde_json::to_string(&self.status).expect("status serializes"),
                serde_json::to_string(&self.actionability_labels)
                    .expect("actionability labels serialize"),
                self.resource_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(
            self.finding_id.as_str(),
            "GuardDuty finding id",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            self.finding_type.as_str(),
            "GuardDuty finding type",
            MAX_IDENTIFIER_BYTES,
        )?;
        self.created_at.validate()?;
        self.updated_at.validate()?;
        if self.created_at > self.updated_at {
            return Err(ModelError::InvalidValue {
                field: "finding timestamp order",
            });
        }
        if self.actionability_labels.len() > 8 {
            return Err(ModelError::BoundExceeded {
                field: "actionability labels",
            });
        }
        for pair in self.actionability_labels.windows(2) {
            if pair[0] >= pair[1] {
                return Err(if pair[0] == pair[1] {
                    ModelError::Duplicate {
                        field: "actionability labels",
                    }
                } else {
                    ModelError::InvalidValue {
                        field: "actionability label order",
                    }
                });
            }
        }
        Digest::parse(self.resource_digest.as_str().to_owned()).map_err(|_| {
            ModelError::InvalidDigest {
                field: "resource digest",
            }
        })?;
        if self.finding_digest != self.compute_digest() {
            return Err(ModelError::MismatchedDigest {
                field: "finding digest",
            });
        }
        Ok(())
    }

    pub fn non_adoptable(&self) -> bool {
        self.status.is_non_adoptable()
            || !self.severity.is_known()
            || !self.confidence.is_known()
            || !self.resource_kind.is_known()
            || self
                .actionability_labels
                .iter()
                .any(|label| !label.is_known())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsGuardDutyFindingScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub detector_id: DetectorId,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
}

impl AwsGuardDutyFindingScope {
    pub fn new(
        account_id: impl Into<String>,
        region: impl Into<String>,
        detector_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        project_id: impl Into<String>,
        project_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            account_id: AwsAccountId::new(account_id)?,
            region: AwsRegion::new(region)?,
            detector_id: DetectorId::new(detector_id)?,
            mission_id: MissionId::new(mission_id)?,
            mission_revision: Revision::new(mission_revision)?,
            project_id: ProjectId::new(project_id)?,
            project_revision: Revision::new(project_revision)?,
            work_product_id: WorkProductId::new(work_product_id)?,
            work_product_revision: Revision::new(work_product_revision)?,
            permission_digest: crate::permission_digest(),
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-guardduty-scope/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.detector_id.as_str().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.mission_revision.get().to_string(),
                self.project_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.work_product_id.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest != crate::permission_digest() {
            return Err(ModelError::MismatchedDigest {
                field: "scope permission digest",
            });
        }
        if self.account_id.as_str().len() != 12
            || !self
                .account_id
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            return Err(ModelError::InvalidValue {
                field: "AWS account id",
            });
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }
}

/// The only credential boundary exposed by the plugin. The opaque handle is
/// consumed to derive a digest and is never retained, displayed, or serialized.
#[derive(Clone)]
pub struct SecretReference {
    state: Arc<SecretState>,
}

#[derive(Debug)]
struct SecretState {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: AtomicBool,
}

pub type SigV4SecretReference = SecretReference;

impl SecretReference {
    pub fn new(
        opaque_handle: impl AsRef<str>,
        scope: &AwsGuardDutyFindingScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_handle = opaque_handle.as_ref();
        validate_text(opaque_handle, "opaque SigV4 handle", 512)?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "hartevo.aws-guardduty-secret-reference/v1",
            &[
                opaque_handle.to_owned(),
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            state: Arc::new(SecretState {
                reference_digest,
                scope_digest,
                credential_revision,
                revoked: AtomicBool::new(false),
            }),
        })
    }

    pub fn sigv4(
        opaque_handle: impl AsRef<str>,
        scope: &AwsGuardDutyFindingScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, scope, credential_revision)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.state.reference_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.reference_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.state.scope_digest
    }

    pub fn credential_revision(&self) -> Revision {
        self.state.credential_revision
    }

    pub fn revoke(&self) {
        self.state.revoked.store(true, Ordering::Release);
    }

    pub fn is_revoked(&self) -> bool {
        self.state.revoked.load(Ordering::Acquire)
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.state.reference_digest)
            .field("scope_digest", &self.state.scope_digest)
            .field("credential_revision", &self.state.credential_revision)
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

impl fmt::Display for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretReference(<redacted>)")
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest() == other.reference_digest()
            && self.scope_digest() == other.scope_digest()
            && self.credential_revision() == other.credential_revision()
    }
}

impl Eq for SecretReference {}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "SecretReference is opaque and non-serializing",
        ))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingCriteria {
    pub finding_ids: Vec<FindingId>,
    pub finding_types: Vec<FindingType>,
    pub severities: Vec<FindingSeverity>,
    pub confidence_bands: Vec<ConfidenceBand>,
    pub resource_kinds: Vec<ResourceKind>,
    pub statuses: Vec<FindingStatus>,
    pub created_after: Option<Timestamp>,
    pub created_before: Option<Timestamp>,
    pub updated_after: Option<Timestamp>,
    pub updated_before: Option<Timestamp>,
}

pub type ListFindingsCriteria = FindingCriteria;

fn validate_unique<T: Ord>(values: &[T], field: &'static str) -> Result<(), ModelError> {
    if values.len() > MAX_CRITERION_VALUES {
        return Err(ModelError::BoundExceeded { field });
    }
    let mut sorted = values.iter().collect::<Vec<_>>();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ModelError::Duplicate { field });
    }
    Ok(())
}

impl FindingCriteria {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_unique(&self.finding_ids, "finding id criteria")?;
        validate_unique(&self.finding_types, "finding type criteria")?;
        validate_unique(&self.severities, "severity criteria")?;
        validate_unique(&self.confidence_bands, "confidence criteria")?;
        validate_unique(&self.resource_kinds, "resource kind criteria")?;
        validate_unique(&self.statuses, "status criteria")?;
        if self.severities.iter().any(|value| !value.is_known())
            || self.confidence_bands.iter().any(|value| !value.is_known())
            || self.resource_kinds.iter().any(|value| !value.is_known())
            || self
                .statuses
                .iter()
                .any(|value| matches!(value, FindingStatus::Unknown))
        {
            return Err(ModelError::InvalidValue {
                field: "allowlisted finding criteria",
            });
        }
        if let (Some(after), Some(before)) = (&self.created_after, &self.created_before)
            && after > before
        {
            return Err(ModelError::InvalidValue {
                field: "created time range",
            });
        }
        if let (Some(after), Some(before)) = (&self.updated_after, &self.updated_before)
            && after > before
        {
            return Err(ModelError::InvalidValue {
                field: "updated time range",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        let mut finding_ids = self
            .finding_ids
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        finding_ids.sort_unstable();
        let mut finding_types = self
            .finding_types
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        finding_types.sort_unstable();
        let mut severities = self
            .severities
            .iter()
            .map(|value| serde_json::to_string(value).expect("severity serializes"))
            .collect::<Vec<_>>();
        severities.sort_unstable();
        let mut confidence_bands = self
            .confidence_bands
            .iter()
            .map(|value| serde_json::to_string(value).expect("confidence serializes"))
            .collect::<Vec<_>>();
        confidence_bands.sort_unstable();
        let mut resource_kinds = self
            .resource_kinds
            .iter()
            .map(|value| serde_json::to_string(value).expect("resource kind serializes"))
            .collect::<Vec<_>>();
        resource_kinds.sort_unstable();
        let mut statuses = self
            .statuses
            .iter()
            .map(|value| serde_json::to_string(value).expect("status serializes"))
            .collect::<Vec<_>>();
        statuses.sort_unstable();
        Digest::from_fields(
            "hartevo.aws-guardduty-criteria/v1",
            &[
                finding_ids.join(","),
                finding_types.join(","),
                severities.join(","),
                confidence_bands.join(","),
                resource_kinds.join(","),
                statuses.join(","),
                self.created_after
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.created_before
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.updated_after
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.updated_before
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }

    pub fn matches(&self, finding: &AwsGuardDutyFinding) -> bool {
        (self.finding_ids.is_empty() || self.finding_ids.contains(&finding.finding_id))
            && (self.finding_types.is_empty() || self.finding_types.contains(&finding.finding_type))
            && (self.severities.is_empty() || self.severities.contains(&finding.severity))
            && (self.confidence_bands.is_empty()
                || self.confidence_bands.contains(&finding.confidence))
            && (self.resource_kinds.is_empty()
                || self.resource_kinds.contains(&finding.resource_kind))
            && (self.statuses.is_empty() || self.statuses.contains(&finding.status))
            && self
                .created_after
                .as_ref()
                .is_none_or(|value| finding.created_at >= *value)
            && self
                .created_before
                .as_ref()
                .is_none_or(|value| finding.created_at <= *value)
            && self
                .updated_after
                .as_ref()
                .is_none_or(|value| finding.updated_at >= *value)
            && self
                .updated_before
                .as_ref()
                .is_none_or(|value| finding.updated_at <= *value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardDutyFindingQuery {
    pub criteria: FindingCriteria,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_findings: usize,
    pub include_statistics: bool,
    pub max_statistics_buckets: usize,
}

pub type AwsGuardDutyQuery = GuardDutyFindingQuery;
pub type AwsGuardDutyFindingQuery = GuardDutyFindingQuery;

impl Default for GuardDutyFindingQuery {
    fn default() -> Self {
        Self {
            criteria: FindingCriteria::default(),
            page_size: MAX_LIST_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_findings: MAX_FINDINGS,
            include_statistics: false,
            max_statistics_buckets: MAX_STATISTICS_BUCKETS,
        }
    }
}

impl GuardDutyFindingQuery {
    pub fn new(criteria: FindingCriteria) -> Result<Self, ModelError> {
        let query = Self {
            criteria,
            ..Self::default()
        };
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.criteria.validate()?;
        if self.page_size == 0 || self.page_size > MAX_LIST_PAGE_SIZE {
            return Err(ModelError::BoundExceeded {
                field: "ListFindings page size",
            });
        }
        if self.max_pages == 0 || self.max_pages > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "ListFindings pages",
            });
        }
        if self.max_findings == 0 || self.max_findings > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded { field: "findings" });
        }
        if self.max_statistics_buckets == 0 || self.max_statistics_buckets > MAX_STATISTICS_BUCKETS
        {
            return Err(ModelError::BoundExceeded {
                field: "statistics buckets",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-guardduty-query/v1",
            &[
                self.criteria.digest().as_str().to_owned(),
                self.page_size.to_string(),
                self.max_pages.to_string(),
                self.max_findings.to_string(),
                self.include_statistics.to_string(),
                self.max_statistics_buckets.to_string(),
            ],
        )
    }

    #[must_use]
    pub fn with_statistics(mut self, enabled: bool) -> Self {
        self.include_statistics = enabled;
        self
    }

    #[must_use]
    pub fn with_page_size(mut self, page_size: u16) -> Self {
        self.page_size = page_size;
        self
    }

    #[must_use]
    pub fn with_max_pages(mut self, max_pages: u16) -> Self {
        self.max_pages = max_pages;
        self
    }

    #[must_use]
    pub fn with_max_findings(mut self, max_findings: usize) -> Self {
        self.max_findings = max_findings;
        self
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    pub token_digest: Digest,
    pub scope_digest: Digest,
    pub detector_id: DetectorId,
    pub query_digest: Digest,
    pub page_number: u16,
}

impl OpaquePageToken {
    pub fn from_provider(
        opaque_token: impl AsRef<str>,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let opaque_token = opaque_token.as_ref();
        validate_text(opaque_token, "opaque pagination token", 1024)?;
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "pagination page number",
            });
        }
        Ok(Self {
            token_digest: Digest::from_fields(
                "hartevo.aws-guardduty-page-token/v1",
                &[opaque_token.to_owned()],
            ),
            scope_digest: scope.digest(),
            detector_id: scope.detector_id.clone(),
            query_digest: query.digest(),
            page_number,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn validate_for(
        &self,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
        expected_page: u16,
    ) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.detector_id != scope.detector_id
            || self.query_digest != query.digest()
            || self.page_number != expected_page
        {
            return Err(ModelError::MismatchedDigest {
                field: "opaque pagination binding",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("detector_id", &self.detector_id)
            .field("query_digest", &self.query_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdAllowlist {
    pub finding_ids: Vec<FindingId>,
    pub source_list_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub allowlist_digest: Digest,
}

impl FindingIdAllowlist {
    pub fn new(
        mut finding_ids: Vec<FindingId>,
        source_list_digest: Digest,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
    ) -> Result<Self, ModelError> {
        if finding_ids.is_empty() || finding_ids.len() > MAX_GET_BATCH {
            return Err(ModelError::BoundExceeded {
                field: "GetFindings id batch",
            });
        }
        finding_ids.sort_unstable();
        let mut seen = BTreeSet::new();
        for finding_id in &finding_ids {
            if !seen.insert(finding_id) {
                return Err(ModelError::Duplicate {
                    field: "GetFindings id batch",
                });
            }
        }
        let allowlist_digest = Digest::from_fields(
            "hartevo.aws-guardduty-allowlist/v1",
            &[
                source_list_digest.as_str().to_owned(),
                scope.digest().as_str().to_owned(),
                query.digest().as_str().to_owned(),
                finding_ids
                    .iter()
                    .map(FindingId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        Ok(Self {
            finding_ids,
            source_list_digest,
            scope_digest: scope.digest(),
            query_digest: query.digest(),
            allowlist_digest,
        })
    }

    pub fn contains(&self, finding_id: &FindingId) -> bool {
        self.finding_ids.contains(finding_id)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-guardduty-allowlist/v1",
            &[
                self.source_list_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.finding_ids
                    .iter()
                    .map(FindingId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.finding_ids.is_empty() || self.finding_ids.len() > MAX_GET_BATCH {
            return Err(ModelError::BoundExceeded {
                field: "GetFindings id batch",
            });
        }
        let mut seen = BTreeSet::new();
        for finding_id in &self.finding_ids {
            if !seen.insert(finding_id) {
                return Err(ModelError::Duplicate {
                    field: "GetFindings id batch",
                });
            }
        }
        if self.finding_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ModelError::InvalidValue {
                field: "GetFindings id order",
            });
        }
        Digest::parse(self.source_list_digest.as_str().to_owned()).map_err(|_| {
            ModelError::InvalidDigest {
                field: "source list digest",
            }
        })?;
        Digest::parse(self.scope_digest.as_str().to_owned()).map_err(|_| {
            ModelError::InvalidDigest {
                field: "allowlist scope digest",
            }
        })?;
        Digest::parse(self.query_digest.as_str().to_owned()).map_err(|_| {
            ModelError::InvalidDigest {
                field: "allowlist query digest",
            }
        })?;
        if self.allowlist_digest != self.compute_digest() {
            return Err(ModelError::MismatchedDigest {
                field: "allowlist digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectorDiscovery {
    pub detector_ids: Vec<DetectorId>,
    pub detector_digest: Digest,
    pub complete: bool,
    pub response_digest: Digest,
}

impl DetectorDiscovery {
    pub fn new(
        mut detector_ids: Vec<DetectorId>,
        complete: bool,
        response_digest: Digest,
    ) -> Result<Self, ModelError> {
        if detector_ids.len() > MAX_DETECTORS {
            return Err(ModelError::BoundExceeded { field: "detectors" });
        }
        detector_ids.sort_unstable();
        for pair in detector_ids.windows(2) {
            if pair[0] == pair[1] {
                return Err(ModelError::Duplicate { field: "detectors" });
            }
        }
        let detector_digest = Digest::from_fields(
            "hartevo.aws-guardduty-detectors/v1",
            &[detector_ids
                .iter()
                .map(DetectorId::as_str)
                .collect::<Vec<_>>()
                .join(",")],
        );
        Ok(Self {
            detector_ids,
            detector_digest,
            complete,
            response_digest,
        })
    }

    pub fn contains(&self, detector_id: &DetectorId) -> bool {
        self.detector_ids.contains(detector_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingStatistics {
    pub total: u32,
    pub severity_counts: BTreeMap<FindingSeverity, u32>,
    pub resource_kind_counts: BTreeMap<ResourceKind, u32>,
    pub statistics_digest: Digest,
}

impl FindingStatistics {
    pub fn new(
        total: u32,
        severity_counts: BTreeMap<FindingSeverity, u32>,
        resource_kind_counts: BTreeMap<ResourceKind, u32>,
    ) -> Result<Self, ModelError> {
        if severity_counts.len() + resource_kind_counts.len() > MAX_STATISTICS_BUCKETS {
            return Err(ModelError::BoundExceeded {
                field: "statistics buckets",
            });
        }
        if severity_counts.keys().any(|key| !key.is_known())
            || resource_kind_counts.keys().any(|key| !key.is_known())
        {
            return Err(ModelError::InvalidValue {
                field: "statistics buckets",
            });
        }
        let mut value = Self {
            total,
            severity_counts,
            resource_kind_counts,
            statistics_digest: Digest::from_text("pending-statistics-digest"),
        };
        value.statistics_digest = value.compute_digest();
        Ok(value)
    }

    pub fn compute_digest(&self) -> Digest {
        digest_serialized(&(
            self.total,
            &self.severity_counts,
            &self.resource_kind_counts,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.severity_counts.len() + self.resource_kind_counts.len() > MAX_STATISTICS_BUCKETS
            || self.severity_counts.keys().any(|key| !key.is_known())
            || self.resource_kind_counts.keys().any(|key| !key.is_known())
        {
            return Err(ModelError::InvalidValue {
                field: "statistics buckets",
            });
        }
        if self.statistics_digest != self.compute_digest() {
            return Err(ModelError::MismatchedDigest {
                field: "statistics digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    Stale,
    Archived,
    Unknown,
    AccessLoss,
    Revoked,
    Tampered,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    Timeout,
}

impl EvidenceStatus {
    pub const fn non_adoptable(self) -> bool {
        !matches!(self, Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    ProviderMarkedPartial,
    PageLimitReached,
    FindingLimitReached,
    MissingBatchItems,
    StatisticsUnavailable,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_descriptions_retained: bool,
    pub access_key_user_ip_geo_details_retained: bool,
    pub threat_intel_payload_retained: bool,
    pub unbounded_resources_retained: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_requests_retained: bool,
    pub raw_responses_retained: bool,
    pub raw_secrets_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsGuardDutyFindingEvidence {
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub detector_discovery: DetectorDiscovery,
    pub findings: Vec<AwsGuardDutyFinding>,
    pub statistics: Option<FindingStatistics>,
    pub receipts: Vec<RequestReceipt>,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub criteria_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub redaction: RedactionSummary,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    status: &'a EvidenceStatus,
    partial_reason: &'a Option<PartialReason>,
    provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    detector_discovery: &'a DetectorDiscovery,
    findings: &'a [AwsGuardDutyFinding],
    statistics: &'a Option<FindingStatistics>,
    receipts: &'a [RequestReceipt],
    plugin_version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    criteria_digest: &'a Digest,
    registration_digest: &'a Digest,
    redaction: &'a RedactionSummary,
}

impl AwsGuardDutyFindingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        provenance: TransportProvenance,
        detector_discovery: DetectorDiscovery,
        findings: Vec<AwsGuardDutyFinding>,
        statistics: Option<FindingStatistics>,
        receipts: Vec<RequestReceipt>,
        provider_digest: Digest,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        if findings.len() > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded { field: "findings" });
        }
        for finding in &findings {
            finding.validate()?;
        }
        if let Some(statistics) = &statistics {
            statistics.validate()?;
        }
        let mut evidence = Self {
            status,
            partial_reason,
            provenance,
            connected: provenance.connected(),
            native: provenance.native(),
            first_party: provenance.first_party(),
            detector_discovery,
            findings,
            statistics,
            receipts,
            plugin_version_digest: crate::version_digest(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            api_digest: crate::api_digest(),
            permission_digest: crate::permission_digest(),
            scope_digest: scope.digest(),
            query_digest: query.digest(),
            criteria_digest: query.criteria.digest(),
            registration_digest,
            evidence_digest: Digest::from_text("pending-evidence-digest"),
            redaction: RedactionSummary::default(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Digest {
        digest_serialized(&EvidenceDigestInput {
            status: &self.status,
            partial_reason: &self.partial_reason,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            detector_discovery: &self.detector_discovery,
            findings: &self.findings,
            statistics: &self.statistics,
            receipts: &self.receipts,
            plugin_version_digest: &self.plugin_version_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            query_digest: &self.query_digest,
            criteria_digest: &self.criteria_digest,
            registration_digest: &self.registration_digest,
            redaction: &self.redaction,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
    ) -> Result<(), ModelError> {
        if self.connected || self.native || self.first_party || self.provenance.connected() {
            return Err(ModelError::InvalidValue {
                field: "non-native provenance",
            });
        }
        if self.plugin_version_digest != crate::version_digest()
            || self.contract_digest != crate::contract_digest()
            || self.api_digest != crate::api_digest()
            || self.permission_digest != crate::permission_digest()
            || self.scope_digest != scope.digest()
            || self.query_digest != query.digest()
            || self.criteria_digest != query.criteria.digest()
        {
            return Err(ModelError::MismatchedDigest {
                field: "evidence binding",
            });
        }
        if self.findings.len() > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded { field: "findings" });
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        if let Some(statistics) = &self.statistics {
            statistics.validate()?;
        }
        let expected_detector_digest = DetectorDiscovery::new(
            self.detector_discovery.detector_ids.clone(),
            self.detector_discovery.complete,
            self.detector_discovery.response_digest.clone(),
        )?
        .detector_digest;
        if self.detector_discovery.detector_digest != expected_detector_digest {
            return Err(ModelError::MismatchedDigest {
                field: "detector digest",
            });
        }
        if self.redaction != RedactionSummary::default() {
            return Err(ModelError::InvalidValue {
                field: "redaction boundary",
            });
        }
        if self.evidence_digest != self.compute_digest() {
            return Err(ModelError::MismatchedDigest {
                field: "evidence digest",
            });
        }
        Ok(())
    }

    pub const fn review_eligible(&self) -> bool {
        matches!(self.status, EvidenceStatus::Complete)
    }

    /// Layer 1 never adopts evidence into Hartevo Outcome or Work Product.
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A compact digest-only helper for redacted provider errors.
pub fn failure_digest(operation: &str, code: &str) -> Digest {
    Digest::from_fields(
        "hartevo.aws-guardduty-provider-failure/v1",
        &[operation.to_owned(), code.to_owned()],
    )
}

/// Build deterministic counts from normalized findings only.
pub fn statistics_from_findings(
    findings: &[AwsGuardDutyFinding],
) -> Result<FindingStatistics, ModelError> {
    let mut severity_counts = BTreeMap::new();
    let mut resource_kind_counts = BTreeMap::new();
    for finding in findings {
        *severity_counts.entry(finding.severity).or_insert(0) += 1;
        *resource_kind_counts
            .entry(finding.resource_kind)
            .or_insert(0) += 1;
    }
    FindingStatistics::new(findings.len() as u32, severity_counts, resource_kind_counts)
}

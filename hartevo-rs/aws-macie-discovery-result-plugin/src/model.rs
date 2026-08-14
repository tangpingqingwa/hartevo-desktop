//! Typed, bounded Macie discovery evidence.
//!
//! This module intentionally contains only a normalized projection. It has no
//! raw AWS request/response types, object keys, object paths, descriptions,
//! sample data, actor identity, credential bytes, or arbitrary provider JSON.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_MACIE_CONTRACT_VERSION, AWS_MACIE_GET_FINDINGS_PERMISSION,
    AWS_MACIE_LIST_FINDINGS_PERMISSION, AWS_MACIE_PLUGIN_VERSION_TEXT,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_TIMESTAMP_LENGTH: usize = 64;
pub const MAX_FILTER_VALUES: usize = 16;
pub const MAX_CLASSIFICATION_TYPES: usize = 32;
pub const MAX_LIST_PAGE_SIZE: u16 = 50;
pub const MAX_FINDING_IDS_PER_GET: usize = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_FINDINGS: usize = 200;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains a raw object key or path")]
    RawObjectPath { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    InvalidValue { field: &'static str },
    #[error("{field} exceeds the configured bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains a duplicate value")]
    Duplicate { field: &'static str },
}

fn validate_text(value: &str, field: &'static str, max_length: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max_length {
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

macro_rules! bounded_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_LENGTH)?;
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

bounded_id!(AwsAccountId, "AWS account id");
bounded_id!(AwsRegion, "AWS region");
bounded_id!(FindingId, "Macie finding id");
bounded_id!(ProjectId, "Hartevo project id");
bounded_id!(MissionId, "Mission id");
bounded_id!(ConsentId, "Consent id");
bounded_id!(PolicyId, "Macie policy id");

/// A resource identifier is accepted only as an owner-resource reference. A
/// slash, URI path marker, fragment, or query marker is rejected so an S3
/// object key/path cannot cross the Layer-1 boundary.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "resource id", MAX_IDENTIFIER_LENGTH)?;
        if value.contains('/')
            || value.contains('?')
            || value.contains('#')
            || value.contains("s3://")
        {
            return Err(ModelError::RawObjectPath {
                field: "resource id",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ResourceId").field(&self.0).finish()
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ResourceId {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

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
        Self(format!("{:x}", Sha256::digest(value)))
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

fn validate_digest(value: &Digest, field: &'static str) -> Result<(), ModelError> {
    if Digest::parse(value.as_str()).ok().as_ref() == Some(value) {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

fn validate_serialized_size<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<(), ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::InvalidValue {
        field: "bounded serialization",
    })?;
    if bytes.len() > crate::AWS_MACIE_MAX_RESPONSE_BYTES {
        return Err(ModelError::BoundExceeded { field });
    }
    Ok(())
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

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ModelError::InvalidValue {
            field: "canonical digest input",
        })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    ProviderUnknown,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacieResourceType {
    S3Bucket,
    S3Object,
    Other,
    Unknown,
}

impl MacieResourceType {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacieFindingCategory {
    Classification,
    Policy,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacieSeverity {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationStatus {
    Complete,
    Partial,
    Skipped,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacieFindingStatus {
    New,
    Open,
    Updated,
    Archived,
    Suppressed,
    Expired,
    ProviderUnknown,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "timestamp", MAX_TIMESTAMP_LENGTH)?;
        if !value.contains('T') || !(value.ends_with('Z') || value.contains('+')) {
            return Err(ModelError::InvalidValue { field: "timestamp" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieResourceScope {
    pub resource_id: ResourceId,
    pub resource_type: MacieResourceType,
    pub owner_account_id: AwsAccountId,
    pub owner_region: AwsRegion,
}

impl MacieResourceScope {
    pub fn new(
        resource_id: ResourceId,
        resource_type: MacieResourceType,
        owner_account_id: AwsAccountId,
        owner_region: AwsRegion,
    ) -> Self {
        Self {
            resource_id,
            resource_type,
            owner_account_id,
            owner_region,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("MacieResourceScope is serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassificationScope {
    pub category: MacieFindingCategory,
    pub type_digests: Vec<Digest>,
    pub max_count: u64,
}

impl ClassificationScope {
    pub fn new(category: MacieFindingCategory) -> Self {
        Self {
            category,
            type_digests: Vec::new(),
            max_count: 1_000_000,
        }
    }

    pub fn with_type_digest(mut self, digest: Digest) -> Result<Self, ModelError> {
        validate_digest(&digest, "classification type digest")?;
        if !self.type_digests.contains(&digest) {
            if self.type_digests.len() >= MAX_CLASSIFICATION_TYPES {
                return Err(ModelError::BoundExceeded {
                    field: "classification type digests",
                });
            }
            self.type_digests.push(digest);
        }
        Ok(self)
    }

    #[must_use]
    pub fn with_max_count(mut self, max_count: u64) -> Self {
        self.max_count = max_count;
        self
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("ClassificationScope is serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyScope {
    pub policy_id: PolicyId,
    pub policy_revision: Revision,
}

impl PolicyScope {
    pub fn new(policy_id: PolicyId, policy_revision: Revision) -> Self {
        Self {
            policy_id,
            policy_revision,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("PolicyScope is serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub consent_id: ConsentId,
    pub consent_revision: Revision,
}

impl ConsentScope {
    pub fn new(consent_id: ConsentId, consent_revision: Revision) -> Self {
        Self {
            consent_id,
            consent_revision,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("ConsentScope is serializable")
    }
}

/// Exact account/region/finding/resource/classification/policy/Mission/
/// Project/Consent scope. The secret reference is bound to this digest but is
/// deliberately not part of this serializable value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieDiscoveryScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub finding_id: FindingId,
    pub resource: MacieResourceScope,
    pub classification: ClassificationScope,
    pub policy: PolicyScope,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub consent: ConsentScope,
    pub permission_digest: Digest,
}

impl MacieDiscoveryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        finding_id: FindingId,
        resource: MacieResourceScope,
        classification: ClassificationScope,
        policy: PolicyScope,
        project_id: ProjectId,
        mission_id: MissionId,
        consent: ConsentScope,
    ) -> Self {
        Self {
            account_id,
            region,
            finding_id,
            resource,
            classification,
            policy,
            project_id,
            project_revision: Revision(1),
            mission_id,
            mission_revision: Revision(1),
            consent,
            permission_digest: permission_digest(),
        }
    }

    #[must_use]
    pub fn with_revisions(
        mut self,
        project_revision: Revision,
        mission_revision: Revision,
        consent_revision: Revision,
    ) -> Self {
        self.project_revision = project_revision;
        self.mission_revision = mission_revision;
        self.consent.consent_revision = consent_revision;
        self
    }

    #[must_use]
    pub fn with_permission_digest(mut self, permission_digest: Digest) -> Self {
        self.permission_digest = permission_digest;
        self
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        AwsAccountId::new(self.account_id.as_str().to_owned())?;
        AwsRegion::new(self.region.as_str().to_owned())?;
        FindingId::new(self.finding_id.as_str().to_owned())?;
        ResourceId::new(self.resource.resource_id.as_str().to_owned())?;
        AwsAccountId::new(self.resource.owner_account_id.as_str().to_owned())?;
        AwsRegion::new(self.resource.owner_region.as_str().to_owned())?;
        ProjectId::new(self.project_id.as_str().to_owned())?;
        MissionId::new(self.mission_id.as_str().to_owned())?;
        ConsentId::new(self.consent.consent_id.as_str().to_owned())?;
        PolicyId::new(self.policy.policy_id.as_str().to_owned())?;
        Revision::new(self.project_revision.get())?;
        Revision::new(self.mission_revision.get())?;
        Revision::new(self.consent.consent_revision.get())?;
        Revision::new(self.policy.policy_revision.get())?;
        if self.resource.owner_account_id != self.account_id
            || self.resource.owner_region != self.region
        {
            return Err(ModelError::InvalidValue {
                field: "resource account and region binding",
            });
        }
        if self.classification.type_digests.len() > MAX_CLASSIFICATION_TYPES
            || self.classification.max_count > 1_000_000
            || self
                .classification
                .type_digests
                .iter()
                .any(|digest| validate_digest(digest, "classification type digest").is_err())
        {
            return Err(ModelError::BoundExceeded {
                field: "Macie discovery scope",
            });
        }
        if self.permission_digest != permission_digest() {
            return Err(ModelError::InvalidValue {
                field: "permission digest",
            });
        }
        validate_digest(&self.permission_digest, "permission digest")?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("MacieDiscoveryScope is serializable")
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn resource_digest(&self) -> Digest {
        self.resource.digest()
    }

    pub fn classification_digest(&self) -> Digest {
        self.classification.digest()
    }

    pub fn policy_digest(&self) -> Digest {
        self.policy.digest()
    }
}

pub fn permission_digest() -> Digest {
    Digest::from_fields(
        "hartevo.aws-macie-permissions/v1",
        &[
            AWS_MACIE_LIST_FINDINGS_PERMISSION.to_owned(),
            AWS_MACIE_GET_FINDINGS_PERMISSION.to_owned(),
        ],
    )
}

/// Host-owned credential identity. The raw reference is private and this type
/// intentionally does not implement Serialize or Deserialize.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: Revision,
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &MacieDiscoveryScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "SigV4 secret reference",
            MAX_IDENTIFIER_LENGTH,
        )?;
        Ok(Self {
            reference_id,
            scope_digest: scope.digest(),
            credential_revision: Revision::new(credential_revision)?,
        })
    }

    pub fn from_scope_digest(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "SigV4 secret reference",
            MAX_IDENTIFIER_LENGTH,
        )?;
        Ok(Self {
            reference_id,
            scope_digest,
            credential_revision: Revision::new(credential_revision)?,
        })
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-macie-sigv4-secret-reference/v1",
            &[
                self.reference_id.clone(),
                self.scope_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn is_for_scope(&self, scope: &MacieDiscoveryScope) -> bool {
        self.scope_digest == scope.digest()
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SigV4SecretReference({})",
            self.reference_digest()
        )
    }
}

pub type SecretReference = SigV4SecretReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedFindingField {
    Description,
    Title,
    DetailedResultsLocation,
    JobReference,
    ObjectKey,
    ObjectPath,
    SampleData,
    SensitiveDataOccurrences,
    ActorIdentity,
    IpAddress,
    RawTags,
    RawProviderPayload,
    ProviderCredentialMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub redacted_fields: Vec<RedactedFindingField>,
    pub raw_pii_retained: bool,
    pub raw_object_keys_retained: bool,
    pub raw_object_paths_retained: bool,
    pub full_descriptions_retained: bool,
    pub raw_provider_payload_retained: bool,
    pub sample_data_retained: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            redacted_fields: vec![
                RedactedFindingField::Description,
                RedactedFindingField::Title,
                RedactedFindingField::DetailedResultsLocation,
                RedactedFindingField::JobReference,
                RedactedFindingField::ObjectKey,
                RedactedFindingField::ObjectPath,
                RedactedFindingField::SampleData,
                RedactedFindingField::SensitiveDataOccurrences,
                RedactedFindingField::ActorIdentity,
                RedactedFindingField::IpAddress,
                RedactedFindingField::RawTags,
                RedactedFindingField::RawProviderPayload,
                RedactedFindingField::ProviderCredentialMaterial,
            ],
            raw_pii_retained: false,
            raw_object_keys_retained: false,
            raw_object_paths_retained: false,
            full_descriptions_retained: false,
            raw_provider_payload_retained: false,
            sample_data_retained: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassificationTypeCount {
    pub type_digest: Digest,
    pub count: u64,
}

impl ClassificationTypeCount {
    pub fn new(type_digest: Digest, count: u64) -> Result<Self, ModelError> {
        if count > 1_000_000 {
            return Err(ModelError::BoundExceeded {
                field: "classification type count",
            });
        }
        Ok(Self { type_digest, count })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassificationMetadata {
    pub category: MacieFindingCategory,
    pub total_count: u64,
    pub type_counts: Vec<ClassificationTypeCount>,
    pub status: ClassificationStatus,
    pub additional_occurrences: bool,
    pub classification_digest: Digest,
}

impl ClassificationMetadata {
    pub fn new(
        category: MacieFindingCategory,
        total_count: u64,
        status: ClassificationStatus,
        additional_occurrences: bool,
    ) -> Result<Self, ModelError> {
        if total_count > 1_000_000 {
            return Err(ModelError::BoundExceeded {
                field: "classification count",
            });
        }
        let mut metadata = Self {
            category,
            total_count,
            type_counts: Vec::new(),
            status,
            additional_occurrences,
            classification_digest: Digest::from_text("pending-classification-digest"),
        };
        metadata.classification_digest = metadata.compute_digest()?;
        Ok(metadata)
    }

    pub fn with_type_count(
        mut self,
        type_count: ClassificationTypeCount,
    ) -> Result<Self, ModelError> {
        if self
            .type_counts
            .iter()
            .any(|existing| existing.type_digest == type_count.type_digest)
        {
            return Err(ModelError::Duplicate {
                field: "classification type digest",
            });
        }
        if self.type_counts.len() >= MAX_CLASSIFICATION_TYPES {
            return Err(ModelError::BoundExceeded {
                field: "classification type counts",
            });
        }
        self.type_counts.push(type_count);
        self.classification_digest = self.compute_digest()?;
        Ok(self)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.category,
            self.total_count,
            &self.type_counts,
            self.status,
            self.additional_occurrences,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.type_counts.len() > MAX_CLASSIFICATION_TYPES
            || self.type_counts.iter().any(|value| value.count > 1_000_000)
            || self.classification_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "classification digest",
            });
        }
        for type_count in &self.type_counts {
            validate_digest(&type_count.type_digest, "classification type digest")?;
        }
        validate_digest(&self.classification_digest, "classification digest")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMetadata {
    pub policy_kind: MacieFindingCategory,
    pub policy_revision: Revision,
    pub policy_action_digest: Option<Digest>,
    pub policy_first_seen: Option<Timestamp>,
    pub policy_last_seen: Option<Timestamp>,
    pub policy_digest: Digest,
}

impl PolicyMetadata {
    pub fn new(policy_scope: &PolicyScope, policy_kind: MacieFindingCategory) -> Self {
        let mut metadata = Self {
            policy_kind,
            policy_revision: policy_scope.policy_revision,
            policy_action_digest: None,
            policy_first_seen: None,
            policy_last_seen: None,
            policy_digest: Digest::from_text("pending-policy-digest"),
        };
        metadata.policy_digest = metadata.compute_digest(policy_scope);
        metadata
    }

    #[must_use]
    pub fn with_action_digest(mut self, action_digest: Digest, policy_scope: &PolicyScope) -> Self {
        self.policy_action_digest = Some(action_digest);
        self.policy_digest = self.compute_digest(policy_scope);
        self
    }

    #[must_use]
    pub fn with_seen_times(
        mut self,
        first_seen: Option<Timestamp>,
        last_seen: Option<Timestamp>,
        policy_scope: &PolicyScope,
    ) -> Self {
        self.policy_first_seen = first_seen;
        self.policy_last_seen = last_seen;
        self.policy_digest = self.compute_digest(policy_scope);
        self
    }

    fn compute_digest(&self, policy_scope: &PolicyScope) -> Digest {
        Digest::from_fields(
            "hartevo.aws-macie-policy-metadata/v1",
            &[
                policy_scope.digest().as_str().to_owned(),
                serde_json::to_string(&self.policy_kind).expect("policy kind serializes"),
                self.policy_revision.get().to_string(),
                self.policy_action_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.policy_first_seen
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.policy_last_seen
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self, policy_scope: &PolicyScope) -> Result<(), ModelError> {
        if self.policy_revision != policy_scope.policy_revision
            || self.policy_digest != self.compute_digest(policy_scope)
        {
            return Err(ModelError::InvalidDigest {
                field: "policy digest",
            });
        }
        self.validate_digest()
    }

    fn validate_digest(&self) -> Result<(), ModelError> {
        if let Some(action_digest) = &self.policy_action_digest {
            validate_digest(action_digest, "policy action digest")?;
        }
        if let Some(first_seen) = &self.policy_first_seen {
            Timestamp::new(first_seen.as_str().to_owned())?;
        }
        if let Some(last_seen) = &self.policy_last_seen {
            Timestamp::new(last_seen.as_str().to_owned())?;
        }
        validate_digest(&self.policy_digest, "policy digest")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieFinding {
    pub finding_id: FindingId,
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub severity: MacieSeverity,
    pub category: MacieFindingCategory,
    pub resource_type: MacieResourceType,
    pub resource_reference_digest: Digest,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub lifecycle: MacieFindingStatus,
    pub classification: ClassificationMetadata,
    pub policy: PolicyMetadata,
    pub redaction: RedactionSummary,
    pub finding_digest: Digest,
}

pub type MacieFindingProjection = MacieFinding;

impl MacieFinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &MacieDiscoveryScope,
        severity: MacieSeverity,
        lifecycle: MacieFindingStatus,
        classification: ClassificationMetadata,
        policy: PolicyMetadata,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self, ModelError> {
        classification.validate()?;
        policy.validate(&scope.policy)?;
        if classification.category != scope.classification.category
            && classification.category != MacieFindingCategory::Unknown
        {
            return Err(ModelError::InvalidValue {
                field: "finding classification scope",
            });
        }
        let mut finding = Self {
            finding_id: scope.finding_id.clone(),
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            severity,
            category: classification.category,
            resource_type: scope.resource.resource_type,
            resource_reference_digest: scope.resource.digest(),
            created_at,
            updated_at,
            lifecycle,
            classification,
            policy,
            redaction: RedactionSummary::default(),
            finding_digest: Digest::from_text("pending-finding-digest"),
        };
        finding.finding_digest = finding.compute_digest()?;
        Ok(finding)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.finding_id,
            &self.account_id,
            &self.region,
            self.severity,
            self.category,
            self.resource_type,
            &self.resource_reference_digest,
            &self.created_at,
            &self.updated_at,
            self.lifecycle,
            &self.classification,
            &self.policy,
            &self.redaction,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.redaction.raw_pii_retained
            || self.redaction.raw_object_keys_retained
            || self.redaction.raw_object_paths_retained
            || self.redaction.full_descriptions_retained
            || self.redaction.raw_provider_payload_retained
            || self.redaction.sample_data_retained
            || self.redaction != RedactionSummary::default()
        {
            return Err(ModelError::InvalidValue {
                field: "finding redaction",
            });
        }
        FindingId::new(self.finding_id.as_str().to_owned())?;
        AwsAccountId::new(self.account_id.as_str().to_owned())?;
        AwsRegion::new(self.region.as_str().to_owned())?;
        Timestamp::new(self.created_at.as_str().to_owned())?;
        Timestamp::new(self.updated_at.as_str().to_owned())?;
        validate_digest(&self.resource_reference_digest, "resource reference digest")?;
        self.classification.validate()?;
        self.policy.validate_digest()?;
        if self.finding_digest != self.compute_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "finding digest",
            });
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &MacieDiscoveryScope) -> bool {
        self.finding_id == scope.finding_id
            && self.account_id == scope.account_id
            && self.region == scope.region
            && self.resource_type == scope.resource.resource_type
            && self.resource_reference_digest == scope.resource.digest()
            && self.category == scope.classification.category
            && self.policy.policy_revision == scope.policy.policy_revision
    }

    pub fn classification_digest(&self) -> &Digest {
        &self.classification.classification_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy.policy_digest
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingFilter {
    severities: Vec<MacieSeverity>,
    statuses: Vec<MacieFindingStatus>,
    categories: Vec<MacieFindingCategory>,
    resource_types: Vec<MacieResourceType>,
}

impl FindingFilter {
    pub fn all() -> Self {
        Self::default()
    }

    pub fn with_severity(mut self, severity: MacieSeverity) -> Result<Self, ModelError> {
        add_unique(&mut self.severities, severity, "severity filters")?;
        Ok(self)
    }

    pub fn with_status(mut self, status: MacieFindingStatus) -> Result<Self, ModelError> {
        add_unique(&mut self.statuses, status, "status filters")?;
        Ok(self)
    }

    pub fn with_category(mut self, category: MacieFindingCategory) -> Result<Self, ModelError> {
        add_unique(&mut self.categories, category, "category filters")?;
        Ok(self)
    }

    pub fn with_resource_type(
        mut self,
        resource_type: MacieResourceType,
    ) -> Result<Self, ModelError> {
        add_unique(
            &mut self.resource_types,
            resource_type,
            "resource type filters",
        )?;
        Ok(self)
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("FindingFilter is serializable")
    }

    pub fn matches(&self, finding: &MacieFinding) -> bool {
        (self.severities.is_empty() || self.severities.contains(&finding.severity))
            && (self.statuses.is_empty() || self.statuses.contains(&finding.lifecycle))
            && (self.categories.is_empty() || self.categories.contains(&finding.category))
            && (self.resource_types.is_empty()
                || self.resource_types.contains(&finding.resource_type))
    }

    pub fn severities(&self) -> &[MacieSeverity] {
        &self.severities
    }

    pub fn statuses(&self) -> &[MacieFindingStatus] {
        &self.statuses
    }

    pub fn categories(&self) -> &[MacieFindingCategory] {
        &self.categories
    }

    pub fn resource_types(&self) -> &[MacieResourceType] {
        &self.resource_types
    }
}

fn add_unique<T: Eq>(values: &mut Vec<T>, value: T, field: &'static str) -> Result<(), ModelError> {
    if !values.contains(&value) {
        if values.len() >= MAX_FILTER_VALUES {
            return Err(ModelError::BoundExceeded { field });
        }
        values.push(value);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdAllowlist {
    ids: Vec<FindingId>,
}

impl FindingIdAllowlist {
    pub fn new(ids: Vec<FindingId>) -> Result<Self, ModelError> {
        if ids.len() > MAX_FINDING_IDS_PER_GET {
            return Err(ModelError::BoundExceeded {
                field: "finding id allowlist",
            });
        }
        for (index, id) in ids.iter().enumerate() {
            if ids[..index].contains(id) {
                return Err(ModelError::Duplicate {
                    field: "finding id allowlist",
                });
            }
        }
        Ok(Self { ids })
    }

    pub fn empty() -> Self {
        Self { ids: Vec::new() }
    }

    pub fn for_get(ids: Vec<FindingId>) -> Result<Self, ModelError> {
        let allowlist = Self::new(ids)?;
        if allowlist.ids.is_empty() {
            return Err(ModelError::Empty {
                field: "GetFindings allowlist",
            });
        }
        Ok(allowlist)
    }

    pub fn as_slice(&self) -> &[FindingId] {
        &self.ids
    }

    fn into_ids(self) -> Vec<FindingId> {
        self.ids
    }

    pub fn contains(&self, finding_id: &FindingId) -> bool {
        self.ids.contains(finding_id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("FindingIdAllowlist is serializable")
    }
}

pub type FindingAllowlist = FindingIdAllowlist;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OpaquePageToken {
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(provider_token: impl AsRef<str>) -> Result<Self, ModelError> {
        let provider_token = provider_token.as_ref();
        validate_text(provider_token, "provider page token", MAX_IDENTIFIER_LENGTH)?;
        Ok(Self {
            digest: Digest::from_text(provider_token),
        })
    }

    pub fn from_digest(digest: Digest) -> Self {
        Self { digest }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacieApiOperation {
    ListFindings,
    GetFindings,
}

impl fmt::Display for MacieApiOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListFindings => formatter.write_str("ListFindings"),
            Self::GetFindings => formatter.write_str("GetFindings"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageBinding {
    pub operation: MacieApiOperation,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<Digest>,
    pub finding_allowlist_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListFindingsRequest {
    scope_digest: Digest,
    filter: FindingFilter,
    page_number: u16,
    page_size: u16,
    page_token: Option<OpaquePageToken>,
    filter_digest: Digest,
    request_digest: Digest,
}

impl ListFindingsRequest {
    pub fn new(
        scope: &MacieDiscoveryScope,
        filter: FindingFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_LIST_PAGE_SIZE {
            return Err(ModelError::BoundExceeded {
                field: "ListFindings page size",
            });
        }
        Self::build(scope.digest(), filter, page_size, 1, None)
    }

    fn build(
        scope_digest: Digest,
        filter: FindingFilter,
        page_size: u16,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "ListFindings page number",
            });
        }
        let filter_digest = filter.digest();
        let token_digest = page_token.as_ref().map(|token| token.digest().clone());
        let request_digest = digest_serializable(&(
            MacieApiOperation::ListFindings,
            &scope_digest,
            &filter_digest,
            page_number,
            page_size,
            &token_digest,
        ))?;
        Ok(Self {
            scope_digest,
            filter,
            page_number,
            page_size,
            page_token,
            filter_digest,
            request_digest,
        })
    }

    pub fn next_page(&self, page_token: OpaquePageToken) -> Result<Self, ModelError> {
        Self::build(
            self.scope_digest.clone(),
            self.filter.clone(),
            self.page_size,
            self.page_number.saturating_add(1),
            Some(page_token),
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn binding(&self) -> PageBinding {
        PageBinding {
            operation: MacieApiOperation::ListFindings,
            scope_digest: self.scope_digest.clone(),
            filter_digest: self.filter_digest.clone(),
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
            finding_allowlist_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetFindingsRequest {
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
    finding_ids: FindingIdAllowlist,
    finding_allowlist_digest: Digest,
    request_digest: Digest,
}

impl GetFindingsRequest {
    pub fn new(
        scope: &MacieDiscoveryScope,
        list_request: &ListFindingsRequest,
        finding_ids: FindingIdAllowlist,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if list_request.scope_digest() != &scope.digest() {
            return Err(ModelError::InvalidValue {
                field: "GetFindings scope binding",
            });
        }
        let finding_ids = FindingIdAllowlist::for_get(finding_ids.into_ids())?;
        Self::build(
            scope.digest(),
            list_request.filter_digest().clone(),
            list_request.page_number(),
            finding_ids,
        )
    }

    fn build(
        scope_digest: Digest,
        filter_digest: Digest,
        page_number: u16,
        finding_ids: FindingIdAllowlist,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "GetFindings page number",
            });
        }
        let finding_allowlist_digest = finding_ids.digest();
        let request_digest = digest_serializable(&(
            MacieApiOperation::GetFindings,
            &scope_digest,
            &filter_digest,
            page_number,
            &finding_allowlist_digest,
        ))?;
        Ok(Self {
            scope_digest,
            filter_digest,
            page_number,
            finding_ids,
            finding_allowlist_digest,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn finding_ids(&self) -> &FindingIdAllowlist {
        &self.finding_ids
    }

    pub fn finding_allowlist_digest(&self) -> &Digest {
        &self.finding_allowlist_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn binding(&self) -> PageBinding {
        PageBinding {
            operation: MacieApiOperation::GetFindings,
            scope_digest: self.scope_digest.clone(),
            filter_digest: self.filter_digest.clone(),
            page_number: self.page_number,
            page_size: u16::try_from(self.finding_ids.len())
                .expect("GetFindings allowlist is bounded"),
            page_token_digest: None,
            finding_allowlist_digest: Some(self.finding_allowlist_digest.clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieReadRequest {
    filter: FindingFilter,
    page_size: u16,
    max_pages: u16,
    max_findings: usize,
}

impl MacieReadRequest {
    pub fn new(
        filter: FindingFilter,
        page_size: u16,
        max_pages: u16,
        max_findings: usize,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_LIST_PAGE_SIZE {
            return Err(ModelError::BoundExceeded {
                field: "ListFindings page size",
            });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "Macie read pages",
            });
        }
        if max_findings == 0 || max_findings > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded {
                field: "Macie read findings",
            });
        }
        Ok(Self {
            filter,
            page_size,
            max_pages,
            max_findings,
        })
    }

    pub fn bounded(filter: FindingFilter) -> Result<Self, ModelError> {
        Self::new(filter, MAX_LIST_PAGE_SIZE, MAX_PAGES, MAX_FINDINGS)
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn max_findings(&self) -> usize {
        self.max_findings
    }

    pub fn first_list_page(
        &self,
        scope: &MacieDiscoveryScope,
    ) -> Result<ListFindingsRequest, ModelError> {
        ListFindingsRequest::new(scope, self.filter.clone(), self.page_size)
    }
}

pub type FindingsReadRequest = MacieReadRequest;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLossKind {
    BlockedEnv,
    AccessDenied,
    CredentialUnavailable,
    ProviderUnavailable,
    Throttled,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessLossEvidence {
    pub kind: AccessLossKind,
    pub provider_code: String,
    pub after_operation: MacieApiOperation,
    pub after_page: u16,
    pub detail_digest: Digest,
}

impl AccessLossEvidence {
    pub fn new(
        kind: AccessLossKind,
        provider_code: impl Into<String>,
        after_operation: MacieApiOperation,
        after_page: u16,
    ) -> Result<Self, ModelError> {
        let provider_code = provider_code.into();
        validate_text(
            &provider_code,
            "provider access-loss code",
            MAX_IDENTIFIER_LENGTH,
        )?;
        Ok(Self {
            kind,
            detail_digest: Digest::from_text(&provider_code),
            provider_code,
            after_operation,
            after_page,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderUnknownEvidence {
    pub provider_code: String,
    pub detail_digest: Digest,
    pub after_operation: MacieApiOperation,
    pub after_page: u16,
}

impl ProviderUnknownEvidence {
    pub fn new(
        provider_code: impl Into<String>,
        after_operation: MacieApiOperation,
        after_page: u16,
    ) -> Result<Self, ModelError> {
        let provider_code = provider_code.into();
        validate_text(
            &provider_code,
            "provider unknown code",
            MAX_IDENTIFIER_LENGTH,
        )?;
        Ok(Self {
            detail_digest: Digest::from_text(&provider_code),
            provider_code,
            after_operation,
            after_page,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    ProviderMarkedPartial,
    PageLimitReached,
    FindingLimitReached,
    AllowlistLimitReached,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListFindingsPage {
    pub binding: PageBinding,
    pub finding_ids: FindingIdAllowlist,
    pub next_page: Option<OpaquePageToken>,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
    pub provider_unknown: Option<ProviderUnknownEvidence>,
    pub provider_revision: String,
    pub response_digest: Digest,
}

impl ListFindingsPage {
    pub fn new(
        request: &ListFindingsRequest,
        finding_ids: FindingIdAllowlist,
        next_page: Option<OpaquePageToken>,
        partial: bool,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if finding_ids.len() > usize::from(request.page_size()) {
            return Err(ModelError::BoundExceeded {
                field: "ListFindings ids per page",
            });
        }
        let provider_revision = provider_revision.into();
        validate_text(
            &provider_revision,
            "provider revision",
            MAX_IDENTIFIER_LENGTH,
        )?;
        let mut page = Self {
            binding: request.binding(),
            finding_ids,
            next_page,
            partial,
            access_loss: None,
            provider_unknown: None,
            provider_revision,
            response_digest: Digest::from_text("pending-list-response-digest"),
        };
        validate_serialized_size(&page, "ListFindings response")?;
        page.response_digest = page.compute_digest()?;
        Ok(page)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.binding,
            &self.finding_ids,
            self.next_page.as_ref().map(OpaquePageToken::digest),
            self.partial,
            &self.access_loss,
            &self.provider_unknown,
            &self.provider_revision,
        ))
    }

    pub fn with_access_loss(mut self, access_loss: AccessLossEvidence) -> Result<Self, ModelError> {
        self.partial = true;
        self.access_loss = Some(access_loss);
        self.response_digest = self.compute_digest()?;
        validate_serialized_size(&self, "ListFindings response")?;
        Ok(self)
    }

    pub fn with_provider_unknown(
        mut self,
        provider_unknown: ProviderUnknownEvidence,
    ) -> Result<Self, ModelError> {
        self.partial = true;
        self.provider_unknown = Some(provider_unknown);
        self.response_digest = self.compute_digest()?;
        validate_serialized_size(&self, "ListFindings response")?;
        Ok(self)
    }

    pub fn validate_for(&self, request: &ListFindingsRequest) -> Result<(), ModelError> {
        if self.binding != request.binding()
            || self.finding_ids.len() > usize::from(request.page_size())
            || self.response_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "ListFindings response",
            });
        }
        validate_serialized_size(self, "ListFindings response")?;
        Ok(())
    }
}

pub type ListFindingsResponse = ListFindingsPage;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetFindingsPage {
    pub binding: PageBinding,
    pub findings: Vec<MacieFinding>,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
    pub provider_unknown: Option<ProviderUnknownEvidence>,
    pub provider_revision: String,
    pub response_digest: Digest,
}

impl GetFindingsPage {
    pub fn new(
        request: &GetFindingsRequest,
        findings: Vec<MacieFinding>,
        partial: bool,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if findings.len() > request.finding_ids().len() {
            return Err(ModelError::BoundExceeded {
                field: "GetFindings findings per allowlist",
            });
        }
        if findings.iter().enumerate().any(|(index, finding)| {
            !request.finding_ids().contains(&finding.finding_id)
                || findings[..index]
                    .iter()
                    .any(|previous| previous.finding_id == finding.finding_id)
                || finding.validate().is_err()
        }) {
            return Err(ModelError::InvalidValue {
                field: "GetFindings allowlisted finding projection",
            });
        }
        let provider_revision = provider_revision.into();
        validate_text(
            &provider_revision,
            "provider revision",
            MAX_IDENTIFIER_LENGTH,
        )?;
        let mut page = Self {
            binding: request.binding(),
            findings,
            partial,
            access_loss: None,
            provider_unknown: None,
            provider_revision,
            response_digest: Digest::from_text("pending-get-response-digest"),
        };
        validate_serialized_size(&page, "GetFindings response")?;
        page.response_digest = page.compute_digest()?;
        Ok(page)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.binding,
            &self.findings,
            self.partial,
            &self.access_loss,
            &self.provider_unknown,
            &self.provider_revision,
        ))
    }

    pub fn with_access_loss(mut self, access_loss: AccessLossEvidence) -> Result<Self, ModelError> {
        self.partial = true;
        self.access_loss = Some(access_loss);
        self.response_digest = self.compute_digest()?;
        validate_serialized_size(&self, "GetFindings response")?;
        Ok(self)
    }

    pub fn with_provider_unknown(
        mut self,
        provider_unknown: ProviderUnknownEvidence,
    ) -> Result<Self, ModelError> {
        self.partial = true;
        self.provider_unknown = Some(provider_unknown);
        self.response_digest = self.compute_digest()?;
        validate_serialized_size(&self, "GetFindings response")?;
        Ok(self)
    }

    pub fn validate_for(&self, request: &GetFindingsRequest) -> Result<(), ModelError> {
        if self.binding != request.binding()
            || self.findings.len() > request.finding_ids().len()
            || self.findings.iter().enumerate().any(|(index, finding)| {
                !request.finding_ids().contains(&finding.finding_id)
                    || self.findings[..index]
                        .iter()
                        .any(|previous| previous.finding_id == finding.finding_id)
                    || finding.validate().is_err()
            })
            || self.response_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "GetFindings response",
            });
        }
        validate_serialized_size(self, "GetFindings response")?;
        Ok(())
    }
}

pub type GetFindingsResponse = GetFindingsPage;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
    Stale,
    Tampered,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub classification_digest: Digest,
    pub policy_digest: Digest,
    pub finding_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieDiscoveryEvidence {
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub credential_revision: Revision,
    pub filter_digest: Digest,
    pub finding_allowlist_digest: Digest,
    pub list_page_bindings: Vec<PageBinding>,
    pub get_page_bindings: Vec<PageBinding>,
    pub list_response_digests: Vec<Digest>,
    pub get_response_digests: Vec<Digest>,
    pub findings: Vec<MacieFinding>,
    pub provenance: ProviderProvenance,
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub access_loss: Option<AccessLossEvidence>,
    pub provider_unknown: Option<ProviderUnknownEvidence>,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    plugin_version: &'a str,
    plugin_version_digest: &'a Digest,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    credential_revision: Revision,
    filter_digest: &'a Digest,
    finding_allowlist_digest: &'a Digest,
    list_page_bindings: &'a [PageBinding],
    get_page_bindings: &'a [PageBinding],
    list_response_digests: &'a [Digest],
    get_response_digests: &'a [Digest],
    findings: &'a [MacieFinding],
    provenance: ProviderProvenance,
    status: EvidenceStatus,
    partial_reason: &'a Option<PartialReason>,
    access_loss: &'a Option<AccessLossEvidence>,
    provider_unknown: &'a Option<ProviderUnknownEvidence>,
    redaction: &'a RedactionSummary,
}

impl MacieDiscoveryEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_revision: String,
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
        credential_revision: Revision,
        filter_digest: Digest,
        finding_allowlist_digest: Digest,
        list_page_bindings: Vec<PageBinding>,
        get_page_bindings: Vec<PageBinding>,
        list_response_digests: Vec<Digest>,
        get_response_digests: Vec<Digest>,
        findings: Vec<MacieFinding>,
        provenance: ProviderProvenance,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        access_loss: Option<AccessLossEvidence>,
        provider_unknown: Option<ProviderUnknownEvidence>,
    ) -> Result<Self, ModelError> {
        if list_page_bindings.is_empty()
            || list_page_bindings.len() > usize::from(MAX_PAGES)
            || get_page_bindings.len() > usize::from(MAX_PAGES)
            || list_page_bindings.len() != list_response_digests.len()
            || get_page_bindings.len() != get_response_digests.len()
        {
            return Err(ModelError::BoundExceeded {
                field: "evidence pages",
            });
        }
        if findings.len() > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded {
                field: "evidence findings",
            });
        }
        validate_text(
            &provider_revision,
            "provider revision",
            MAX_IDENTIFIER_LENGTH,
        )?;
        validate_status_fields(
            status,
            partial_reason.as_ref(),
            access_loss.as_ref(),
            provider_unknown.as_ref(),
        )?;
        let plugin_version = AWS_MACIE_PLUGIN_VERSION_TEXT.to_owned();
        let plugin_version_digest = Digest::from_text(&plugin_version);
        let contract_version = AWS_MACIE_CONTRACT_VERSION.to_owned();
        let redaction = RedactionSummary::default();
        let mut evidence = Self {
            plugin_version,
            plugin_version_digest,
            contract_version,
            contract_digest: crate::contract_digest(),
            provider_revision,
            provider_digest,
            permission_digest,
            scope_digest,
            registration_digest,
            credential_revision,
            filter_digest,
            finding_allowlist_digest,
            list_page_bindings,
            get_page_bindings,
            list_response_digests,
            get_response_digests,
            findings,
            provenance,
            status,
            partial_reason,
            access_loss,
            provider_unknown,
            redaction,
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        evidence.evidence_digest = evidence.compute_digest()?;
        Ok(evidence)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&EvidenceDigestInput {
            plugin_version: &self.plugin_version,
            plugin_version_digest: &self.plugin_version_digest,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            credential_revision: self.credential_revision,
            filter_digest: &self.filter_digest,
            finding_allowlist_digest: &self.finding_allowlist_digest,
            list_page_bindings: &self.list_page_bindings,
            get_page_bindings: &self.get_page_bindings,
            list_response_digests: &self.list_response_digests,
            get_response_digests: &self.get_response_digests,
            findings: &self.findings,
            provenance: self.provenance,
            status: self.status,
            partial_reason: &self.partial_reason,
            access_loss: &self.access_loss,
            provider_unknown: &self.provider_unknown,
            redaction: &self.redaction,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.plugin_version != AWS_MACIE_PLUGIN_VERSION_TEXT
            || self.plugin_version_digest != Digest::from_text(&self.plugin_version)
            || self.contract_version != AWS_MACIE_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_revision != crate::AWS_MACIE_PROVIDER_REVISION
            || self.provider_digest != crate::provider::provider_digest()
            || self.permission_digest != permission_digest()
            || self.redaction.raw_pii_retained
            || self.redaction.raw_object_keys_retained
            || self.redaction.raw_object_paths_retained
            || self.redaction.full_descriptions_retained
            || self.redaction.raw_provider_payload_retained
            || self.redaction.sample_data_retained
            || self.redaction != RedactionSummary::default()
            || self.list_page_bindings.is_empty()
            || self.list_page_bindings.len() > usize::from(MAX_PAGES)
            || self.get_page_bindings.len() > usize::from(MAX_PAGES)
            || self.list_page_bindings.len() != self.list_response_digests.len()
            || self.get_page_bindings.len() != self.get_response_digests.len()
            || self.findings.len() > MAX_FINDINGS
            || self.list_page_bindings.iter().any(|binding| {
                binding.operation != MacieApiOperation::ListFindings
                    || binding.scope_digest != self.scope_digest
                    || binding.filter_digest != self.filter_digest
            })
            || self.get_page_bindings.iter().any(|binding| {
                binding.operation != MacieApiOperation::GetFindings
                    || binding.scope_digest != self.scope_digest
                    || binding.filter_digest != self.filter_digest
            })
            || self
                .findings
                .iter()
                .any(|finding| finding.validate().is_err())
            || validate_status_fields(
                self.status,
                self.partial_reason.as_ref(),
                self.access_loss.as_ref(),
                self.provider_unknown.as_ref(),
            )
            .is_err()
            || self.evidence_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "Macie discovery evidence",
            });
        }
        Ok(())
    }

    pub fn digests(&self) -> EvidenceDigests {
        EvidenceDigests {
            plugin_version_digest: self.plugin_version_digest.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            classification_digest: self.findings.first().map_or_else(
                || Digest::from_text("no-classification"),
                |finding| finding.classification_digest().clone(),
            ),
            policy_digest: self.findings.first().map_or_else(
                || Digest::from_text("no-policy"),
                |finding| finding.policy_digest().clone(),
            ),
            finding_digest: Digest::from_fields(
                "hartevo.aws-macie-finding-digests/v1",
                &self
                    .findings
                    .iter()
                    .map(|finding| finding.finding_digest.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ),
            evidence_digest: self.evidence_digest.clone(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status == EvidenceStatus::Complete
    }
}

fn validate_status_fields(
    status: EvidenceStatus,
    partial_reason: Option<&PartialReason>,
    access_loss: Option<&AccessLossEvidence>,
    provider_unknown: Option<&ProviderUnknownEvidence>,
) -> Result<(), ModelError> {
    match status {
        EvidenceStatus::Complete
            if partial_reason.is_some() || access_loss.is_some() || provider_unknown.is_some() =>
        {
            Err(ModelError::InvalidValue {
                field: "complete evidence status",
            })
        }
        EvidenceStatus::Partial if partial_reason.is_none() => Err(ModelError::InvalidValue {
            field: "partial evidence reason",
        }),
        EvidenceStatus::AccessLost if access_loss.is_none() => Err(ModelError::InvalidValue {
            field: "access-loss evidence",
        }),
        EvidenceStatus::ProviderUnknown if provider_unknown.is_none() => {
            Err(ModelError::InvalidValue {
                field: "provider-unknown evidence",
            })
        }
        _ => Ok(()),
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieDiscoveryProposal {
    pub evidence: MacieDiscoveryEvidence,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub adopted: bool,
}

impl MacieDiscoveryProposal {
    pub fn new(evidence: MacieDiscoveryEvidence) -> Result<Self, ModelError> {
        evidence.validate()?;
        let proposal_digest = digest_serializable(&(
            &evidence.evidence_digest,
            &evidence.scope_digest,
            &evidence.registration_digest,
        ))?;
        Ok(Self {
            evidence,
            proposal_digest,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            adopted: false,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.evidence.validate()?;
        let expected = digest_serializable(&(
            &self.evidence.evidence_digest,
            &self.evidence.scope_digest,
            &self.evidence.registration_digest,
        ))?;
        if self.proposal_digest != expected
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.adopted
        {
            return Err(ModelError::InvalidValue {
                field: "Macie proposal authority",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieDiscoveryRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub record_digest: Digest,
    pub durable: bool,
    pub verified: bool,
    pub adopted: bool,
}

impl MacieDiscoveryRecord {
    pub fn new(proposal: &MacieDiscoveryProposal) -> Result<Self, ModelError> {
        proposal.validate()?;
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            registration_digest: proposal.evidence.registration_digest.clone(),
            record_digest: Digest::from_text("pending-record-digest"),
            durable: false,
            verified: false,
            adopted: false,
        };
        record.record_digest = digest_serializable(&(
            &record.proposal_digest,
            &record.evidence_digest,
            &record.scope_digest,
            &record.registration_digest,
            record.durable,
            record.verified,
            record.adopted,
        ))?;
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    VerifiedReadOnly,
    PartialEvidence,
    AccessLost,
    Stale,
    Tampered,
    ProviderUnknown,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieDiscoveryVerification {
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub status: VerificationStatus,
    pub accepted: bool,
    pub independent_live_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl MacieDiscoveryVerification {
    pub fn from_record(
        record: &MacieDiscoveryRecord,
        evidence: &MacieDiscoveryEvidence,
    ) -> Result<Self, ModelError> {
        evidence.validate()?;
        let status = match evidence.status {
            EvidenceStatus::Complete => VerificationStatus::VerifiedReadOnly,
            EvidenceStatus::Partial => VerificationStatus::PartialEvidence,
            EvidenceStatus::AccessLost => VerificationStatus::AccessLost,
            EvidenceStatus::Stale => VerificationStatus::Stale,
            EvidenceStatus::Tampered => VerificationStatus::Tampered,
            EvidenceStatus::ProviderUnknown => VerificationStatus::ProviderUnknown,
        };
        Ok(Self {
            record_digest: record.record_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            status,
            accepted: evidence.status == EvidenceStatus::Complete,
            independent_live_readback: false,
            connected: false,
            native: false,
            first_party: false,
            verification_authority: false,
            outcome_authority: false,
        })
    }
}

pub const fn aws_macie_api_version() -> &'static str {
    crate::AWS_MACIE_API_VERSION
}

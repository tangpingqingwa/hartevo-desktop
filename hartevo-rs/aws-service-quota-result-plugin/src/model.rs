//! Typed, bounded, digest-only models for the AWS Service Quotas Layer-1 seam.
//!
//! The model deliberately has no serialisable representation for a secret,
//! raw quota value, usage series, usage-metric dimensions, requester,
//! support-case identifier, quota name/ARN, or provider payload. Those values
//! can be used transiently by a parser and are reduced to digests before they
//! enter a public evidence type.

use std::{collections::BTreeSet, fmt, ops::Deref};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_QUOTAS: usize = 64;
pub const MAX_HISTORY_ENTRIES: usize = 64;
pub const MAX_HISTORY_WINDOW_SECONDS: i64 = 2_592_000;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_RETRIES: u8 = 2;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
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
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} has a stale revision")]
    StaleRevision { field: &'static str },
    #[error("{field} is outside the bounded history window")]
    OutsideHistoryWindow { field: &'static str },
    #[error("registration is already revoked or reversed")]
    AlreadyRevoked,
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
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_code(
    value: &str,
    field: &'static str,
    max: usize,
    min: usize,
) -> Result<(), ModelError> {
    validate_text(value, field, max)?;
    if value.len() < min
        || !value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || character == '-'))
    {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
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

bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
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

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAccountId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type AccountId = AwsAccountId;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

pub type Region = AwsRegion;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type DeploymentRevision = Revision;
pub type MissionRevision = Revision;
pub type ProjectRevision = Revision;
pub type WorkProductRevision = Revision;
pub type QuotaRevision = Revision;
pub type UsageRevision = Revision;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).unwrap_or_default())
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceCode(String);

impl ServiceCode {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_code(&value, "service code", 63, 1)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ServiceCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceCode")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for ServiceCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuotaCode(String);

impl QuotaCode {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_code(&value, "quota code", 128, 1)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for QuotaCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaCode")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for QuotaCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceQuotaIdentity {
    pub service_code: ServiceCode,
    pub quota_code: QuotaCode,
}

impl ServiceQuotaIdentity {
    pub const fn from_parts(service_code: ServiceCode, quota_code: QuotaCode) -> Self {
        Self {
            service_code,
            quota_code,
        }
    }

    pub fn new(
        service_code: impl Into<String>,
        quota_code: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self::from_parts(
            ServiceCode::new(service_code)?,
            QuotaCode::new(quota_code)?,
        ))
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-identity/v1",
            &[
                self.service_code.as_str().to_owned(),
                self.quota_code.as_str().to_owned(),
            ],
        )
    }
}

pub type AwsServiceQuotaIdentity = ServiceQuotaIdentity;
pub type QuotaIdentity = ServiceQuotaIdentity;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaBinding {
    pub identity: ServiceQuotaIdentity,
    pub revision: Revision,
    pub usage_revision: Revision,
}

impl QuotaBinding {
    pub fn new(
        identity: ServiceQuotaIdentity,
        revision: Revision,
        usage_revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_positive(revision.get(), "quota revision")?;
        validate_positive(usage_revision.get(), "usage revision")?;
        Ok(Self {
            identity,
            revision,
            usage_revision,
        })
    }

    pub fn for_quota(
        service_code: impl Into<String>,
        quota_code: impl Into<String>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            ServiceQuotaIdentity::new(service_code, quota_code)?,
            revision,
            revision,
        )
    }

    pub fn with_usage_revision(mut self, usage_revision: Revision) -> Result<Self, ModelError> {
        validate_positive(usage_revision.get(), "usage revision")?;
        self.usage_revision = usage_revision;
        Ok(self)
    }

    pub fn quota_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-binding/v1",
            &[
                self.identity.digest().to_string(),
                self.revision.get().to_string(),
                self.usage_revision.get().to_string(),
            ],
        )
    }
}

pub type AwsServiceQuotaBinding = QuotaBinding;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    ListServiceQuotas,
    GetServiceQuota,
    GetAWSDefaultServiceQuota,
    ListRequestedServiceQuotaChangeHistoryByQuota,
}

impl PermissionAction {
    pub const ALL: [Self; 4] = [
        Self::ListServiceQuotas,
        Self::GetServiceQuota,
        Self::GetAWSDefaultServiceQuota,
        Self::ListRequestedServiceQuotaChangeHistoryByQuota,
    ];

    pub const fn api_name(&self) -> &'static str {
        match self {
            Self::ListServiceQuotas => "ListServiceQuotas",
            Self::GetServiceQuota => "GetServiceQuota",
            Self::GetAWSDefaultServiceQuota => "GetAWSDefaultServiceQuota",
            Self::ListRequestedServiceQuotaChangeHistoryByQuota => {
                "ListRequestedServiceQuotaChangeHistoryByQuota"
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id,
            revision,
            allowed_actions: PermissionAction::ALL.into_iter().collect(),
        })
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(Self {
            id,
            revision,
            allowed_actions,
        })
    }

    pub fn allows(&self, action: &PermissionAction) -> bool {
        self.allowed_actions.contains(action)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub service_code: ServiceCode,
    pub quotas: Vec<QuotaBinding>,
    pub permission_digest: Digest,
}

impl AwsServiceQuotaScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AwsAccountId,
        region: AwsRegion,
        service_code: ServiceCode,
        quotas: impl IntoIterator<Item = QuotaBinding>,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let quotas = quotas.into_iter().collect::<Vec<_>>();
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            service_code,
            quotas,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn single(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AwsAccountId,
        region: AwsRegion,
        service_code: ServiceCode,
        quota_code: QuotaCode,
        quota_revision: Revision,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            service_code.clone(),
            [QuotaBinding::for_quota(
                service_code.as_str(),
                quota_code.as_str(),
                quota_revision,
            )?],
            permission_digest,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.quotas.is_empty() {
            return Err(ModelError::Empty {
                field: "quota allowlist",
            });
        }
        if self.quotas.len() > MAX_QUOTAS {
            return Err(ModelError::TooMany {
                field: "quota allowlist",
            });
        }
        if self.permission_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        let mut seen = BTreeSet::new();
        for quota in &self.quotas {
            if quota.identity.service_code != self.service_code {
                return Err(ModelError::ScopeMismatch {
                    field: "quota service code",
                });
            }
            if !seen.insert(quota.identity.quota_code.clone()) {
                return Err(ModelError::Duplicate {
                    field: "quota code allowlist",
                });
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn quota_digest(&self) -> Digest {
        let mut values = self
            .quotas
            .iter()
            .map(QuotaBinding::quota_digest)
            .collect::<Vec<_>>();
        values.sort();
        Digest::from_parts(
            "hartevo-aws-service-quota-allowlist/v1",
            &values
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    pub fn usage_fence_digest(&self) -> Digest {
        let mut values = self
            .quotas
            .iter()
            .map(|quota| {
                Digest::from_parts(
                    "hartevo-aws-service-quota-usage-fence/v1",
                    &[
                        quota.identity.digest().to_string(),
                        quota.usage_revision.get().to_string(),
                    ],
                )
            })
            .collect::<Vec<_>>();
        values.sort();
        Digest::from_parts(
            "hartevo-aws-service-quota-usage-fences/v1",
            &values
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    pub fn allows(&self, identity: &ServiceQuotaIdentity) -> bool {
        self.quotas.iter().any(|quota| quota.identity == *identity)
    }

    pub fn quota(&self, identity: &ServiceQuotaIdentity) -> Option<&QuotaBinding> {
        self.quotas.iter().find(|quota| quota.identity == *identity)
    }

    pub fn quota_by_digest(&self, digest: &Digest) -> Option<&QuotaBinding> {
        self.quotas
            .iter()
            .find(|quota| quota.identity.digest() == *digest || quota.quota_digest() == *digest)
    }

    pub fn quota_revision(&self, identity: &ServiceQuotaIdentity) -> Option<Revision> {
        self.quota(identity).map(|quota| quota.revision)
    }

    pub fn usage_revision(&self, identity: &ServiceQuotaIdentity) -> Option<Revision> {
        self.quota(identity).map(|quota| quota.usage_revision)
    }

    pub fn quota_identities(&self) -> Vec<ServiceQuotaIdentity> {
        self.quotas
            .iter()
            .map(|quota| quota.identity.clone())
            .collect()
    }
}

pub type AwsServiceQuotaScopeBinding = AwsServiceQuotaScope;

/// A SigV4 reference is reduced to a digest at construction time. Neither
/// the supplied reference nor signing material is retained or serialised.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
    revision: Revision,
}

impl SecretReference {
    pub fn sigv4(
        reference: impl AsRef<str>,
        scope: &AwsServiceQuotaScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let value = reference.as_ref();
        validate_text(value, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        let revision = Revision::new(revision)?;
        let digest = Digest::from_parts(
            "hartevo-aws-service-quota-sigv4-secret/v1",
            &[
                scope.region.as_str().to_owned(),
                scope.account_id.as_str().to_owned(),
                scope.digest().to_string(),
                revision.get().to_string(),
                value.to_owned(),
            ],
        );
        Ok(Self {
            digest,
            region: scope.region.clone(),
            revision,
        })
    }

    pub fn new(
        reference: impl AsRef<str>,
        scope: &AwsServiceQuotaScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::sigv4(reference, scope, revision)
    }

    pub fn for_scope(
        reference: impl AsRef<str>,
        scope: &AwsServiceQuotaScope,
    ) -> Result<Self, ModelError> {
        Self::sigv4(reference, scope, 1)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn signing_service(&self) -> &'static str {
        "servicequotas"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest)
            .field("signing_service", &self.signing_service())
            .field("signing_region", &self.region)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuotaAppliedAtLevel {
    Account,
    Resource,
    All,
}

impl QuotaAppliedAtLevel {
    pub const fn api_value(self) -> &'static str {
        match self {
            Self::Account => "ACCOUNT",
            Self::Resource => "RESOURCE",
            Self::All => "ALL",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub max_entries: u16,
}

impl HistoryWindow {
    pub fn new(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        max_entries: u16,
    ) -> Result<Self, ModelError> {
        if max_entries == 0 || usize::from(max_entries) > MAX_HISTORY_ENTRIES {
            return Err(ModelError::Invalid {
                field: "history entry bound",
            });
        }
        let duration = end.signed_duration_since(start);
        if duration < Duration::zero() || duration.num_seconds() > MAX_HISTORY_WINDOW_SECONDS {
            return Err(ModelError::Invalid {
                field: "history window",
            });
        }
        Ok(Self {
            start,
            end,
            max_entries,
        })
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl OpaqueCursor {
    pub fn new(
        raw_token: impl AsRef<str>,
        binding_digest: &Digest,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        if raw_token.is_empty()
            || raw_token.len() > MAX_CURSOR_BYTES
            || raw_token.chars().any(char::is_control)
            || page_number == 0
        {
            return Err(ModelError::InvalidCursor {
                field: "opaque pagination token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_text(raw_token),
            binding_digest: binding_digest.clone(),
            page_number,
        })
    }

    pub fn from_digest(
        token_digest: Digest,
        binding_digest: Digest,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        if token_digest.is_zero() || binding_digest.is_zero() || page_number == 0 {
            return Err(ModelError::InvalidCursor {
                field: "opaque pagination digest",
            });
        }
        Ok(Self {
            token_digest,
            binding_digest,
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

pub type Cursor = OpaqueCursor;
pub type ServiceQuotaCursor = OpaqueCursor;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsServiceQuotaOperation {
    ListServiceQuotas,
    GetServiceQuota,
    GetAWSDefaultServiceQuota,
    ListRequestedServiceQuotaChangeHistoryByQuota,
}

impl AwsServiceQuotaOperation {
    pub const ALL: [Self; 4] = [
        Self::ListServiceQuotas,
        Self::GetServiceQuota,
        Self::GetAWSDefaultServiceQuota,
        Self::ListRequestedServiceQuotaChangeHistoryByQuota,
    ];

    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ListServiceQuotas => "ListServiceQuotas",
            Self::GetServiceQuota => "GetServiceQuota",
            Self::GetAWSDefaultServiceQuota => "GetAWSDefaultServiceQuota",
            Self::ListRequestedServiceQuotaChangeHistoryByQuota => {
                "ListRequestedServiceQuotaChangeHistoryByQuota"
            }
        }
    }

    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::ListServiceQuotas => PermissionAction::ListServiceQuotas,
            Self::GetServiceQuota => PermissionAction::GetServiceQuota,
            Self::GetAWSDefaultServiceQuota => PermissionAction::GetAWSDefaultServiceQuota,
            Self::ListRequestedServiceQuotaChangeHistoryByQuota => {
                PermissionAction::ListRequestedServiceQuotaChangeHistoryByQuota
            }
        }
    }
}

pub type ServiceQuotaOperation = AwsServiceQuotaOperation;
pub type AwsServiceQuotaReadOperation = AwsServiceQuotaOperation;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
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

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    MalformedResponse,
    Unknown,
}

impl TransportErrorKind {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited => Some(429),
            Self::ServerFailure => Some(500),
            Self::Timeout | Self::BlockedEnvironment | Self::MalformedResponse | Self::Unknown => {
                None
            }
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::ServerFailure | Self::Timeout
        )
    }

    pub const fn access_loss(self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[error("AWS Service Quotas transport failure: {kind:?}")]
pub struct TransportError {
    pub kind: TransportErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(kind: TransportErrorKind) -> Self {
        let label = match kind {
            TransportErrorKind::BadRequest => "400",
            TransportErrorKind::Unauthorized => "401",
            TransportErrorKind::Forbidden => "403",
            TransportErrorKind::NotFound => "404",
            TransportErrorKind::Conflict => "409",
            TransportErrorKind::RateLimited => "429",
            TransportErrorKind::ServerFailure => "5xx",
            TransportErrorKind::Timeout => "timeout",
            TransportErrorKind::BlockedEnvironment => "BLOCKED_ENV",
            TransportErrorKind::MalformedResponse => "malformed",
            TransportErrorKind::Unknown => "unknown",
        };
        Self {
            kind,
            status_code: kind.status_code(),
            error_digest: Digest::from_text(label),
        }
    }

    pub const fn retryable(&self) -> bool {
        self.kind.retryable()
    }

    pub const fn is_access_loss(&self) -> bool {
        self.kind.access_loss()
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind,
            status_code: self.status_code,
            error_digest: self.error_digest.clone(),
            retryable: self.retryable(),
            access_loss: self.is_access_loss(),
            blocked_env: matches!(self.kind, TransportErrorKind::BlockedEnvironment),
        }
    }

    pub fn bad_request() -> Self {
        Self::new(TransportErrorKind::BadRequest)
    }

    pub fn unauthorized() -> Self {
        Self::new(TransportErrorKind::Unauthorized)
    }

    pub fn forbidden() -> Self {
        Self::new(TransportErrorKind::Forbidden)
    }

    pub fn not_found() -> Self {
        Self::new(TransportErrorKind::NotFound)
    }

    pub fn conflict() -> Self {
        Self::new(TransportErrorKind::Conflict)
    }

    pub fn rate_limited() -> Self {
        Self::new(TransportErrorKind::RateLimited)
    }

    pub fn server_failure() -> Self {
        Self::new(TransportErrorKind::ServerFailure)
    }

    pub fn timeout() -> Self {
        Self::new(TransportErrorKind::Timeout)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportErrorKind::BlockedEnvironment)
    }

    pub fn malformed() -> Self {
        Self::new(TransportErrorKind::MalformedResponse)
    }
}

pub type AwsServiceQuotaTransportError = TransportError;
pub type ProviderErrorKind = TransportErrorKind;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: TransportErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retryable: bool,
    pub access_loss: bool,
    pub blocked_env: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaEvidenceState {
    Complete,
    Partial,
    StaleUsage,
    PaginationIncomplete,
    InsufficientData,
    AccessLoss,
    ProviderUnknown,
    RegistrationRevoked,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    RequestBudget,
    ResponseTooLarge,
    CursorReplay,
    MissingQuota,
    StaleUsage,
    HistoryWindow,
    ObservationConflict,
    ProviderConflict,
    ProviderError,
    MalformedResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaPostureDigest {
    pub quota_identity_digest: Digest,
    pub unit_digest: Digest,
    pub applied_value_digest: Option<Digest>,
    pub default_value_digest: Option<Digest>,
    pub adjustable_digest: Digest,
    pub global_digest: Digest,
    pub usage_metric_digest: Option<Digest>,
    pub request_history_digest: Option<Digest>,
    pub usage_revision: Revision,
    pub observed_at: DateTime<Utc>,
    pub posture_digest: Digest,
}

impl QuotaPostureDigest {
    #[allow(clippy::too_many_arguments)]
    pub fn from_component_digests(
        identity: &ServiceQuotaIdentity,
        unit_digest: Digest,
        applied_value_digest: Option<Digest>,
        default_value_digest: Option<Digest>,
        adjustable_digest: Digest,
        global_digest: Digest,
        usage_metric_digest: Option<Digest>,
        request_history_digest: Option<Digest>,
        usage_revision: Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if unit_digest.is_zero() || adjustable_digest.is_zero() || global_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "quota posture component digest",
            });
        }
        let mut posture = Self {
            quota_identity_digest: identity.digest(),
            unit_digest,
            applied_value_digest,
            default_value_digest,
            adjustable_digest,
            global_digest,
            usage_metric_digest,
            request_history_digest,
            usage_revision,
            observed_at,
            posture_digest: Digest::zero(),
        };
        posture.posture_digest = posture.recomputed_digest();
        Ok(posture)
    }

    pub fn fixture(
        identity: &ServiceQuotaIdentity,
        usage_revision: Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::from_component_digests(
            identity,
            Digest::from_text("None"),
            Some(Digest::from_text("fixture-applied-value")),
            Some(Digest::from_text("fixture-default-value")),
            Digest::from_text("adjustable=true"),
            Digest::from_text("global=false"),
            Some(Digest::from_text("fixture-usage-metric")),
            Some(Digest::from_text("fixture-history-state")),
            usage_revision,
            observed_at,
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-posture/v1",
            &[
                self.quota_identity_digest.to_string(),
                self.unit_digest.to_string(),
                self.applied_value_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.default_value_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.adjustable_digest.to_string(),
                self.global_digest.to_string(),
                self.usage_metric_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.request_history_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.usage_revision.get().to_string(),
                self.observed_at.to_rfc3339(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.quota_identity_digest.is_zero()
            || self.posture_digest != self.recomputed_digest()
            || self.usage_revision.get() == 0
        {
            return Err(ModelError::Invalid {
                field: "quota posture digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaReadRequest {
    pub operation: AwsServiceQuotaOperation,
    pub scope_digest: Digest,
    pub service_code: ServiceCode,
    pub quota: Option<ServiceQuotaIdentity>,
    pub allowed_quota_digests: Vec<Digest>,
    pub applied_at_level: QuotaAppliedAtLevel,
    pub history_window: Option<HistoryWindow>,
    pub max_results: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub max_requests: u16,
    pub max_retries: u8,
    pub observed_at: DateTime<Utc>,
    pub page_number: u16,
    pub cursor: Option<OpaqueCursor>,
    pub filter_digest: Digest,
    pub request_digest: Digest,
}

impl AwsServiceQuotaReadRequest {
    pub fn list_service_quotas(
        scope: &AwsServiceQuotaScope,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::ListServiceQuotas,
            None,
            QuotaAppliedAtLevel::All,
            None,
            max_results,
            cursor,
            Utc::now(),
        )
    }

    pub fn list_service_quotas_at(
        scope: &AwsServiceQuotaScope,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::ListServiceQuotas,
            None,
            QuotaAppliedAtLevel::All,
            None,
            max_results,
            cursor,
            observed_at,
        )
    }

    pub fn get_service_quota(
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::GetServiceQuota,
            Some(quota),
            QuotaAppliedAtLevel::Account,
            None,
            1,
            None,
            Utc::now(),
        )
    }

    pub fn get_service_quota_at(
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::GetServiceQuota,
            Some(quota),
            QuotaAppliedAtLevel::Account,
            None,
            1,
            None,
            observed_at,
        )
    }

    pub fn get_aws_default_service_quota(
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::GetAWSDefaultServiceQuota,
            Some(quota),
            QuotaAppliedAtLevel::Account,
            None,
            1,
            None,
            Utc::now(),
        )
    }

    pub fn get_aws_default_service_quota_at(
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::GetAWSDefaultServiceQuota,
            Some(quota),
            QuotaAppliedAtLevel::Account,
            None,
            1,
            None,
            observed_at,
        )
    }

    pub fn list_requested_service_quota_change_history_by_quota(
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
        history_window: HistoryWindow,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota,
            Some(quota),
            QuotaAppliedAtLevel::All,
            Some(history_window),
            max_results,
            cursor,
            Utc::now(),
        )
    }

    pub fn list_requested_service_quota_change_history_by_quota_at(
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
        history_window: HistoryWindow,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota,
            Some(quota),
            QuotaAppliedAtLevel::All,
            Some(history_window),
            max_results,
            cursor,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        scope: &AwsServiceQuotaScope,
        operation: AwsServiceQuotaOperation,
        quota: Option<ServiceQuotaIdentity>,
        applied_at_level: QuotaAppliedAtLevel,
        history_window: Option<HistoryWindow>,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if max_results == 0 || max_results > PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if matches!(
            operation,
            AwsServiceQuotaOperation::GetServiceQuota
                | AwsServiceQuotaOperation::GetAWSDefaultServiceQuota
        ) && max_results != 1
        {
            return Err(ModelError::Invalid {
                field: "single quota page size",
            });
        }
        if matches!(
            operation,
            AwsServiceQuotaOperation::GetServiceQuota
                | AwsServiceQuotaOperation::GetAWSDefaultServiceQuota
                | AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota
        ) && quota.is_none()
        {
            return Err(ModelError::Invalid {
                field: "quota selector",
            });
        }
        if matches!(
            operation,
            AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota
        ) && history_window.is_none()
        {
            return Err(ModelError::Invalid {
                field: "history window",
            });
        }
        if !matches!(
            operation,
            AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota
        ) && history_window.is_some()
        {
            return Err(ModelError::Unsupported {
                field: "history window for non-history operation",
            });
        }
        if let Some(quota) = &quota
            && !scope.allows(quota)
        {
            return Err(ModelError::ScopeMismatch {
                field: "quota selector",
            });
        }
        let allowed_quota_digests = scope
            .quotas
            .iter()
            .map(|entry| entry.identity.digest())
            .collect::<Vec<_>>();
        let filter_digest = Digest::from_parts(
            "hartevo-aws-service-quota-filter/v1",
            &[
                scope.digest().to_string(),
                operation.api_name().to_owned(),
                quota
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().to_string()),
                applied_at_level.api_value().to_owned(),
                history_window
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().to_string()),
                max_results.to_string(),
                MAX_PAGES.to_string(),
                MAX_RESPONSE_BYTES.to_string(),
                MAX_REQUESTS_PER_READ.to_string(),
                MAX_RETRIES.to_string(),
                observed_at.to_rfc3339(),
            ],
        );
        if let Some(cursor) = &cursor
            && cursor.binding_digest() != &filter_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor filter binding",
            });
        }
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        let request_digest = Digest::from_parts(
            "hartevo-aws-service-quota-request/v1",
            &[
                filter_digest.to_string(),
                page_number.to_string(),
                cursor
                    .as_ref()
                    .map_or_else(String::new, |value| value.token_digest().to_string()),
            ],
        );
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            service_code: scope.service_code.clone(),
            quota,
            allowed_quota_digests,
            applied_at_level,
            history_window,
            max_results,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_requests: MAX_REQUESTS_PER_READ,
            max_retries: MAX_RETRIES,
            observed_at,
            page_number,
            cursor,
            filter_digest,
            request_digest,
        })
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self, ModelError> {
        if let Some(cursor) = &cursor
            && (cursor.binding_digest() != &self.filter_digest
                || cursor.page_number() != self.page_number.saturating_add(1))
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor page binding",
            });
        }
        let mut next = self.clone();
        next.cursor = cursor;
        next.page_number = next.cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        next.request_digest = Digest::from_parts(
            "hartevo-aws-service-quota-request/v1",
            &[
                next.filter_digest.to_string(),
                next.page_number.to_string(),
                next.cursor
                    .as_ref()
                    .map_or_else(String::new, |value| value.token_digest().to_string()),
            ],
        );
        Ok(next)
    }

    pub fn validate_against(
        &self,
        scope: &AwsServiceQuotaScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.service_code != scope.service_code
            || !permission.allows(&self.operation.permission())
        {
            return Err(ModelError::ScopeMismatch {
                field: "request scope or permission",
            });
        }
        let expected_quota_digests = scope
            .quotas
            .iter()
            .map(|quota| quota.identity.digest())
            .collect::<Vec<_>>();
        if self.allowed_quota_digests != expected_quota_digests {
            return Err(ModelError::ScopeMismatch {
                field: "request quota allowlist",
            });
        }
        if self.max_results == 0
            || self.max_results > PAGE_SIZE
            || self.max_pages != MAX_PAGES
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || self.max_requests != MAX_REQUESTS_PER_READ
            || self.max_retries != MAX_RETRIES
            || self.page_number == 0
            || self.page_number > self.max_pages
        {
            return Err(ModelError::Invalid {
                field: "bounded read request",
            });
        }
        if let Some(quota) = &self.quota
            && !scope.allows(quota)
        {
            return Err(ModelError::ScopeMismatch {
                field: "request quota",
            });
        }
        if let Some(cursor) = &self.cursor
            && (cursor.binding_digest() != &self.filter_digest
                || cursor.page_number() != self.page_number)
        {
            return Err(ModelError::ScopeMismatch {
                field: "request cursor",
            });
        }
        let expected_request_digest = Digest::from_parts(
            "hartevo-aws-service-quota-request/v1",
            &[
                self.filter_digest.to_string(),
                self.page_number.to_string(),
                self.cursor
                    .as_ref()
                    .map_or_else(String::new, |value| value.token_digest().to_string()),
            ],
        );
        if self.request_digest != expected_request_digest {
            return Err(ModelError::ScopeMismatch {
                field: "request digest",
            });
        }
        if self.filter_digest
            != Self::build(
                scope,
                self.operation,
                self.quota.clone(),
                self.applied_at_level,
                self.history_window.clone(),
                self.max_results,
                None,
                self.observed_at,
            )?
            .filter_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "request filter digest",
            });
        }
        Ok(())
    }

    pub fn is_paginated(&self) -> bool {
        matches!(
            self.operation,
            AwsServiceQuotaOperation::ListServiceQuotas
                | AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota
        )
    }
}

impl fmt::Debug for AwsServiceQuotaReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsServiceQuotaReadRequest")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("service_code", &self.service_code)
            .field("quota", &self.quota)
            .field("allowed_quota_digests", &self.allowed_quota_digests)
            .field("applied_at_level", &self.applied_at_level)
            .field("history_window", &self.history_window)
            .field("max_results", &self.max_results)
            .field("max_pages", &self.max_pages)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_requests", &self.max_requests)
            .field("max_retries", &self.max_retries)
            .field("observed_at", &self.observed_at)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("filter_digest", &self.filter_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

macro_rules! request_wrapper {
    ($name:ident, $constructor:ident, ($($arg:ident : $ty:ty),* $(,)?)) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            inner: AwsServiceQuotaReadRequest,
        }

        impl $name {
            pub fn new($($arg: $ty),*) -> Result<Self, ModelError> {
                Ok(Self { inner: AwsServiceQuotaReadRequest::$constructor($($arg),*)? })
            }

            pub fn as_inner(&self) -> &AwsServiceQuotaReadRequest {
                &self.inner
            }

            pub fn into_inner(self) -> AwsServiceQuotaReadRequest {
                self.inner
            }
        }

        impl Deref for $name {
            type Target = AwsServiceQuotaReadRequest;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl From<$name> for AwsServiceQuotaReadRequest {
            fn from(value: $name) -> Self {
                value.inner
            }
        }
    };
}

request_wrapper!(
    ListServiceQuotasRequest,
    list_service_quotas,
    (scope: &AwsServiceQuotaScope, max_results: u16, cursor: Option<OpaqueCursor>)
);
request_wrapper!(
    GetServiceQuotaRequest,
    get_service_quota,
    (scope: &AwsServiceQuotaScope, quota: ServiceQuotaIdentity)
);
request_wrapper!(
    GetAWSDefaultServiceQuotaRequest,
    get_aws_default_service_quota,
    (scope: &AwsServiceQuotaScope, quota: ServiceQuotaIdentity)
);
request_wrapper!(
    ListRequestedServiceQuotaChangeHistoryByQuotaRequest,
    list_requested_service_quota_change_history_by_quota,
    (
        scope: &AwsServiceQuotaScope,
        quota: ServiceQuotaIdentity,
        history_window: HistoryWindow,
        max_results: u16,
        cursor: Option<OpaqueCursor>
    )
);

pub type ServiceQuotaRequest = AwsServiceQuotaReadRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaReadPage {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub operation: AwsServiceQuotaOperation,
    pub provider_revision: ProviderRevision,
    pub page_number: u16,
    pub observations: Vec<QuotaPostureDigest>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsServiceQuotaReadPage {
    pub fn new(
        request: &AwsServiceQuotaReadRequest,
        observations: Vec<QuotaPostureDigest>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        Self::new_with_provider_revision(
            request,
            observations,
            next_cursor,
            response_bytes,
            provenance,
            ProviderRevision::new("aws-service-quotas-read-r1")?,
        )
    }

    pub fn new_with_provider_revision(
        request: &AwsServiceQuotaReadRequest,
        observations: Vec<QuotaPostureDigest>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if response_bytes == 0 || response_bytes > request.max_response_bytes {
            return Err(ModelError::Invalid {
                field: "provider response bytes",
            });
        }
        if observations.len() > usize::from(request.max_results) {
            return Err(ModelError::TooMany {
                field: "quota observations per page",
            });
        }
        if !request.is_paginated() && observations.len() > 1 {
            return Err(ModelError::TooMany {
                field: "single quota observations",
            });
        }
        for observation in &observations {
            observation.validate()?;
            if !request
                .allowed_quota_digests
                .iter()
                .any(|digest| digest == &observation.quota_identity_digest)
            {
                return Err(ModelError::ScopeMismatch {
                    field: "quota observation allowlist",
                });
            }
            if let Some(quota) = &request.quota
                && quota.digest() != observation.quota_identity_digest
            {
                return Err(ModelError::ScopeMismatch {
                    field: "quota observation selector",
                });
            }
        }
        if let Some(cursor) = &next_cursor
            && (cursor.binding_digest() != &request.filter_digest
                || cursor.page_number() != request.page_number.saturating_add(1))
        {
            return Err(ModelError::ScopeMismatch {
                field: "next cursor binding",
            });
        }
        let mut page = Self {
            scope_digest: request.scope_digest.clone(),
            filter_digest: request.filter_digest.clone(),
            request_digest: request.request_digest.clone(),
            operation: request.operation,
            provider_revision,
            page_number: request.page_number,
            observations,
            next_cursor,
            response_bytes,
            provenance,
            page_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn with_declared_digest(mut self, page_digest: Digest) -> Self {
        self.page_digest = page_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(
        &self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<(), ModelError> {
        if self.scope_digest != request.scope_digest
            || self.filter_digest != request.filter_digest
            || self.request_digest != request.request_digest
            || self.operation != request.operation
            || self.provider_revision.as_str().is_empty()
            || self.page_number != request.page_number
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.page_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "provider page integrity",
            });
        }
        if self.observations.len() > usize::from(request.max_results)
            || (!request.is_paginated() && self.observations.len() > 1)
        {
            return Err(ModelError::TooMany {
                field: "provider page observations",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && (cursor.binding_digest() != &request.filter_digest
                || cursor.page_number() != request.page_number.saturating_add(1))
        {
            return Err(ModelError::ScopeMismatch {
                field: "next cursor binding",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
            if !request
                .allowed_quota_digests
                .iter()
                .any(|digest| digest == &observation.quota_identity_digest)
            {
                return Err(ModelError::ScopeMismatch {
                    field: "quota observation allowlist",
                });
            }
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-page/v1",
            &[
                self.scope_digest.to_string(),
                self.filter_digest.to_string(),
                self.request_digest.to_string(),
                self.operation.api_name().to_owned(),
                self.provider_revision.as_str().to_owned(),
                self.page_number.to_string(),
                self.observations
                    .iter()
                    .map(|value| value.posture_digest.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.next_cursor
                    .as_ref()
                    .map_or_else(String::new, |value| value.token_digest().to_string()),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

pub type AwsServiceQuotaPage = AwsServiceQuotaReadPage;
pub type ServiceQuotaReadPage = AwsServiceQuotaReadPage;

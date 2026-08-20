//! Typed, redacted AWS ACM certificate scope and metadata projections.
//!
//! The model deliberately has no representation for private keys, certificate
//! bytes, validation records, DNS/email tokens, or account PII in evidence.
//! Raw certificate names are accepted only at the input edge and are reduced
//! to digests before a provider response is retained.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_SAN_ENTRIES: usize = 100;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains control characters or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not an opaque bounded cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked")]
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
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@*".contains(&byte)))
    {
        return Err(ModelError::InvalidCharacters { field });
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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
        let mut encoded = Vec::new();
        append_part(&mut encoded, domain);
        for (name, value) in fields {
            append_part(&mut encoded, name);
            append_part(&mut encoded, value);
        }
        Self::from_bytes(&encoded)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest { field: "digest" })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest { field: "digest" })
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

fn append_part(buffer: &mut Vec<u8>, value: &str) {
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
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

identifier_type!(DeploymentId, "deployment id");
identifier_type!(MissionId, "Mission id");
identifier_type!(ProjectId, "Project id");
identifier_type!(WorkProductId, "Work Product id");
identifier_type!(PermissionId, "permission id");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-acm-account/v1", &[("value", self.0.clone())])
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

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("AccountId", 1)?;
        object.serialize_field("digest", &self.digest())?;
        object.end()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "AWS region")?;
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

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-acm-region/v1", &[("value", self.0.clone())])
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificateArn(String);

impl CertificateArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "certificate ARN", MAX_ARN_BYTES)?;
        if !value.starts_with("arn:aws:acm:") {
            return Err(ModelError::Invalid {
                field: "certificate ARN",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-acm-certificate-arn/v1", &[("value", self.0.clone())])
    }
}

impl fmt::Debug for CertificateArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateArn")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for CertificateArn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("CertificateArn", 1)?;
        object.serialize_field("digest", &self.digest())?;
        object.end()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DomainName(String);

impl DomainName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().trim().to_ascii_lowercase();
        validate_text(&value, "certificate domain", MAX_DOMAIN_BYTES)?;
        if value.starts_with("*.") {
            if value.len() <= 2 {
                return Err(ModelError::Invalid {
                    field: "certificate domain",
                });
            }
        } else if value.contains('*') {
            return Err(ModelError::InvalidCharacters {
                field: "certificate domain",
            });
        }
        if value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-._*".contains(&byte)))
        {
            return Err(ModelError::InvalidCharacters {
                field: "certificate domain",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-acm-domain/v1", &[("value", self.0.clone())])
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DomainName")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for DomainName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("DomainName", 1)?;
        object.serialize_field("digest", &self.digest())?;
        object.end()
    }
}

#[derive(Clone, Debug, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateStatus {
    PendingValidation,
    Issued,
    Inactive,
    Expired,
    ValidationTimedOut,
    Revoked,
    Failed,
}

impl CertificateStatus {
    pub const fn is_issued(self) -> bool {
        matches!(self, Self::Issued)
    }
}

#[derive(Clone, Debug, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateIssuer {
    Amazon,
    AmazonPrivateCa,
    Unknown,
}

#[derive(Clone, Debug, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcPrime256V1,
    EcSecP384R1,
    EcSecP521R1,
    Unknown,
}

#[derive(Clone, Debug, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyUsage {
    Any,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    Unknown,
}

#[derive(Clone, Debug, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RenewalEligibility {
    Eligible,
    Ineligible,
    Unknown,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CertificateIdentity {
    arn: CertificateArn,
    domain: DomainName,
    san_digests: Vec<Digest>,
}

impl CertificateIdentity {
    pub fn new(
        arn: CertificateArn,
        domain: DomainName,
        sans: impl IntoIterator<Item = String>,
    ) -> Result<Self, ModelError> {
        let mut san_digests = Vec::new();
        let mut seen = BTreeSet::new();
        for san in sans {
            let san = DomainName::new(san)?;
            let digest = san.digest();
            if !seen.insert(digest.clone()) {
                return Err(ModelError::Duplicate {
                    field: "subject alternative name",
                });
            }
            san_digests.push(digest);
        }
        if san_digests.len() > MAX_SAN_ENTRIES {
            return Err(ModelError::TooMany {
                field: "subject alternative names",
            });
        }
        san_digests.sort();
        Ok(Self {
            arn,
            domain,
            san_digests,
        })
    }

    pub fn arn(&self) -> &CertificateArn {
        &self.arn
    }

    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    pub fn arn_digest(&self) -> Digest {
        self.arn.digest()
    }

    pub fn domain_digest(&self) -> Digest {
        self.domain.digest()
    }

    pub fn san_digests(&self) -> &[Digest] {
        &self.san_digests
    }

    pub fn certificate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-certificate-identity/v1",
            &[
                ("arn", self.arn_digest().as_str().to_owned()),
                ("domain", self.domain_digest().as_str().to_owned()),
                (
                    "sans",
                    self.san_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }

    pub fn matches_scope(&self, scope: &AwsAcmCertificateScope) -> bool {
        self.arn_digest() == scope.certificate.arn_digest()
            && self.domain_digest() == scope.certificate.domain_digest()
            && self.san_digests == scope.certificate.san_digests
    }
}

impl fmt::Debug for CertificateIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateIdentity")
            .field("arn_digest", &self.arn_digest())
            .field("domain_digest", &self.domain_digest())
            .field("san_digests", &self.san_digests)
            .finish()
    }
}

impl Serialize for CertificateIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("CertificateIdentity", 3)?;
        object.serialize_field("arnDigest", &self.arn_digest())?;
        object.serialize_field("domainDigest", &self.domain_digest())?;
        object.serialize_field("sanDigests", &self.san_digests)?;
        object.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmCertificateScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account: AccountId,
    pub region: AwsRegion,
    pub certificate: CertificateIdentity,
    pub certificate_revision: Revision,
    pub permission_digest: Digest,
}

impl AwsAcmCertificateScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account: AccountId,
        region: AwsRegion,
        certificate: CertificateIdentity,
        certificate_revision: Revision,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account,
            region,
            certificate,
            certificate_revision,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        CertificateArn::new(self.certificate.arn.as_str().to_owned())?;
        DomainName::new(self.certificate.domain.as_str().to_owned())?;
        if self.certificate.san_digests.len() > MAX_SAN_ENTRIES {
            return Err(ModelError::TooMany {
                field: "subject alternative names",
            });
        }
        for digest in &self.certificate.san_digests {
            digest.validate()?;
        }
        if self.certificate_revision.get() == 0 {
            return Err(ModelError::MustBePositive {
                field: "certificate revision",
            });
        }
        self.permission_digest.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-scope/v1",
            &[
                ("deployment", self.deployment.id.as_str().to_owned()),
                (
                    "deployment_revision",
                    self.deployment.revision.get().to_string(),
                ),
                ("mission", self.mission.id.as_str().to_owned()),
                ("mission_revision", self.mission.revision.get().to_string()),
                ("project", self.project.id.as_str().to_owned()),
                ("project_revision", self.project.revision.get().to_string()),
                ("work_product", self.work_product.id.as_str().to_owned()),
                (
                    "work_product_revision",
                    self.work_product.revision.get().to_string(),
                ),
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "certificate",
                    self.certificate.certificate_digest().as_str().to_owned(),
                ),
                (
                    "certificate_revision",
                    self.certificate_revision.get().to_string(),
                ),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn certificate_digest(&self) -> Digest {
        self.certificate.certificate_digest()
    }
}

pub type AwsAcmScope = AwsAcmCertificateScope;

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    scope_digest: Digest,
    region: AwsRegion,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn sigv4(
        reference: impl AsRef<str>,
        scope: &AwsAcmCertificateScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let value = reference.as_ref();
        validate_identifier(value, "SigV4 secret reference")?;
        let revision = Revision::new(revision)?;
        Ok(Self {
            digest: Digest::from_parts(
                "aws-acm-sigv4-secret/v1",
                &[
                    ("reference", value.to_owned()),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("region", scope.region.digest().as_str().to_owned()),
                    ("revision", revision.get().to_string()),
                ],
            ),
            scope_digest: scope.digest(),
            region: scope.region.clone(),
            revision,
            revoked: false,
        })
    }

    pub fn new(
        reference: impl AsRef<str>,
        scope: &AwsAcmCertificateScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::sigv4(reference, scope, revision)
    }

    pub fn for_acm(
        reference: impl AsRef<str>,
        scope: &AwsAcmCertificateScope,
    ) -> Result<Self, ModelError> {
        Self::sigv4(reference, scope, 1)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn signing_service(&self) -> &'static str {
        "acm"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self, scope: &AwsAcmCertificateScope) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::ScopeMismatch {
                field: "revoked secret reference",
            });
        }
        if self.scope_digest != scope.digest() || self.region != scope.region {
            return Err(ModelError::ScopeMismatch {
                field: "secret reference scope",
            });
        }
        self.digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &self.signing_service())
            .field("signing_region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    ListCertificates,
    SearchCertificates,
    DescribeCertificate,
}

impl PermissionAction {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ListCertificates => "acm:ListCertificates",
            Self::SearchCertificates => "acm:SearchCertificates",
            Self::DescribeCertificate => "acm:DescribeCertificate",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
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
            allowed_actions: [
                PermissionAction::ListCertificates,
                PermissionAction::SearchCertificates,
                PermissionAction::DescribeCertificate,
            ]
            .into_iter()
            .collect(),
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

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-permission/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                (
                    "actions",
                    self.allowed_actions
                        .iter()
                        .map(|action| action.api_name())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AcmOperation {
    ListCertificates,
    SearchCertificates,
    DescribeCertificate,
}

impl AcmOperation {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ListCertificates => "ListCertificates",
            Self::SearchCertificates => "SearchCertificates",
            Self::DescribeCertificate => "DescribeCertificate",
        }
    }

    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::ListCertificates => PermissionAction::ListCertificates,
            Self::SearchCertificates => PermissionAction::SearchCertificates,
            Self::DescribeCertificate => PermissionAction::DescribeCertificate,
        }
    }
}

#[derive(Clone, Debug, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
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
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCertificatesFilter {
    pub statuses: BTreeSet<CertificateStatus>,
    pub key_algorithms: BTreeSet<KeyAlgorithm>,
    pub key_usages: BTreeSet<KeyUsage>,
    pub page_size: u16,
}

impl ListCertificatesFilter {
    pub fn all(page_size: u16) -> Result<Self, ModelError> {
        let filter = Self {
            statuses: BTreeSet::new(),
            key_algorithms: BTreeSet::new(),
            key_usages: BTreeSet::new(),
            page_size,
        };
        filter.validate()?;
        Ok(filter)
    }

    pub fn new(
        statuses: impl IntoIterator<Item = CertificateStatus>,
        key_algorithms: impl IntoIterator<Item = KeyAlgorithm>,
        key_usages: impl IntoIterator<Item = KeyUsage>,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        let filter = Self {
            statuses: statuses.into_iter().collect(),
            key_algorithms: key_algorithms.into_iter().collect(),
            key_usages: key_usages.into_iter().collect(),
            page_size,
        };
        filter.validate()?;
        Ok(filter)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(ModelError::Invalid {
                field: "ListCertificates page size",
            });
        }
        if self.statuses.len() > 7 || self.key_algorithms.len() > 7 || self.key_usages.len() > 8 {
            return Err(ModelError::TooMany {
                field: "allowlisted certificate filters",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-list-filter/v1",
            &[
                (
                    "statuses",
                    self.statuses
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "key_algorithms",
                    self.key_algorithms
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "key_usages",
                    self.key_usages
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("page_size", self.page_size.to_string()),
            ],
        )
    }

    pub fn allows(&self, projection: &CertificateProjection) -> bool {
        (self.statuses.is_empty() || self.statuses.contains(&projection.status))
            && (self.key_algorithms.is_empty()
                || self.key_algorithms.contains(&projection.key_algorithm))
            && (self.key_usages.is_empty()
                || projection
                    .key_usages
                    .iter()
                    .any(|usage| self.key_usages.contains(usage)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchCertificatesFilter {
    pub exact_domain: DomainName,
    pub statuses: BTreeSet<CertificateStatus>,
    pub key_algorithms: BTreeSet<KeyAlgorithm>,
    pub key_usages: BTreeSet<KeyUsage>,
    pub page_size: u16,
}

impl SearchCertificatesFilter {
    pub fn for_domain(domain: DomainName, page_size: u16) -> Result<Self, ModelError> {
        Self::new(domain, [], [], [], page_size)
    }

    pub fn new(
        exact_domain: DomainName,
        statuses: impl IntoIterator<Item = CertificateStatus>,
        key_algorithms: impl IntoIterator<Item = KeyAlgorithm>,
        key_usages: impl IntoIterator<Item = KeyUsage>,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        let filter = Self {
            exact_domain,
            statuses: statuses.into_iter().collect(),
            key_algorithms: key_algorithms.into_iter().collect(),
            key_usages: key_usages.into_iter().collect(),
            page_size,
        };
        filter.validate()?;
        Ok(filter)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(ModelError::Invalid {
                field: "SearchCertificates page size",
            });
        }
        if self.statuses.len() > 7 || self.key_algorithms.len() > 7 || self.key_usages.len() > 8 {
            return Err(ModelError::TooMany {
                field: "allowlisted certificate filters",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-search-filter/v1",
            &[
                ("domain", self.exact_domain.digest().as_str().to_owned()),
                (
                    "statuses",
                    self.statuses
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "key_algorithms",
                    self.key_algorithms
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "key_usages",
                    self.key_usages
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("page_size", self.page_size.to_string()),
            ],
        )
    }

    pub fn allows(&self, projection: &CertificateProjection) -> bool {
        projection.domain_digest == self.exact_domain.digest()
            && (self.statuses.is_empty() || self.statuses.contains(&projection.status))
            && (self.key_algorithms.is_empty()
                || self.key_algorithms.contains(&projection.key_algorithm))
            && (self.key_usages.is_empty()
                || projection
                    .key_usages
                    .iter()
                    .any(|usage| self.key_usages.contains(usage)))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueNextToken {
    token_digest: Digest,
    operation: AcmOperation,
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
}

impl OpaqueNextToken {
    pub fn for_request(
        raw_token: impl AsRef<str>,
        operation: AcmOperation,
        scope: &AwsAcmCertificateScope,
        filter_digest: Digest,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        validate_text(raw_token, "provider NextToken", MAX_CURSOR_BYTES)?;
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::InvalidCursor {
                field: "provider NextToken page",
            });
        }
        filter_digest.validate()?;
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-acm-next-token/v1",
                &[
                    ("operation", operation.api_name().to_owned()),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter_digest.as_str().to_owned()),
                    ("token", raw_token.to_owned()),
                ],
            ),
            operation,
            scope_digest: scope.digest(),
            filter_digest,
            page_number,
        })
    }

    pub fn new(raw_token: impl AsRef<str>) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        validate_text(raw_token, "provider NextToken", MAX_CURSOR_BYTES)?;
        let filter_digest = Digest::from_text("unbound-acm-filter");
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-acm-unbound-next-token/v1",
                &[("token", raw_token.to_owned())],
            ),
            operation: AcmOperation::ListCertificates,
            scope_digest: Digest::from_text("unbound-acm-scope"),
            filter_digest,
            page_number: 1,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn validate_for(
        &self,
        operation: AcmOperation,
        scope: &AwsAcmCertificateScope,
        filter_digest: &Digest,
        expected_page: u16,
    ) -> Result<(), ModelError> {
        if self.operation != operation
            || self.scope_digest != scope.digest()
            || &self.filter_digest != filter_digest
            || self.page_number != expected_page
        {
            return Err(ModelError::ScopeMismatch {
                field: "opaque NextToken binding",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for OpaqueNextToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueNextToken")
            .field("token_digest", &self.token_digest)
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaqueNextToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("OpaqueNextToken", 1)?;
        object.serialize_field("opaque", &true)?;
        object.end()
    }
}

pub type OpaquePageToken = OpaqueNextToken;

/// Raw provider fields are accepted only at this constructor boundary. The
/// resulting retained projection contains digests and bounded metadata only.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateDescriptionInput {
    certificate_arn: String,
    domain: String,
    subject_alternative_names: Vec<String>,
    status: CertificateStatus,
    issuer: CertificateIssuer,
    key_algorithm: KeyAlgorithm,
    key_usages: BTreeSet<KeyUsage>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    renewal_eligibility: RenewalEligibility,
    in_use: bool,
    certificate_revision: Revision,
    observed_at: DateTime<Utc>,
}

impl CertificateDescriptionInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_arn: impl Into<String>,
        domain: impl Into<String>,
        subject_alternative_names: impl IntoIterator<Item = String>,
        status: CertificateStatus,
        issuer: CertificateIssuer,
        key_algorithm: KeyAlgorithm,
        key_usages: impl IntoIterator<Item = KeyUsage>,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
        renewal_eligibility: RenewalEligibility,
        in_use: bool,
        certificate_revision: Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let subject_alternative_names = subject_alternative_names.into_iter().collect::<Vec<_>>();
        if subject_alternative_names.len() > MAX_SAN_ENTRIES {
            return Err(ModelError::TooMany {
                field: "subject alternative names",
            });
        }
        let key_usages = key_usages.into_iter().collect::<BTreeSet<_>>();
        if key_usages.is_empty() {
            return Err(ModelError::Empty {
                field: "certificate key usage",
            });
        }
        let input = Self {
            certificate_arn: certificate_arn.into(),
            domain: domain.into(),
            subject_alternative_names,
            status,
            issuer,
            key_algorithm,
            key_usages,
            not_before,
            not_after,
            renewal_eligibility,
            in_use,
            certificate_revision,
            observed_at,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn issued(
        certificate_arn: impl Into<String>,
        domain: impl Into<String>,
        subject_alternative_names: impl IntoIterator<Item = String>,
        observed_at: DateTime<Utc>,
        certificate_revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            certificate_arn,
            domain,
            subject_alternative_names,
            CertificateStatus::Issued,
            CertificateIssuer::Amazon,
            KeyAlgorithm::Rsa2048,
            [KeyUsage::ServerAuth],
            Some(observed_at),
            Some(observed_at + chrono::Duration::days(90)),
            RenewalEligibility::Eligible,
            true,
            certificate_revision,
            observed_at,
        )
    }

    pub fn pending_validation(
        certificate_arn: impl Into<String>,
        domain: impl Into<String>,
        subject_alternative_names: impl IntoIterator<Item = String>,
        observed_at: DateTime<Utc>,
        certificate_revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            certificate_arn,
            domain,
            subject_alternative_names,
            CertificateStatus::PendingValidation,
            CertificateIssuer::Amazon,
            KeyAlgorithm::Rsa2048,
            [KeyUsage::ServerAuth],
            None,
            None,
            RenewalEligibility::Unknown,
            false,
            certificate_revision,
            observed_at,
        )
    }

    fn validate(&self) -> Result<(), ModelError> {
        CertificateArn::new(self.certificate_arn.clone())?;
        DomainName::new(self.domain.clone())?;
        let mut seen = BTreeSet::new();
        for san in &self.subject_alternative_names {
            let digest = DomainName::new(san.clone())?.digest();
            if !seen.insert(digest) {
                return Err(ModelError::Duplicate {
                    field: "subject alternative name",
                });
            }
        }
        if self.certificate_revision.get() == 0 {
            return Err(ModelError::MustBePositive {
                field: "certificate revision",
            });
        }
        if let (Some(not_before), Some(not_after)) = (self.not_before, self.not_after)
            && not_before >= not_after
        {
            return Err(ModelError::Invalid {
                field: "certificate validity window",
            });
        }
        if self.status == CertificateStatus::Issued
            && (self.not_before.is_none() || self.not_after.is_none())
        {
            return Err(ModelError::Invalid {
                field: "issued certificate validity window",
            });
        }
        Ok(())
    }

    pub fn certificate_arn(&self) -> &str {
        &self.certificate_arn
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn subject_alternative_names(&self) -> &[String] {
        &self.subject_alternative_names
    }

    pub fn status(&self) -> CertificateStatus {
        self.status
    }

    pub fn issuer(&self) -> CertificateIssuer {
        self.issuer
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        self.key_algorithm
    }

    pub fn key_usages(&self) -> &BTreeSet<KeyUsage> {
        &self.key_usages
    }

    pub fn not_before(&self) -> Option<DateTime<Utc>> {
        self.not_before
    }

    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        self.not_after
    }

    pub fn renewal_eligibility(&self) -> RenewalEligibility {
        self.renewal_eligibility
    }

    pub const fn in_use(&self) -> bool {
        self.in_use
    }

    pub const fn certificate_revision(&self) -> Revision {
        self.certificate_revision
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl fmt::Debug for CertificateDescriptionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateDescriptionInput")
            .field(
                "certificate_arn_digest",
                &Digest::from_text(&self.certificate_arn),
            )
            .field("domain_digest", &Digest::from_text(&self.domain))
            .field("san_count", &self.subject_alternative_names.len())
            .field("status", &self.status)
            .field("issuer", &self.issuer)
            .field("key_algorithm", &self.key_algorithm)
            .field("key_usages", &self.key_usages)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("renewal_eligibility", &self.renewal_eligibility)
            .field("in_use", &self.in_use)
            .field("certificate_revision", &self.certificate_revision)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProjection {
    pub certificate_arn_digest: Digest,
    pub domain_digest: Digest,
    pub san_digests: Vec<Digest>,
    pub status: CertificateStatus,
    pub issuer: CertificateIssuer,
    pub key_algorithm: KeyAlgorithm,
    pub key_usages: BTreeSet<KeyUsage>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub renewal_eligibility: RenewalEligibility,
    pub in_use: bool,
    pub certificate_revision: Revision,
    pub observed_at: DateTime<Utc>,
    pub certificate_digest: Digest,
}

impl CertificateProjection {
    pub fn from_input(input: &CertificateDescriptionInput) -> Result<Self, ModelError> {
        let arn = CertificateArn::new(input.certificate_arn.clone())?;
        let domain = DomainName::new(input.domain.clone())?;
        let identity =
            CertificateIdentity::new(arn, domain, input.subject_alternative_names.clone())?;
        let mut projection = Self {
            certificate_arn_digest: identity.arn_digest(),
            domain_digest: identity.domain_digest(),
            san_digests: identity.san_digests.clone(),
            status: input.status,
            issuer: input.issuer,
            key_algorithm: input.key_algorithm,
            key_usages: input.key_usages.clone(),
            not_before: input.not_before,
            not_after: input.not_after,
            renewal_eligibility: input.renewal_eligibility,
            in_use: input.in_use,
            certificate_revision: input.certificate_revision,
            observed_at: input.observed_at,
            certificate_digest: Digest::zero(),
        };
        projection.certificate_digest = projection.recomputed_digest();
        Ok(projection)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-certificate-projection/v1",
            &[
                ("arn", self.certificate_arn_digest.as_str().to_owned()),
                ("domain", self.domain_digest.as_str().to_owned()),
                (
                    "sans",
                    self.san_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("status", format!("{:?}", self.status)),
                ("issuer", format!("{:?}", self.issuer)),
                ("key_algorithm", format!("{:?}", self.key_algorithm)),
                (
                    "key_usages",
                    self.key_usages
                        .iter()
                        .map(|usage| format!("{usage:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "not_before",
                    self.not_before
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "not_after",
                    self.not_after
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "renewal_eligibility",
                    format!("{:?}", self.renewal_eligibility),
                ),
                ("in_use", self.in_use.to_string()),
                (
                    "certificate_revision",
                    self.certificate_revision.get().to_string(),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        self.certificate_arn_digest.validate()?;
        self.domain_digest.validate()?;
        if self.san_digests.len() > MAX_SAN_ENTRIES {
            return Err(ModelError::TooMany {
                field: "subject alternative names",
            });
        }
        for digest in &self.san_digests {
            digest.validate()?;
        }
        if self.certificate_revision.get() == 0 {
            return Err(ModelError::MustBePositive {
                field: "certificate revision",
            });
        }
        if self.key_usages.is_empty() {
            return Err(ModelError::Empty {
                field: "certificate key usage",
            });
        }
        if let (Some(not_before), Some(not_after)) = (self.not_before, self.not_after)
            && not_before >= not_after
        {
            return Err(ModelError::Invalid {
                field: "certificate validity window",
            });
        }
        if self.certificate_digest != self.recomputed_digest() {
            return Err(ModelError::Invalid {
                field: "certificate projection digest",
            });
        }
        Ok(())
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn arn_digest(&self) -> &Digest {
        &self.certificate_arn_digest
    }

    pub fn domain_digest(&self) -> &Digest {
        &self.domain_digest
    }

    pub fn san_digests(&self) -> &[Digest] {
        &self.san_digests
    }

    pub fn usages(&self) -> &BTreeSet<KeyUsage> {
        &self.key_usages
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSummary {
    pub projection: CertificateProjection,
}

impl CertificateSummary {
    pub fn from_input(input: &CertificateDescriptionInput) -> Result<Self, ModelError> {
        Ok(Self {
            projection: CertificateProjection::from_input(input)?,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        self.projection.validate_integrity()
    }

    pub fn projection(&self) -> &CertificateProjection {
        &self.projection
    }
}

impl Serialize for CertificateSummary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.projection.serialize(serializer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateDescription {
    pub projection: CertificateProjection,
}

impl CertificateDescription {
    pub fn from_input(input: &CertificateDescriptionInput) -> Result<Self, ModelError> {
        Ok(Self {
            projection: CertificateProjection::from_input(input)?,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        self.projection.validate_integrity()
    }

    pub fn projection(&self) -> &CertificateProjection {
        &self.projection
    }
}

pub type CertificateMetadata = CertificateProjection;
pub type CertificateSummaryInput = CertificateDescriptionInput;

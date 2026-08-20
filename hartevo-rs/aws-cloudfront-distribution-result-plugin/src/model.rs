use std::{collections::BTreeSet, fmt, fmt::Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsCloudFrontDistributionError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_ALIAS_COUNT, MAX_BEHAVIOR_COUNT, MAX_IDENTIFIER_BYTES,
    MAX_ORIGIN_COUNT, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
};

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
            Err(AwsCloudFrontDistributionError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsCloudFrontDistributionError::InvalidDigest)
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

fn valid_domain(value: &str) -> bool {
    valid_text(value, 512, false)
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
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
                    Err(AwsCloudFrontDistributionError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-cloudfront-", $field, "/v1"),
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
                    Err(AwsCloudFrontDistributionError::InvalidIdentifier { field: $field })
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
    };
}

redacted_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_text!(DistributionId, "distribution-id", |value: &str| {
    (1..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
});
redacted_text!(DistributionArn, "distribution-arn", valid_arn);
redacted_text!(DomainName, "domain-name", valid_domain);

#[derive(Clone, Eq, PartialEq)]
pub struct DistributionIdentity {
    id: DistributionId,
    arn: DistributionArn,
    domain_name: DomainName,
}

impl DistributionIdentity {
    pub fn new(id: DistributionId, arn: DistributionArn, domain_name: DomainName) -> Result<Self> {
        let identity = Self {
            id,
            arn,
            domain_name,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn id(&self) -> &DistributionId {
        &self.id
    }

    pub fn arn(&self) -> &DistributionArn {
        &self.arn
    }

    pub fn domain_name(&self) -> &DomainName {
        &self.domain_name
    }

    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    pub fn arn_digest(&self) -> Digest {
        self.arn.digest()
    }

    pub fn domain_name_digest(&self) -> Digest {
        self.domain_name.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-distribution-identity/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("arn", self.arn_digest().as_str().to_owned()),
                ("domain", self.domain_name_digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn.validate()?;
        self.domain_name.validate()
    }
}

impl fmt::Debug for DistributionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributionIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConfigRevision {
    value: String,
    digest: Digest,
}

impl ConfigRevision {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsCloudFrontDistributionError::InvalidText {
                field: "config-revision",
            });
        }
        Ok(Self {
            digest: Digest::from_parts(
                "aws-cloudfront-config-revision/v1",
                &[("value", value.clone())],
            ),
            value,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ConfigRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigRevision")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataDigestFences {
    pub aliases_digest: Option<Digest>,
    pub origins_digest: Option<Digest>,
    pub cache_behaviors_digest: Option<Digest>,
    pub tls_digest: Option<Digest>,
    pub waf_digest: Option<Digest>,
}

impl MetadataDigestFences {
    pub fn none() -> Self {
        Self {
            aliases_digest: None,
            origins_digest: None,
            cache_behaviors_digest: None,
            tls_digest: None,
            waf_digest: None,
        }
    }

    pub fn new(
        aliases_digest: Option<Digest>,
        origins_digest: Option<Digest>,
        cache_behaviors_digest: Option<Digest>,
        tls_digest: Option<Digest>,
        waf_digest: Option<Digest>,
    ) -> Result<Self> {
        let fences = Self {
            aliases_digest,
            origins_digest,
            cache_behaviors_digest,
            tls_digest,
            waf_digest,
        };
        fences.validate()?;
        Ok(fences)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-metadata-fences/v1",
            &[
                ("aliases", optional_digest(self.aliases_digest.as_ref())),
                ("origins", optional_digest(self.origins_digest.as_ref())),
                (
                    "cache_behaviors",
                    optional_digest(self.cache_behaviors_digest.as_ref()),
                ),
                ("tls", optional_digest(self.tls_digest.as_ref())),
                ("waf", optional_digest(self.waf_digest.as_ref())),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.aliases_digest,
            &self.origins_digest,
            &self.cache_behaviors_digest,
            &self.tls_digest,
            &self.waf_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }
}

fn optional_digest(value: Option<&Digest>) -> String {
    value.map_or_else(String::new, |digest| digest.as_str().to_owned())
}

macro_rules! revision_identity {
    ($name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsCloudFrontDistributionError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn id_digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-cloudfront-", $field, "-id/v1"),
                    &[("id", self.id.clone())],
                )
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id_digest().as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsCloudFrontDistributionError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id_digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

revision_identity!(MissionIdentity, "aws-cloudfront-mission/v1", "mission");
revision_identity!(ProjectIdentity, "aws-cloudfront-project/v1", "project");
revision_identity!(
    DeploymentIdentity,
    "aws-cloudfront-deployment/v1",
    "deployment"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AwsCloudFrontDistributionScope {
    account: AwsAccountId,
    region: AwsRegion,
    distribution: DistributionIdentity,
    expected_etag_digest: Option<Digest>,
    config_revision: ConfigRevision,
    metadata_fences: MetadataDigestFences,
    mission: MissionIdentity,
    project: ProjectIdentity,
    deployment: DeploymentIdentity,
}

impl AwsCloudFrontDistributionScope {
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        distribution: DistributionIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        deployment: DeploymentIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            distribution,
            expected_etag_digest: None,
            config_revision: ConfigRevision::new("unbound-layer1-config-revision")?,
            metadata_fences: MetadataDigestFences::none(),
            mission,
            project,
            deployment,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_distribution(
        account: AwsAccountId,
        region: AwsRegion,
        distribution: DistributionIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        deployment: DeploymentIdentity,
    ) -> Result<Self> {
        Self::new(account, region, distribution, mission, project, deployment)
    }

    pub fn with_configuration_fence(
        mut self,
        expected_etag: Option<impl Into<String>>,
        config_revision: ConfigRevision,
        metadata_fences: MetadataDigestFences,
    ) -> Result<Self> {
        self.expected_etag_digest = expected_etag
            .map(Into::into)
            .map(|etag| {
                if valid_text(&etag, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "aws-cloudfront-etag/v1",
                        &[("value", etag)],
                    ))
                } else {
                    Err(AwsCloudFrontDistributionError::InvalidText { field: "etag" })
                }
            })
            .transpose()?;
        self.config_revision = config_revision;
        self.metadata_fences = metadata_fences;
        self.validate()?;
        Ok(self)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn distribution(&self) -> &DistributionIdentity {
        &self.distribution
    }

    pub fn expected_etag_digest(&self) -> Option<&Digest> {
        self.expected_etag_digest.as_ref()
    }

    pub fn config_revision(&self) -> &ConfigRevision {
        &self.config_revision
    }

    pub fn metadata_fences(&self) -> &MetadataDigestFences {
        &self.metadata_fences
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn deployment(&self) -> &DeploymentIdentity {
        &self.deployment
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-distribution-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "distribution",
                    self.distribution.digest().as_str().to_owned(),
                ),
                ("etag", optional_digest(self.expected_etag_digest.as_ref())),
                (
                    "config_revision",
                    self.config_revision.digest().as_str().to_owned(),
                ),
                ("fences", self.metadata_fences.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("deployment", self.deployment.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.distribution.validate()?;
        self.expected_etag_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.config_revision.digest().validate()?;
        self.metadata_fences.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.deployment.validate()
    }
}

impl fmt::Debug for AwsCloudFrontDistributionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFrontDistributionScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("distribution", &self.distribution)
            .field("config_revision", &self.config_revision)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
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
            return Err(AwsCloudFrontDistributionError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-cloudfront-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-cloudfront-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsCloudFrontDistributionScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-cloudfront-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn kind(&self) -> SecretKind {
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

    pub(crate) fn validate(&self, scope: &AwsCloudFrontDistributionScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsCloudFrontDistributionError::InvalidSecretReference);
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
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

    pub const fn is_first_party(self) -> bool {
        false
    }
}

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
            "aws-cloudfront-permissions/v1",
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

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsCloudFrontDistributionError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
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
            "aws-cloudfront-consent/v1",
            &[
                ("id", self.id.clone()),
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

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.expires_at <= DateTime::<Utc>::MIN_UTC
        {
            Err(AwsCloudFrontDistributionError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionStatus {
    InProgress,
    Deployed,
    Unknown,
}

impl DistributionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Deployed => "deployed",
            Self::Unknown => "unknown",
        }
    }

    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ViewerCertificateInput {
    source: String,
    minimum_protocol_version: String,
    ssl_support_method: String,
    cloudfront_default_certificate: bool,
}

impl ViewerCertificateInput {
    pub fn new(
        source: impl Into<String>,
        minimum_protocol_version: impl Into<String>,
        ssl_support_method: impl Into<String>,
        cloudfront_default_certificate: bool,
    ) -> Result<Self> {
        let input = Self {
            source: source.into(),
            minimum_protocol_version: minimum_protocol_version.into(),
            ssl_support_method: ssl_support_method.into(),
            cloudfront_default_certificate,
        };
        input.validate()?;
        Ok(input)
    }

    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("certificate-source", self.source.as_str()),
            (
                "minimum-protocol-version",
                self.minimum_protocol_version.as_str(),
            ),
            ("ssl-support-method", self.ssl_support_method.as_str()),
        ] {
            if !valid_identifier(value, MAX_IDENTIFIER_BYTES) {
                return Err(AwsCloudFrontDistributionError::InvalidIdentifier { field });
            }
        }
        Ok(())
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-viewer-certificate/v1",
            &[
                (
                    "source",
                    Digest::from_text(&self.source).as_str().to_owned(),
                ),
                (
                    "minimum_protocol_version",
                    Digest::from_text(&self.minimum_protocol_version)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "ssl_support_method",
                    Digest::from_text(&self.ssl_support_method)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "cloudfront_default",
                    self.cloudfront_default_certificate.to_string(),
                ),
            ],
        )
    }
}

impl fmt::Debug for ViewerCertificateInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ViewerCertificateInput")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OriginMetadataInput {
    id: String,
    domain_name: String,
    protocol_policy: String,
    origin_access_control_id: Option<String>,
    connection_attempts: u8,
    connection_timeout_seconds: u8,
}

impl OriginMetadataInput {
    pub fn new(
        id: impl Into<String>,
        domain_name: impl Into<String>,
        protocol_policy: impl Into<String>,
        origin_access_control_id: Option<impl Into<String>>,
        connection_attempts: u8,
        connection_timeout_seconds: u8,
    ) -> Result<Self> {
        let input = Self {
            id: id.into(),
            domain_name: domain_name.into(),
            protocol_policy: protocol_policy.into(),
            origin_access_control_id: origin_access_control_id.map(Into::into),
            connection_attempts,
            connection_timeout_seconds,
        };
        input.validate()?;
        Ok(input)
    }

    fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || !valid_domain(&self.domain_name)
            || !valid_identifier(&self.protocol_policy, MAX_IDENTIFIER_BYTES)
            || self.connection_attempts == 0
            || self.connection_timeout_seconds == 0
            || self
                .origin_access_control_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsCloudFrontDistributionError::InvalidIdentifier {
                field: "origin-metadata",
            });
        }
        Ok(())
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-origin-metadata/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                (
                    "domain",
                    Digest::from_text(&self.domain_name).as_str().to_owned(),
                ),
                (
                    "protocol_policy",
                    Digest::from_text(&self.protocol_policy).as_str().to_owned(),
                ),
                (
                    "access_control",
                    self.origin_access_control_id
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            Digest::from_text(value).as_str().to_owned()
                        }),
                ),
                ("connection_attempts", self.connection_attempts.to_string()),
                (
                    "connection_timeout_seconds",
                    self.connection_timeout_seconds.to_string(),
                ),
            ],
        )
    }
}

impl fmt::Debug for OriginMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginMetadataInput")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CacheBehaviorMetadataInput {
    path_pattern: String,
    target_origin_id: String,
    viewer_protocol_policy: String,
    cache_policy_id: Option<String>,
    origin_request_policy_id: Option<String>,
    response_headers_policy_id: Option<String>,
}

impl CacheBehaviorMetadataInput {
    pub fn new(
        path_pattern: impl Into<String>,
        target_origin_id: impl Into<String>,
        viewer_protocol_policy: impl Into<String>,
        cache_policy_id: Option<impl Into<String>>,
        origin_request_policy_id: Option<impl Into<String>>,
        response_headers_policy_id: Option<impl Into<String>>,
    ) -> Result<Self> {
        let input = Self {
            path_pattern: path_pattern.into(),
            target_origin_id: target_origin_id.into(),
            viewer_protocol_policy: viewer_protocol_policy.into(),
            cache_policy_id: cache_policy_id.map(Into::into),
            origin_request_policy_id: origin_request_policy_id.map(Into::into),
            response_headers_policy_id: response_headers_policy_id.map(Into::into),
        };
        input.validate()?;
        Ok(input)
    }

    fn validate(&self) -> Result<()> {
        if !valid_text(&self.path_pattern, MAX_IDENTIFIER_BYTES, true)
            || !valid_identifier(&self.target_origin_id, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&self.viewer_protocol_policy, MAX_IDENTIFIER_BYTES)
            || [
                &self.cache_policy_id,
                &self.origin_request_policy_id,
                &self.response_headers_policy_id,
            ]
            .into_iter()
            .flatten()
            .any(|value| !valid_identifier(value, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsCloudFrontDistributionError::InvalidIdentifier {
                field: "cache-behavior-metadata",
            });
        }
        Ok(())
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-cache-behavior-metadata/v1",
            &[
                (
                    "path_pattern",
                    Digest::from_text(&self.path_pattern).as_str().to_owned(),
                ),
                (
                    "target_origin",
                    Digest::from_text(&self.target_origin_id)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "viewer_protocol_policy",
                    Digest::from_text(&self.viewer_protocol_policy)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "cache_policy",
                    self.cache_policy_id
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            Digest::from_text(value).as_str().to_owned()
                        }),
                ),
                (
                    "origin_request_policy",
                    self.origin_request_policy_id
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            Digest::from_text(value).as_str().to_owned()
                        }),
                ),
                (
                    "response_headers_policy",
                    self.response_headers_policy_id
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            Digest::from_text(value).as_str().to_owned()
                        }),
                ),
            ],
        )
    }
}

impl fmt::Debug for CacheBehaviorMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheBehaviorMetadataInput")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DistributionConfigInput {
    etag: String,
    config_revision: String,
    aliases: Vec<String>,
    origins: Vec<OriginMetadataInput>,
    cache_behaviors: Vec<CacheBehaviorMetadataInput>,
    viewer_certificate: ViewerCertificateInput,
    web_acl_id: Option<String>,
}

impl DistributionConfigInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        etag: impl Into<String>,
        config_revision: impl Into<String>,
        aliases: Vec<String>,
        origins: Vec<OriginMetadataInput>,
        cache_behaviors: Vec<CacheBehaviorMetadataInput>,
        viewer_certificate: ViewerCertificateInput,
        web_acl_id: Option<impl Into<String>>,
    ) -> Result<Self> {
        let input = Self {
            etag: etag.into(),
            config_revision: config_revision.into(),
            aliases,
            origins,
            cache_behaviors,
            viewer_certificate,
            web_acl_id: web_acl_id.map(Into::into),
        };
        input.validate()?;
        Ok(input)
    }

    fn validate(&self) -> Result<()> {
        if !valid_text(&self.etag, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&self.config_revision, MAX_IDENTIFIER_BYTES, true)
            || self.aliases.len() > MAX_ALIAS_COUNT
            || self.origins.len() > MAX_ORIGIN_COUNT
            || self.cache_behaviors.len() > MAX_BEHAVIOR_COUNT
            || self.aliases.iter().any(|alias| !valid_domain(alias))
            || self
                .web_acl_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsCloudFrontDistributionError::InvalidRequest);
        }
        self.origins
            .iter()
            .try_for_each(OriginMetadataInput::validate)?;
        self.cache_behaviors
            .iter()
            .try_for_each(CacheBehaviorMetadataInput::validate)?;
        self.viewer_certificate.validate()
    }

    fn raw_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-distribution-config-input/v1",
            &[
                ("etag", Digest::from_text(&self.etag).as_str().to_owned()),
                (
                    "revision",
                    Digest::from_text(&self.config_revision).as_str().to_owned(),
                ),
                (
                    "aliases",
                    digest_values("aliases", &self.aliases).as_str().to_owned(),
                ),
                (
                    "origins",
                    self.origins
                        .iter()
                        .map(OriginMetadataInput::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cache_behaviors",
                    self.cache_behaviors
                        .iter()
                        .map(CacheBehaviorMetadataInput::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "viewer_certificate",
                    self.viewer_certificate.digest().as_str().to_owned(),
                ),
                (
                    "web_acl",
                    self.web_acl_id.as_ref().map_or_else(String::new, |value| {
                        Digest::from_text(value).as_str().to_owned()
                    }),
                ),
            ],
        )
    }
}

impl fmt::Debug for DistributionConfigInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributionConfigInput")
            .field("digest", &self.raw_digest())
            .finish()
    }
}

fn digest_values(domain: &str, values: &[String]) -> Digest {
    let mut digests = values
        .iter()
        .map(|value| Digest::from_text(value).as_str().to_owned())
        .collect::<Vec<_>>();
    digests.sort_unstable();
    Digest::from_parts(
        &format!("aws-cloudfront-{domain}-metadata/v1"),
        &[("items", digests.join("\n"))],
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct DistributionSummary {
    identity: DistributionIdentity,
    status: DistributionStatus,
    enabled: bool,
    last_modified_time: DateTime<Utc>,
    etag_digest: Digest,
}

impl DistributionSummary {
    pub fn new(
        identity: DistributionIdentity,
        status: DistributionStatus,
        enabled: bool,
        last_modified_time: DateTime<Utc>,
        etag: impl Into<String>,
    ) -> Result<Self> {
        let etag = etag.into();
        if !valid_text(&etag, MAX_IDENTIFIER_BYTES, true) || !status.is_known() {
            return Err(AwsCloudFrontDistributionError::InvalidResponse);
        }
        let summary = Self {
            identity,
            status,
            enabled,
            last_modified_time,
            etag_digest: Digest::from_parts("aws-cloudfront-etag/v1", &[("value", etag)]),
        };
        summary.validate()?;
        Ok(summary)
    }

    pub fn identity(&self) -> &DistributionIdentity {
        &self.identity
    }

    pub const fn status(&self) -> DistributionStatus {
        self.status
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn last_modified_time(&self) -> DateTime<Utc> {
        self.last_modified_time
    }

    pub fn etag_digest(&self) -> &Digest {
        &self.etag_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-distribution-summary/v1",
            &[
                ("identity", self.identity.digest().as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("enabled", self.enabled.to_string()),
                ("last_modified", self.last_modified_time.to_rfc3339()),
                ("etag", self.etag_digest.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        if !self.status.is_known() || !is_valid_time(self.last_modified_time) {
            return Err(AwsCloudFrontDistributionError::InvalidResponse);
        }
        self.etag_digest.validate()
    }

    pub(crate) fn validate_against(&self, scope: &AwsCloudFrontDistributionScope) -> Result<()> {
        self.validate()?;
        if self.identity.digest() != scope.distribution.digest() {
            return Err(AwsCloudFrontDistributionError::DistributionNotAllowed);
        }
        if scope
            .expected_etag_digest()
            .is_some_and(|expected| expected != &self.etag_digest)
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        Ok(())
    }
}

impl fmt::Debug for DistributionSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributionSummary")
            .field("identity", &self.identity)
            .field("status", &self.status)
            .field("enabled", &self.enabled)
            .field("last_modified_time", &self.last_modified_time)
            .field("etag_digest", &self.etag_digest)
            .finish()
    }
}

impl Serialize for DistributionSummary {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DistributionSummary", 8)?;
        state.serialize_field("distributionIdDigest", &self.identity.id_digest())?;
        state.serialize_field("distributionArnDigest", &self.identity.arn_digest())?;
        state.serialize_field("domainNameDigest", &self.identity.domain_name_digest())?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("enabled", &self.enabled)?;
        state.serialize_field("lastModifiedTime", &self.last_modified_time)?;
        state.serialize_field("etagDigest", &self.etag_digest)?;
        state.serialize_field("summaryDigest", &self.digest())?;
        state.end()
    }
}

fn is_valid_time(value: DateTime<Utc>) -> bool {
    value > DateTime::<Utc>::MIN_UTC && value < DateTime::<Utc>::MAX_UTC
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewerCertificateSummary {
    pub certificate_source_digest: Digest,
    pub minimum_protocol_version_digest: Digest,
    pub ssl_support_method_digest: Digest,
    pub cloudfront_default_certificate: bool,
    pub tls_digest: Digest,
}

impl ViewerCertificateSummary {
    fn from_input(input: &ViewerCertificateInput) -> Self {
        Self {
            certificate_source_digest: Digest::from_text(&input.source),
            minimum_protocol_version_digest: Digest::from_text(&input.minimum_protocol_version),
            ssl_support_method_digest: Digest::from_text(&input.ssl_support_method),
            cloudfront_default_certificate: input.cloudfront_default_certificate,
            tls_digest: input.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WafSummary {
    pub associated: bool,
    pub web_acl_reference_digest: Option<Digest>,
    pub waf_digest: Digest,
}

impl WafSummary {
    fn from_web_acl(web_acl_id: Option<&str>) -> Self {
        let web_acl_reference_digest = web_acl_id.map(Digest::from_text);
        let waf_digest = Digest::from_parts(
            "aws-cloudfront-waf-association/v1",
            &[
                ("associated", web_acl_reference_digest.is_some().to_string()),
                (
                    "web_acl",
                    web_acl_reference_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        Self {
            associated: web_acl_reference_digest.is_some(),
            web_acl_reference_digest,
            waf_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheBehaviorSummary {
    pub behavior_count: u16,
    pub default_behavior_digest: Digest,
    pub additional_behaviors_digest: Digest,
    pub cache_behaviors_digest: Digest,
}

impl CacheBehaviorSummary {
    fn from_inputs(inputs: &[CacheBehaviorMetadataInput]) -> Self {
        let digests = inputs
            .iter()
            .map(CacheBehaviorMetadataInput::digest)
            .collect::<Vec<_>>();
        let additional_behaviors_digest = Digest::from_parts(
            "aws-cloudfront-additional-cache-behaviors/v1",
            &[(
                "items",
                digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        let default_behavior_digest = digests
            .first()
            .cloned()
            .unwrap_or_else(|| Digest::from_text("aws-cloudfront-no-default-cache-behavior"));
        let cache_behaviors_digest = Digest::from_parts(
            "aws-cloudfront-cache-behaviors/v1",
            &[
                ("count", inputs.len().to_string()),
                (
                    "items",
                    digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            behavior_count: inputs.len() as u16,
            default_behavior_digest,
            additional_behaviors_digest,
            cache_behaviors_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributionConfigMetadata {
    pub distribution_digest: Digest,
    pub etag_digest: Digest,
    pub config_revision_digest: Digest,
    pub aliases_digest: Digest,
    pub alias_count: u16,
    pub origins_digest: Digest,
    pub origin_count: u16,
    pub tls: ViewerCertificateSummary,
    pub waf: WafSummary,
    pub cache_behaviors: CacheBehaviorSummary,
    pub config_digest: Digest,
}

impl DistributionConfigMetadata {
    pub fn new(
        scope: &AwsCloudFrontDistributionScope,
        input: DistributionConfigInput,
    ) -> Result<Self> {
        input.validate()?;
        let etag_digest = Digest::from_parts("aws-cloudfront-etag/v1", &[("value", input.etag)]);
        let config_revision_digest = Digest::from_parts(
            "aws-cloudfront-config-revision/v1",
            &[("value", input.config_revision)],
        );
        if scope
            .expected_etag_digest()
            .is_some_and(|expected| expected != &etag_digest)
            || (scope.config_revision().as_str() != "unbound-layer1-config-revision"
                && *scope.config_revision().digest() != config_revision_digest)
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        let aliases_digest = digest_values("aliases", &input.aliases);
        let origins_digest = Digest::from_parts(
            "aws-cloudfront-origins/v1",
            &[(
                "items",
                input
                    .origins
                    .iter()
                    .map(OriginMetadataInput::digest)
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        let tls = ViewerCertificateSummary::from_input(&input.viewer_certificate);
        let waf = WafSummary::from_web_acl(input.web_acl_id.as_deref());
        let cache_behaviors = CacheBehaviorSummary::from_inputs(&input.cache_behaviors);
        let mut metadata = Self {
            distribution_digest: scope.distribution.digest(),
            etag_digest,
            config_revision_digest,
            aliases_digest,
            alias_count: input.aliases.len() as u16,
            origins_digest,
            origin_count: input.origins.len() as u16,
            tls,
            waf,
            cache_behaviors,
            config_digest: Digest::from_text("unsealed-aws-cloudfront-config"),
        };
        metadata.config_digest = metadata.digest();
        if let Some(expected) = scope.metadata_fences().aliases_digest.as_ref()
            && expected != &metadata.aliases_digest
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        if let Some(expected) = scope.metadata_fences().origins_digest.as_ref()
            && expected != &metadata.origins_digest
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        if let Some(expected) = scope.metadata_fences().cache_behaviors_digest.as_ref()
            && expected != &metadata.cache_behaviors.cache_behaviors_digest
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        if let Some(expected) = scope.metadata_fences().tls_digest.as_ref()
            && expected != &metadata.tls.tls_digest
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        if let Some(expected) = scope.metadata_fences().waf_digest.as_ref()
            && expected != &metadata.waf.waf_digest
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        Ok(metadata)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-distribution-config-metadata/v1",
            &[
                ("distribution", self.distribution_digest.as_str().to_owned()),
                ("etag", self.etag_digest.as_str().to_owned()),
                (
                    "config_revision",
                    self.config_revision_digest.as_str().to_owned(),
                ),
                ("aliases", self.aliases_digest.as_str().to_owned()),
                ("alias_count", self.alias_count.to_string()),
                ("origins", self.origins_digest.as_str().to_owned()),
                ("origin_count", self.origin_count.to_string()),
                ("tls", self.tls.tls_digest.as_str().to_owned()),
                ("waf", self.waf.waf_digest.as_str().to_owned()),
                (
                    "cache_behaviors",
                    self.cache_behaviors
                        .cache_behaviors_digest
                        .as_str()
                        .to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate_against(
        &self,
        scope: &AwsCloudFrontDistributionScope,
        expected_etag: &Digest,
    ) -> Result<()> {
        if self.distribution_digest != scope.distribution.digest()
            || &self.etag_digest != expected_etag
            || self.config_digest != self.digest()
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributionProjection {
    pub distribution_identity_digest: Digest,
    pub distribution_id_digest: Digest,
    pub distribution_arn_digest: Digest,
    pub domain_name_digest: Digest,
    pub status: DistributionStatus,
    pub enabled: bool,
    pub last_modified_time: DateTime<Utc>,
    pub etag_digest: Digest,
    pub config_revision_digest: Digest,
    pub aliases_digest: Digest,
    pub alias_count: u16,
    pub origins_digest: Digest,
    pub origin_count: u16,
    pub tls: ViewerCertificateSummary,
    pub waf: WafSummary,
    pub cache_behaviors: CacheBehaviorSummary,
    pub projection_digest: Digest,
}

impl DistributionProjection {
    pub fn from_parts(
        summary: &DistributionSummary,
        config: &DistributionConfigMetadata,
    ) -> Result<Self> {
        let mut projection = Self {
            distribution_identity_digest: summary.identity.digest(),
            distribution_id_digest: summary.identity.id_digest(),
            distribution_arn_digest: summary.identity.arn_digest(),
            domain_name_digest: summary.identity.domain_name_digest(),
            status: summary.status,
            enabled: summary.enabled,
            last_modified_time: summary.last_modified_time,
            etag_digest: summary.etag_digest.clone(),
            config_revision_digest: config.config_revision_digest.clone(),
            aliases_digest: config.aliases_digest.clone(),
            alias_count: config.alias_count,
            origins_digest: config.origins_digest.clone(),
            origin_count: config.origin_count,
            tls: config.tls.clone(),
            waf: config.waf.clone(),
            cache_behaviors: config.cache_behaviors.clone(),
            projection_digest: Digest::from_text("unsealed-aws-cloudfront-projection"),
        };
        if summary.identity.digest() != config.distribution_digest
            || summary.etag_digest != config.etag_digest
        {
            return Err(AwsCloudFrontDistributionError::ConfigDrift);
        }
        projection.projection_digest = projection.digest();
        Ok(projection)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-distribution-projection/v1",
            &[
                (
                    "identity",
                    self.distribution_identity_digest.as_str().to_owned(),
                ),
                ("id", self.distribution_id_digest.as_str().to_owned()),
                ("arn", self.distribution_arn_digest.as_str().to_owned()),
                ("domain", self.domain_name_digest.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("enabled", self.enabled.to_string()),
                ("last_modified", self.last_modified_time.to_rfc3339()),
                ("etag", self.etag_digest.as_str().to_owned()),
                (
                    "config_revision",
                    self.config_revision_digest.as_str().to_owned(),
                ),
                ("aliases", self.aliases_digest.as_str().to_owned()),
                ("alias_count", self.alias_count.to_string()),
                ("origins", self.origins_digest.as_str().to_owned()),
                ("origin_count", self.origin_count.to_string()),
                ("tls", self.tls.tls_digest.as_str().to_owned()),
                ("waf", self.waf.waf_digest.as_str().to_owned()),
                (
                    "cache_behaviors",
                    self.cache_behaviors
                        .cache_behaviors_digest
                        .as_str()
                        .to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        if !self.status.is_known() || self.projection_digest != self.digest() {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudFrontEvidenceState {
    Ready,
    InProgress,
    Disabled,
    Partial,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ConfigDrift,
    PaginationLoop,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl CloudFrontEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Ready | Self::Disabled | Self::InProgress)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

pub fn project_projection(identity: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

pub fn deployment_projection(identity: &DeploymentIdentity) -> DeploymentProjection {
    DeploymentProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    pub fn new(operation: impl Into<String>, request_digest: Digest, path_digest: Digest) -> Self {
        let operation = operation.into();
        let receipt_digest = Digest::from_parts(
            "aws-cloudfront-request-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("request", request_digest.as_str().to_owned()),
                ("path", path_digest.as_str().to_owned()),
                ("redacted", "true".to_owned()),
            ],
        );
        Self {
            operation,
            request_digest,
            path_digest,
            redacted: true,
            receipt_digest,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted
            || self.receipt_digest
                != Digest::from_parts(
                    "aws-cloudfront-request-receipt/v1",
                    &[
                        ("operation", self.operation.clone()),
                        ("request", self.request_digest.as_str().to_owned()),
                        ("path", self.path_digest.as_str().to_owned()),
                        ("redacted", "true".to_owned()),
                    ],
                )
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        Ok(())
    }

    pub const fn is_redacted(&self) -> bool {
        self.redacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub cost_basis: String,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsCloudFrontDistributionError::PartialEvidence);
        }
        let operation = operation.into();
        let bounded_request_units = 1;
        let cost_basis = "layer1_metadata_read_estimate".to_owned();
        let receipt_digest = Digest::from_parts(
            "aws-cloudfront-cost-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("response_bytes", response_bytes.to_string()),
                ("request_units", bounded_request_units.to_string()),
                ("cost_basis", cost_basis.clone()),
                ("redacted", "true".to_owned()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units,
            cost_basis,
            redacted: true,
            receipt_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.receipt_digest
                != Digest::from_parts(
                    "aws-cloudfront-cost-receipt/v1",
                    &[
                        ("operation", self.operation.clone()),
                        ("response_bytes", self.response_bytes.to_string()),
                        ("request_units", self.bounded_request_units.to_string()),
                        ("cost_basis", self.cost_basis.clone()),
                        ("redacted", "true".to_owned()),
                    ],
                )
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn cost_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub const fn is_redacted(&self) -> bool {
        self.redacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub distribution_digest: Digest,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub config_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.distribution_digest.validate()?;
        self.list_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.get_digest.as_ref().map(Digest::validate).transpose()?;
        self.config_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    pub receipt_count: u16,
    pub total_response_bytes: u64,
    pub cost_digest: Digest,
}

impl CostSummary {
    pub fn from_receipts(receipts: &[CostReceipt]) -> Self {
        let total_response_bytes: u64 = receipts.iter().map(|receipt| receipt.response_bytes).sum();
        let cost_digest = Digest::from_parts(
            "aws-cloudfront-cost-summary/v1",
            &[
                ("count", receipts.len().to_string()),
                ("bytes", total_response_bytes.to_string()),
                (
                    "receipts",
                    receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            receipt_count: receipts.len() as u16,
            total_response_bytes,
            cost_digest,
        }
    }
}

pub fn join_digests(values: impl IntoIterator<Item = Digest>) -> String {
    values
        .into_iter()
        .map(|digest| digest.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}

pub(crate) fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(AwsCloudFrontDistributionError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_page_number(page_number: u16) -> Result<()> {
    if page_number == 0 || page_number > MAX_PAGES {
        Err(AwsCloudFrontDistributionError::InvalidRequest)
    } else {
        Ok(())
    }
}

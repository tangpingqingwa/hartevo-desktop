use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsPersonalizeRecommendationError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_FAILURE_REASON_BYTES, MAX_IDENTIFIER_BYTES, MAX_RESULTS};

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
            Err(AwsPersonalizeRecommendationError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsPersonalizeRecommendationError::InvalidDigest)
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
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

macro_rules! opaque_identity {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name {
            digest: Digest,
        }

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self> {
                let value = value.as_ref();
                if !valid_text(value, MAX_IDENTIFIER_BYTES, true) {
                    return Err(AwsPersonalizeRecommendationError::InvalidIdentifier {
                        field: $field,
                    });
                }
                Ok(Self {
                    digest: Digest::from_parts($domain, &[("value", value.to_owned())]),
                })
            }

            pub fn from_digest(digest: Digest) -> Result<Self> {
                digest.validate()?;
                Ok(Self { digest })
            }

            pub fn digest(&self) -> Digest {
                self.digest.clone()
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest.as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                self.digest.validate()
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AwsPersonalizeRecommendationError::InvalidIdentifier { field: "account" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-personalize-account/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.0.len() == 12 && self.0.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(())
        } else {
            Err(AwsPersonalizeRecommendationError::InvalidIdentifier { field: "account" })
        }
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&format!("account:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

opaque_identity!(CampaignIdentity, "campaign", "aws-personalize-campaign/v1");
opaque_identity!(
    RecommenderIdentity,
    "recommender",
    "aws-personalize-recommender/v1"
);
opaque_identity!(
    SolutionVersionIdentity,
    "solution-version",
    "aws-personalize-solution-version/v1"
);
opaque_identity!(FilterIdentity, "filter", "aws-personalize-filter/v1");
opaque_identity!(
    UserFingerprint,
    "user-fingerprint",
    "aws-personalize-user-fingerprint/v1"
);
opaque_identity!(
    ItemFingerprint,
    "item-fingerprint",
    "aws-personalize-item-fingerprint/v1"
);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !valid_identifier(&value, 64) {
            return Err(AwsPersonalizeRecommendationError::InvalidIdentifier { field: "region" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-personalize-region/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0, 64) {
            Ok(())
        } else {
            Err(AwsPersonalizeRecommendationError::InvalidIdentifier { field: "region" })
        }
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PersonalizeDomain(String);

impl PersonalizeDomain {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !valid_identifier(&value, 64) {
            return Err(AwsPersonalizeRecommendationError::InvalidIdentifier { field: "domain" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-personalize-domain/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0, 64) {
            Ok(())
        } else {
            Err(AwsPersonalizeRecommendationError::InvalidIdentifier { field: "domain" })
        }
    }
}

impl fmt::Debug for PersonalizeDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PersonalizeDomain")
            .field(&self.0)
            .finish()
    }
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
                    return Err(AwsPersonalizeRecommendationError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.clone()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsPersonalizeRecommendationError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("idDigest", &self.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

revision_identity!(MissionIdentity, "aws-personalize-mission/v1", "mission");
revision_identity!(ProjectIdentity, "aws-personalize-project/v1", "project");
revision_identity!(
    WorkProductIdentity,
    "aws-personalize-work-product/v1",
    "work-product"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AwsPersonalizeRecommendationScope {
    account: AwsAccountId,
    region: AwsRegion,
    domain: PersonalizeDomain,
    campaign: Option<CampaignIdentity>,
    recommender: Option<RecommenderIdentity>,
    solution_version: Option<SolutionVersionIdentity>,
    filter: Option<FilterIdentity>,
    user_fingerprint: Option<UserFingerprint>,
    item_fingerprint: Option<ItemFingerprint>,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl AwsPersonalizeRecommendationScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        domain: PersonalizeDomain,
        campaign: Option<CampaignIdentity>,
        recommender: Option<RecommenderIdentity>,
        solution_version: Option<SolutionVersionIdentity>,
        filter: Option<FilterIdentity>,
        user_fingerprint: Option<UserFingerprint>,
        item_fingerprint: Option<ItemFingerprint>,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            domain,
            campaign,
            recommender,
            solution_version,
            filter,
            user_fingerprint,
            item_fingerprint,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn domain(&self) -> &PersonalizeDomain {
        &self.domain
    }

    pub fn campaign(&self) -> Option<&CampaignIdentity> {
        self.campaign.as_ref()
    }

    pub fn recommender(&self) -> Option<&RecommenderIdentity> {
        self.recommender.as_ref()
    }

    pub fn solution_version(&self) -> Option<&SolutionVersionIdentity> {
        self.solution_version.as_ref()
    }

    pub fn filter(&self) -> Option<&FilterIdentity> {
        self.filter.as_ref()
    }

    pub fn user_fingerprint(&self) -> Option<&UserFingerprint> {
        self.user_fingerprint.as_ref()
    }

    pub fn item_fingerprint(&self) -> Option<&ItemFingerprint> {
        self.item_fingerprint.as_ref()
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-personalize-recommendation-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("domain", self.domain.digest().as_str().to_owned()),
                (
                    "campaign",
                    self.campaign
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "recommender",
                    self.recommender
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "solution_version",
                    self.solution_version
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "filter",
                    self.filter
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "user_fingerprint",
                    self.user_fingerprint
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "item_fingerprint",
                    self.item_fingerprint
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.domain.validate()?;
        if self.campaign.is_none() && self.recommender.is_none() {
            return Err(AwsPersonalizeRecommendationError::InvalidScope);
        }
        self.campaign
            .as_ref()
            .map(CampaignIdentity::validate)
            .transpose()?;
        self.recommender
            .as_ref()
            .map(RecommenderIdentity::validate)
            .transpose()?;
        self.solution_version
            .as_ref()
            .map(SolutionVersionIdentity::validate)
            .transpose()?;
        self.filter
            .as_ref()
            .map(FilterIdentity::validate)
            .transpose()?;
        if self.user_fingerprint.is_none() && self.item_fingerprint.is_none() {
            return Err(AwsPersonalizeRecommendationError::InvalidScope);
        }
        self.user_fingerprint
            .as_ref()
            .map(UserFingerprint::validate)
            .transpose()?;
        self.item_fingerprint
            .as_ref()
            .map(ItemFingerprint::validate)
            .transpose()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsPersonalizeRecommendationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsPersonalizeRecommendationScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("domain", &self.domain)
            .field("campaign", &self.campaign)
            .field("recommender", &self.recommender)
            .field("solution_version", &self.solution_version)
            .field("filter", &self.filter)
            .field("user_fingerprint", &self.user_fingerprint)
            .field("item_fingerprint", &self.item_fingerprint)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingTarget {
    Campaign,
    Recommender,
}

impl ServingTarget {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Campaign => "campaign",
            Self::Recommender => "recommender",
        }
    }
}

pub type RecommendationTarget = ServingTarget;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// An opaque SigV4 reference. The caller-supplied handle is hashed and
/// dropped immediately; it is not serializable, displayable, or present in
/// Debug output.
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
            return Err(AwsPersonalizeRecommendationError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-personalize-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-personalize-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsPersonalizeRecommendationScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-personalize-opaque-sigv4-reference/v1",
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

    pub(crate) fn validate(&self, scope: &AwsPersonalizeRecommendationScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsPersonalizeRecommendationError::InvalidSecretReference);
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
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
            "aws-personalize-permissions/v1",
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
            || self.permissions.len() != LAYER1_PERMISSIONS.len()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || !LAYER1_PERMISSIONS
                .iter()
                .all(|permission| self.permissions.contains(*permission))
        {
            Err(AwsPersonalizeRecommendationError::InvalidPermissionSnapshot)
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
            "aws-personalize-consent/v1",
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
            || self.permissions.len() != LAYER1_PERMISSIONS.len()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || !LAYER1_PERMISSIONS
                .iter()
                .all(|permission| self.permissions.contains(*permission))
            || self.expires_at <= DateTime::<Utc>::MIN_UTC
        {
            Err(AwsPersonalizeRecommendationError::InvalidConsent)
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
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecommendationEvidenceState {
    Active,
    Pending,
    Failed,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Active,
    CreatePending,
    CreateFailed,
    UpdatePending,
    UpdateFailed,
    DeletePending,
    DeleteFailed,
    DeleteComplete,
    Unknown,
}

impl CampaignStatus {
    pub const fn state(self) -> RecommendationEvidenceState {
        match self {
            Self::Active => RecommendationEvidenceState::Active,
            Self::CreatePending | Self::UpdatePending | Self::DeletePending => {
                RecommendationEvidenceState::Pending
            }
            Self::CreateFailed | Self::UpdateFailed | Self::DeleteFailed => {
                RecommendationEvidenceState::Failed
            }
            Self::DeleteComplete => RecommendationEvidenceState::Expired,
            Self::Unknown => RecommendationEvidenceState::ProviderUnknown,
        }
    }
}

pub type RecommenderStatus = CampaignStatus;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRevision {
    pub revision_digest: Digest,
    pub solution_version_digest: Option<Digest>,
}

impl ModelRevision {
    pub fn new(
        model_revision: impl AsRef<str>,
        solution_version: Option<impl AsRef<str>>,
    ) -> Result<Self> {
        let model_revision = model_revision.as_ref();
        if !valid_text(model_revision, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsPersonalizeRecommendationError::InvalidIdentifier {
                field: "model-revision",
            });
        }
        let solution_version_digest = solution_version
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES * 8, false) {
                    Ok(Digest::from_parts(
                        "aws-personalize-solution-version/v1",
                        &[("value", value)],
                    ))
                } else {
                    Err(AwsPersonalizeRecommendationError::InvalidIdentifier {
                        field: "solution-version",
                    })
                }
            })
            .transpose()?;
        Ok(Self {
            revision_digest: Digest::from_parts(
                "aws-personalize-model-revision/v1",
                &[("revision", model_revision.to_owned())],
            ),
            solution_version_digest,
        })
    }

    pub fn from_digest(
        revision_digest: Digest,
        solution_version_digest: Option<Digest>,
    ) -> Result<Self> {
        revision_digest.validate()?;
        if let Some(digest) = &solution_version_digest {
            digest.validate()?;
        }
        Ok(Self {
            revision_digest,
            solution_version_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.revision_digest.validate()?;
        self.solution_version_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignMetadataInput {
    pub status: CampaignStatus,
    pub model_revision: ModelRevision,
    pub failure_reason: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecommenderMetadataInput {
    pub status: RecommenderStatus,
    pub model_revision: ModelRevision,
    pub failure_reason: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignMetadata {
    pub campaign_digest: Digest,
    pub status: CampaignStatus,
    pub model_revision: ModelRevision,
    pub failure_reason_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub metadata_digest: Digest,
}

impl CampaignMetadata {
    pub fn new(
        scope: &AwsPersonalizeRecommendationScope,
        input: CampaignMetadataInput,
    ) -> Result<Self> {
        let campaign = scope
            .campaign()
            .ok_or(AwsPersonalizeRecommendationError::UnsupportedOperation)?;
        input.model_revision.validate()?;
        if let Some(reason) = input.failure_reason.as_deref() {
            validate_failure_reason(reason)?;
        }
        let failure_reason_digest = input.failure_reason.map(|reason| {
            Digest::from_parts("aws-personalize-failure-reason/v1", &[("reason", reason)])
        });
        let metadata_digest = Digest::from_parts(
            "aws-personalize-campaign-metadata/v1",
            &[
                ("campaign", campaign.digest().as_str().to_owned()),
                ("status", format!("{:?}", input.status)),
                (
                    "model_revision",
                    input.model_revision.revision_digest.as_str().to_owned(),
                ),
                (
                    "solution_version",
                    input
                        .model_revision
                        .solution_version_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "failure_reason",
                    failure_reason_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("observed_at", input.observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            campaign_digest: campaign.digest(),
            status: input.status,
            model_revision: input.model_revision,
            failure_reason_digest,
            observed_at: input.observed_at,
            metadata_digest,
        })
    }

    pub(crate) fn validate_against(&self, scope: &AwsPersonalizeRecommendationScope) -> Result<()> {
        if scope.campaign().map(CampaignIdentity::digest) != Some(self.campaign_digest.clone())
            || self.model_revision.validate().is_err()
            || self.model_revision.solution_version_digest
                != scope
                    .solution_version()
                    .map(SolutionVersionIdentity::digest)
        {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        self.validate_digest()?;
        if self
            .failure_reason_digest
            .as_ref()
            .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }

    pub(crate) fn validate_digest(&self) -> Result<()> {
        if self.metadata_digest != self.calculate_metadata_digest() {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_metadata_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-personalize-campaign-metadata/v1",
            &[
                ("campaign", self.campaign_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "model_revision",
                    self.model_revision.revision_digest.as_str().to_owned(),
                ),
                (
                    "solution_version",
                    self.model_revision
                        .solution_version_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "failure_reason",
                    self.failure_reason_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommenderMetadata {
    pub recommender_digest: Digest,
    pub status: RecommenderStatus,
    pub model_revision: ModelRevision,
    pub failure_reason_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub metadata_digest: Digest,
}

impl RecommenderMetadata {
    pub fn new(
        scope: &AwsPersonalizeRecommendationScope,
        input: RecommenderMetadataInput,
    ) -> Result<Self> {
        let recommender = scope
            .recommender()
            .ok_or(AwsPersonalizeRecommendationError::UnsupportedOperation)?;
        input.model_revision.validate()?;
        if let Some(reason) = input.failure_reason.as_deref() {
            validate_failure_reason(reason)?;
        }
        let failure_reason_digest = input.failure_reason.map(|reason| {
            Digest::from_parts("aws-personalize-failure-reason/v1", &[("reason", reason)])
        });
        let metadata_digest = Digest::from_parts(
            "aws-personalize-recommender-metadata/v1",
            &[
                ("recommender", recommender.digest().as_str().to_owned()),
                ("status", format!("{:?}", input.status)),
                (
                    "model_revision",
                    input.model_revision.revision_digest.as_str().to_owned(),
                ),
                (
                    "solution_version",
                    input
                        .model_revision
                        .solution_version_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "failure_reason",
                    failure_reason_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("observed_at", input.observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            recommender_digest: recommender.digest(),
            status: input.status,
            model_revision: input.model_revision,
            failure_reason_digest,
            observed_at: input.observed_at,
            metadata_digest,
        })
    }

    pub(crate) fn validate_against(&self, scope: &AwsPersonalizeRecommendationScope) -> Result<()> {
        if scope.recommender().map(RecommenderIdentity::digest)
            != Some(self.recommender_digest.clone())
            || self.model_revision.validate().is_err()
            || self.model_revision.solution_version_digest
                != scope
                    .solution_version()
                    .map(SolutionVersionIdentity::digest)
        {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        self.validate_digest()?;
        if self
            .failure_reason_digest
            .as_ref()
            .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }

    pub(crate) fn validate_digest(&self) -> Result<()> {
        if self.metadata_digest != self.calculate_metadata_digest() {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_metadata_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-personalize-recommender-metadata/v1",
            &[
                ("recommender", self.recommender_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "model_revision",
                    self.model_revision.revision_digest.as_str().to_owned(),
                ),
                (
                    "solution_version",
                    self.model_revision
                        .solution_version_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "failure_reason",
                    self.failure_reason_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationItemKind {
    Item,
    Action,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreBucket {
    Missing,
    Zero,
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

impl ScoreBucket {
    pub fn from_score(score: Option<f64>) -> Result<Self> {
        let Some(score) = score else {
            return Ok(Self::Missing);
        };
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        if score == 0.0 {
            Ok(Self::Zero)
        } else if score < 0.2 {
            Ok(Self::VeryLow)
        } else if score < 0.4 {
            Ok(Self::Low)
        } else if score < 0.6 {
            Ok(Self::Medium)
        } else if score < 0.8 {
            Ok(Self::High)
        } else {
            Ok(Self::VeryHigh)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedRecommendationIdentifier {
    pub kind: RecommendationItemKind,
    pub identifier_digest: Digest,
}

impl RedactedRecommendationIdentifier {
    pub fn new(kind: RecommendationItemKind, raw_identifier: impl AsRef<str>) -> Result<Self> {
        let raw_identifier = raw_identifier.as_ref();
        if !valid_text(raw_identifier, MAX_IDENTIFIER_BYTES, false) {
            return Err(AwsPersonalizeRecommendationError::InvalidIdentifier {
                field: "recommendation-identifier",
            });
        }
        Ok(Self {
            kind,
            identifier_digest: Digest::from_parts(
                "aws-personalize-recommendation-identifier/v1",
                &[
                    ("kind", format!("{kind:?}")),
                    ("value", raw_identifier.to_owned()),
                ],
            ),
        })
    }

    pub fn redacted(&self) -> String {
        format!(
            "{}:{}",
            match self.kind {
                RecommendationItemKind::Item => "item",
                RecommendationItemKind::Action => "action",
            },
            &self.identifier_digest.as_str()[..16]
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.identifier_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendationItem {
    pub identifier: RedactedRecommendationIdentifier,
    pub rank: u16,
    pub score_bucket: ScoreBucket,
}

impl RecommendationItem {
    pub fn new(
        kind: RecommendationItemKind,
        raw_identifier: impl AsRef<str>,
        rank: u16,
        score: Option<f64>,
    ) -> Result<Self> {
        if rank == 0 || rank > MAX_RESULTS {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        Ok(Self {
            identifier: RedactedRecommendationIdentifier::new(kind, raw_identifier)?,
            rank,
            score_bucket: ScoreBucket::from_score(score)?,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.rank == 0 || self.rank > MAX_RESULTS {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        self.identifier.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendationResult {
    pub operation: RecommendationOperation,
    pub items: Vec<RecommendationItem>,
    pub result_digest: Digest,
}

impl RecommendationResult {
    pub fn new(operation: RecommendationOperation, items: Vec<RecommendationItem>) -> Result<Self> {
        if items.len() > MAX_RESULTS as usize {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        for (index, item) in items.iter().enumerate() {
            item.validate()?;
            if item.rank != index as u16 + 1 {
                return Err(AwsPersonalizeRecommendationError::NonContiguousRanking);
            }
            if items[..index].iter().any(|previous| {
                previous.identifier.identifier_digest == item.identifier.identifier_digest
            }) {
                return Err(AwsPersonalizeRecommendationError::InvalidRequest);
            }
        }
        let result_digest = Digest::from_parts(
            "aws-personalize-recommendation-result/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                (
                    "items",
                    items
                        .iter()
                        .map(|item| {
                            format!(
                                "{}:{}:{:?}",
                                item.identifier.identifier_digest.as_str(),
                                item.rank,
                                item.score_bucket
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Ok(Self {
            operation,
            items,
            result_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let rebuilt = Self::new(self.operation, self.items.clone())?;
        if rebuilt.result_digest != self.result_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum RecommendationOperation {
    GetRecommendations,
    GetPersonalizedRanking,
}

impl RecommendationOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetRecommendations => "GetRecommendations",
            Self::GetPersonalizedRanking => "GetPersonalizedRanking",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.digest(),
            revision: value.revision(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.digest(),
            revision: value.revision(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: value.digest(),
            revision: value.revision(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub request_digest: Digest,
    pub campaign_metadata_digest: Option<Digest>,
    pub recommender_metadata_digest: Option<Digest>,
    pub result_digest: Option<Digest>,
    pub response_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn new(
        request_digest: Digest,
        campaign_metadata_digest: Option<Digest>,
        recommender_metadata_digest: Option<Digest>,
        result_digest: Option<Digest>,
        response_digests: Vec<Digest>,
    ) -> Result<Self> {
        request_digest.validate()?;
        for digest in response_digests.iter().chain(
            campaign_metadata_digest
                .iter()
                .chain(recommender_metadata_digest.iter())
                .chain(result_digest.iter()),
        ) {
            digest.validate()?;
        }
        let evidence_digest = Digest::from_parts(
            "aws-personalize-evidence/v1",
            &[
                ("request", request_digest.as_str().to_owned()),
                (
                    "campaign",
                    campaign_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "recommender",
                    recommender_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "result",
                    result_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "responses",
                    response_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Ok(Self {
            request_digest,
            campaign_metadata_digest,
            recommender_metadata_digest,
            result_digest,
            response_digests,
            evidence_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let rebuilt = Self::new(
            self.request_digest.clone(),
            self.campaign_metadata_digest.clone(),
            self.recommender_metadata_digest.clone(),
            self.result_digest.clone(),
            self.response_digests.clone(),
        )?;
        if rebuilt.evidence_digest != self.evidence_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

pub(crate) fn validate_failure_reason(value: &str) -> Result<()> {
    if valid_text(value, MAX_FAILURE_REASON_BYTES, true) {
        Ok(())
    } else {
        Err(AwsPersonalizeRecommendationError::InvalidText {
            field: "failure-reason",
        })
    }
}

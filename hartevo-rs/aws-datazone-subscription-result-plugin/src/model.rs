use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsDataZoneSubscriptionResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
};

pub const MAX_DATAZONE_ID_BYTES: usize = 64;

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
            Err(AwsDataZoneSubscriptionResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsDataZoneSubscriptionResultError::InvalidDigest)
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
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_revision(value: &str) -> bool {
    valid_text(value, MAX_DATAZONE_ID_BYTES, false)
}

macro_rules! opaque_id {
    ($name:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsDataZoneSubscriptionResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsDataZoneSubscriptionResultError::InvalidIdentifier { field: $field })
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

opaque_id!(
    AwsAccountId,
    "account",
    "aws-datazone-account/v1",
    |value: &str| { value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) }
);
opaque_id!(
    AwsRegion,
    "region",
    "aws-datazone-region/v1",
    |value: &str| { valid_identifier(value, 64) }
);
opaque_id!(
    DataZoneDomainId,
    "domain",
    "aws-datazone-domain/v1",
    |value: &str| {
        (value.starts_with("dzd-") || value.starts_with("dzd_"))
            && valid_identifier(value, MAX_DATAZONE_ID_BYTES)
    }
);
opaque_id!(
    DataZoneAssetId,
    "asset",
    "aws-datazone-asset/v1",
    |value: &str| { valid_identifier(value, MAX_DATAZONE_ID_BYTES) }
);
opaque_id!(
    DataZoneSubscriptionRequestId,
    "subscription-request",
    "aws-datazone-subscription-request/v1",
    |value: &str| { valid_identifier(value, MAX_DATAZONE_ID_BYTES) }
);
opaque_id!(
    DataZoneSubscriptionId,
    "subscription",
    "aws-datazone-subscription/v1",
    |value: &str| { valid_identifier(value, MAX_DATAZONE_ID_BYTES) }
);
opaque_id!(
    DataZoneProjectId,
    "datazone-project",
    "aws-datazone-project-id/v1",
    |value: &str| { valid_identifier(value, MAX_DATAZONE_ID_BYTES) }
);
opaque_id!(
    DataZoneListingId,
    "listing",
    "aws-datazone-listing-id/v1",
    |value: &str| { valid_identifier(value, MAX_DATAZONE_ID_BYTES) }
);
opaque_id!(
    DataZoneSubscriptionGrantId,
    "subscription-grant",
    "aws-datazone-subscription-grant/v1",
    |value: &str| { valid_identifier(value, MAX_DATAZONE_ID_BYTES) }
);
opaque_id!(
    DataZoneRevision,
    "revision",
    "aws-datazone-revision/v1",
    |value: &str| { valid_revision(value) }
);

#[derive(Clone, Eq, PartialEq)]
pub struct DataZoneAssetIdentity {
    id: DataZoneAssetId,
    revision: String,
}

impl DataZoneAssetIdentity {
    pub fn new(id: DataZoneAssetId, revision: impl Into<String>) -> Result<Self> {
        let revision = revision.into();
        if !valid_revision(&revision) {
            return Err(AwsDataZoneSubscriptionResultError::InvalidIdentifier {
                field: "asset-revision",
            });
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &DataZoneAssetId {
        &self.id
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-asset-revision/v1",
            &[("revision", self.revision.clone())],
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-asset-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision_digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if valid_revision(&self.revision) {
            Ok(())
        } else {
            Err(AwsDataZoneSubscriptionResultError::InvalidIdentifier {
                field: "asset-revision",
            })
        }
    }
}

impl fmt::Debug for DataZoneAssetIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataZoneAssetIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DataZoneSubscriptionRequestIdentity {
    id: DataZoneSubscriptionRequestId,
}

impl DataZoneSubscriptionRequestIdentity {
    pub fn new(id: DataZoneSubscriptionRequestId) -> Self {
        Self { id }
    }

    pub fn id(&self) -> &DataZoneSubscriptionRequestId {
        &self.id
    }

    pub fn digest(&self) -> Digest {
        self.id.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl fmt::Debug for DataZoneSubscriptionRequestIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataZoneSubscriptionRequestIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DataZoneSubscriptionIdentity {
    id: DataZoneSubscriptionId,
}

impl DataZoneSubscriptionIdentity {
    pub fn new(id: DataZoneSubscriptionId) -> Self {
        Self { id }
    }

    pub fn id(&self) -> &DataZoneSubscriptionId {
        &self.id
    }

    pub fn digest(&self) -> Digest {
        self.id.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl fmt::Debug for DataZoneSubscriptionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataZoneSubscriptionIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

macro_rules! scoped_identity {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsDataZoneSubscriptionResultError::InvalidScope);
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
                    Err(AwsDataZoneSubscriptionResultError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

scoped_identity!(MissionIdentity, "aws-datazone-mission/v1");
scoped_identity!(ProjectIdentity, "aws-datazone-project/v1");
scoped_identity!(WorkProductIdentity, "aws-datazone-work-product/v1");

#[derive(Clone, Eq, PartialEq)]
pub struct AwsDataZoneSubscriptionScope {
    account: AwsAccountId,
    region: AwsRegion,
    domain: DataZoneDomainId,
    datazone_project: DataZoneProjectId,
    asset: DataZoneAssetIdentity,
    listing: DataZoneListingId,
    subscription_request: DataZoneSubscriptionRequestIdentity,
    subscription: DataZoneSubscriptionIdentity,
    subscription_grant: DataZoneSubscriptionGrantId,
    revision: DataZoneRevision,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsDataZoneSubscriptionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        domain: DataZoneDomainId,
        datazone_project: DataZoneProjectId,
        asset: DataZoneAssetIdentity,
        listing: DataZoneListingId,
        subscription_request: DataZoneSubscriptionRequestIdentity,
        subscription: DataZoneSubscriptionIdentity,
        subscription_grant: DataZoneSubscriptionGrantId,
        revision: DataZoneRevision,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            domain,
            datazone_project,
            asset,
            listing,
            subscription_request,
            subscription,
            subscription_grant,
            revision,
            mission,
            project,
            work_product,
        };
        if scope.asset().revision() != scope.revision().as_str() {
            return Err(AwsDataZoneSubscriptionResultError::InvalidScope);
        }
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn domain(&self) -> &DataZoneDomainId {
        &self.domain
    }

    pub fn datazone_project(&self) -> &DataZoneProjectId {
        &self.datazone_project
    }

    pub fn asset(&self) -> &DataZoneAssetIdentity {
        &self.asset
    }

    pub fn listing(&self) -> &DataZoneListingId {
        &self.listing
    }

    pub fn subscription_request(&self) -> &DataZoneSubscriptionRequestIdentity {
        &self.subscription_request
    }

    pub fn subscription(&self) -> &DataZoneSubscriptionIdentity {
        &self.subscription
    }

    pub fn subscription_grant(&self) -> &DataZoneSubscriptionGrantId {
        &self.subscription_grant
    }

    pub fn revision(&self) -> &DataZoneRevision {
        &self.revision
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-subscription-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("domain", self.domain.digest().as_str().to_owned()),
                (
                    "datazone_project",
                    self.datazone_project.digest().as_str().to_owned(),
                ),
                ("asset", self.asset.digest().as_str().to_owned()),
                ("listing", self.listing.digest().as_str().to_owned()),
                (
                    "subscription_request",
                    self.subscription_request.digest().as_str().to_owned(),
                ),
                (
                    "subscription",
                    self.subscription.digest().as_str().to_owned(),
                ),
                (
                    "subscription_grant",
                    self.subscription_grant.digest().as_str().to_owned(),
                ),
                ("revision", self.revision.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
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
        self.datazone_project.validate()?;
        self.asset.validate()?;
        self.listing.validate()?;
        self.subscription_request.validate()?;
        self.subscription.validate()?;
        self.subscription_grant.validate()?;
        self.revision.validate()?;
        if self.asset.revision() != self.revision.as_str() {
            return Err(AwsDataZoneSubscriptionResultError::InvalidScope);
        }
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsDataZoneSubscriptionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataZoneSubscriptionScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("domain", &self.domain)
            .field("datazone_project", &self.datazone_project)
            .field("asset", &self.asset)
            .field("listing", &self.listing)
            .field("subscription_request", &self.subscription_request)
            .field("subscription", &self.subscription)
            .field("subscription_grant", &self.subscription_grant)
            .field("revision", &self.revision)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

pub type AwsDataZoneScope = AwsDataZoneSubscriptionScope;
pub type AwsDataZoneSubscriptionResultScope = AwsDataZoneSubscriptionScope;

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
            return Err(AwsDataZoneSubscriptionResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-datazone-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-datazone-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsDataZoneSubscriptionScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-datazone-opaque-sigv4-reference/v1",
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

    pub(crate) fn validate(&self, scope: &AwsDataZoneSubscriptionScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::InvalidSecretReference);
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
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
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
            "aws-datazone-permissions/v1",
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
            Err(AwsDataZoneSubscriptionResultError::InvalidPermissionSnapshot)
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
            "aws-datazone-consent/v1",
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
        {
            Err(AwsDataZoneSubscriptionResultError::InvalidConsent)
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
pub enum SubscriptionRequestStatus {
    Pending,
    Accepted,
    Rejected,
}

impl SubscriptionRequestStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Accepted => "ACCEPTED",
            Self::Rejected => "REJECTED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubscriptionStatus {
    Approved,
    Revoked,
    Cancelled,
}

impl SubscriptionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "APPROVED",
            Self::Revoked => "REVOKED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetMetadataInput {
    pub status: String,
    pub revision: String,
    pub type_identifier: String,
    pub type_revision: String,
    pub listing_id: String,
    pub owning_project_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetMetadata {
    pub asset_digest: Digest,
    pub status_digest: Digest,
    pub revision_digest: Digest,
    pub type_digest: Digest,
    pub listing_digest: Digest,
    pub owner_project_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AssetMetadata {
    pub fn new(scope: &AwsDataZoneSubscriptionScope, input: AssetMetadataInput) -> Result<Self> {
        scope.validate()?;
        if !valid_text(&input.status, MAX_DATAZONE_ID_BYTES, false)
            || !valid_revision(&input.revision)
            || !valid_identifier(&input.type_identifier, MAX_DATAZONE_ID_BYTES)
            || !valid_revision(&input.type_revision)
        {
            return Err(AwsDataZoneSubscriptionResultError::InvalidText {
                field: "asset-metadata",
            });
        }
        if input.created_at > input.updated_at {
            return Err(AwsDataZoneSubscriptionResultError::InvalidText {
                field: "asset-timestamps",
            });
        }
        let listing_id = DataZoneListingId::new(input.listing_id)?;
        let owner_project_id = DataZoneProjectId::new(input.owning_project_id)?;
        Ok(Self {
            asset_digest: scope.asset().digest(),
            status_digest: Digest::from_parts(
                "aws-datazone-asset-status/v1",
                &[("status", input.status)],
            ),
            revision_digest: Digest::from_parts(
                "aws-datazone-asset-revision/v1",
                &[("revision", input.revision)],
            ),
            type_digest: Digest::from_parts(
                "aws-datazone-asset-type/v1",
                &[
                    ("identifier", input.type_identifier),
                    ("revision", input.type_revision),
                ],
            ),
            listing_digest: listing_id.digest(),
            owner_project_digest: owner_project_id.digest(),
            created_at: input.created_at,
            updated_at: input.updated_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-asset-metadata/v1",
            &[
                ("asset", self.asset_digest.as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("type", self.type_digest.as_str().to_owned()),
                ("listing", self.listing_digest.as_str().to_owned()),
                (
                    "owner_project",
                    self.owner_project_digest.as_str().to_owned(),
                ),
                ("created_at", self.created_at.to_rfc3339()),
                ("updated_at", self.updated_at.to_rfc3339()),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsDataZoneSubscriptionScope) -> Result<()> {
        if self.asset_digest != scope.asset().digest()
            || self.revision_digest != scope.asset().revision_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::EvidenceDrift);
        }
        self.asset_digest.validate()?;
        self.status_digest.validate()?;
        self.revision_digest.validate()?;
        self.type_digest.validate()?;
        if self.listing_digest != self_scope_listing_digest(scope)
            || self.owner_project_digest != scope.datazone_project().digest()
            || self.created_at > self.updated_at
        {
            return Err(AwsDataZoneSubscriptionResultError::EvidenceDrift);
        }
        self.listing_digest.validate()?;
        self.owner_project_digest.validate()
    }
}

fn self_scope_listing_digest(scope: &AwsDataZoneSubscriptionScope) -> Digest {
    scope.listing().digest()
}

pub type AssetProjection = AssetMetadata;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRequestMetadataInput {
    pub status: SubscriptionRequestStatus,
    pub revision: String,
    pub reviewer_role: String,
    pub request_reason: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub asset_digest: Digest,
    pub subscription_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRequestMetadata {
    pub request_digest: Digest,
    pub asset_digest: Digest,
    pub status: SubscriptionRequestStatus,
    pub status_digest: Digest,
    pub revision_digest: Digest,
    pub request_reason_digest: Digest,
    pub reviewer_role_digest: Digest,
    pub subscription_digest: Option<Digest>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl SubscriptionRequestMetadata {
    pub fn for_scope(
        scope: &AwsDataZoneSubscriptionScope,
        status: SubscriptionRequestStatus,
        revision: impl Into<String>,
        reviewer_role: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            scope,
            SubscriptionRequestMetadataInput {
                status,
                revision: revision.into(),
                reviewer_role: reviewer_role.into(),
                request_reason: "fixture request reason".to_owned(),
                created_at: default_metadata_time(),
                updated_at: default_metadata_time(),
                expires_at: None,
                asset_digest: scope.asset().digest(),
                subscription_digest: Some(scope.subscription().digest()),
            },
        )
    }

    pub fn new(
        scope: &AwsDataZoneSubscriptionScope,
        input: SubscriptionRequestMetadataInput,
    ) -> Result<Self> {
        scope.validate()?;
        if !valid_revision(&input.revision)
            || !valid_text(&input.reviewer_role, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&input.request_reason, 4096, true)
            || input.created_at > input.updated_at
            || input
                .expires_at
                .is_some_and(|expires_at| expires_at <= input.created_at)
        {
            return Err(AwsDataZoneSubscriptionResultError::InvalidText {
                field: "subscription-request-metadata",
            });
        }
        input.asset_digest.validate()?;
        if input.asset_digest != scope.asset().digest() {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        if let Some(subscription_digest) = &input.subscription_digest {
            subscription_digest.validate()?;
        }
        Ok(Self {
            request_digest: scope.subscription_request().digest(),
            asset_digest: input.asset_digest,
            status: input.status,
            status_digest: Digest::from_parts(
                "aws-datazone-subscription-request-status/v1",
                &[("status", input.status.as_str().to_owned())],
            ),
            revision_digest: Digest::from_parts(
                "aws-datazone-subscription-request-revision/v1",
                &[("revision", input.revision)],
            ),
            request_reason_digest: Digest::from_parts(
                "aws-datazone-subscription-request-reason/v1",
                &[("reason", input.request_reason)],
            ),
            reviewer_role_digest: Digest::from_parts(
                "aws-datazone-subscription-request-reviewer-role/v1",
                &[("role", input.reviewer_role)],
            ),
            subscription_digest: input.subscription_digest,
            created_at: input.created_at,
            updated_at: input.updated_at,
            expires_at: input.expires_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-subscription-request-metadata/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("asset", self.asset_digest.as_str().to_owned()),
                ("status_value", self.status.as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                (
                    "request_reason",
                    self.request_reason_digest.as_str().to_owned(),
                ),
                (
                    "reviewer_role",
                    self.reviewer_role_digest.as_str().to_owned(),
                ),
                (
                    "subscription",
                    self.subscription_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("created_at", self.created_at.to_rfc3339()),
                ("updated_at", self.updated_at.to_rfc3339()),
                (
                    "expires_at",
                    self.expires_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsDataZoneSubscriptionScope) -> Result<()> {
        if self.request_digest != scope.subscription_request().digest()
            || self.asset_digest != scope.asset().digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        self.request_digest.validate()?;
        self.asset_digest.validate()?;
        self.status_digest.validate()?;
        self.revision_digest.validate()?;
        self.request_reason_digest.validate()?;
        self.reviewer_role_digest.validate()?;
        if self.created_at > self.updated_at
            || self
                .expires_at
                .is_some_and(|expires_at| expires_at <= self.created_at)
        {
            return Err(AwsDataZoneSubscriptionResultError::EvidenceDrift);
        }
        self.subscription_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

pub type SubscriptionRequestProjection = SubscriptionRequestMetadata;
pub type AwsDataZoneSubscriptionRequestStatus = SubscriptionRequestStatus;
pub type AwsDataZoneSubscriptionStatus = SubscriptionStatus;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionMetadataInput {
    pub status: SubscriptionStatus,
    pub revision: String,
    pub request_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionMetadata {
    pub subscription_digest: Digest,
    pub request_digest: Digest,
    pub grant_digest: Digest,
    pub status: SubscriptionStatus,
    pub status_digest: Digest,
    pub revision_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SubscriptionMetadata {
    pub fn for_scope(
        scope: &AwsDataZoneSubscriptionScope,
        status: SubscriptionStatus,
        revision: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            scope,
            SubscriptionMetadataInput {
                status,
                revision: revision.into(),
                request_digest: scope.subscription_request().digest(),
                created_at: default_metadata_time(),
                updated_at: default_metadata_time(),
            },
        )
    }

    pub fn new(
        scope: &AwsDataZoneSubscriptionScope,
        input: SubscriptionMetadataInput,
    ) -> Result<Self> {
        scope.validate()?;
        if !valid_revision(&input.revision) || input.created_at > input.updated_at {
            return Err(AwsDataZoneSubscriptionResultError::InvalidText {
                field: "subscription-metadata",
            });
        }
        if input.request_digest != scope.subscription_request().digest() {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        input.request_digest.validate()?;
        Ok(Self {
            subscription_digest: scope.subscription().digest(),
            request_digest: input.request_digest,
            grant_digest: scope.subscription_grant().digest(),
            status: input.status,
            status_digest: Digest::from_parts(
                "aws-datazone-subscription-status/v1",
                &[("status", input.status.as_str().to_owned())],
            ),
            revision_digest: Digest::from_parts(
                "aws-datazone-subscription-revision/v1",
                &[("revision", input.revision)],
            ),
            created_at: input.created_at,
            updated_at: input.updated_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-subscription-metadata/v1",
            &[
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("grant", self.grant_digest.as_str().to_owned()),
                ("status_value", self.status.as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("created_at", self.created_at.to_rfc3339()),
                ("updated_at", self.updated_at.to_rfc3339()),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsDataZoneSubscriptionScope) -> Result<()> {
        if self.subscription_digest != scope.subscription().digest()
            || self.request_digest != scope.subscription_request().digest()
            || self.grant_digest != scope.subscription_grant().digest()
            || self.created_at > self.updated_at
        {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        self.subscription_digest.validate()?;
        self.request_digest.validate()?;
        self.grant_digest.validate()?;
        self.status_digest.validate()?;
        self.revision_digest.validate()
    }
}

pub type SubscriptionProjection = SubscriptionMetadata;

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRequestFilter {
    asset_digest: Digest,
    status: Option<SubscriptionRequestStatus>,
    max_results: u16,
}

impl SubscriptionRequestFilter {
    pub fn for_scope(
        scope: &AwsDataZoneSubscriptionScope,
        max_results: u16,
        status: Option<SubscriptionRequestStatus>,
    ) -> Result<Self> {
        let filter = Self {
            asset_digest: scope.asset().digest(),
            status,
            max_results,
        };
        filter.validate_against(scope)?;
        Ok(filter)
    }

    pub fn asset_digest(&self) -> &Digest {
        &self.asset_digest
    }

    pub const fn status(&self) -> Option<SubscriptionRequestStatus> {
        self.status
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-subscription-request-filter/v1",
            &[
                ("asset", self.asset_digest.as_str().to_owned()),
                (
                    "status",
                    self.status
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsDataZoneSubscriptionScope) -> Result<()> {
        if self.asset_digest != scope.asset().digest()
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
        {
            return Err(AwsDataZoneSubscriptionResultError::FilterMismatch);
        }
        self.asset_digest.validate()
    }
}

impl fmt::Debug for SubscriptionRequestFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionRequestFilter")
            .field("asset_digest", &self.asset_digest)
            .field("status", &self.status)
            .field("max_results", &self.max_results)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    token_digest: Digest,
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_token: impl AsRef<str>,
        scope: &AwsDataZoneSubscriptionScope,
        filter: &SubscriptionRequestFilter,
        page_number: u16,
    ) -> Result<Self> {
        filter.validate_against(scope)?;
        if page_number == 0
            || page_number > MAX_PAGES
            || !valid_text(opaque_token.as_ref(), 8192, true)
        {
            return Err(AwsDataZoneSubscriptionResultError::CursorMismatch);
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-datazone-opaque-next-token/v1",
                &[("token", opaque_token.as_ref().to_owned())],
            ),
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(
        &self,
        scope: &AwsDataZoneSubscriptionScope,
        filter: &SubscriptionRequestFilter,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != filter.digest()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            return Err(AwsDataZoneSubscriptionResultError::CursorMismatch);
        }
        self.token_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataZoneEvidenceState {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Ready,
    Partial,
    NotFound,
    AccessLost,
    Throttled,
    Tampered,
    Drift,
    ProviderUnknown,
    Revoked,
}

impl DataZoneEvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Accepted
                | Self::Rejected
                | Self::Expired
                | Self::Ready
                | Self::Revoked
        )
    }
}

pub type SubscriptionEvidenceState = DataZoneEvidenceState;
pub type AwsDataZoneEvidenceState = DataZoneEvidenceState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub asset_digest: Option<Digest>,
    pub subscription_request_details_digest: Option<Digest>,
    pub subscription_digest: Option<Digest>,
    pub evidence_digest: Digest,
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
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub(crate) fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.digest(),
        revision: identity.revision(),
    }
}

pub(crate) fn project_projection(identity: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: identity.digest(),
        revision: identity.revision(),
    }
}

pub(crate) fn work_product_projection(identity: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: identity.digest(),
        revision: identity.revision(),
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes <= MAX_RESPONSE_BYTES {
        Ok(())
    } else {
        Err(AwsDataZoneSubscriptionResultError::PartialEvidence)
    }
}

fn default_metadata_time() -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("fixed metadata timestamp")
}

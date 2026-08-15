use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    fmt::Write,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsAppSyncApiResultError, Result};
use crate::{
    FORBIDDEN_PERMISSIONS, LAYER1_PERMISSIONS, MAX_ASSOCIATIONS, MAX_IDENTIFIER_BYTES,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
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
            Err(AwsAppSyncApiResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsAppSyncApiResultError::InvalidDigest)
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
        formatter.write_str(&self.0)
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
                    Err(AwsAppSyncApiResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-appsync-", $field, "/v1"),
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
                    Err(AwsAppSyncApiResultError::InvalidIdentifier { field: $field })
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
redacted_text!(ApiId, "api-id", |value: &str| {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
});
redacted_text!(ApiArn, "api-arn", valid_arn);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppSyncApiType {
    Graphql,
    Event,
}

impl AppSyncApiType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graphql => "GRAPHQL",
            Self::Event => "EVENT",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApiIdentity {
    id: ApiId,
    arn: ApiArn,
}

impl ApiIdentity {
    pub fn new(id: ApiId, arn: ApiArn) -> Result<Self> {
        let identity = Self { id, arn };
        identity.validate()?;
        Ok(identity)
    }

    pub fn id(&self) -> &ApiId {
        &self.id
    }

    pub fn arn(&self) -> &ApiArn {
        &self.arn
    }

    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    pub fn arn_digest(&self) -> Digest {
        self.arn.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-api-identity/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("arn", self.arn_digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn.validate()
    }
}

pub type AppSyncApiIdentity = ApiIdentity;

impl fmt::Debug for ApiIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

macro_rules! scoped_identity {
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
                    return Err(AwsAppSyncApiResultError::InvalidScope);
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
                    concat!("aws-appsync-", $field, "-id/v1"),
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
                    Err(AwsAppSyncApiResultError::InvalidScope)
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

scoped_identity!(MissionIdentity, "aws-appsync-mission/v1", "mission");
scoped_identity!(ProjectIdentity, "aws-appsync-project/v1", "project");
scoped_identity!(
    WorkProductIdentity,
    "aws-appsync-work-product/v1",
    "work-product"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionFence {
    pub schema_revision_digest: Option<Digest>,
    pub schema_digest: Option<Digest>,
    pub deployment_revision_digest: Option<Digest>,
    pub data_source_digest: Option<Digest>,
    pub resolver_digest: Option<Digest>,
    pub association_revision_digest: Option<Digest>,
}

impl RevisionFence {
    pub fn none() -> Self {
        Self {
            schema_revision_digest: None,
            schema_digest: None,
            deployment_revision_digest: None,
            data_source_digest: None,
            resolver_digest: None,
            association_revision_digest: None,
        }
    }

    pub fn new(
        schema_revision_digest: Option<Digest>,
        schema_digest: Option<Digest>,
        deployment_revision_digest: Option<Digest>,
        data_source_digest: Option<Digest>,
        resolver_digest: Option<Digest>,
        association_revision_digest: Option<Digest>,
    ) -> Result<Self> {
        let fence = Self {
            schema_revision_digest,
            schema_digest,
            deployment_revision_digest,
            data_source_digest,
            resolver_digest,
            association_revision_digest,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-revision-fence/v1",
            &[
                (
                    "schema_revision",
                    optional_digest(self.schema_revision_digest.as_ref()),
                ),
                ("schema", optional_digest(self.schema_digest.as_ref())),
                (
                    "deployment_revision",
                    optional_digest(self.deployment_revision_digest.as_ref()),
                ),
                (
                    "data_sources",
                    optional_digest(self.data_source_digest.as_ref()),
                ),
                ("resolvers", optional_digest(self.resolver_digest.as_ref())),
                (
                    "association_revision",
                    optional_digest(self.association_revision_digest.as_ref()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.schema_revision_digest,
            &self.schema_digest,
            &self.deployment_revision_digest,
            &self.data_source_digest,
            &self.resolver_digest,
            &self.association_revision_digest,
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

#[derive(Clone, Eq, PartialEq)]
pub struct AwsAppSyncApiScope {
    account: AwsAccountId,
    region: AwsRegion,
    api: ApiIdentity,
    api_type: AppSyncApiType,
    revision_fence: RevisionFence,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsAppSyncApiScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        api: ApiIdentity,
        api_type: AppSyncApiType,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            api,
            api_type,
            revision_fence: RevisionFence::none(),
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_api(
        account: AwsAccountId,
        region: AwsRegion,
        api: ApiIdentity,
        api_type: AppSyncApiType,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::new(
            account,
            region,
            api,
            api_type,
            mission,
            project,
            work_product,
        )
    }

    pub fn with_revision_fence(mut self, revision_fence: RevisionFence) -> Result<Self> {
        revision_fence.validate()?;
        self.revision_fence = revision_fence;
        self.validate()?;
        Ok(self)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn api(&self) -> &ApiIdentity {
        &self.api
    }

    pub fn api_type(&self) -> AppSyncApiType {
        self.api_type
    }

    pub fn revision_fence(&self) -> &RevisionFence {
        &self.revision_fence
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
            "aws-appsync-api-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("api", self.api.digest().as_str().to_owned()),
                ("api_type", self.api_type.as_str().to_owned()),
                (
                    "revision_fence",
                    self.revision_fence.digest().as_str().to_owned(),
                ),
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
        self.api.validate()?;
        self.revision_fence.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

pub type AppSyncScope = AwsAppSyncApiScope;

impl fmt::Debug for AwsAppSyncApiScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppSyncApiScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("api", &self.api)
            .field("api_type", &self.api_type)
            .field("revision_fence", &self.revision_fence)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4,
    ApiKey,
    Oidc,
}

/// An opaque reference to host-owned credentials. The caller's handle is
/// hashed and dropped; it is never serialized, displayed, or retained.
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
        Self::with_kind(SecretKind::Sigv4, opaque_handle, revision)
    }

    pub fn with_kind(
        kind: SecretKind,
        opaque_handle: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsAppSyncApiResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-appsync-opaque-secret-reference/v1",
            &[
                ("kind", kind.as_str().to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-appsync-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsAppSyncApiScope,
        revision: u64,
    ) -> Result<Self> {
        Self::bound(SecretKind::Sigv4, opaque_handle, scope, revision)
    }

    pub fn api_key(
        opaque_handle: impl Into<String>,
        scope: &AwsAppSyncApiScope,
        revision: u64,
    ) -> Result<Self> {
        Self::bound(SecretKind::ApiKey, opaque_handle, scope, revision)
    }

    pub fn oidc(
        opaque_handle: impl Into<String>,
        scope: &AwsAppSyncApiScope,
        revision: u64,
    ) -> Result<Self> {
        Self::bound(SecretKind::Oidc, opaque_handle, scope, revision)
    }

    fn bound(
        kind: SecretKind,
        opaque_handle: impl Into<String>,
        scope: &AwsAppSyncApiScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::with_kind(kind, opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-appsync-opaque-secret-reference/v1",
            &[
                ("kind", kind.as_str().to_owned()),
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

    pub(crate) fn validate(&self, scope: &AwsAppSyncApiScope) -> Result<()> {
        if self.revision == 0 || self.revoked || self.scope_digest != scope.digest() {
            return Err(AwsAppSyncApiResultError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sigv4 => "sigv4",
            Self::ApiKey => "api_key",
            Self::Oidc => "oidc",
        }
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
    pub forbidden_permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S, J, T>(revision: u64, permissions: I, forbidden_permissions: J) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        J: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            forbidden_permissions: forbidden_permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            forbidden_permissions: FORBIDDEN_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-permissions/v1",
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
                (
                    "forbidden",
                    self.forbidden_permissions
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
            || FORBIDDEN_PERMISSIONS
                .iter()
                .any(|permission| !self.forbidden_permissions.contains(*permission))
            || self
                .permissions
                .iter()
                .any(|permission| self.forbidden_permissions.contains(permission))
        {
            Err(AwsAppSyncApiResultError::InvalidPermissionSnapshot)
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
            "aws-appsync-consent/v1",
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
            Err(AwsAppSyncApiResultError::InvalidConsent)
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
pub enum ApiLifecycleState {
    Active,
    Disabled,
    Degraded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchemaCreationStatus {
    Processing,
    Active,
    Deleting,
    Failed,
    Success,
    NotApplicable,
    Unknown,
}

impl SchemaCreationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "PROCESSING",
            Self::Active => "ACTIVE",
            Self::Deleting => "DELETING",
            Self::Failed => "FAILED",
            Self::Success => "SUCCESS",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentState {
    Active,
    Processing,
    Failed,
    Unknown,
}

impl DeploymentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Processing => "PROCESSING",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiSummary {
    pub api_identity_digest: Digest,
    pub api_type: AppSyncApiType,
    pub lifecycle: ApiLifecycleState,
    pub enabled: bool,
    pub last_modified_time: DateTime<Utc>,
    pub revision_digest: Digest,
    pub summary_digest: Digest,
}

impl ApiSummary {
    pub fn new(
        identity: ApiIdentity,
        api_type: AppSyncApiType,
        lifecycle: ApiLifecycleState,
        enabled: bool,
        last_modified_time: DateTime<Utc>,
        revision: impl Into<String>,
    ) -> Result<Self> {
        identity.validate()?;
        let revision = revision.into();
        if !valid_text(&revision, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsAppSyncApiResultError::InvalidText {
                field: "api-revision",
            });
        }
        let api_identity_digest = identity.digest();
        let revision_digest =
            Digest::from_parts("aws-appsync-api-revision/v1", &[("value", revision)]);
        let summary_digest = Digest::from_parts(
            "aws-appsync-api-summary/v1",
            &[
                ("api", api_identity_digest.as_str().to_owned()),
                ("type", api_type.as_str().to_owned()),
                ("lifecycle", format!("{lifecycle:?}")),
                ("enabled", enabled.to_string()),
                ("last_modified", last_modified_time.to_rfc3339()),
                ("revision", revision_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            api_identity_digest,
            api_type,
            lifecycle,
            enabled,
            last_modified_time,
            revision_digest,
            summary_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.summary_digest
    }

    pub(crate) fn validate_against(&self, scope: &AwsAppSyncApiScope) -> Result<()> {
        if self.api_identity_digest != scope.api.digest()
            || self.api_type != scope.api_type
            || self.summary_digest != self.recompute_digest()
        {
            return Err(AwsAppSyncApiResultError::ApiDrift);
        }
        self.revision_digest.validate()
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-api-summary/v1",
            &[
                ("api", self.api_identity_digest.as_str().to_owned()),
                ("type", self.api_type.as_str().to_owned()),
                ("lifecycle", format!("{:?}", self.lifecycle)),
                ("enabled", self.enabled.to_string()),
                ("last_modified", self.last_modified_time.to_rfc3339()),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiMetadata {
    pub api_identity_digest: Digest,
    pub api_type: AppSyncApiType,
    pub enabled: bool,
    pub endpoint_digest: Digest,
    pub authentication_mode_digest: Digest,
    pub event_configuration_digest: Option<Digest>,
    pub visibility_digest: Digest,
    pub waf_digest: Option<Digest>,
    pub xray_enabled: bool,
    pub updated_at: DateTime<Utc>,
    pub config_revision_digest: Digest,
    pub metadata_digest: Digest,
}

impl ApiMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I, S>(
        scope: &AwsAppSyncApiScope,
        endpoint: impl Into<String>,
        authentication_modes: I,
        event_configuration: Option<impl Into<String>>,
        visibility: impl Into<String>,
        waf_arn: Option<impl Into<String>>,
        enabled: bool,
        xray_enabled: bool,
        config_revision: impl Into<String>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        scope.validate()?;
        let endpoint = endpoint.into();
        let visibility = visibility.into();
        let config_revision = config_revision.into();
        if !valid_text(&endpoint, MAX_IDENTIFIER_BYTES, false)
            || !valid_text(&visibility, MAX_IDENTIFIER_BYTES, false)
            || !valid_text(&config_revision, MAX_IDENTIFIER_BYTES, true)
        {
            return Err(AwsAppSyncApiResultError::InvalidText {
                field: "api-metadata",
            });
        }
        let authentication_modes = authentication_modes
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        if authentication_modes.is_empty()
            || authentication_modes
                .iter()
                .any(|mode| !valid_identifier(mode, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsAppSyncApiResultError::InvalidText {
                field: "authentication-mode",
            });
        }
        let event_configuration_digest = event_configuration.map(Into::into).map(Digest::from_text);
        let waf_digest = waf_arn.map(Into::into).map(Digest::from_text);
        let mut metadata = Self {
            api_identity_digest: scope.api.digest(),
            api_type: scope.api_type,
            enabled,
            endpoint_digest: Digest::from_text(endpoint),
            authentication_mode_digest: Digest::from_parts(
                "aws-appsync-authentication-modes/v1",
                &[("modes", authentication_modes.join("\n"))],
            ),
            event_configuration_digest,
            visibility_digest: Digest::from_text(visibility),
            waf_digest,
            xray_enabled,
            updated_at,
            config_revision_digest: Digest::from_text(config_revision),
            metadata_digest: Digest::from_text("unsealed-aws-appsync-api-metadata"),
        };
        metadata.metadata_digest = metadata.recompute_digest();
        Ok(metadata)
    }

    pub(crate) fn validate_against(&self, scope: &AwsAppSyncApiScope) -> Result<()> {
        if self.api_identity_digest != scope.api.digest()
            || self.api_type != scope.api_type
            || self.metadata_digest != self.recompute_digest()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        self.config_revision_digest.validate()?;
        Ok(())
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-api-metadata/v1",
            &[
                ("api", self.api_identity_digest.as_str().to_owned()),
                ("type", self.api_type.as_str().to_owned()),
                ("enabled", self.enabled.to_string()),
                ("endpoint", self.endpoint_digest.as_str().to_owned()),
                ("auth", self.authentication_mode_digest.as_str().to_owned()),
                (
                    "event_config",
                    optional_digest(self.event_configuration_digest.as_ref()),
                ),
                ("visibility", self.visibility_digest.as_str().to_owned()),
                ("waf", optional_digest(self.waf_digest.as_ref())),
                ("xray", self.xray_enabled.to_string()),
                ("updated_at", self.updated_at.to_rfc3339()),
                (
                    "config_revision",
                    self.config_revision_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaDeploymentMetadata {
    pub api_identity_digest: Digest,
    pub schema_revision_digest: Digest,
    pub schema_digest: Digest,
    pub schema_status: SchemaCreationStatus,
    pub deployment_state: DeploymentState,
    pub deployment_revision_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub metadata_digest: Digest,
}

impl SchemaDeploymentMetadata {
    pub fn new(
        scope: &AwsAppSyncApiScope,
        schema_revision: impl Into<String>,
        schema_hash_or_opaque: impl Into<String>,
        schema_status: SchemaCreationStatus,
        deployment_state: DeploymentState,
        deployment_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        let schema_revision = schema_revision.into();
        let schema_hash_or_opaque = schema_hash_or_opaque.into();
        let deployment_revision = deployment_revision.into();
        if !valid_text(&schema_revision, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&schema_hash_or_opaque, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&deployment_revision, MAX_IDENTIFIER_BYTES, true)
        {
            return Err(AwsAppSyncApiResultError::InvalidText {
                field: "schema-revision",
            });
        }
        let mut metadata = Self {
            api_identity_digest: scope.api.digest(),
            schema_revision_digest: Digest::from_text(schema_revision),
            schema_digest: Digest::from_text(schema_hash_or_opaque),
            schema_status,
            deployment_state,
            deployment_revision_digest: Digest::from_text(deployment_revision),
            observed_at,
            metadata_digest: Digest::from_text("unsealed-aws-appsync-schema-metadata"),
        };
        metadata.metadata_digest = metadata.recompute_digest();
        Ok(metadata)
    }

    pub(crate) fn validate_against(&self, scope: &AwsAppSyncApiScope) -> Result<()> {
        if self.api_identity_digest != scope.api.digest()
            || self.metadata_digest != self.recompute_digest()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        for digest in [
            &self.schema_revision_digest,
            &self.schema_digest,
            &self.deployment_revision_digest,
        ] {
            digest.validate()?;
        }
        let fence = scope.revision_fence();
        if fence
            .schema_revision_digest
            .as_ref()
            .is_some_and(|expected| expected != &self.schema_revision_digest)
            || fence
                .schema_digest
                .as_ref()
                .is_some_and(|expected| expected != &self.schema_digest)
            || fence
                .deployment_revision_digest
                .as_ref()
                .is_some_and(|expected| expected != &self.deployment_revision_digest)
        {
            return Err(AwsAppSyncApiResultError::RevisionDrift);
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-schema-deployment-metadata/v1",
            &[
                ("api", self.api_identity_digest.as_str().to_owned()),
                (
                    "schema_revision",
                    self.schema_revision_digest.as_str().to_owned(),
                ),
                ("schema", self.schema_digest.as_str().to_owned()),
                ("schema_status", self.schema_status.as_str().to_owned()),
                ("deployment", self.deployment_state.as_str().to_owned()),
                (
                    "deployment_revision",
                    self.deployment_revision_digest.as_str().to_owned(),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

impl SchemaCreationStatus {
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed | Self::Deleting | Self::Unknown)
    }
}

impl DeploymentState {
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed | Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssociationKind {
    DataSource,
    Resolver,
}

impl AssociationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataSource => "DATA_SOURCE",
            Self::Resolver => "RESOLVER",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociationPage {
    pub api_identity_digest: Digest,
    pub kind: AssociationKind,
    pub page_number: u16,
    pub item_count: u16,
    pub items_digest: Digest,
    pub next_cursor_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl AssociationPage {
    pub(crate) fn new(
        scope: &AwsAppSyncApiScope,
        kind: AssociationKind,
        page_number: u16,
        items_digest: Digest,
        item_count: usize,
        next_cursor_digest: Option<Digest>,
    ) -> Result<Self> {
        if item_count > MAX_ASSOCIATIONS || item_count > u16::MAX as usize {
            return Err(AwsAppSyncApiResultError::PartialEvidence);
        }
        let mut page = Self {
            api_identity_digest: scope.api.digest(),
            kind,
            page_number,
            item_count: item_count as u16,
            items_digest,
            next_cursor_digest,
            page_digest: Digest::from_text("unsealed-aws-appsync-association-page"),
        };
        page.page_digest = page.recompute_digest();
        Ok(page)
    }

    pub(crate) fn validate(
        &self,
        scope: &AwsAppSyncApiScope,
        expected_kind: AssociationKind,
    ) -> Result<()> {
        if self.api_identity_digest != scope.api.digest()
            || self.kind != expected_kind
            || self.item_count as usize > MAX_ASSOCIATIONS
            || self.page_digest != self.recompute_digest()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        self.items_digest.validate()?;
        if let Some(cursor) = &self.next_cursor_digest {
            cursor.validate()?;
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-association-page/v1",
            &[
                ("api", self.api_identity_digest.as_str().to_owned()),
                ("kind", self.kind.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                ("count", self.item_count.to_string()),
                ("items", self.items_digest.as_str().to_owned()),
                ("cursor", optional_digest(self.next_cursor_digest.as_ref())),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociationProjection {
    pub api_identity_digest: Digest,
    pub data_source_count: u16,
    pub data_source_digest: Digest,
    pub resolver_count: u16,
    pub resolver_digest: Digest,
    pub association_revision_digest: Digest,
    pub association_digest: Digest,
}

impl AssociationProjection {
    pub fn from_pages(
        scope: &AwsAppSyncApiScope,
        data_source_pages: &[AssociationPage],
        resolver_pages: &[AssociationPage],
        association_revision: impl Into<String>,
    ) -> Result<Self> {
        let association_revision = association_revision.into();
        if !valid_text(&association_revision, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsAppSyncApiResultError::InvalidText {
                field: "association-revision",
            });
        }
        let data_source_digest = digest_pages(
            "data-sources",
            data_source_pages,
            scope,
            AssociationKind::DataSource,
        )?;
        let resolver_digest = digest_pages(
            "resolvers",
            resolver_pages,
            scope,
            AssociationKind::Resolver,
        )?;
        let data_source_count = sum_page_counts(data_source_pages)?;
        let resolver_count = sum_page_counts(resolver_pages)?;
        let association_revision_digest = Digest::from_text(association_revision);
        let association_digest = Digest::from_parts(
            "aws-appsync-associations/v1",
            &[
                ("api", scope.api.digest().as_str().to_owned()),
                ("data_sources", data_source_digest.as_str().to_owned()),
                ("resolvers", resolver_digest.as_str().to_owned()),
                ("revision", association_revision_digest.as_str().to_owned()),
            ],
        );
        let projection = Self {
            api_identity_digest: scope.api.digest(),
            data_source_count,
            data_source_digest,
            resolver_count,
            resolver_digest,
            association_revision_digest,
            association_digest,
        };
        let fence = scope.revision_fence();
        if fence
            .data_source_digest
            .as_ref()
            .is_some_and(|expected| expected != &projection.data_source_digest)
            || fence
                .resolver_digest
                .as_ref()
                .is_some_and(|expected| expected != &projection.resolver_digest)
            || fence
                .association_revision_digest
                .as_ref()
                .is_some_and(|expected| expected != &projection.association_revision_digest)
        {
            return Err(AwsAppSyncApiResultError::RevisionDrift);
        }
        Ok(projection)
    }

    pub fn validate_integrity(&self, scope: &AwsAppSyncApiScope) -> Result<()> {
        if self.api_identity_digest != scope.api.digest()
            || self.data_source_count as usize > MAX_ASSOCIATIONS
            || self.resolver_count as usize > MAX_ASSOCIATIONS
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        for digest in [
            &self.data_source_digest,
            &self.resolver_digest,
            &self.association_revision_digest,
            &self.association_digest,
        ] {
            digest.validate()?;
        }
        Ok(())
    }
}

fn sum_page_counts(pages: &[AssociationPage]) -> Result<u16> {
    let count: usize = pages.iter().map(|page| page.item_count as usize).sum();
    if count > MAX_ASSOCIATIONS || count > u16::MAX as usize {
        Err(AwsAppSyncApiResultError::PartialEvidence)
    } else {
        Ok(count as u16)
    }
}

fn digest_pages(
    domain: &str,
    pages: &[AssociationPage],
    scope: &AwsAppSyncApiScope,
    kind: AssociationKind,
) -> Result<Digest> {
    for page in pages {
        page.validate(scope, kind)?;
    }
    Ok(Digest::from_parts(
        &format!("aws-appsync-{domain}/v1"),
        &[(
            "pages",
            pages
                .iter()
                .map(|page| page.page_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join("\n"),
        )],
    ))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppSyncEvidenceState {
    #[serde(rename = "AVAILABLE")]
    Available,
    #[serde(rename = "DISABLED")]
    Disabled,
    #[serde(rename = "DEGRADED")]
    Degraded,
    #[serde(rename = "PARTIAL")]
    Partial,
    #[serde(rename = "STALE")]
    Stale,
    #[serde(rename = "ACCESS_LOST")]
    AccessLost,
    #[serde(rename = "PROVIDER_UNKNOWN")]
    ProviderUnknown,
    #[serde(rename = "TAMPERED")]
    Tampered,
    #[serde(rename = "REVOKED")]
    Revoked,
}

impl AppSyncEvidenceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "AVAILABLE",
            Self::Disabled => "DISABLED",
            Self::Degraded => "DEGRADED",
            Self::Partial => "PARTIAL",
            Self::Stale => "STALE",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Tampered => "TAMPERED",
            Self::Revoked => "REVOKED",
        }
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Available | Self::Disabled | Self::Degraded | Self::Stale
        )
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
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
pub struct WorkProductProjection {
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

pub fn work_product_projection(identity: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
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
            "aws-appsync-request-receipt/v1",
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
                    "aws-appsync-request-receipt/v1",
                    &[
                        ("operation", self.operation.clone()),
                        ("request", self.request_digest.as_str().to_owned()),
                        ("path", self.path_digest.as_str().to_owned()),
                        ("redacted", "true".to_owned()),
                    ],
                )
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        self.path_digest.validate()
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
            return Err(AwsAppSyncApiResultError::PartialEvidence);
        }
        let operation = operation.into();
        let bounded_request_units = 1;
        let cost_basis = "layer1_metadata_read_estimate".to_owned();
        let receipt_digest = Digest::from_parts(
            "aws-appsync-cost-receipt/v1",
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
        if !self.redacted || self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        let expected = Digest::from_parts(
            "aws-appsync-cost-receipt/v1",
            &[
                ("operation", self.operation.clone()),
                ("response_bytes", self.response_bytes.to_string()),
                ("request_units", self.bounded_request_units.to_string()),
                ("cost_basis", self.cost_basis.clone()),
                ("redacted", "true".to_owned()),
            ],
        );
        if self.receipt_digest != expected {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_revision_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub api_digest: Option<Digest>,
    pub schema_digest: Option<Digest>,
    pub deployment_digest: Option<Digest>,
    pub association_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_revision_digest,
            &self.permission_digest,
            &self.scope_digest,
        ] {
            digest.validate()?;
        }
        for digest in [
            &self.api_digest,
            &self.schema_digest,
            &self.deployment_digest,
            &self.association_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        self.evidence_digest.validate()?;
        Ok(())
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
            "aws-appsync-cost-summary/v1",
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

pub fn digest_items(domain: &str, items: impl IntoIterator<Item = String>) -> Digest {
    let mut items = items.into_iter().collect::<Vec<_>>();
    items.sort_unstable();
    Digest::from_parts(
        domain,
        &[
            ("items", items.join("\n")),
            ("count", items.len().to_string()),
        ],
    )
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
        Err(AwsAppSyncApiResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_page_number(page_number: u16) -> Result<()> {
    if page_number == 0 || page_number > MAX_PAGES {
        Err(AwsAppSyncApiResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsAppSyncApiResultError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_cursor_seen(seen: &mut HashSet<Digest>, cursor: &Digest) -> Result<()> {
    if seen.insert(cursor.clone()) {
        Ok(())
    } else {
        Err(AwsAppSyncApiResultError::PaginationLoop)
    }
}

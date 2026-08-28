//! Exact Google Play, artifact, and Mission scope plus redacted evidence.
//!
//! The models in this module are intentionally smaller than the Android
//! Publisher response.  They retain identifiers, lifecycle state, rollout
//! buckets, bounded version-code digests, and receipt digests only.  They do
//! not retain release notes, tester data, APK/AAB bytes, signing material,
//! access tokens, private keys, or an unconstrained provider payload.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    CONTRACT_VERSION, MAX_IDENTIFIER_BYTES, MAX_RELEASES, MAX_VERSION_CODES_PER_RELEASE,
    PROVIDER_ID, PROVIDER_REVISION, Result, digest_serialized_with_domain, validate_identifier,
    validate_text,
};

/// A lower-case SHA-256 digest used as a stable boundary, not as an external
/// provider receipt or a kernel verification claim.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value))
        } else {
            Err(crate::GooglePlayReleaseResultError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    pub fn from_text(value: &str) -> Self {
        Self(sha256_hex(value.as_bytes()))
    }

    pub fn from_parts(domain: &str, fields: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut input = String::from(domain);
        for (name, value) in fields {
            input.push('\0');
            input.push_str(&name);
            input.push('=');
            input.push_str(&value);
        }
        Self::from_text(&input)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
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

impl FromStr for Digest {
    type Err = crate::GooglePlayReleaseResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self> {
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
            type Err = crate::GooglePlayReleaseResultError;

            fn from_str(value: &str) -> Result<Self> {
                Self::parse(value)
            }
        }
    };
}

bounded_identifier!(DeveloperAccountId, "developer account");
bounded_identifier!(ArtifactId, "artifact id");
bounded_identifier!(ReleaseId, "release id");
bounded_identifier!(DeploymentIdentity, "deployment identity");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PackageName(String);

impl PackageName {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "package name", MAX_IDENTIFIER_BYTES, false)?;
        if !value.contains('.')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(crate::GooglePlayReleaseResultError::InvalidIdentifier {
                field: "package name",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PackageName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("PackageName").field(&self.0).finish()
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for PackageName {
    type Err = crate::GooglePlayReleaseResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TrackName(String);

impl TrackName {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_identifier(&value, "track")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TrackName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("TrackName").field(&self.0).finish()
    }
}

impl fmt::Display for TrackName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TrackName {
    type Err = crate::GooglePlayReleaseResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormFactor {
    Phone,
    Tablet,
    Wear,
    Tv,
    Automotive,
    Other,
}

impl FormFactor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phone => "phone",
            Self::Tablet => "tablet",
            Self::Wear => "wear",
            Self::Tv => "tv",
            Self::Automotive => "automotive",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ServiceAccount,
    OAuth,
}

impl CredentialKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceAccount => "service_account",
            Self::OAuth => "oauth",
        }
    }
}

/// Opaque credential identity.  The constructor hashes the caller-owned
/// handle immediately and never stores that handle, a token, or key bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    credential_kind: CredentialKind,
    reference_digest: Digest,
    credential_revision: u64,
    scope_digest: Digest,
    permission_digest: Digest,
    revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("credential_kind", &self.credential_kind)
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 6)?;
        state.serialize_field("credentialKind", &self.credential_kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            credential_kind: CredentialKind,
            reference_digest: Digest,
            credential_revision: u64,
            scope_digest: Digest,
            permission_digest: Digest,
            revoked: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.credential_revision == 0
            || !wire.reference_digest.is_sha256()
            || !wire.scope_digest.is_sha256()
            || !wire.permission_digest.is_sha256()
        {
            return Err(serde::de::Error::custom("invalid opaque SecretReference"));
        }
        Ok(Self {
            credential_kind: wire.credential_kind,
            reference_digest: wire.reference_digest,
            credential_revision: wire.credential_revision,
            scope_digest: wire.scope_digest,
            permission_digest: wire.permission_digest,
            revoked: wire.revoked,
        })
    }
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl AsRef<str>,
        credential_kind: CredentialKind,
        credential_revision: u64,
    ) -> Result<Self> {
        if credential_revision == 0 {
            return Err(crate::GooglePlayReleaseResultError::InvalidSecretReference);
        }
        let handle = opaque_handle.as_ref();
        validate_text(handle, "opaque secret handle", MAX_IDENTIFIER_BYTES, true)?;
        Ok(Self {
            credential_kind,
            reference_digest: Digest::from_parts(
                "googleplay-release-result/secret-reference/v1",
                [
                    ("kind".to_owned(), credential_kind.as_str().to_owned()),
                    ("handle".to_owned(), handle.to_owned()),
                    ("revision".to_owned(), credential_revision.to_string()),
                ],
            ),
            credential_revision,
            scope_digest: Digest::from_text("unbound-secret-scope"),
            permission_digest: Digest::from_text("unbound-secret-permission"),
            revoked: false,
        })
    }

    pub fn for_service_account(opaque_handle: impl AsRef<str>, revision: u64) -> Result<Self> {
        Self::new(opaque_handle, CredentialKind::ServiceAccount, revision)
    }

    pub fn for_oauth(opaque_handle: impl AsRef<str>, revision: u64) -> Result<Self> {
        Self::new(opaque_handle, CredentialKind::OAuth, revision)
    }

    pub fn bind_to(
        mut self,
        scope: &GooglePlayReleaseScope,
        permissions: &PermissionSnapshot,
    ) -> Result<Self> {
        scope.validate()?;
        permissions.validate()?;
        self.scope_digest = scope.digest();
        self.permission_digest = permissions.digest.clone();
        Ok(self)
    }

    pub fn credential_kind(&self) -> CredentialKind {
        self.credential_kind
    }

    pub fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(mut self) -> Self {
        self.revoked = true;
        self
    }

    pub fn is_bound_to(
        &self,
        scope: &GooglePlayReleaseScope,
        permissions: &PermissionSnapshot,
    ) -> bool {
        !self.revoked
            && self.scope_digest == scope.digest()
            && self.permission_digest == permissions.digest
    }
}

/// A short-lived bearer token borrowed by one official GET.  It is not
/// serializable or cloneable and its bytes are zeroized on drop.
pub struct AccessTokenLease {
    value: String,
    expires_at_epoch_seconds: u64,
}

impl fmt::Debug for AccessTokenLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessTokenLease")
            .field("value", &"<redacted>")
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

impl AccessTokenLease {
    pub fn new(value: impl Into<String>, expires_at_epoch_seconds: u64) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(crate::GooglePlayReleaseResultError::InvalidCredential);
        }
        Ok(Self {
            value,
            expires_at_epoch_seconds,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn validate_at(&self, epoch_seconds: u64) -> Result<()> {
        if epoch_seconds >= self.expires_at_epoch_seconds {
            Err(crate::GooglePlayReleaseResultError::CredentialExpired)
        } else {
            Ok(())
        }
    }
}

impl Drop for AccessTokenLease {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub read_scopes: Vec<String>,
    pub write_scopes: Vec<String>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only() -> Self {
        let read_scopes = vec!["androidpublisher.releases.read".to_owned()];
        let write_scopes = Vec::new();
        let digest = digest_serialized_with_domain(
            "googleplay-release-result/permission/v1",
            &(&read_scopes, &write_scopes),
        );
        Self {
            read_scopes,
            write_scopes,
            digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.read_scopes != ["androidpublisher.releases.read"]
            || !self.write_scopes.is_empty()
            || self.digest
                != digest_serialized_with_domain(
                    "googleplay-release-result/permission/v1",
                    &(&self.read_scopes, &self.write_scopes),
                )
        {
            return Err(crate::GooglePlayReleaseResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    pub id: String,
    pub revision: u64,
}

fn validate_revision_scope(id: &str, field: &'static str, revision: u64) -> Result<()> {
    validate_identifier(id, field)?;
    if revision == 0 {
        return Err(crate::GooglePlayReleaseResultError::InvalidScope);
    }
    Ok(())
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_revision_scope(&id, "Project id", revision)?;
        Ok(Self { id, revision })
    }
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_revision_scope(&id, "Mission id", revision)?;
        Ok(Self { id, revision })
    }
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_revision_scope(&id, "Work Product id", revision)?;
        Ok(Self { id, revision })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactBinding {
    pub artifact_id: ArtifactId,
    pub version_code: u64,
    pub artifact_digest: Digest,
}

impl ArtifactBinding {
    pub fn new(
        artifact_id: ArtifactId,
        version_code: u64,
        artifact_digest: Digest,
    ) -> Result<Self> {
        if version_code == 0 || !artifact_digest.is_sha256() {
            return Err(crate::GooglePlayReleaseResultError::InvalidScope);
        }
        Ok(Self {
            artifact_id,
            version_code,
            artifact_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ReleaseSelector {
    Any,
    Exact(ReleaseId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RolloutSelector {
    Any,
    Exact(RolloutBucket),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayReleaseScope {
    pub developer_account: DeveloperAccountId,
    pub package_name: PackageName,
    pub track: TrackName,
    pub form_factor: FormFactor,
    pub release_selector: ReleaseSelector,
    pub rollout: RolloutSelector,
    pub artifact: ArtifactBinding,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub deployment_identity: Option<DeploymentIdentity>,
}

impl GooglePlayReleaseScope {
    pub fn new(
        developer_account: DeveloperAccountId,
        package_name: PackageName,
        track: TrackName,
        form_factor: FormFactor,
        release_selector: ReleaseSelector,
        artifact: ArtifactBinding,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        deployment_identity: Option<DeploymentIdentity>,
    ) -> Result<Self> {
        let scope = Self {
            developer_account,
            package_name,
            track,
            form_factor,
            release_selector,
            rollout: RolloutSelector::Any,
            artifact,
            project,
            mission,
            work_product,
            deployment_identity,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_rollout(mut self, rollout: RolloutSelector) -> Result<Self> {
        if let RolloutSelector::Exact(bucket) = &rollout {
            bucket.validate()?;
        }
        self.rollout = rollout;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(self.developer_account.as_str(), "developer account")?;
        if let RolloutSelector::Exact(bucket) = &self.rollout {
            bucket.validate()?;
        }
        if self.artifact.version_code == 0 || !self.artifact.artifact_digest.is_sha256() {
            return Err(crate::GooglePlayReleaseResultError::InvalidScope);
        }
        validate_revision_scope(&self.project.id, "Project id", self.project.revision)?;
        validate_revision_scope(&self.mission.id, "Mission id", self.mission.revision)?;
        validate_revision_scope(
            &self.work_product.id,
            "Work Product id",
            self.work_product.revision,
        )?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized_with_domain("googleplay-release-result/scope/v1", self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseLifecycleState {
    Draft,
    NotSentForReview,
    InReview,
    ApprovedNotPublished,
    NotApproved,
    Published,
}

impl ReleaseLifecycleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::NotSentForReview => "NOT_SENT_FOR_REVIEW",
            Self::InReview => "IN_REVIEW",
            Self::ApprovedNotPublished => "APPROVED_NOT_PUBLISHED",
            Self::NotApproved => "NOT_APPROVED",
            Self::Published => "PUBLISHED",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "DRAFT" => Ok(Self::Draft),
            "NOT_SENT_FOR_REVIEW" => Ok(Self::NotSentForReview),
            "IN_REVIEW" => Ok(Self::InReview),
            "APPROVED_NOT_PUBLISHED" => Ok(Self::ApprovedNotPublished),
            "NOT_APPROVED" => Ok(Self::NotApproved),
            "PUBLISHED" => Ok(Self::Published),
            _ => Err(crate::GooglePlayReleaseResultError::UnsupportedLifecycleState),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseResultStatus {
    Draft,
    NotSentForReview,
    InReview,
    ApprovedNotPublished,
    NotApproved,
    Published,
    Halted,
    Stale,
    AccessLost,
    Partial,
    ProviderUnknown,
}

impl ReleaseResultStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::NotSentForReview => "NOT_SENT_FOR_REVIEW",
            Self::InReview => "IN_REVIEW",
            Self::ApprovedNotPublished => "APPROVED_NOT_PUBLISHED",
            Self::NotApproved => "NOT_APPROVED",
            Self::Published => "PUBLISHED",
            Self::Halted => "HALTED",
            Self::Stale => "STALE",
            Self::AccessLost => "ACCESS_LOST",
            Self::Partial => "PARTIAL",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
        }
    }

    pub const fn is_provider_state(self) -> bool {
        matches!(
            self,
            Self::Stale | Self::AccessLost | Self::Partial | Self::ProviderUnknown
        )
    }
}

impl From<ReleaseLifecycleState> for ReleaseResultStatus {
    fn from(value: ReleaseLifecycleState) -> Self {
        match value {
            ReleaseLifecycleState::Draft => Self::Draft,
            ReleaseLifecycleState::NotSentForReview => Self::NotSentForReview,
            ReleaseLifecycleState::InReview => Self::InReview,
            ReleaseLifecycleState::ApprovedNotPublished => Self::ApprovedNotPublished,
            ReleaseLifecycleState::NotApproved => Self::NotApproved,
            ReleaseLifecycleState::Published => Self::Published,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RolloutBucket {
    Full,
    UserFraction { millionths: u32 },
    CountryTargeted { targeting_digest: Digest },
    Halted,
}

impl RolloutBucket {
    pub fn user_fraction(millionths: u32) -> Result<Self> {
        if millionths == 0 || millionths > 1_000_000 {
            return Err(crate::GooglePlayReleaseResultError::InvalidRollout);
        }
        Ok(Self::UserFraction { millionths })
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Full | Self::Halted => Ok(()),
            Self::UserFraction { millionths } => {
                if *millionths == 0 || *millionths > 1_000_000 {
                    Err(crate::GooglePlayReleaseResultError::InvalidRollout)
                } else {
                    Ok(())
                }
            }
            Self::CountryTargeted { targeting_digest } => {
                if targeting_digest.is_sha256() {
                    Ok(())
                } else {
                    Err(crate::GooglePlayReleaseResultError::InvalidRollout)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveArtifactVersionCodeDigest {
    pub version_code: u64,
    pub version_code_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayReleaseSummary {
    pub release_id: ReleaseId,
    pub release_name: Option<String>,
    pub lifecycle_state: ReleaseLifecycleState,
    pub active_artifact_version_code_digests: Vec<ActiveArtifactVersionCodeDigest>,
    pub rollout_bucket: RolloutBucket,
    pub country_targeting_digest: Option<Digest>,
    pub artifact_binding_matches: bool,
    pub release_digest: Digest,
}

impl GooglePlayReleaseSummary {
    pub fn validate(&self) -> Result<()> {
        if self.active_artifact_version_code_digests.is_empty()
            || self.active_artifact_version_code_digests.len() > MAX_VERSION_CODES_PER_RELEASE
            || self
                .active_artifact_version_code_digests
                .iter()
                .any(|artifact| {
                    artifact.version_code == 0 || !artifact.version_code_digest.is_sha256()
                })
            || !self.release_digest.is_sha256()
            || self
                .country_targeting_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_sha256())
        {
            return Err(crate::GooglePlayReleaseResultError::InvalidEvidence);
        }
        self.rollout_bucket.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayReleaseEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub developer_account: DeveloperAccountId,
    pub package_name: PackageName,
    pub track: TrackName,
    pub form_factor: FormFactor,
    pub release_selector: ReleaseSelector,
    pub rollout: RolloutSelector,
    pub artifact: ArtifactBinding,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub deployment_identity: Option<DeploymentIdentity>,
    pub status: ReleaseResultStatus,
    pub completeness: EvidenceCompleteness,
    pub releases: Vec<GooglePlayReleaseSummary>,
    pub receipts: Vec<crate::GooglePlayResponseReceipt>,
    pub provenance: crate::TransportProvenance,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_write_performed: bool,
    pub kernel_authority: bool,
    pub raw_release_notes_retained: bool,
    pub tester_pii_retained: bool,
    pub artifact_bytes_retained: bool,
    pub evidence_digest: Digest,
}

impl GooglePlayReleaseEvidence {
    pub fn for_scope(
        registration: &crate::GooglePlayRegistration,
        status: ReleaseResultStatus,
        completeness: EvidenceCompleteness,
        releases: Vec<GooglePlayReleaseSummary>,
        receipts: Vec<crate::GooglePlayResponseReceipt>,
        provenance: crate::TransportProvenance,
    ) -> Result<Self> {
        let scope = registration.scope();
        let mut evidence = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: PROVIDER_REVISION.to_owned(),
            provider_digest: crate::provider_digest(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            developer_account: scope.developer_account.clone(),
            package_name: scope.package_name.clone(),
            track: scope.track.clone(),
            form_factor: scope.form_factor,
            release_selector: scope.release_selector.clone(),
            rollout: scope.rollout.clone(),
            artifact: scope.artifact.clone(),
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            deployment_identity: scope.deployment_identity.clone(),
            status,
            completeness,
            releases,
            receipts,
            provenance,
            read_only: true,
            connected: false,
            native: false,
            external_write_performed: false,
            kernel_authority: false,
            raw_release_notes_retained: false,
            tester_pii_retained: false,
            artifact_bytes_retained: false,
            evidence_digest: Digest::from_text("unsealed-googleplay-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != PROVIDER_REVISION
            || self.provider_digest != crate::provider_digest()
            || self.releases.len() > MAX_RELEASES
            || self.scope_digest
                != (GooglePlayReleaseScope {
                    developer_account: self.developer_account.clone(),
                    package_name: self.package_name.clone(),
                    track: self.track.clone(),
                    form_factor: self.form_factor,
                    release_selector: self.release_selector.clone(),
                    rollout: self.rollout.clone(),
                    artifact: self.artifact.clone(),
                    project: self.project.clone(),
                    mission: self.mission.clone(),
                    work_product: self.work_product.clone(),
                    deployment_identity: self.deployment_identity.clone(),
                })
                .digest()
            || !self.read_only
            || self.connected
            || self.native
            || self.external_write_performed
            || self.kernel_authority
            || self.raw_release_notes_retained
            || self.tester_pii_retained
            || self.artifact_bytes_retained
            || self.receipts.len() > MAX_RELEASES
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(crate::GooglePlayReleaseResultError::TamperedEvidence);
        }
        for release in &self.releases {
            release.validate()?;
        }
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        Ok(())
    }

    pub fn contains_artifact_version_code(&self) -> bool {
        self.releases.iter().any(|release| {
            release.artifact_binding_matches
                && release
                    .active_artifact_version_code_digests
                    .iter()
                    .any(|artifact| artifact.version_code == self.artifact.version_code)
        })
    }

    fn calculate_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct EvidenceDigestInput<'a> {
            contract_version: &'a str,
            contract_digest: &'a Digest,
            provider_id: &'a str,
            provider_revision: &'a str,
            provider_digest: &'a Digest,
            registration_digest: &'a Digest,
            scope_digest: &'a Digest,
            status: ReleaseResultStatus,
            completeness: &'a EvidenceCompleteness,
            releases: &'a [GooglePlayReleaseSummary],
            receipts: &'a [crate::GooglePlayResponseReceipt],
            provenance: crate::TransportProvenance,
            read_only: bool,
            connected: bool,
            native: bool,
            external_write_performed: bool,
            kernel_authority: bool,
        }
        digest_serialized_with_domain(
            "googleplay-release-result/evidence/v1",
            &EvidenceDigestInput {
                contract_version: &self.contract_version,
                contract_digest: &self.contract_digest,
                provider_id: &self.provider_id,
                provider_revision: &self.provider_revision,
                provider_digest: &self.provider_digest,
                registration_digest: &self.registration_digest,
                scope_digest: &self.scope_digest,
                status: self.status,
                completeness: &self.completeness,
                releases: &self.releases,
                receipts: &self.receipts,
                provenance: self.provenance,
                read_only: self.read_only,
                connected: self.connected,
                native: self.native,
                external_write_performed: self.external_write_performed,
                kernel_authority: self.kernel_authority,
            },
        )
    }
}

/// Safe fixture payload.  Provider JSON is normalized into this shape before
/// it reaches the service; no raw Android Publisher object is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayReleasePayload {
    pub release_id: ReleaseId,
    pub release_name: Option<String>,
    pub lifecycle_state: ReleaseLifecycleState,
    pub version_codes: Vec<u64>,
    pub user_fraction_millionths: Option<u32>,
    pub country_targeting_digest: Option<Digest>,
    pub artifact_digests: BTreeMap<u64, Digest>,
    pub halted: bool,
}

impl GooglePlayReleasePayload {
    pub fn new(
        release_id: ReleaseId,
        lifecycle_state: ReleaseLifecycleState,
        version_codes: Vec<u64>,
    ) -> Result<Self> {
        if version_codes.is_empty()
            || version_codes.len() > MAX_VERSION_CODES_PER_RELEASE
            || version_codes.contains(&0)
        {
            return Err(crate::GooglePlayReleaseResultError::InvalidProviderData);
        }
        Ok(Self {
            release_name: Some(release_id.as_str().to_owned()),
            release_id,
            lifecycle_state,
            version_codes,
            user_fraction_millionths: None,
            country_targeting_digest: None,
            artifact_digests: BTreeMap::new(),
            halted: false,
        })
    }

    pub fn with_user_fraction(mut self, millionths: u32) -> Result<Self> {
        RolloutBucket::user_fraction(millionths)?;
        self.user_fraction_millionths = Some(millionths);
        Ok(self)
    }

    pub fn with_country_targeting_digest(mut self, digest: Digest) -> Result<Self> {
        if !digest.is_sha256() {
            return Err(crate::GooglePlayReleaseResultError::InvalidDigest {
                field: "country targeting digest",
            });
        }
        self.country_targeting_digest = Some(digest);
        Ok(self)
    }

    pub fn with_artifact_digest(mut self, version_code: u64, digest: Digest) -> Result<Self> {
        if !self.version_codes.contains(&version_code) || !digest.is_sha256() {
            return Err(crate::GooglePlayReleaseResultError::InvalidProviderData);
        }
        self.artifact_digests.insert(version_code, digest);
        Ok(self)
    }

    pub const fn halted(mut self) -> Self {
        self.halted = true;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayTrackPayload {
    pub package_name: Option<PackageName>,
    pub track: TrackName,
    pub releases: Vec<GooglePlayReleasePayload>,
    pub partial: bool,
}

impl GooglePlayTrackPayload {
    pub fn new(track: TrackName, releases: Vec<GooglePlayReleasePayload>) -> Result<Self> {
        if releases.len() > MAX_RELEASES {
            return Err(crate::GooglePlayReleaseResultError::BoundExceeded {
                field: "release summaries",
            });
        }
        Ok(Self {
            package_name: None,
            track,
            releases,
            partial: false,
        })
    }

    pub fn with_package_name(mut self, package_name: PackageName) -> Self {
        self.package_name = Some(package_name);
        self
    }

    pub fn with_user_fraction(mut self, millionths: u32) -> Result<Self> {
        if self.releases.len() != 1 {
            return Err(crate::GooglePlayReleaseResultError::InvalidProviderData);
        }
        let release = self
            .releases
            .pop()
            .ok_or(crate::GooglePlayReleaseResultError::InvalidProviderData)?
            .with_user_fraction(millionths)?;
        self.releases.push(release);
        Ok(self)
    }

    pub fn with_country_targeting_digest(mut self, digest: Digest) -> Result<Self> {
        if self.releases.len() != 1 {
            return Err(crate::GooglePlayReleaseResultError::InvalidProviderData);
        }
        let release = self
            .releases
            .pop()
            .ok_or(crate::GooglePlayReleaseResultError::InvalidProviderData)?
            .with_country_targeting_digest(digest)?;
        self.releases.push(release);
        Ok(self)
    }

    pub fn with_artifact_digest(mut self, version_code: u64, digest: Digest) -> Result<Self> {
        if self.releases.len() != 1 {
            return Err(crate::GooglePlayReleaseResultError::InvalidProviderData);
        }
        let release = self
            .releases
            .pop()
            .ok_or(crate::GooglePlayReleaseResultError::InvalidProviderData)?
            .with_artifact_digest(version_code, digest)?;
        self.releases.push(release);
        Ok(self)
    }

    pub const fn partial(mut self) -> Self {
        self.partial = true;
        self
    }
}

/// A canonical below-kernel proposal target, retained by the Mission
/// consumer.  The proposal type itself lives in `consumer.rs`.
pub fn scope_digest(scope: &GooglePlayReleaseScope) -> Digest {
    scope.digest()
}

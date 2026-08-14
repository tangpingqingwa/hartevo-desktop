//! Exact App Store Connect/Mission/Project/Work Product scope and bounded
//! provider payloads.  Provider payloads are ephemeral input to the provider;
//! only digests and redacted receipts cross into evidence.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    AppStoreConnectReleaseResultError, MAX_IDENTIFIER_BYTES, MAX_ITEMS_PER_PAGE, MAX_RELATIONSHIPS,
    Result, digest_serialized_with_domain, sha256_hex, validate_identifier, validate_text,
};

/// A validated lower-case SHA-256 identity.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if crate::valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AppStoreConnectReleaseResultError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    pub fn from_text(value: &str) -> Result<Self> {
        Self::parse(sha256_hex(value.as_bytes()))
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self> {
        Self::parse(sha256_hex(value))
    }

    pub fn from_parts(domain: &str, fields: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut input = String::from(domain);
        for (name, value) in fields {
            input.push('\0');
            input.push_str(&name);
            input.push('=');
            input.push_str(&value);
        }
        Self::from_text(&input).expect("digest domain values are valid")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        crate::valid_digest(&self.0)
    }

    pub fn validate(&self) -> Result<()> {
        if self.is_sha256() {
            Ok(())
        } else {
            Err(AppStoreConnectReleaseResultError::InvalidDigest {
                field: "SHA-256 digest",
            })
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

impl FromStr for Digest {
    type Err = AppStoreConnectReleaseResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

/// Bounded opaque identifiers.  They can be rendered in an allowlisted path,
/// but they never represent an arbitrary URL, script, or provider payload.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_identifier(&value, "opaque provider identifier")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Identifier").field(&self.0).finish()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Identifier {
    type Err = AppStoreConnectReleaseResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiOriginScope {
    pub origin: String,
    pub revision: u64,
}

impl ApiOriginScope {
    pub fn new(origin: impl Into<String>, revision: u64) -> Result<Self> {
        let origin = origin.into();
        validate_text(&origin, "App Store Connect API origin", 256, false)?;
        let Some(host) = origin.strip_prefix("https://") else {
            return Err(AppStoreConnectReleaseResultError::InvalidApiOrigin);
        };
        if host.is_empty()
            || host.contains('/')
            || host.contains('?')
            || host.contains('#')
            || revision == 0
        {
            return Err(AppStoreConnectReleaseResultError::InvalidApiOrigin);
        }
        Ok(Self {
            origin: origin.trim_end_matches('/').to_owned(),
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.origin.clone(), self.revision).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Platform {
    Ios,
    MacOs,
    TvOs,
    VisionOs,
    WatchOs,
}

impl Platform {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "IOS",
            Self::MacOs => "MAC_OS",
            Self::TvOs => "TV_OS",
            Self::VisionOs => "VISION_OS",
            Self::WatchOs => "WATCH_OS",
        }
    }
}

macro_rules! simple_scope {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: Identifier,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(AppStoreConnectReleaseResultError::InvalidScope);
                }
                Ok(Self {
                    id: Identifier::parse(id.into())?,
                    revision,
                })
            }

            pub fn validate(&self) -> Result<()> {
                Self::new(self.id.as_str(), self.revision).map(|_| ())
            }
        }

        const _: &str = $field;
    };
}

simple_scope!(TeamScope, "team id");
simple_scope!(PreReleaseVersionScope, "pre-release version id");
simple_scope!(ProjectScope, "Project id");
simple_scope!(MissionScope, "Mission id");
simple_scope!(WorkProductScope, "Work Product id");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppScope {
    pub id: Identifier,
    pub bundle_id: Identifier,
    pub revision: u64,
}

impl AppScope {
    pub fn new(id: impl Into<String>, bundle_id: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            bundle_id: Identifier::parse(bundle_id.into())?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.id.as_str(), self.bundle_id.as_str(), self.revision).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildScope {
    pub id: Identifier,
    pub version: Identifier,
    pub build_number: Identifier,
    pub artifact_digest: Digest,
    pub revision: u64,
}

impl BuildScope {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        build_number: impl Into<String>,
        artifact_digest: Digest,
        revision: u64,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        artifact_digest.validate()?;
        Ok(Self {
            id: Identifier::parse(id.into())?,
            version: Identifier::parse(version.into())?,
            build_number: Identifier::parse(build_number.into())?,
            artifact_digest,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.id.as_str(),
            self.version.as_str(),
            self.build_number.as_str(),
            self.artifact_digest.clone(),
            self.revision,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreVersionScope {
    pub id: Identifier,
    pub version: Identifier,
    pub platform: Platform,
    pub revision: u64,
}

impl AppStoreVersionScope {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        platform: Platform,
        revision: u64,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            version: Identifier::parse(version.into())?,
            platform,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.id.as_str(),
            self.version.as_str(),
            self.platform,
            self.revision,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OptionalResourceScope {
    pub id: Option<Identifier>,
    pub revision: u64,
}

impl OptionalResourceScope {
    pub fn none(revision: u64) -> Result<Self> {
        Self::new(None::<String>, revision)
    }

    pub fn with_id(id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(Some(id.into()), revision)
    }

    pub fn new(id: Option<impl Into<String>>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: id
                .map(|value| Identifier::parse(value.into()))
                .transpose()?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.id.as_ref().map(|value| value.as_str().to_owned()),
            self.revision,
        )
        .map(|_| ())
    }
}

pub type BetaGroupScope = OptionalResourceScope;
pub type ReviewScope = OptionalResourceScope;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseScope {
    pub id: Identifier,
    pub revision: u64,
}

impl ReleaseScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.id.as_str(), self.revision).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactScope {
    pub digest: Digest,
    pub revision: u64,
}

impl ArtifactScope {
    pub fn new(digest: Digest, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        digest.validate()?;
        Ok(Self { digest, revision })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.digest.clone(), self.revision).map(|_| ())
    }
}

/// The full mobile release scope.  Every resource, revision, artifact, and
/// below-kernel Mission target is digest-bound before registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreConnectScope {
    pub api_origin: ApiOriginScope,
    pub team: TeamScope,
    pub app: AppScope,
    pub platform: Platform,
    pub pre_release_version: PreReleaseVersionScope,
    pub build: BuildScope,
    pub app_store_version: AppStoreVersionScope,
    pub beta_group: BetaGroupScope,
    pub review: ReviewScope,
    pub release: ReleaseScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub artifact: ArtifactScope,
}

impl AppStoreConnectScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_origin: ApiOriginScope,
        team: TeamScope,
        app: AppScope,
        platform: Platform,
        pre_release_version: PreReleaseVersionScope,
        build: BuildScope,
        app_store_version: AppStoreVersionScope,
        beta_group: BetaGroupScope,
        review: ReviewScope,
        release: ReleaseScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        artifact: ArtifactScope,
    ) -> Result<Self> {
        let scope = Self {
            api_origin,
            team,
            app,
            platform,
            pre_release_version,
            build,
            app_store_version,
            beta_group,
            review,
            release,
            project,
            mission,
            work_product,
            artifact,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.api_origin.validate()?;
        self.team.validate()?;
        self.app.validate()?;
        self.pre_release_version.validate()?;
        self.build.validate()?;
        self.app_store_version.validate()?;
        self.beta_group.validate()?;
        self.review.validate()?;
        self.release.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.artifact.validate()?;
        if self.build.artifact_digest != self.artifact.digest
            || self.app_store_version.platform != self.platform
        {
            return Err(AppStoreConnectReleaseResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::parse(digest_serialized_with_domain(
            "appstoreconnect-release-result/scope/v1",
            self,
        ))
        .expect("scope digest is valid")
    }
}

/// Only digests of the opaque handle and Apple team-key material are retained.
/// The team key ID, issuer ID, private-key bytes, and any future JWT are not
/// fields of this type and therefore cannot be serialized or cloned from it.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(opaque_handle: impl AsRef<str>) -> Result<Self> {
        let handle = opaque_handle.as_ref();
        validate_text(
            handle,
            "opaque SecretReference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        Ok(Self {
            reference_digest: Digest::from_text(handle)?,
            scope_digest: Digest::from_text("unbound-appstoreconnect-secret-scope")?,
            permission_digest: Digest::from_text("unbound-appstoreconnect-secret-permission")?,
            revoked: false,
        })
    }

    /// Construct a reference from Apple team key metadata while retaining no
    /// key ID, issuer ID, private-key bytes, or JWT.  The private key is only
    /// borrowed long enough to compute a digest.
    pub fn from_apple_team_key_material(
        opaque_handle: impl AsRef<str>,
        team_key_id: &str,
        issuer_id: &str,
        private_key_material: &[u8],
    ) -> Result<Self> {
        let handle = opaque_handle.as_ref();
        validate_text(
            handle,
            "opaque SecretReference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        validate_identifier(team_key_id, "Apple team key ID")?;
        validate_identifier(issuer_id, "Apple issuer ID")?;
        if private_key_material.is_empty() {
            return Err(AppStoreConnectReleaseResultError::InvalidSecretReference);
        }
        let private_key_digest = sha256_hex(private_key_material);
        let reference_digest = Digest::from_parts(
            "appstoreconnect-release-result/apple-team-key-reference/v1",
            [
                ("handle".to_owned(), sha256_hex(handle.as_bytes())),
                ("team_key_id".to_owned(), sha256_hex(team_key_id.as_bytes())),
                ("issuer_id".to_owned(), sha256_hex(issuer_id.as_bytes())),
                ("private_key".to_owned(), private_key_digest),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: Digest::from_text("unbound-appstoreconnect-secret-scope")?,
            permission_digest: Digest::from_text("unbound-appstoreconnect-secret-permission")?,
            revoked: false,
        })
    }

    pub fn bind_to(
        mut self,
        scope: &AppStoreConnectScope,
        permissions: &PermissionSnapshot,
    ) -> Result<Self> {
        scope.validate()?;
        permissions.validate()?;
        self.scope_digest = scope.digest();
        self.permission_digest = permissions.digest.clone();
        Ok(self)
    }

    pub fn is_bound_to(
        &self,
        scope: &AppStoreConnectScope,
        permissions: &PermissionSnapshot,
    ) -> bool {
        self.scope_digest == scope.digest() && self.permission_digest == permissions.digest
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(AppStoreConnectReleaseResultError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

pub const REQUIRED_READ_SCOPES: [&str; 12] = [
    "apps.read",
    "pre_release_versions.read",
    "builds.read",
    "app_store_versions.read",
    "beta_groups.read",
    "beta_app_review_submissions.read",
    "review_submissions.read",
    "team.scope",
    "project.scope",
    "mission.scope",
    "work_product.scope",
    "artifact.scope",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub read_scopes: Vec<String>,
    pub write_scopes: Vec<String>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only() -> Self {
        let mut read_scopes = REQUIRED_READ_SCOPES
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        read_scopes.sort();
        Self {
            digest: Self::calculate_digest(&read_scopes, &[]),
            read_scopes,
            write_scopes: Vec::new(),
        }
    }

    pub fn new(mut read_scopes: Vec<String>, mut write_scopes: Vec<String>) -> Result<Self> {
        read_scopes.sort();
        read_scopes.dedup();
        write_scopes.sort();
        write_scopes.dedup();
        let snapshot = Self {
            digest: Self::calculate_digest(&read_scopes, &write_scopes),
            read_scopes,
            write_scopes,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<()> {
        let mut expected = REQUIRED_READ_SCOPES
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        expected.sort();
        if self.read_scopes != expected
            || !self.write_scopes.is_empty()
            || self.digest != Self::calculate_digest(&self.read_scopes, &self.write_scopes)
        {
            return Err(AppStoreConnectReleaseResultError::InvalidPermissionSnapshot);
        }
        self.digest.validate()
    }

    fn calculate_digest(read_scopes: &[String], write_scopes: &[String]) -> Digest {
        Digest::from_parts(
            "appstoreconnect-release-result/permissions/v1",
            [
                (
                    "read".to_owned(),
                    serde_json::to_string(read_scopes).unwrap(),
                ),
                (
                    "write".to_owned(),
                    serde_json::to_string(write_scopes).unwrap(),
                ),
            ],
        )
    }
}

/// An opaque pagination token.  Only its digest is retained in a request and
/// receipt; this prevents arbitrary provider links from becoming executable.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PageToken(Digest);

impl PageToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        validate_text(
            value,
            "opaque pagination token",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        Ok(Self(Digest::from_text(value)?))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for PageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("PageToken").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BuildProcessingState {
    Processing,
    Complete,
    Failed,
    Invalid,
    Expired,
    Removed,
    Unknown,
}

impl BuildProcessingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "PROCESSING",
            Self::Complete => "COMPLETE",
            Self::Failed => "FAILED",
            Self::Invalid => "INVALID",
            Self::Expired => "EXPIRED",
            Self::Removed => "REMOVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BetaReviewState {
    WaitingForReview,
    InReview,
    Approved,
    Rejected,
    Expired,
    Removed,
    None,
    Unknown,
}

impl BetaReviewState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitingForReview => "WAITING_FOR_REVIEW",
            Self::InReview => "IN_REVIEW",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Expired => "EXPIRED",
            Self::Removed => "REMOVED",
            Self::None => "NONE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppStoreState {
    PrepareForSubmission,
    WaitingForReview,
    InReview,
    PendingDeveloperRelease,
    PendingAppleRelease,
    ReadyForSale,
    DeveloperRemovedFromSale,
    RemovedFromSale,
    Rejected,
    MetadataRejected,
    InvalidBinary,
    ProcessingForAppStore,
    Expired,
    Removed,
    Unknown,
}

impl AppStoreState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrepareForSubmission => "PREPARE_FOR_SUBMISSION",
            Self::WaitingForReview => "WAITING_FOR_REVIEW",
            Self::InReview => "IN_REVIEW",
            Self::PendingDeveloperRelease => "PENDING_DEVELOPER_RELEASE",
            Self::PendingAppleRelease => "PENDING_APPLE_RELEASE",
            Self::ReadyForSale => "READY_FOR_SALE",
            Self::DeveloperRemovedFromSale => "DEVELOPER_REMOVED_FROM_SALE",
            Self::RemovedFromSale => "REMOVED_FROM_SALE",
            Self::Rejected => "REJECTED",
            Self::MetadataRejected => "METADATA_REJECTED",
            Self::InvalidBinary => "INVALID_BINARY",
            Self::ProcessingForAppStore => "PROCESSING_FOR_APP_STORE",
            Self::Expired => "EXPIRED",
            Self::Removed => "REMOVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewState {
    WaitingForReview,
    InReview,
    Accepted,
    Rejected,
    DeveloperRejected,
    MetadataRejected,
    Expired,
    Removed,
    None,
    Unknown,
}

impl ReviewState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitingForReview => "WAITING_FOR_REVIEW",
            Self::InReview => "IN_REVIEW",
            Self::Accepted => "ACCEPTED",
            Self::Rejected => "REJECTED",
            Self::DeveloperRejected => "DEVELOPER_REJECTED",
            Self::MetadataRejected => "METADATA_REJECTED",
            Self::Expired => "EXPIRED",
            Self::Removed => "REMOVED",
            Self::None => "NONE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseState {
    PendingDeveloperRelease,
    PendingAppleRelease,
    ReadyForSale,
    Released,
    DeveloperRemovedFromSale,
    RemovedFromSale,
    Expired,
    Removed,
    Unknown,
}

impl ReleaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingDeveloperRelease => "PENDING_DEVELOPER_RELEASE",
            Self::PendingAppleRelease => "PENDING_APPLE_RELEASE",
            Self::ReadyForSale => "READY_FOR_SALE",
            Self::Released => "RELEASED",
            Self::DeveloperRemovedFromSale => "DEVELOPER_REMOVED_FROM_SALE",
            Self::RemovedFromSale => "REMOVED_FROM_SALE",
            Self::Expired => "EXPIRED",
            Self::Removed => "REMOVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppPayload {
    pub id: String,
    pub team_id: String,
    pub bundle_id: String,
    pub revision: u64,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreReleaseVersionPayload {
    pub id: String,
    pub app_id: String,
    pub version: String,
    pub platform: Platform,
    pub revision: u64,
    pub expired: bool,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildPayload {
    pub id: String,
    pub app_id: String,
    pub pre_release_version_id: String,
    pub app_store_version_id: Option<String>,
    pub version: String,
    pub build_number: String,
    pub processing_state: BuildProcessingState,
    pub beta_review_state: BetaReviewState,
    pub artifact_digest: Digest,
    pub revision: u64,
    pub expired: bool,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreVersionPayload {
    pub id: String,
    pub app_id: String,
    pub pre_release_version_id: String,
    pub version: String,
    pub release_id: String,
    pub platform: Platform,
    pub app_store_state: AppStoreState,
    pub review_state: ReviewState,
    pub release_state: ReleaseState,
    pub build_id: Option<String>,
    pub revision: u64,
    pub expired: bool,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BetaGroupPayload {
    pub id: String,
    pub app_id: String,
    pub build_ids: Vec<String>,
    pub revision: u64,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BetaAppReviewSubmissionPayload {
    pub id: String,
    pub build_id: String,
    pub app_id: String,
    pub state: BetaReviewState,
    pub revision: u64,
    pub expired: bool,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSubmissionPayload {
    pub id: String,
    pub app_id: String,
    pub app_store_version_id: Option<String>,
    pub platform: Platform,
    pub state: ReviewState,
    pub revision: u64,
    pub expired: bool,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkagePayload {
    pub source_type: String,
    pub source_id: String,
    pub relationship: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelationshipLink {
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelationshipPayload {
    pub source_type: String,
    pub source_id: String,
    pub relationship: String,
    pub links: Vec<RelationshipLink>,
    pub next: Option<PageToken>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<PageToken>,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, next: Option<PageToken>) -> Result<Self> {
        if items.len() > MAX_ITEMS_PER_PAGE {
            return Err(AppStoreConnectReleaseResultError::PaginationLimit);
        }
        Ok(Self { items, next })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum AppStoreConnectResponseBody {
    Apps(Page<AppPayload>),
    App(AppPayload),
    PreReleaseVersions(Page<PreReleaseVersionPayload>),
    PreReleaseVersion(PreReleaseVersionPayload),
    Builds(Page<BuildPayload>),
    Build(BuildPayload),
    AppStoreVersions(Page<AppStoreVersionPayload>),
    AppStoreVersion(AppStoreVersionPayload),
    BetaGroups(Page<BetaGroupPayload>),
    BetaGroup(BetaGroupPayload),
    BetaReviewSubmission(BetaAppReviewSubmissionPayload),
    ReviewSubmissions(Page<ReviewSubmissionPayload>),
    ReviewSubmission(ReviewSubmissionPayload),
    Linkage(LinkagePayload),
    Relationships(RelationshipPayload),
}

impl AppStoreConnectResponseBody {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Apps(_) => "apps",
            Self::App(_) => "app",
            Self::PreReleaseVersions(_) => "pre_release_versions",
            Self::PreReleaseVersion(_) => "pre_release_version",
            Self::Builds(_) => "builds",
            Self::Build(_) => "build",
            Self::AppStoreVersions(_) => "app_store_versions",
            Self::AppStoreVersion(_) => "app_store_version",
            Self::BetaGroups(_) => "beta_groups",
            Self::BetaGroup(_) => "beta_group",
            Self::BetaReviewSubmission(_) => "beta_review_submission",
            Self::ReviewSubmissions(_) => "review_submissions",
            Self::ReviewSubmission(_) => "review_submission",
            Self::Linkage(_) => "linkage",
            Self::Relationships(_) => "relationships",
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::parse(crate::digest_serialized(self)).expect("response body digest is valid")
    }
}

pub(crate) fn validate_collection_len<T>(values: &[T]) -> Result<()> {
    if values.len() > MAX_ITEMS_PER_PAGE {
        Err(AppStoreConnectReleaseResultError::PaginationLimit)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_relationships(value: &RelationshipPayload) -> Result<()> {
    validate_identifier(&value.source_type, "relationship source type")?;
    validate_identifier(&value.source_id, "relationship source id")?;
    validate_identifier(&value.relationship, "relationship name")?;
    if value.links.len() > MAX_RELATIONSHIPS {
        return Err(AppStoreConnectReleaseResultError::PaginationLimit);
    }
    for link in &value.links {
        validate_identifier(&link.resource_type, "relationship resource type")?;
        validate_identifier(&link.resource_id, "relationship resource id")?;
    }
    Ok(())
}

pub(crate) fn validate_payload_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_identifier(value, field)
}

pub(crate) fn validate_payload_state(value: &str) -> Result<()> {
    validate_text(value, "provider state", 128, false)
}

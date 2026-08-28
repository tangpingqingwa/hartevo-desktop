//! Safe, typed values for the GitHub secret-scanning Layer-1 boundary.
//!
//! The model intentionally has no field capable of holding a secret, token,
//! raw location, code line, comment, or user identity. Constructors that take
//! provider text hash it immediately and retain only the resulting digest.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    ALERT_ENDPOINT, ALERTS_ORG_ENDPOINT, ALERTS_REPOSITORY_ENDPOINT, CONTRACT_VERSION,
    EVIDENCE_POLICY_INPUT, PROVIDER_API_REVISION, PROVIDER_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 16;
pub const MAX_ALERTS: usize = 256;
pub const MAX_LOCATIONS: usize = 64;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_REQUESTS_PER_READ: usize = 8;
pub const MAX_PROVIDER_ERRORS: usize = 8;
pub const MAX_LOCATION_LINE: u32 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("text contains forbidden control characters or is too long")]
    InvalidText,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("GitHub repository identity is invalid")]
    InvalidRepository,
    #[error("Git ref must be an exact refs/ value")]
    InvalidRef,
    #[error("commit SHA is not a lower-case SHA-1 or SHA-256 value")]
    InvalidCommit,
    #[error("alert number must be non-zero")]
    InvalidAlertNumber,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("permission snapshot is incomplete, duplicated, or contains a write")]
    InvalidPermissions,
    #[error("secret-scanning query is invalid")]
    InvalidQuery,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("opaque cursor is invalid")]
    InvalidCursor,
    #[error("redacted location is invalid or outside its bound")]
    InvalidLocation,
    #[error("secret-scanning alert is invalid")]
    InvalidAlert,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or SecretReference is already revoked")]
    AlreadyRevoked,
    #[error("registration is not reversible in its current state")]
    NotReversible,
}

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

    pub fn from_parts(domain: &str, fields: &[impl AsRef<str>]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field.as_ref());
        }
        Self::from_bytes(&bytes)
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
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

    pub fn validate(&self) -> Result<(), ModelError> {
        if valid_digest(&self.0) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
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

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, maximum: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte != 0 && !byte.is_ascii_control())
        && value.trim() == value
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_github_component(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                if valid_identifier(&self.0) {
                    Ok(())
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(&self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_identifier!(InstallationId);
string_identifier!(OrganizationName);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RefName(String);

impl RefName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_text(&value, MAX_IDENTIFIER_BYTES, false)
            && value.starts_with("refs/")
            && !value.contains("..")
            && !value.contains('\n')
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRef)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if valid_text(&self.0, MAX_IDENTIFIER_BYTES, false)
            && self.0.starts_with("refs/")
            && !self.0.contains("..")
            && !self.0.contains('\n')
        {
            Ok(())
        } else {
            Err(ModelError::InvalidRef)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let valid_length = value.len() == 40 || value.len() == 64;
        if valid_length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidCommit)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let valid_length = self.0.len() == 40 || self.0.len() == 64;
        if valid_length
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            Ok(())
        } else {
            Err(ModelError::InvalidCommit)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn validate(self) -> Result<(), ModelError> {
        if self.0 == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AlertNumber(u64);

impl AlertNumber {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidAlertNumber)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn validate(self) -> Result<(), ModelError> {
        if self.0 == 0 {
            Err(ModelError::InvalidAlertNumber)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAuthKind {
    App,
    OAuth,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryIdentity {
    owner: String,
    name: String,
    web_url_digest: Digest,
}

impl RepositoryIdentity {
    pub fn new(
        owner: impl Into<String>,
        name: impl Into<String>,
        web_url: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let owner = owner.into();
        let name = name.into();
        let web_url = web_url.into();
        if !valid_github_component(&owner)
            || !valid_github_component(&name)
            || !valid_text(&web_url, MAX_IDENTIFIER_BYTES, false)
            || !web_url.starts_with("https://")
        {
            return Err(ModelError::InvalidRepository);
        }
        Ok(Self {
            owner,
            name,
            web_url_digest: Digest::from_text(web_url),
        })
    }

    pub fn from_parts(
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let owner = owner.into();
        let name = name.into();
        Self::new(
            owner.clone(),
            name.clone(),
            format!("https://github.com/{owner}/{name}"),
        )
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    pub fn web_url_digest(&self) -> &Digest {
        &self.web_url_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if valid_github_component(&self.owner)
            && valid_github_component(&self.name)
            && !self.web_url_digest.is_zero()
        {
            self.web_url_digest.validate()
        } else {
            Err(ModelError::InvalidRepository)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeBinding {
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
}

impl MissionScopeBinding {
    pub fn new(
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
    ) -> Result<Self, ModelError> {
        let binding = Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.project_revision.get() == 0
            || self.mission_revision.get() == 0
            || self.work_product_revision.get() == 0
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Open,
    Resolved,
}

impl AlertState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityClass {
    Active,
    Inactive,
    Unknown,
}

impl ValidityClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretTypeClass {
    DefaultPattern,
    GenericPattern,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    Commit,
    WikiCommit,
    IssueTitle,
    IssueBody,
    IssueComment,
    DiscussionTitle,
    DiscussionBody,
    DiscussionComment,
    PullRequestTitle,
    PullRequestBody,
    PullRequestComment,
    PullRequestReview,
    PullRequestReviewComment,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretType {
    pub secret_type_digest: Digest,
    pub class: SecretTypeClass,
}

impl SecretType {
    /// Hash a provider secret-type identifier without retaining its spelling.
    pub fn from_provider_text(
        secret_type: impl AsRef<str>,
        class: SecretTypeClass,
    ) -> Result<Self, ModelError> {
        let secret_type = secret_type.as_ref();
        if !valid_text(secret_type, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidText);
        }
        Self::from_digest(
            Digest::from_parts("github-secret-scanning-secret-type/v1", &[secret_type]),
            class,
        )
    }

    pub fn from_digest(
        secret_type_digest: Digest,
        class: SecretTypeClass,
    ) -> Result<Self, ModelError> {
        secret_type_digest.validate()?;
        if secret_type_digest.is_zero() {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            secret_type_digest,
            class,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.secret_type_digest.validate()?;
        if self.secret_type_digest.is_zero() {
            Err(ModelError::InvalidDigest)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedLocation {
    pub kind: LocationKind,
    pub path_digest: Digest,
    pub region_digest: Digest,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub commit_digest: Digest,
    pub ref_digest: Digest,
}

impl RedactedLocation {
    /// Hash raw provider location text immediately. No raw path, region, or
    /// code line is stored in the returned value.
    #[allow(clippy::too_many_arguments)]
    pub fn from_provider_text(
        kind: LocationKind,
        path: impl AsRef<str>,
        region: impl AsRef<str>,
        start_line: Option<u32>,
        end_line: Option<u32>,
        commit: &CommitSha,
        git_ref: &RefName,
    ) -> Result<Self, ModelError> {
        let path = path.as_ref();
        let region = region.as_ref();
        if !valid_text(path, MAX_IDENTIFIER_BYTES, false)
            || !valid_text(region, MAX_IDENTIFIER_BYTES, false)
        {
            return Err(ModelError::InvalidText);
        }
        Self::from_digests(
            kind,
            Digest::from_parts("github-secret-scanning-path/v1", &[path]),
            Digest::from_parts("github-secret-scanning-region/v1", &[region]),
            start_line,
            end_line,
            commit.digest(),
            git_ref.digest(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_digests(
        kind: LocationKind,
        path_digest: Digest,
        region_digest: Digest,
        start_line: Option<u32>,
        end_line: Option<u32>,
        commit_digest: Digest,
        ref_digest: Digest,
    ) -> Result<Self, ModelError> {
        let location = Self {
            kind,
            path_digest,
            region_digest,
            start_line,
            end_line,
            commit_digest,
            ref_digest,
        };
        location.validate()?;
        Ok(location)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.path_digest.validate()?;
        self.region_digest.validate()?;
        self.commit_digest.validate()?;
        self.ref_digest.validate()?;
        if self.path_digest.is_zero()
            || self.region_digest.is_zero()
            || self.commit_digest.is_zero()
            || self.ref_digest.is_zero()
        {
            return Err(ModelError::InvalidLocation);
        }
        match (self.start_line, self.end_line) {
            (Some(start), Some(end)) if start > 0 && end >= start && end <= MAX_LOCATION_LINE => {}
            (None, None) => {}
            _ => return Err(ModelError::InvalidLocation),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PushProtectionMetadata {
    pub bypassed: bool,
    pub bypassed_at: Option<DateTime<Utc>>,
    pub bypass_request_present: bool,
    pub publicly_leaked: bool,
    pub multi_repo: bool,
    pub base64_encoded: bool,
}

impl PushProtectionMetadata {
    pub fn new(
        bypassed: bool,
        bypassed_at: Option<DateTime<Utc>>,
        bypass_request_present: bool,
        publicly_leaked: bool,
        multi_repo: bool,
        base64_encoded: bool,
    ) -> Result<Self, ModelError> {
        if bypassed && bypassed_at.is_none() {
            return Err(ModelError::InvalidAlert);
        }
        if !bypassed && bypassed_at.is_some() {
            return Err(ModelError::InvalidAlert);
        }
        Ok(Self {
            bypassed,
            bypassed_at,
            bypass_request_present,
            publicly_leaked,
            multi_repo,
            base64_encoded,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<Permission>,
    pub permission_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    SecretScanningAlertsRead,
    MetadataRead,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecretScanningAlertsRead => "secret_scanning_alerts:read",
            Self::MetadataRead => "metadata:read",
        }
    }
}

impl PermissionSnapshot {
    pub fn new(permissions: impl IntoIterator<Item = Permission>) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions
            != BTreeSet::from([
                Permission::SecretScanningAlertsRead,
                Permission::MetadataRead,
            ])
        {
            return Err(ModelError::InvalidPermissions);
        }
        let permission_digest = Digest::from_parts(
            "github-secret-scanning-permissions/v1",
            &permissions
                .iter()
                .map(|permission| permission.as_str())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    pub fn least_privilege() -> Self {
        Self::new([
            Permission::SecretScanningAlertsRead,
            Permission::MetadataRead,
        ])
        .expect("the required read permissions are always valid")
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn contains(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if Self::new(self.permissions.iter().copied())? == *self {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretScanningQuery {
    pub states: BTreeSet<AlertState>,
    pub validities: BTreeSet<ValidityClass>,
    pub secret_type_digests: BTreeSet<Digest>,
    pub is_bypassed: Option<bool>,
    pub hide_secret: bool,
    pub query_digest: Digest,
}

impl SecretScanningQuery {
    pub fn new(
        states: impl IntoIterator<Item = AlertState>,
        validities: impl IntoIterator<Item = ValidityClass>,
    ) -> Result<Self, ModelError> {
        let states = states.into_iter().collect::<BTreeSet<_>>();
        let validities = validities.into_iter().collect::<BTreeSet<_>>();
        if states.is_empty() || validities.is_empty() {
            return Err(ModelError::InvalidQuery);
        }
        let mut query = Self {
            states,
            validities,
            secret_type_digests: BTreeSet::new(),
            is_bypassed: None,
            hide_secret: true,
            query_digest: Digest::zero(),
        };
        query.query_digest = query.computed_digest();
        Ok(query)
    }

    pub fn all() -> Self {
        Self::new(
            [AlertState::Open, AlertState::Resolved],
            [
                ValidityClass::Active,
                ValidityClass::Inactive,
                ValidityClass::Unknown,
            ],
        )
        .expect("the all query is valid")
    }

    pub fn with_secret_type_digests(
        mut self,
        digests: impl IntoIterator<Item = Digest>,
    ) -> Result<Self, ModelError> {
        self.secret_type_digests = digests.into_iter().collect();
        if self.secret_type_digests.len() > MAX_ALERTS
            || self.secret_type_digests.iter().any(Digest::is_zero)
        {
            return Err(ModelError::InvalidQuery);
        }
        self.query_digest = self.computed_digest();
        Ok(self)
    }

    pub fn with_bypass_filter(mut self, is_bypassed: Option<bool>) -> Self {
        self.is_bypassed = is_bypassed;
        self.query_digest = self.computed_digest();
        self
    }

    pub fn digest(&self) -> &Digest {
        &self.query_digest
    }

    pub const fn hides_secret(&self) -> bool {
        self.hide_secret
    }

    pub fn allows(&self, state: AlertState, validity: ValidityClass, secret_type: &Digest) -> bool {
        self.states.contains(&state)
            && self.validities.contains(&validity)
            && (self.secret_type_digests.is_empty()
                || self.secret_type_digests.contains(secret_type))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.states.is_empty()
            || self.validities.is_empty()
            || !self.hide_secret
            || self.secret_type_digests.iter().any(Digest::is_zero)
            || self.query_digest != self.computed_digest()
        {
            Err(ModelError::InvalidQuery)
        } else {
            Ok(())
        }
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.states,
            &self.validities,
            &self.secret_type_digests,
            self.is_bypassed,
            self.hide_secret,
        ))
    }

    pub fn query_digest_for_request(
        &self,
        page: u16,
        per_page: u16,
        cursor: Option<&OpaqueCursor>,
    ) -> Digest {
        Digest::from_serialized(&(
            &self.query_digest,
            page,
            per_page,
            cursor.map(OpaqueCursor::digest),
            true,
        ))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if !valid_text(value, MAX_CURSOR_BYTES, false) {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token_digest: Digest::from_parts("github-secret-scanning-cursor/v1", &[value]),
            binding_digest: None,
        })
    }

    pub fn from_digest(token_digest: Digest) -> Result<Self, ModelError> {
        token_digest.validate()?;
        if token_digest.is_zero() {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token_digest,
            binding_digest: None,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.token_digest.is_zero()
            || self.token_digest.validate().is_err()
            || self
                .binding_digest
                .as_ref()
                .is_some_and(|digest| digest.is_zero() || digest.validate().is_err())
        {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
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

/// Opaque handle into host-managed GitHub App or OAuth material.
///
/// The raw reference identifier is hashed during construction and is never
/// retained, serialized, or printed. There is intentionally no `Serialize`
/// implementation for this type.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GithubAuthKind,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GithubSecretScanningScope,
        credential_revision: u64,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_text(&reference_id, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = Digest::from_parts(
            "github-secret-scanning-secret-reference/v1",
            &[
                format!("{auth_kind:?}"),
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &GithubSecretScanningScope,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, scope, 1, auth_kind)
    }

    pub fn app(
        reference_id: impl Into<String>,
        scope: &GithubSecretScanningScope,
    ) -> Result<Self, ModelError> {
        Self::for_scope(reference_id, scope, GithubAuthKind::App)
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &GithubSecretScanningScope,
    ) -> Result<Self, ModelError> {
        Self::for_scope(reference_id, scope, GithubAuthKind::OAuth)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GithubAuthKind {
        self.auth_kind
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn validate_for_scope(&self, scope: &GithubSecretScanningScope) -> Result<(), ModelError> {
        if self.scope_digest == *scope.digest()
            && self.reference_digest.validate().is_ok()
            && self.credential_revision.get() > 0
        {
            Ok(())
        } else {
            Err(ModelError::InvalidSecretReference)
        }
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubSecretScanningScope {
    pub installation_id: InstallationId,
    pub organization: OrganizationName,
    pub repository: RepositoryIdentity,
    pub git_ref: RefName,
    pub commit_sha: CommitSha,
    pub alert_number: AlertNumber,
    pub expected_alert_state: AlertState,
    pub expected_validity: ValidityClass,
    pub permissions: PermissionSnapshot,
    pub query: SecretScanningQuery,
    pub mission: MissionScopeBinding,
    pub evidence_policy_digest: Digest,
    pub scope_digest: Digest,
}

pub type SecretScanningScope = GithubSecretScanningScope;

impl GithubSecretScanningScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: InstallationId,
        organization: OrganizationName,
        repository: RepositoryIdentity,
        git_ref: RefName,
        commit_sha: CommitSha,
        alert_number: AlertNumber,
        expected_alert_state: AlertState,
        expected_validity: ValidityClass,
        permissions: PermissionSnapshot,
        query: SecretScanningQuery,
        mission: MissionScopeBinding,
    ) -> Result<Self, ModelError> {
        let mut scope = Self {
            installation_id,
            organization,
            repository,
            git_ref,
            commit_sha,
            alert_number,
            expected_alert_state,
            expected_validity,
            permissions,
            query,
            mission,
            evidence_policy_digest: Self::evidence_policy_digest(),
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.computed_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn evidence_policy_digest() -> Digest {
        Digest::from_text(EVIDENCE_POLICY_INPUT)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.installation_id.validate()?;
        self.organization.validate()?;
        self.repository.validate()?;
        self.git_ref.validate()?;
        self.commit_sha.validate()?;
        self.alert_number.validate()?;
        self.mission.project_id.validate()?;
        self.mission.mission_id.validate()?;
        self.mission.work_product_id.validate()?;
        self.mission.project_revision.validate()?;
        self.mission.mission_revision.validate()?;
        self.mission.work_product_revision.validate()?;
        self.permissions.validate()?;
        self.query.validate()?;
        self.mission.validate()?;
        self.evidence_policy_digest.validate()?;
        if self.evidence_policy_digest != Self::evidence_policy_digest()
            || self.scope_digest != self.computed_digest()
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn installation_digest(&self) -> Digest {
        self.installation_id.digest()
    }

    pub fn organization_digest(&self) -> Digest {
        self.organization.digest()
    }

    pub fn repository_digest(&self) -> Digest {
        self.repository.digest()
    }

    pub fn ref_digest(&self) -> Digest {
        self.git_ref.digest()
    }

    pub fn commit_digest(&self) -> Digest {
        self.commit_sha.digest()
    }

    pub fn alert_digest(&self) -> Digest {
        Digest::from_parts(
            "github-secret-scanning-alert-scope/v1",
            &[
                self.alert_number.get().to_string(),
                self.expected_alert_state.as_str().to_owned(),
                self.expected_validity.as_str().to_owned(),
            ],
        )
    }

    pub fn query_digest(&self) -> &Digest {
        self.query.digest()
    }

    /// Digest fence for the immutable evidence policy/query binding carried by
    /// a registration. The concrete alert projection receives its own
    /// evidence digest after a bounded read.
    pub fn evidence_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "github-secret-scanning-evidence-binding/v1",
            &[
                self.evidence_policy_digest.to_string(),
                self.query_digest().to_string(),
                "complete".to_owned(),
            ],
        )
    }

    pub fn provider_scope_digest(&self) -> Digest {
        Digest::from_parts(
            "github-secret-scanning-provider-scope/v1",
            &[
                self.installation_digest().to_string(),
                self.organization_digest().to_string(),
                self.repository_digest().to_string(),
                self.ref_digest().to_string(),
                self.commit_digest().to_string(),
            ],
        )
    }

    pub fn api_fence_digest(&self) -> Digest {
        Digest::from_parts(
            "github-secret-scanning-api-fence/v1",
            &[
                PROVIDER_ID,
                PROVIDER_API_REVISION,
                ALERTS_REPOSITORY_ENDPOINT,
                ALERTS_ORG_ENDPOINT,
                ALERT_ENDPOINT,
                CONTRACT_VERSION,
            ],
        )
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.installation_id,
            &self.organization,
            &self.repository,
            &self.git_ref,
            &self.commit_sha,
            self.alert_number,
            self.expected_alert_state,
            self.expected_validity,
            &self.permissions,
            &self.query,
            &self.mission,
            &self.evidence_policy_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretScanningAlert {
    pub number: AlertNumber,
    pub state: AlertState,
    pub opened_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub secret_type: SecretType,
    pub validity: ValidityClass,
    pub installation_digest: Digest,
    pub organization_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_digest: Digest,
    pub locations: Vec<RedactedLocation>,
    pub has_more_locations: bool,
    pub push_protection: PushProtectionMetadata,
    pub alert_digest: Digest,
}

pub type GithubSecretScanningAlert = SecretScanningAlert;
pub type SecretScanningAlertRecord = SecretScanningAlert;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretScanningAlertInput {
    pub number: AlertNumber,
    pub state: AlertState,
    pub opened_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub secret_type: SecretType,
    pub validity: ValidityClass,
    pub installation_digest: Digest,
    pub organization_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_digest: Digest,
    pub locations: Vec<RedactedLocation>,
    pub has_more_locations: bool,
    pub push_protection: PushProtectionMetadata,
}

impl SecretScanningAlert {
    pub fn new(input: SecretScanningAlertInput) -> Result<Self, ModelError> {
        let mut alert = Self {
            number: input.number,
            state: input.state,
            opened_at: input.opened_at,
            resolved_at: input.resolved_at,
            secret_type: input.secret_type,
            validity: input.validity,
            installation_digest: input.installation_digest,
            organization_digest: input.organization_digest,
            repository_digest: input.repository_digest,
            ref_digest: input.ref_digest,
            commit_digest: input.commit_digest,
            locations: input.locations,
            has_more_locations: input.has_more_locations,
            push_protection: input.push_protection,
            alert_digest: Digest::zero(),
        };
        alert.alert_digest = alert.computed_digest();
        alert.validate()?;
        Ok(alert)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.number.get() == 0
            || self.secret_type.validate().is_err()
            || self.locations.len() > MAX_LOCATIONS
            || self
                .locations
                .iter()
                .any(|location| location.validate().is_err())
            || self.resolved_at.is_some() != matches!(self.state, AlertState::Resolved)
            || self.alert_digest != self.computed_digest()
        {
            return Err(ModelError::InvalidAlert);
        }
        for digest in [
            &self.installation_digest,
            &self.organization_digest,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_digest,
        ] {
            digest.validate()?;
            if digest.is_zero() {
                return Err(ModelError::InvalidAlert);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.alert_digest
    }

    pub fn unresolved(&self) -> bool {
        matches!(self.state, AlertState::Open)
    }

    pub fn location_digest(&self) -> Digest {
        Digest::from_serialized(&self.locations)
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.number,
            self.state,
            self.opened_at,
            self.resolved_at,
            &self.secret_type,
            self.validity,
            &self.installation_digest,
            &self.organization_digest,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_digest,
            &self.locations,
            self.has_more_locations,
            &self.push_protection,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedRateReceipt {
    pub limit: Option<u32>,
    pub remaining: Option<u32>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u32>,
}

impl RedactedRateReceipt {
    pub const fn empty() -> Self {
        Self {
            limit: None,
            remaining: None,
            reset_at: None,
            retry_after_seconds: None,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedRequestReceipt {
    pub operation: SecretScanningOperation,
    pub method: String,
    pub endpoint_digest: Digest,
    pub query_digest: Digest,
    pub page: u16,
    pub cursor_digest: Option<Digest>,
    pub status: u16,
    pub response_digest: Digest,
    pub rate: RedactedRateReceipt,
    pub receipt_digest: Digest,
}

impl RedactedRequestReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: SecretScanningOperation,
        endpoint_digest: Digest,
        query_digest: Digest,
        page: u16,
        cursor_digest: Option<Digest>,
        status: u16,
        response_digest: Digest,
        rate: RedactedRateReceipt,
    ) -> Result<Self, ModelError> {
        if page == 0 || method_is_not_get("GET") || status == 0 {
            return Err(ModelError::InvalidAlert);
        }
        endpoint_digest.validate()?;
        query_digest.validate()?;
        response_digest.validate()?;
        if endpoint_digest.is_zero() || query_digest.is_zero() || response_digest.is_zero() {
            return Err(ModelError::InvalidAlert);
        }
        if let Some(cursor_digest) = &cursor_digest {
            cursor_digest.validate()?;
        }
        let mut receipt = Self {
            operation,
            method: "GET".to_owned(),
            endpoint_digest,
            query_digest,
            page,
            cursor_digest,
            status,
            response_digest,
            rate,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.method != "GET" || self.page == 0 || self.status == 0 {
            return Err(ModelError::InvalidAlert);
        }
        self.endpoint_digest.validate()?;
        self.query_digest.validate()?;
        self.response_digest.validate()?;
        if self.endpoint_digest.is_zero()
            || self.query_digest.is_zero()
            || self.response_digest.is_zero()
        {
            return Err(ModelError::InvalidAlert);
        }
        if let Some(cursor_digest) = &self.cursor_digest {
            cursor_digest.validate()?;
        }
        if self.receipt_digest != self.computed_digest() {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            &self.method,
            &self.endpoint_digest,
            &self.query_digest,
            self.page,
            &self.cursor_digest,
            self.status,
            &self.response_digest,
            &self.rate,
        ))
    }
}

fn method_is_not_get(method: &str) -> bool {
    method != "GET"
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScanningOperation {
    ListRepositoryAlerts,
    ListOrganizationAlerts,
    GetRepositoryAlert,
    GetOrganizationAlertFromBoundedList,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubSecretScanningEvidence {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub alert: SecretScanningAlert,
    pub response_receipts: Vec<RedactedRequestReceipt>,
    pub provenance: TransportProvenance,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl GithubSecretScanningEvidence {
    pub fn new(
        scope: &GithubSecretScanningScope,
        alert: SecretScanningAlert,
        response_receipts: Vec<RedactedRequestReceipt>,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if response_receipts.is_empty() || response_receipts.len() > MAX_REQUESTS_PER_READ {
            return Err(ModelError::InvalidAlert);
        }
        let mut evidence = Self {
            scope_digest: scope.digest().clone(),
            query_digest: scope.query_digest().clone(),
            alert,
            response_receipts,
            provenance,
            partial: false,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence.validate(scope)?;
        Ok(evidence)
    }

    pub fn validate(&self, scope: &GithubSecretScanningScope) -> Result<(), ModelError> {
        if self.partial
            || self.connected
            || self.native
            || self.first_party
            || self.scope_digest != *scope.digest()
            || self.query_digest != *scope.query_digest()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.response_receipts.is_empty()
            || self.response_receipts.len() > MAX_REQUESTS_PER_READ
            || self
                .response_receipts
                .iter()
                .any(|receipt| receipt.validate().is_err())
            || self.alert.validate().is_err()
            || self.evidence_digest != self.computed_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn unresolved(&self) -> bool {
        self.alert.unresolved()
    }

    pub fn path_region_digest(&self) -> Digest {
        self.alert.location_digest()
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.query_digest,
            &self.alert,
            &self.response_receipts,
            self.provenance,
            self.partial,
            self.connected,
            self.native,
            self.first_party,
        ))
    }
}

impl fmt::Display for GithubSecretScanningEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GithubSecretScanningEvidence({})",
            self.evidence_digest
        )
    }
}

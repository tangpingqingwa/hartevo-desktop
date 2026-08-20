//! Typed identities, exact scope, opaque credentials, and redacted evidence
//! primitives for the GitHub code-scanning boundary.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    ALERT_ENDPOINT, ALERTS_ENDPOINT, ANALYSES_ENDPOINT, CONTRACT_VERSION, PROVIDER_API_REVISION,
    PROVIDER_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_RULES: usize = 256;
pub const MAX_LOCATIONS: usize = 64;
pub const MAX_PAGE_SIZE: u32 = 50;
pub const MAX_ALERT_PAGES: u32 = 16;
pub const MAX_ANALYSIS_PAGES: u32 = 16;
pub const MAX_ALERTS: usize = 1_024;
pub const MAX_RESPONSE_BYTES: u32 = 1_048_576;
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
    #[error("rule allowlist is empty, duplicated, or too large")]
    InvalidRuleAllowlist,
    #[error("CodeQL scope is invalid")]
    InvalidScope,
    #[error("read-only permission snapshot is incomplete or contains a write")]
    InvalidPermissions,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("redacted location is invalid or outside its bound")]
    InvalidLocation,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or SecretReference is already revoked")]
    AlreadyRevoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
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

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("contract value must serialize");
        Self::from_bytes(&bytes)
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
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
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_identifier!(InstallationId);
string_identifier!(AnalysisId);
string_identifier!(RuleId);
string_identifier!(AlertFingerprint);
string_identifier!(RegistrationId);
string_identifier!(MissionId);
string_identifier!(ProjectId);
string_identifier!(WorkProductId);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RefName(String);

impl RefName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_text(&value, MAX_TEXT_BYTES, false)
            && value.starts_with("refs/")
            && !value.contains("..")
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRef)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAuthKind {
    App,
    OAuth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeScanningTool {
    #[serde(rename = "CodeQL")]
    CodeQL,
}

impl CodeScanningTool {
    pub const fn as_str(self) -> &'static str {
        "CodeQL"
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Open,
    Dismissed,
    Fixed,
    AutoDismissed,
}

impl AlertState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Dismissed => "dismissed",
            Self::Fixed => "fixed",
            Self::AutoDismissed => "auto_dismissed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Warning,
    Note,
    Error,
    Unknown,
}

impl AlertSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Warning => "warning",
            Self::Note => "note",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Queued,
    InProgress,
    Complete,
    Failed,
    Canceled,
    Unknown,
}

impl AnalysisStatus {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    #[serde(rename = "security_events:read")]
    SecurityEventsRead,
    #[serde(rename = "metadata:read")]
    MetadataRead,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecurityEventsRead => "security_events:read",
            Self::MetadataRead => "metadata:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<Permission>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(permissions: impl IntoIterator<Item = Permission>) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&Permission::SecurityEventsRead)
            || !permissions.contains(&Permission::MetadataRead)
        {
            return Err(ModelError::InvalidPermissions);
        }
        let permission_digest = Digest::from_fields(
            "github-codeql-permissions/v1",
            &permissions
                .iter()
                .map(|permission| permission.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    pub fn least_privilege() -> Self {
        Self::new([Permission::SecurityEventsRead, Permission::MetadataRead])
            .expect("the two required permissions are always valid")
    }

    pub fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn contains(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt == *self {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RuleAllowlist {
    rules: BTreeSet<RuleId>,
}

impl RuleAllowlist {
    pub fn new(rules: impl IntoIterator<Item = RuleId>) -> Result<Self, ModelError> {
        let values = rules.into_iter().collect::<Vec<_>>();
        let rules = values.iter().cloned().collect::<BTreeSet<_>>();
        if values.is_empty() || rules.len() > MAX_RULES || values.len() != rules.len() {
            return Err(ModelError::InvalidRuleAllowlist);
        }
        Ok(Self { rules })
    }

    pub fn single(rule: RuleId) -> Self {
        Self::new([rule]).expect("one valid rule is a valid allowlist")
    }

    pub fn contains(&self, rule: &RuleId) -> bool {
        self.rules.contains(rule)
    }

    pub fn rules(&self) -> &BTreeSet<RuleId> {
        &self.rules
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(&self.rules)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.rules.is_empty() || self.rules.len() > MAX_RULES {
            Err(ModelError::InvalidRuleAllowlist)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub owner: String,
    pub name: String,
    pub url: String,
}

impl RepositoryIdentity {
    pub fn new(
        owner: impl Into<String>,
        name: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let repository = Self {
            owner: owner.into(),
            name: name.into(),
            url: url.into(),
        };
        repository.validate()?;
        Ok(repository)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_github_component(&self.owner)
            || !valid_github_component(&self.name)
            || !valid_text(&self.url, MAX_TEXT_BYTES, false)
            || !self.url.starts_with("https://")
        {
            Err(ModelError::InvalidRepository)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedLocation {
    pub path_digest: Digest,
    pub start_line: u32,
    pub end_line: u32,
    pub region_digest: Digest,
}

impl RedactedLocation {
    pub fn new(
        path: impl AsRef<[u8]>,
        start_line: u32,
        end_line: u32,
        region: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        let location = Self {
            path_digest: Digest::from_text(path),
            start_line,
            end_line,
            region_digest: Digest::from_text(region),
        };
        location.validate()?;
        Ok(location)
    }

    pub fn from_digests(
        path_digest: Digest,
        start_line: u32,
        end_line: u32,
        region_digest: Digest,
    ) -> Result<Self, ModelError> {
        let location = Self {
            path_digest,
            start_line,
            end_line,
            region_digest,
        };
        location.validate()?;
        Ok(location)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.path_digest.validate()?;
        self.region_digest.validate()?;
        if self.start_line == 0
            || self.end_line < self.start_line
            || self.end_line > MAX_LOCATION_LINE
        {
            Err(ModelError::InvalidLocation)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
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

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Unmounted,
    Revoked,
}

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Opaque handle into host-managed App or OAuth material.
///
/// The raw reference identifier is hashed during construction and is never
/// retained, serialized, or printed. This type deliberately has no
/// Serialize implementation.
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
        scope: &GithubCodeqlScope,
        credential_revision: u64,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = Digest::from_fields(
            "github-codeql-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
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

    pub fn reference_digest(&self) -> &Digest {
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

    pub fn validate_for_scope(&self, scope: &GithubCodeqlScope) -> Result<(), ModelError> {
        if self.scope_digest == *scope.digest() && self.reference_digest.validate().is_ok() {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCodeqlScope {
    pub installation_id: InstallationId,
    pub repository: RepositoryIdentity,
    pub git_ref: RefName,
    pub commit_sha: CommitSha,
    pub analysis_id: AnalysisId,
    pub tool: CodeScanningTool,
    pub rule_id: RuleId,
    pub rule_allowlist: RuleAllowlist,
    pub alert_number: AlertNumber,
    pub alert_fingerprint: AlertFingerprint,
    pub expected_alert_state: AlertState,
    pub permissions: PermissionSnapshot,
    pub mission: MissionScopeBinding,
    pub evidence_policy_digest: Digest,
    scope_digest: Digest,
}

impl GithubCodeqlScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: InstallationId,
        repository: RepositoryIdentity,
        git_ref: RefName,
        commit_sha: CommitSha,
        analysis_id: AnalysisId,
        tool: CodeScanningTool,
        rule_id: RuleId,
        rule_allowlist: RuleAllowlist,
        alert_number: AlertNumber,
        alert_fingerprint: AlertFingerprint,
        expected_alert_state: AlertState,
        permissions: PermissionSnapshot,
        mission: MissionScopeBinding,
    ) -> Result<Self, ModelError> {
        let mut scope = Self {
            installation_id,
            repository,
            git_ref,
            commit_sha,
            analysis_id,
            tool,
            rule_id,
            rule_allowlist,
            alert_number,
            alert_fingerprint,
            expected_alert_state,
            permissions,
            mission,
            evidence_policy_digest: Self::evidence_policy_digest(),
            scope_digest: Digest::from_text("unsealed-github-codeql-scope"),
        };
        scope.scope_digest = scope.computed_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn evidence_policy_digest() -> Digest {
        Digest::from_text(
            "github-codeql-result/evidence-policy/v1|path-digest|region-digest|bounded-lines|no-source|no-sarif|no-identity",
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.repository.validate()?;
        self.rule_allowlist.validate()?;
        self.permissions.validate()?;
        self.mission.validate()?;
        if self.tool != CodeScanningTool::CodeQL
            || !self.rule_allowlist.contains(&self.rule_id)
            || self.evidence_policy_digest != Self::evidence_policy_digest()
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
        Digest::from_serialized(&self.installation_id)
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

    pub fn analysis_digest(&self) -> Digest {
        Digest::from_serialized(&self.analysis_id)
    }

    pub fn tool_digest(&self) -> Digest {
        Digest::from_text(self.tool.as_str())
    }

    pub fn rule_digest(&self) -> Digest {
        Digest::from_serialized(&self.rule_id)
    }

    pub fn alert_digest(&self) -> Digest {
        Digest::from_fields(
            "github-codeql-alert-scope/v1",
            &[
                self.alert_number.get().to_string(),
                self.alert_fingerprint.as_str().to_owned(),
                self.expected_alert_state.as_str().to_owned(),
                self.rule_id.as_str().to_owned(),
                self.tool.as_str().to_owned(),
                self.analysis_id.as_str().to_owned(),
            ],
        )
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.installation_id,
            &self.repository,
            &self.git_ref,
            &self.commit_sha,
            &self.analysis_id,
            self.tool,
            &self.rule_id,
            &self.rule_allowlist,
            self.alert_number,
            &self.alert_fingerprint,
            self.expected_alert_state,
            &self.permissions,
            &self.mission,
            &self.evidence_policy_digest,
        ))
    }

    pub fn provider_scope_digest(&self) -> Digest {
        Digest::from_fields(
            "github-codeql-provider-scope/v1",
            &[
                self.repository.digest().as_str().to_owned(),
                self.git_ref.digest().as_str().to_owned(),
                self.commit_sha.digest().as_str().to_owned(),
                self.analysis_id.as_str().to_owned(),
            ],
        )
    }

    pub fn api_fence_digest(&self) -> Digest {
        Digest::from_fields(
            "github-codeql-api-fence/v1",
            &[
                PROVIDER_ID.to_owned(),
                PROVIDER_API_REVISION.to_owned(),
                ALERTS_ENDPOINT.to_owned(),
                ALERT_ENDPOINT.to_owned(),
                ANALYSES_ENDPOINT.to_owned(),
                CONTRACT_VERSION.to_owned(),
            ],
        )
    }
}

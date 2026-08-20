//! Layer 1 LaunchDarkly feature-release capability for Hartevo.
//!
//! The crate is intentionally standalone and read/proposal/recording only. It
//! exposes a typed service definition, a provider seam over read-only
//! transports, and a Mission consumer. It has no patch, toggle, approval
//! mutation, scheduling, evaluation, event-ingest, or native-connection
//! authority.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use jsonschema::Validator;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.launchdarkly-release/v1";
pub const CONTRACT_VERSION: &str = "feature-release-contract/v1";
pub const PLUGIN_ID: &str = "launchdarkly-release";
pub const SERVICE_ID: &str = "feature-release";
pub const PROVIDER_ID: &str = "launchdarkly-release";
pub const CONSUMER_ID: &str = "mission-feature-release";
pub const DEFAULT_ADAPTER_REVISION: &str = "launchdarkly-read-adapter/v1";
pub const DEFAULT_API_REVISION: &str = "launchdarkly-rest-read/v1";
pub const MAX_AUDIT_ENTRIES: u8 = 16;
pub const MAX_APPROVAL_ENTRIES: u8 = 8;
pub const MAX_AUDIT_DESCRIPTION_BYTES: usize = 4096;
pub const MAX_IDENTIFIER_BYTES: usize = 128;

const CONTRACT_SCHEMA: &str =
    include_str!("../../../contracts/plugins/launchdarkly-release/feature-release.v1.schema.json");

/// A lowercase SHA-256 digest used for every cross-boundary fingerprint.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Hash bytes without retaining the input bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    /// Hash text without retaining the input text.
    pub fn from_text(text: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(text.as_ref())
    }

    /// Hash a deterministic serde representation.
    ///
    /// # Panics
    ///
    /// Panics only if a type that claims to implement `Serialize` fails its
    /// serializer; all contract types in this crate are infallible.
    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("contract values are serializable");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

/// The bounded HTTP/transport failure vocabulary retained by recordings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Error)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum TransportError {
    #[error("LaunchDarkly returned HTTP {status} (response digest {body_digest})")]
    Http {
        status: u16,
        body_digest: Digest,
        retry_after_seconds: Option<u64>,
    },
    #[error("LaunchDarkly transport is blocked by the environment ({code})")]
    BlockedEnv { code: String },
    #[error("LaunchDarkly transport returned an unknown bounded state ({code})")]
    Unknown { code: String },
}

impl TransportError {
    pub fn http(status: u16, response_body: impl AsRef<[u8]>) -> Self {
        Self::Http {
            status,
            body_digest: Digest::from_bytes(response_body.as_ref()),
            retry_after_seconds: None,
        }
    }

    pub fn http_with_retry_after(
        status: u16,
        response_body: impl AsRef<[u8]>,
        retry_after_seconds: u64,
    ) -> Self {
        Self::Http {
            status,
            body_digest: Digest::from_bytes(response_body.as_ref()),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }

    pub fn blocked_env(code: impl Into<String>) -> Self {
        Self::BlockedEnv {
            code: bounded_code(code.into()),
        }
    }

    pub fn unknown(code: impl Into<String>) -> Self {
        Self::Unknown {
            code: bounded_code(code.into()),
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            Self::BlockedEnv { .. } | Self::Unknown { .. } => None,
        }
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Http { status: 429, .. })
    }
}

/// Errors fail closed at the plugin seam and never contain secret material,
/// targeting attributes, response bodies, or unbounded provider text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FeatureReleaseError {
    #[error("invalid feature-release input: {0}")]
    InvalidInput(String),
    #[error("feature-release scope is invalid")]
    InvalidScope,
    #[error("feature-release digest is invalid")]
    InvalidDigest,
    #[error("secret reference is revoked")]
    SecretReferenceRevoked,
    #[error("secret reference is bound to a different scope")]
    SecretReferenceScopeMismatch,
    #[error("secret reference metadata or lifecycle was tampered")]
    SecretReferenceTampered,
    #[error("least-privilege permission snapshot is invalid or drifted")]
    PermissionDrift,
    #[error("feature-release registration is revoked")]
    RegistrationRevoked,
    #[error("feature-release registration is unregistered")]
    RegistrationUnregistered,
    #[error("feature-release registration fence does not match")]
    RegistrationFenceMismatch,
    #[error("feature-release scope does not match exact evidence")]
    ScopeMismatch,
    #[error("flag version drifted: expected {expected}, observed {actual}")]
    VersionDrift { expected: u64, actual: u64 },
    #[error("semantic patch path is outside the registered scope: {0}")]
    PatchPathNotAllowed(String),
    #[error("semantic patch is invalid")]
    InvalidSemanticPatch,
    #[error("semantic patch digest does not match the dry-run evidence")]
    DryRunMismatch,
    #[error("dry-run validation was rejected")]
    DryRunRejected,
    #[error("provider dry-run state is unknown")]
    DryRunUnknown,
    #[error("dry-run validation cannot become a release receipt")]
    DryRunReceiptForbidden,
    #[error("approval evidence conflicts")]
    ApprovalConflict,
    #[error("approval evidence is stale")]
    ApprovalStale,
    #[error("approval evidence is not approved")]
    ApprovalNotApproved,
    #[error("audit evidence is unbounded")]
    AuditUnbounded,
    #[error("audit evidence is duplicated")]
    AuditDuplicate,
    #[error("audit evidence is missing")]
    AuditMissing,
    #[error("audit evidence does not match the exact release fence")]
    AuditMismatch,
    #[error("read-back flag version is not newer than the proposal base")]
    ReadBackVersionNotNewer,
    #[error("read-back flag fingerprint does not match the receipt")]
    ReadBackFlagMismatch,
    #[error("release receipt digest is tampered")]
    ReceiptTampered,
    #[error("release receipt registration is stale")]
    ReceiptRegistrationStale,
    #[error("provider evidence is unknown")]
    ProviderUnknown,
    #[error("provider evidence is BLOCKED_ENV")]
    BlockedEnv,
    #[error("synthetic fixture or BLOCKED_ENV provenance cannot be accepted")]
    ProvenanceForbidden,
    #[error("feature-release payload does not satisfy its JSON Schema contract")]
    SchemaValidation,
    #[error("transport error: {0}")]
    Transport(TransportError),
}

impl From<TransportError> for FeatureReleaseError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

fn bounded_code(mut code: String) -> String {
    if code.len() > MAX_IDENTIFIER_BYTES {
        code.truncate(MAX_IDENTIFIER_BYTES);
    }
    code
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_revision(value: u64) -> bool {
    value > 0
}

fn valid_bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.contains('\n')
        && !value.contains('\r')
}

fn valid_digest(digest: &Digest) -> bool {
    digest.is_valid()
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.starts_with('/')
        && !path.contains("..")
        && !path.contains('\n')
        && !path.contains('\r')
}

fn valid_base_url(value: &str) -> bool {
    (value.starts_with("https://") && value.len() > 8)
        || (value.starts_with("http://localhost") && value.len() > 16)
        || (value.starts_with("http://127.0.0.1") && value.len() > 16)
}

/// Semantic version of the plugin contribution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The exact approval policy fence included in a release scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalPolicySnapshot {
    pub policy_id: String,
    pub revision: u64,
    pub required: bool,
}

impl ApprovalPolicySnapshot {
    pub fn new(
        policy_id: impl Into<String>,
        revision: u64,
        required: bool,
    ) -> Result<Self, FeatureReleaseError> {
        let snapshot = Self {
            policy_id: policy_id.into(),
            revision,
            required,
        };
        if !valid_identifier(&snapshot.policy_id) || !valid_revision(snapshot.revision) {
            return Err(FeatureReleaseError::InvalidScope);
        }
        Ok(snapshot)
    }

    pub fn required(
        policy_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, FeatureReleaseError> {
        Self::new(policy_id, revision, true)
    }
}

/// One exact Project/Mission/Work Product and LaunchDarkly target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureReleaseScope {
    pub account_id: String,
    pub base_url: String,
    pub project_key: String,
    pub environment_key: String,
    pub environment_id: Option<String>,
    pub flag_key: String,
    pub flag_version: u64,
    pub allowed_variation_paths: BTreeSet<String>,
    pub allowed_targeting_paths: BTreeSet<String>,
    pub approval_policy: ApprovalPolicySnapshot,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub scope_digest: Digest,
}

impl FeatureReleaseScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new<V, T>(
        account_id: impl Into<String>,
        base_url: impl Into<String>,
        project_key: impl Into<String>,
        environment_key: impl Into<String>,
        flag_key: impl Into<String>,
        flag_version: u64,
        allowed_variation_paths: V,
        allowed_targeting_paths: T,
        approval_policy: ApprovalPolicySnapshot,
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        work_product_id: impl Into<String>,
        consent_revision: u64,
        policy_revision: u64,
    ) -> Result<Self, FeatureReleaseError>
    where
        V: IntoIterator,
        V::Item: Into<String>,
        T: IntoIterator,
        T::Item: Into<String>,
    {
        let mut scope = Self {
            account_id: account_id.into(),
            base_url: base_url.into(),
            project_key: project_key.into(),
            environment_key: environment_key.into(),
            environment_id: None,
            flag_key: flag_key.into(),
            flag_version,
            allowed_variation_paths: allowed_variation_paths
                .into_iter()
                .map(Into::into)
                .collect(),
            allowed_targeting_paths: allowed_targeting_paths
                .into_iter()
                .map(Into::into)
                .collect(),
            approval_policy,
            mission_id: mission_id.into(),
            project_id: project_id.into(),
            work_product_id: work_product_id.into(),
            consent_revision,
            policy_revision,
            scope_digest: Digest::from_text("pending"),
        };
        scope.validate_components()?;
        let scope_digest = Digest::from_serialized(&scope_without_digest(&scope));
        scope.scope_digest = scope_digest;
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_environment_id(
        mut self,
        environment_id: impl Into<String>,
    ) -> Result<Self, FeatureReleaseError> {
        let environment_id = environment_id.into();
        if !valid_identifier(&environment_id) {
            return Err(FeatureReleaseError::InvalidScope);
        }
        self.environment_id = Some(environment_id);
        let scope_digest = Digest::from_serialized(&scope_without_digest(&self));
        self.scope_digest = scope_digest;
        self.validate()?;
        Ok(self)
    }

    fn validate_components(&self) -> Result<(), FeatureReleaseError> {
        if !valid_identifier(&self.account_id)
            || !valid_base_url(&self.base_url)
            || !valid_identifier(&self.project_key)
            || !valid_identifier(&self.environment_key)
            || self
                .environment_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_identifier(&self.flag_key)
            || self.flag_version == 0
            || !valid_identifier(&self.mission_id)
            || !valid_identifier(&self.project_id)
            || !valid_identifier(&self.work_product_id)
            || !valid_revision(self.consent_revision)
            || !valid_revision(self.policy_revision)
        {
            return Err(FeatureReleaseError::InvalidScope);
        }
        if self
            .allowed_variation_paths
            .iter()
            .any(|path| !valid_path(path))
            || self
                .allowed_targeting_paths
                .iter()
                .any(|path| !valid_path(path))
            || (self.allowed_variation_paths.is_empty() && self.allowed_targeting_paths.is_empty())
        {
            return Err(FeatureReleaseError::InvalidScope);
        }
        if self.approval_policy.revision != self.policy_revision {
            return Err(FeatureReleaseError::InvalidScope);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), FeatureReleaseError> {
        self.validate_components()?;
        if !valid_digest(&self.scope_digest)
            || self.scope_digest != Digest::from_serialized(&scope_without_digest(self))
        {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }
}

fn scope_without_digest(scope: &FeatureReleaseScope) -> impl Serialize + '_ {
    (
        &scope.account_id,
        &scope.base_url,
        &scope.project_key,
        &scope.environment_key,
        &scope.environment_id,
        &scope.flag_key,
        &scope.flag_version,
        &scope.allowed_variation_paths,
        &scope.allowed_targeting_paths,
        &scope.approval_policy,
        &scope.mission_id,
        &scope.project_id,
        &scope.work_product_id,
        &scope.consent_revision,
        &scope.policy_revision,
    )
}

/// A registration-only permission vocabulary. There are no write permissions
/// in this enum by construction.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureReleasePermission {
    ReadFlag,
    ReadApprovals,
    ReadAuditLog,
}

/// Exact permission and approval snapshot bound into registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub role_id: String,
    pub scope_digest: Digest,
    pub approval_policy_revision: u64,
    pub allowed_operations: BTreeSet<FeatureReleasePermission>,
}

impl PermissionSnapshot {
    pub fn read_only(scope: &FeatureReleaseScope) -> Self {
        Self {
            role_id: "launchdarkly-feature-release-read".into(),
            scope_digest: scope.scope_digest(),
            approval_policy_revision: scope.policy_revision,
            allowed_operations: BTreeSet::from([
                FeatureReleasePermission::ReadFlag,
                FeatureReleasePermission::ReadApprovals,
                FeatureReleasePermission::ReadAuditLog,
            ]),
        }
    }

    pub fn validate_for_scope(
        &self,
        scope: &FeatureReleaseScope,
    ) -> Result<(), FeatureReleaseError> {
        if !valid_identifier(&self.role_id)
            || !valid_digest(&self.scope_digest)
            || self.scope_digest != scope.scope_digest()
            || self.approval_policy_revision != scope.policy_revision
            || self.allowed_operations
                != BTreeSet::from([
                    FeatureReleasePermission::ReadFlag,
                    FeatureReleasePermission::ReadApprovals,
                    FeatureReleasePermission::ReadAuditLog,
                ])
        {
            return Err(FeatureReleaseError::PermissionDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Opaque metadata for a least-privilege service token. Secret bytes are not a
/// field of this type and therefore cannot be serialized, logged, or hashed.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: u64,
    permission_class: String,
    revoked: bool,
    metadata_digest: Digest,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, FeatureReleaseError> {
        let mut reference = Self {
            reference_id: reference_id.into(),
            scope_digest,
            credential_revision,
            permission_class: "least_privilege_read_only_service_token".into(),
            revoked: false,
            metadata_digest: Digest::from_text("pending"),
        };
        reference.metadata_digest = reference.calculate_metadata_digest();
        reference.validate()?;
        Ok(reference)
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &FeatureReleaseScope,
        credential_revision: u64,
    ) -> Result<Self, FeatureReleaseError> {
        Self::new(reference_id, scope.scope_digest(), credential_revision)
    }

    pub fn validate(&self) -> Result<(), FeatureReleaseError> {
        if !valid_identifier(&self.reference_id)
            || !valid_digest(&self.scope_digest)
            || self.credential_revision == 0
            || self.permission_class != "least_privilege_read_only_service_token"
            || !valid_digest(&self.metadata_digest)
            || self.metadata_digest != self.calculate_metadata_digest()
        {
            return Err(FeatureReleaseError::SecretReferenceTampered);
        }
        Ok(())
    }

    fn calculate_metadata_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.reference_id,
            &self.scope_digest,
            &self.credential_revision,
            &self.permission_class,
        ))
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn permission_class(&self) -> &str {
        &self.permission_class
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &Digest::from_text(&self.reference_id))
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("permission_class", &self.permission_class)
            .field("revoked", &self.revoked)
            .field("metadata_digest", &self.metadata_digest)
            .finish()
    }
}

/// Layer 1 transports are deliberately enumerated. There is no native
/// transport variant in this crate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

/// Claim surface for this crate. All authority-bearing flags are permanently
/// false, including for a transport supplied by a caller.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceClaims {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub write_effect: bool,
    pub outcome_authority: bool,
}

impl EvidenceClaims {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            write_effect: false,
            outcome_authority: false,
        }
    }

    fn validate(self) -> Result<(), FeatureReleaseError> {
        if self.connected
            || self.native
            || self.first_party
            || self.write_effect
            || self.outcome_authority
        {
            Err(FeatureReleaseError::PermissionDrift)
        } else {
            Ok(())
        }
    }
}

/// A bounded retry budget. Retrying is metadata-only; Layer 1 never sleeps or
/// performs an unbounded retry loop.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_seconds: u16,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_seconds: u16) -> Result<Self, FeatureReleaseError> {
        if !(1..=4).contains(&max_attempts) || max_backoff_seconds > 60 {
            return Err(FeatureReleaseError::InvalidInput(
                "retry budget is not bounded".into(),
            ));
        }
        Ok(Self {
            max_attempts,
            max_backoff_seconds,
        })
    }

    pub fn validate(&self) -> Result<(), FeatureReleaseError> {
        if !(1..=4).contains(&self.max_attempts) || self.max_backoff_seconds > 60 {
            return Err(FeatureReleaseError::InvalidInput(
                "retry budget is not bounded".into(),
            ));
        }
        Ok(())
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_backoff_seconds: 30,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrySummary {
    pub flag_attempts: u8,
    pub approval_attempts: u8,
    pub audit_attempts: u8,
    pub max_attempts: u8,
    pub bounded: bool,
}

impl RetrySummary {
    #[allow(clippy::too_many_arguments)]
    fn new(
        policy: RetryPolicy,
        flag_attempts: u8,
        approval_attempts: u8,
        audit_attempts: u8,
    ) -> Self {
        Self {
            flag_attempts,
            approval_attempts,
            audit_attempts,
            max_attempts: policy.max_attempts,
            bounded: true,
        }
    }
}

/// Exact redacted feature-flag configuration evidence. Targeting and
/// variation payloads are represented only by digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlagSnapshot {
    pub account_id: String,
    pub base_url: String,
    pub project_key: String,
    pub environment_key: String,
    pub environment_id: Option<String>,
    pub flag_key: String,
    pub flag_version: u64,
    pub variation_digest: Digest,
    pub targeting_digest: Digest,
    pub semantic_digest: Digest,
    pub observed_at: u64,
}

impl FlagSnapshot {
    pub fn for_scope(
        scope: &FeatureReleaseScope,
        flag_version: u64,
        variation_digest: Digest,
        targeting_digest: Digest,
        semantic_digest: Digest,
        observed_at: u64,
    ) -> Result<Self, FeatureReleaseError> {
        let snapshot = Self {
            account_id: scope.account_id.clone(),
            base_url: scope.base_url.clone(),
            project_key: scope.project_key.clone(),
            environment_key: scope.environment_key.clone(),
            environment_id: scope.environment_id.clone(),
            flag_key: scope.flag_key.clone(),
            flag_version,
            variation_digest,
            targeting_digest,
            semantic_digest,
            observed_at,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), FeatureReleaseError> {
        if !valid_identifier(&self.account_id)
            || !valid_base_url(&self.base_url)
            || !valid_identifier(&self.project_key)
            || !valid_identifier(&self.environment_key)
            || self
                .environment_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_identifier(&self.flag_key)
            || self.flag_version == 0
            || !valid_digest(&self.variation_digest)
            || !valid_digest(&self.targeting_digest)
            || !valid_digest(&self.semantic_digest)
        {
            return Err(FeatureReleaseError::InvalidInput(
                "invalid flag snapshot".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_scope(
        &self,
        scope: &FeatureReleaseScope,
    ) -> Result<(), FeatureReleaseError> {
        self.validate()?;
        if self.account_id != scope.account_id
            || self.base_url != scope.base_url
            || self.project_key != scope.project_key
            || self.environment_key != scope.environment_key
            || self.environment_id != scope.environment_id
            || self.flag_key != scope.flag_key
        {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Exact provider/account/base/project/environment/flag/version registration
/// identity carried through proposal, read-back, receipt, and Mission seams.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureReleaseProviderFence {
    pub provider_id: String,
    pub account_id: String,
    pub base_url: String,
    pub project_key: String,
    pub environment_key: String,
    pub environment_id: Option<String>,
    pub flag_key: String,
    pub flag_version: u64,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
}

impl FeatureReleaseProviderFence {
    fn from_flag(flag: &FlagSnapshot, scope_digest: Digest, registration_digest: Digest) -> Self {
        Self {
            provider_id: PROVIDER_ID.into(),
            account_id: flag.account_id.clone(),
            base_url: flag.base_url.clone(),
            project_key: flag.project_key.clone(),
            environment_key: flag.environment_key.clone(),
            environment_id: flag.environment_id.clone(),
            flag_key: flag.flag_key.clone(),
            flag_version: flag.flag_version,
            scope_digest,
            registration_digest,
        }
    }

    fn for_scope(scope: &FeatureReleaseScope, registration_digest: Digest) -> Self {
        Self {
            provider_id: PROVIDER_ID.into(),
            account_id: scope.account_id.clone(),
            base_url: scope.base_url.clone(),
            project_key: scope.project_key.clone(),
            environment_key: scope.environment_key.clone(),
            environment_id: scope.environment_id.clone(),
            flag_key: scope.flag_key.clone(),
            flag_version: scope.flag_version,
            scope_digest: scope.scope_digest(),
            registration_digest,
        }
    }

    fn validate_for_scope(
        &self,
        scope: &FeatureReleaseScope,
        registration_digest: &Digest,
        expected_flag_version: Option<u64>,
    ) -> Result<(), FeatureReleaseError> {
        if self.provider_id != PROVIDER_ID
            || self.account_id != scope.account_id
            || self.base_url != scope.base_url
            || self.project_key != scope.project_key
            || self.environment_key != scope.environment_key
            || self.environment_id != scope.environment_id
            || self.flag_key != scope.flag_key
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != *registration_digest
            || expected_flag_version.is_some_and(|version| self.flag_version != version)
        {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        if self.flag_version == 0
            || !valid_digest(&self.scope_digest)
            || !valid_digest(&self.registration_digest)
        {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        Ok(())
    }

    fn same_target(&self, other: &Self) -> bool {
        self.provider_id == other.provider_id
            && self.account_id == other.account_id
            && self.base_url == other.base_url
            && self.project_key == other.project_key
            && self.environment_key == other.environment_key
            && self.environment_id == other.environment_id
            && self.flag_key == other.flag_key
            && self.scope_digest == other.scope_digest
            && self.registration_digest == other.registration_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Declined,
    Conflicted,
    Stale,
    Unknown,
}

/// Approval metadata contains no reviewer names, comments, or raw provider
/// response. Decision material is retained only as a digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalEvidence {
    pub request_id: String,
    pub status: ApprovalStatus,
    pub project_key: String,
    pub environment_key: String,
    pub environment_id: Option<String>,
    pub flag_key: String,
    pub flag_version: u64,
    pub policy_revision: u64,
    pub scope_digest: Digest,
    pub decision_digest: Digest,
    pub evidence_digest: Digest,
    pub observed_at: u64,
}

impl ApprovalEvidence {
    pub fn for_scope(
        scope: &FeatureReleaseScope,
        request_id: impl Into<String>,
        status: ApprovalStatus,
        flag_version: u64,
        policy_revision: u64,
        decision_material: impl AsRef<[u8]>,
        observed_at: u64,
    ) -> Result<Self, FeatureReleaseError> {
        let evidence = Self {
            request_id: request_id.into(),
            status,
            project_key: scope.project_key.clone(),
            environment_key: scope.environment_key.clone(),
            environment_id: scope.environment_id.clone(),
            flag_key: scope.flag_key.clone(),
            flag_version,
            policy_revision,
            scope_digest: scope.scope_digest(),
            decision_digest: Digest::from_bytes(decision_material.as_ref()),
            evidence_digest: Digest::from_text("pending"),
            observed_at,
        };
        let evidence_digest = Digest::from_serialized(&approval_without_digest(&evidence));
        let evidence = Self {
            evidence_digest,
            ..evidence
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), FeatureReleaseError> {
        if !valid_identifier(&self.request_id)
            || !valid_identifier(&self.project_key)
            || !valid_identifier(&self.environment_key)
            || self
                .environment_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_identifier(&self.flag_key)
            || self.flag_version == 0
            || !valid_revision(self.policy_revision)
            || !valid_digest(&self.scope_digest)
            || !valid_digest(&self.decision_digest)
            || !valid_digest(&self.evidence_digest)
            || self.evidence_digest != Digest::from_serialized(&approval_without_digest(self))
        {
            return Err(FeatureReleaseError::InvalidInput(
                "invalid approval evidence".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_scope(
        &self,
        scope: &FeatureReleaseScope,
    ) -> Result<(), FeatureReleaseError> {
        self.validate()?;
        if self.project_key != scope.project_key
            || self.environment_key != scope.environment_key
            || self.environment_id != scope.environment_id
            || self.flag_key != scope.flag_key
            || self.scope_digest != scope.scope_digest()
        {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        Ok(())
    }
}

fn approval_without_digest(evidence: &ApprovalEvidence) -> serde_json::Value {
    serde_json::json!({
        "requestId": &evidence.request_id,
        "status": &evidence.status,
        "projectKey": &evidence.project_key,
        "environmentKey": &evidence.environment_key,
        "environmentId": &evidence.environment_id,
        "flagKey": &evidence.flag_key,
        "flagVersion": &evidence.flag_version,
        "policyRevision": &evidence.policy_revision,
        "scopeDigest": &evidence.scope_digest,
        "decisionDigest": &evidence.decision_digest,
        "observedAt": &evidence.observed_at
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    ApprovalRequested,
    ApprovalDecided,
    ChangeScheduled,
    ChangeApplied,
    ChangeFailed,
    Unknown,
}

/// One bounded audit-log entry. Description and actor material are never
/// retained; only their digests cross the seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvidence {
    pub entry_id: String,
    pub event_kind: AuditEventKind,
    pub provider_id: String,
    pub account_id: String,
    pub base_url: String,
    pub project_key: String,
    pub environment_key: String,
    pub environment_id: Option<String>,
    pub flag_key: String,
    pub flag_version: u64,
    pub actor_digest: Digest,
    pub description_digest: Digest,
    pub related_approval_id: Option<String>,
    pub related_approval_digest: Option<Digest>,
    pub related_proposal_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub observed_at: u64,
    pub bounded: bool,
    pub evidence_digest: Digest,
}

impl AuditEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn for_scope(
        scope: &FeatureReleaseScope,
        entry_id: impl Into<String>,
        event_kind: AuditEventKind,
        flag_version: u64,
        actor_material: impl AsRef<[u8]>,
        description: impl AsRef<[u8]>,
        related_approval_id: Option<String>,
        related_proposal_digest: Option<Digest>,
        observed_at: u64,
    ) -> Result<Self, FeatureReleaseError> {
        Self::for_scope_with_bindings(
            scope,
            entry_id,
            event_kind,
            flag_version,
            actor_material,
            description,
            related_approval_id,
            None,
            related_proposal_digest,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_scope_with_bindings(
        scope: &FeatureReleaseScope,
        entry_id: impl Into<String>,
        event_kind: AuditEventKind,
        flag_version: u64,
        actor_material: impl AsRef<[u8]>,
        description: impl AsRef<[u8]>,
        related_approval_id: Option<String>,
        related_approval_digest: Option<Digest>,
        related_proposal_digest: Option<Digest>,
        observed_at: u64,
    ) -> Result<Self, FeatureReleaseError> {
        if description.as_ref().len() > MAX_AUDIT_DESCRIPTION_BYTES {
            return Err(FeatureReleaseError::AuditUnbounded);
        }
        let evidence = Self {
            entry_id: entry_id.into(),
            event_kind,
            provider_id: PROVIDER_ID.into(),
            account_id: scope.account_id.clone(),
            base_url: scope.base_url.clone(),
            project_key: scope.project_key.clone(),
            environment_key: scope.environment_key.clone(),
            environment_id: scope.environment_id.clone(),
            flag_key: scope.flag_key.clone(),
            flag_version,
            actor_digest: Digest::from_bytes(actor_material.as_ref()),
            description_digest: Digest::from_bytes(description.as_ref()),
            related_approval_id,
            related_approval_digest,
            related_proposal_digest,
            scope_digest: scope.scope_digest(),
            observed_at,
            bounded: true,
            evidence_digest: Digest::from_text("pending"),
        };
        let evidence_digest = Digest::from_serialized(&audit_without_digest(&evidence));
        let evidence = Self {
            evidence_digest,
            ..evidence
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), FeatureReleaseError> {
        if !valid_identifier(&self.entry_id)
            || self.provider_id != PROVIDER_ID
            || !valid_identifier(&self.account_id)
            || !valid_base_url(&self.base_url)
            || !valid_identifier(&self.project_key)
            || !valid_identifier(&self.environment_key)
            || self
                .environment_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_identifier(&self.flag_key)
            || self.flag_version == 0
            || !valid_digest(&self.actor_digest)
            || !valid_digest(&self.description_digest)
            || !valid_digest(&self.scope_digest)
            || !valid_digest(&self.evidence_digest)
            || self.evidence_digest != Digest::from_serialized(&audit_without_digest(self))
            || !self.bounded
            || self
                .related_approval_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || self
                .related_approval_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .related_proposal_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || (self.event_kind == AuditEventKind::ChangeApplied
                && (self.related_approval_id.is_none()
                    || self.related_approval_digest.is_none()
                    || self.related_proposal_digest.is_none()))
        {
            return Err(FeatureReleaseError::InvalidInput(
                "invalid audit evidence".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_scope(
        &self,
        scope: &FeatureReleaseScope,
    ) -> Result<(), FeatureReleaseError> {
        self.validate()?;
        if self.provider_id != PROVIDER_ID
            || self.account_id != scope.account_id
            || self.base_url != scope.base_url
            || self.project_key != scope.project_key
            || self.environment_key != scope.environment_key
            || self.environment_id != scope.environment_id
            || self.flag_key != scope.flag_key
            || self.scope_digest != scope.scope_digest()
        {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

fn audit_without_digest(evidence: &AuditEvidence) -> serde_json::Value {
    serde_json::json!({
        "entryId": &evidence.entry_id,
        "eventKind": &evidence.event_kind,
        "providerId": &evidence.provider_id,
        "accountId": &evidence.account_id,
        "baseUrl": &evidence.base_url,
        "projectKey": &evidence.project_key,
        "environmentKey": &evidence.environment_key,
        "environmentId": &evidence.environment_id,
        "flagKey": &evidence.flag_key,
        "flagVersion": &evidence.flag_version,
        "actorDigest": &evidence.actor_digest,
        "descriptionDigest": &evidence.description_digest,
        "relatedApprovalId": &evidence.related_approval_id,
        "relatedApprovalDigest": &evidence.related_approval_digest,
        "relatedProposalDigest": &evidence.related_proposal_digest,
        "scopeDigest": &evidence.scope_digest,
        "observedAt": &evidence.observed_at,
        "bounded": &evidence.bounded
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchOperationKind {
    Add,
    Replace,
    Remove,
}

/// Patch values are intentionally constrained to public flag semantics. There
/// is no arbitrary JSON/context-attribute variant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum PatchValue {
    Boolean(bool),
    Number(i64),
    VariationIndex(u16),
    WeightBasisPoints(u16),
    TargetingDigest(Digest),
    Null,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticPatchOperation {
    pub operation: PatchOperationKind,
    pub path: String,
    pub value: Option<PatchValue>,
}

impl SemanticPatchOperation {
    pub fn replace(path: impl Into<String>, value: PatchValue) -> Self {
        Self {
            operation: PatchOperationKind::Replace,
            path: path.into(),
            value: Some(value),
        }
    }

    pub fn add(path: impl Into<String>, value: PatchValue) -> Self {
        Self {
            operation: PatchOperationKind::Add,
            path: path.into(),
            value: Some(value),
        }
    }

    pub fn remove(path: impl Into<String>) -> Self {
        Self {
            operation: PatchOperationKind::Remove,
            path: path.into(),
            value: None,
        }
    }

    fn validate(&self, scope: &FeatureReleaseScope) -> Result<(), FeatureReleaseError> {
        if !valid_path(&self.path) {
            return Err(FeatureReleaseError::InvalidSemanticPatch);
        }
        if !scope.allowed_variation_paths.contains(&self.path)
            && !scope.allowed_targeting_paths.contains(&self.path)
        {
            return Err(FeatureReleaseError::PatchPathNotAllowed(self.path.clone()));
        }
        match (&self.operation, &self.value) {
            (PatchOperationKind::Remove, Some(_))
            | (PatchOperationKind::Add | PatchOperationKind::Replace, None) => {
                Err(FeatureReleaseError::InvalidSemanticPatch)
            }
            (
                PatchOperationKind::Add | PatchOperationKind::Replace,
                Some(PatchValue::TargetingDigest(digest)),
            ) if !valid_digest(digest) => Err(FeatureReleaseError::InvalidDigest),
            (
                PatchOperationKind::Add | PatchOperationKind::Replace,
                Some(PatchValue::WeightBasisPoints(weight)),
            ) if *weight > 10_000 => Err(FeatureReleaseError::InvalidSemanticPatch),
            (PatchOperationKind::Remove, None)
            | (PatchOperationKind::Add | PatchOperationKind::Replace, Some(_)) => Ok(()),
        }
    }
}

/// A canonical semantic patch proposal. The base digests fence the exact flag
/// read; target digests describe the desired public flag configuration without
/// serializing targeting rules or user attributes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticPatch {
    pub base_flag_version: u64,
    pub base_variation_digest: Digest,
    pub base_targeting_digest: Digest,
    pub target_variation_digest: Digest,
    pub target_targeting_digest: Digest,
    pub operations: Vec<SemanticPatchOperation>,
    pub patch_digest: Digest,
}

impl SemanticPatch {
    pub fn new(
        base_flag_version: u64,
        base_variation_digest: Digest,
        base_targeting_digest: Digest,
        target_variation_digest: Digest,
        target_targeting_digest: Digest,
        operations: Vec<SemanticPatchOperation>,
    ) -> Result<Self, FeatureReleaseError> {
        let patch = Self {
            base_flag_version,
            base_variation_digest,
            base_targeting_digest,
            target_variation_digest,
            target_targeting_digest,
            operations,
            patch_digest: Digest::from_text("pending"),
        };
        if patch.base_flag_version == 0
            || !valid_digest(&patch.base_variation_digest)
            || !valid_digest(&patch.base_targeting_digest)
            || !valid_digest(&patch.target_variation_digest)
            || !valid_digest(&patch.target_targeting_digest)
            || patch.operations.is_empty()
            || patch.operations.len() > 32
        {
            return Err(FeatureReleaseError::InvalidSemanticPatch);
        }
        Ok(Self {
            patch_digest: Digest::from_serialized(&patch),
            ..patch
        })
    }

    pub fn validate_against(
        &self,
        scope: &FeatureReleaseScope,
        flag: &FlagSnapshot,
    ) -> Result<(), FeatureReleaseError> {
        self.validate_digest()?;
        if self.base_flag_version != scope.flag_version {
            return Err(FeatureReleaseError::VersionDrift {
                expected: scope.flag_version,
                actual: self.base_flag_version,
            });
        }
        if flag.flag_version != scope.flag_version {
            return Err(FeatureReleaseError::VersionDrift {
                expected: scope.flag_version,
                actual: flag.flag_version,
            });
        }
        if self.base_variation_digest != flag.variation_digest
            || self.base_targeting_digest != flag.targeting_digest
        {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        for operation in &self.operations {
            operation.validate(scope)?;
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), FeatureReleaseError> {
        if !valid_digest(&self.patch_digest)
            || Digest::from_serialized(&Self {
                patch_digest: Digest::from_text("pending"),
                ..self.clone()
            }) != self.patch_digest
        {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunValidationStatus {
    Valid,
    Rejected,
    Unknown,
}

/// Dry-run evidence is validation-only and cannot be converted into a write
/// receipt. The provider transport has no dry-run mutation operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DryRunEvidence {
    pub status: DryRunValidationStatus,
    pub scope_digest: Digest,
    pub base_flag_version: u64,
    pub patch_digest: Digest,
    pub validation_digest: Digest,
    pub claims: EvidenceClaims,
}

impl DryRunEvidence {
    pub fn local_valid(
        scope: &FeatureReleaseScope,
        flag: &FlagSnapshot,
        patch: &SemanticPatch,
    ) -> Result<Self, FeatureReleaseError> {
        patch.validate_against(scope, flag)?;
        let validation_body = (
            &scope.scope_digest(),
            &patch.patch_digest,
            &flag.semantic_digest,
        );
        Ok(Self {
            status: DryRunValidationStatus::Valid,
            scope_digest: scope.scope_digest(),
            base_flag_version: flag.flag_version,
            patch_digest: patch.patch_digest.clone(),
            validation_digest: Digest::from_serialized(&validation_body),
            claims: EvidenceClaims::layer_one(),
        })
    }

    pub fn rejected(
        scope: &FeatureReleaseScope,
        patch: &SemanticPatch,
        reason: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            status: DryRunValidationStatus::Rejected,
            scope_digest: scope.scope_digest(),
            base_flag_version: patch.base_flag_version,
            patch_digest: patch.patch_digest.clone(),
            validation_digest: Digest::from_bytes(reason.as_ref()),
            claims: EvidenceClaims::layer_one(),
        }
    }

    pub fn validate_for(
        &self,
        scope: &FeatureReleaseScope,
        flag: &FlagSnapshot,
        patch: &SemanticPatch,
    ) -> Result<(), FeatureReleaseError> {
        self.claims.validate()?;
        if self.scope_digest != scope.scope_digest()
            || self.base_flag_version != flag.flag_version
            || self.patch_digest != patch.patch_digest
        {
            return Err(FeatureReleaseError::DryRunMismatch);
        }
        match self.status {
            DryRunValidationStatus::Valid => {
                let expected = Digest::from_serialized(&(
                    scope.scope_digest(),
                    &patch.patch_digest,
                    &flag.semantic_digest,
                ));
                if self.validation_digest != expected {
                    return Err(FeatureReleaseError::DryRunMismatch);
                }
                Ok(())
            }
            DryRunValidationStatus::Rejected => Err(FeatureReleaseError::DryRunRejected),
            DryRunValidationStatus::Unknown => Err(FeatureReleaseError::DryRunUnknown),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailability {
    Complete,
    ProviderUnknown,
    BlockedEnv,
}

/// Bounded provider evidence used as the input to proposal compilation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseReadEvidence {
    pub availability: EvidenceAvailability,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub flag: Option<FlagSnapshot>,
    pub approvals: Vec<ApprovalEvidence>,
    pub audit_entries: Vec<AuditEvidence>,
    pub audit_limit: u8,
    pub provider_code_digest: Option<Digest>,
    pub provenance: TransportProvenance,
    pub retry_summary: RetrySummary,
    pub claims: EvidenceClaims,
    pub evidence_digest: Digest,
}

impl ReleaseReadEvidence {
    fn complete(
        scope: &FeatureReleaseScope,
        registration_digest: Digest,
        flag: FlagSnapshot,
        approvals: Vec<ApprovalEvidence>,
        audit_entries: Vec<AuditEvidence>,
        provenance: TransportProvenance,
        retry_summary: RetrySummary,
    ) -> Result<Self, FeatureReleaseError> {
        ensure_complete_provenance(provenance)?;
        if approvals.len() > usize::from(MAX_APPROVAL_ENTRIES)
            || audit_entries.len() > usize::from(MAX_AUDIT_ENTRIES)
        {
            return Err(FeatureReleaseError::AuditUnbounded);
        }
        flag.validate_for_scope(scope)?;
        for approval in &approvals {
            approval.validate_for_scope(scope)?;
        }
        for audit in &audit_entries {
            audit.validate_for_scope(scope)?;
        }
        ensure_unique_approvals(&approvals)?;
        ensure_unique_audits(&audit_entries)?;
        let mut evidence = Self {
            availability: EvidenceAvailability::Complete,
            scope_digest: scope.scope_digest(),
            registration_digest,
            flag: Some(flag),
            approvals,
            audit_entries,
            audit_limit: MAX_AUDIT_ENTRIES,
            provider_code_digest: None,
            provenance,
            retry_summary,
            claims: EvidenceClaims::layer_one(),
            evidence_digest: Digest::from_text("pending"),
        };
        let evidence_digest = Digest::from_serialized(&evidence_without_digest(&evidence));
        evidence.evidence_digest = evidence_digest;
        Ok(evidence)
    }

    pub fn provider_unknown(scope: &FeatureReleaseScope, code: impl AsRef<[u8]>) -> Self {
        Self::unavailable(
            scope,
            EvidenceAvailability::ProviderUnknown,
            Digest::from_text("unavailable"),
            code,
            TransportProvenance::Recording,
        )
    }

    pub fn blocked_env(scope: &FeatureReleaseScope, code: impl AsRef<[u8]>) -> Self {
        Self::unavailable(
            scope,
            EvidenceAvailability::BlockedEnv,
            Digest::from_text("unavailable"),
            code,
            TransportProvenance::BlockedEnv,
        )
    }

    pub fn provider_unknown_for_registration(
        scope: &FeatureReleaseScope,
        registration_digest: Digest,
        code: impl AsRef<[u8]>,
    ) -> Self {
        Self::unavailable(
            scope,
            EvidenceAvailability::ProviderUnknown,
            registration_digest,
            code,
            TransportProvenance::Recording,
        )
    }

    pub fn blocked_env_for_registration(
        scope: &FeatureReleaseScope,
        registration_digest: Digest,
        code: impl AsRef<[u8]>,
    ) -> Self {
        Self::unavailable(
            scope,
            EvidenceAvailability::BlockedEnv,
            registration_digest,
            code,
            TransportProvenance::BlockedEnv,
        )
    }

    fn unavailable(
        scope: &FeatureReleaseScope,
        availability: EvidenceAvailability,
        registration_digest: Digest,
        code: impl AsRef<[u8]>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = Self {
            availability,
            scope_digest: scope.scope_digest(),
            registration_digest,
            flag: None,
            approvals: Vec::new(),
            audit_entries: Vec::new(),
            audit_limit: MAX_AUDIT_ENTRIES,
            provider_code_digest: Some(Digest::from_bytes(code.as_ref())),
            provenance,
            retry_summary: RetrySummary::new(RetryPolicy::default(), 0, 0, 0),
            claims: EvidenceClaims::layer_one(),
            evidence_digest: Digest::from_text("pending"),
        };
        let evidence_digest = Digest::from_serialized(&evidence_without_digest(&evidence));
        evidence.evidence_digest = evidence_digest;
        evidence
    }

    fn validate_fence(
        &self,
        scope: &FeatureReleaseScope,
        registration_digest: &Digest,
    ) -> Result<(), FeatureReleaseError> {
        self.claims.validate()?;
        if self.scope_digest != scope.scope_digest()
            || self.registration_digest != *registration_digest
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        if self.evidence_digest != Digest::from_serialized(&evidence_without_digest(self)) {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        match self.availability {
            EvidenceAvailability::Complete => {
                ensure_complete_provenance(self.provenance)?;
                let flag = self
                    .flag
                    .as_ref()
                    .ok_or(FeatureReleaseError::ProviderUnknown)?;
                flag.validate_for_scope(scope)?;
                if flag.flag_version != scope.flag_version {
                    return Err(FeatureReleaseError::VersionDrift {
                        expected: scope.flag_version,
                        actual: flag.flag_version,
                    });
                }
                ensure_unique_approvals(&self.approvals)?;
                ensure_unique_audits(&self.audit_entries)?;
                for approval in &self.approvals {
                    approval.validate_for_scope(scope)?;
                }
                for audit in &self.audit_entries {
                    audit.validate_for_scope(scope)?;
                }
                Ok(())
            }
            EvidenceAvailability::ProviderUnknown => Err(FeatureReleaseError::ProviderUnknown),
            EvidenceAvailability::BlockedEnv => Err(FeatureReleaseError::BlockedEnv),
        }
    }
}

fn ensure_complete_provenance(provenance: TransportProvenance) -> Result<(), FeatureReleaseError> {
    match provenance {
        TransportProvenance::Recording | TransportProvenance::Loopback => Ok(()),
        TransportProvenance::Fixture | TransportProvenance::BlockedEnv => {
            Err(FeatureReleaseError::ProvenanceForbidden)
        }
    }
}

fn ensure_unique_approvals(approvals: &[ApprovalEvidence]) -> Result<(), FeatureReleaseError> {
    let mut ids = BTreeSet::new();
    if approvals
        .iter()
        .any(|approval| !ids.insert(&approval.request_id))
    {
        return Err(FeatureReleaseError::ApprovalConflict);
    }
    Ok(())
}

fn ensure_unique_audits(audits: &[AuditEvidence]) -> Result<(), FeatureReleaseError> {
    let mut ids = BTreeSet::new();
    if audits.iter().any(|audit| !ids.insert(&audit.entry_id)) {
        return Err(FeatureReleaseError::AuditDuplicate);
    }
    Ok(())
}

fn evidence_without_digest(evidence: &ReleaseReadEvidence) -> impl Serialize + '_ {
    (
        &evidence.availability,
        &evidence.scope_digest,
        &evidence.registration_digest,
        &evidence.flag,
        &evidence.approvals,
        &evidence.audit_entries,
        &evidence.audit_limit,
        &evidence.provider_code_digest,
        &evidence.provenance,
        &evidence.retry_summary,
        &evidence.claims,
    )
}

/// A Mission-bound request to compile one semantic patch proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureReleaseProposalRequest {
    pub scope_digest: Digest,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub patch: SemanticPatch,
    pub dry_run: bool,
    pub request_digest: Digest,
}

impl FeatureReleaseProposalRequest {
    pub fn for_scope(
        scope: &FeatureReleaseScope,
        patch: SemanticPatch,
        dry_run: bool,
    ) -> Result<Self, FeatureReleaseError> {
        let request = Self {
            scope_digest: scope.scope_digest(),
            mission_id: scope.mission_id.clone(),
            project_id: scope.project_id.clone(),
            work_product_id: scope.work_product_id.clone(),
            consent_revision: scope.consent_revision,
            policy_revision: scope.policy_revision,
            patch,
            dry_run,
            request_digest: Digest::from_text("pending"),
        };
        let request_digest = Digest::from_serialized(&request_without_digest(&request));
        let request = Self {
            request_digest,
            ..request
        };
        request.validate(scope)?;
        Ok(request)
    }

    pub fn validate(&self, scope: &FeatureReleaseScope) -> Result<(), FeatureReleaseError> {
        if self.scope_digest != scope.scope_digest()
            || self.mission_id != scope.mission_id
            || self.project_id != scope.project_id
            || self.work_product_id != scope.work_product_id
            || self.consent_revision != scope.consent_revision
            || self.policy_revision != scope.policy_revision
            || !valid_digest(&self.request_digest)
            || self.request_digest != Digest::from_serialized(&request_without_digest(self))
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        Ok(())
    }
}

fn request_without_digest(request: &FeatureReleaseProposalRequest) -> impl Serialize + '_ {
    (
        &request.scope_digest,
        &request.mission_id,
        &request.project_id,
        &request.work_product_id,
        &request.consent_revision,
        &request.policy_revision,
        &request.patch,
        &request.dry_run,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Pending,
    Approved,
    Declined,
    Conflicted,
    Stale,
    Applied,
    Failed,
    Scheduled,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalBlockedReason {
    ApprovalPending,
    ApprovalDeclined,
    ApprovalConflict,
    ApprovalStale,
    AuditNotApplied,
    DryRunOnly,
    VersionDrift,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditFence {
    pub entry_count: u8,
    pub entry_ids: Vec<String>,
    pub entry_digests: Vec<Digest>,
    pub bounded: bool,
}

impl AuditFence {
    fn from_entries(entries: &[AuditEvidence]) -> Result<Self, FeatureReleaseError> {
        ensure_unique_audits(entries)?;
        if entries.len() > usize::from(MAX_AUDIT_ENTRIES) {
            return Err(FeatureReleaseError::AuditUnbounded);
        }
        Ok(Self {
            entry_count: u8::try_from(entries.len()).expect("audit fence is bounded"),
            entry_ids: entries.iter().map(|entry| entry.entry_id.clone()).collect(),
            entry_digests: entries.iter().map(AuditEvidence::fingerprint).collect(),
            bounded: true,
        })
    }
}

/// Mission-adoptable result proposal. This is an observation/proposal seam;
/// it is not a kernel receipt or outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureReleaseResultProposal {
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_fence: Option<FeatureReleaseProviderFence>,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub patch: SemanticPatch,
    pub base_flag: Option<FlagSnapshot>,
    pub base_flag_version: u64,
    pub dry_run: bool,
    pub dry_run_evidence: DryRunEvidence,
    pub approval_status: Option<ApprovalStatus>,
    pub approval: Option<ApprovalEvidence>,
    pub audit_fence: AuditFence,
    pub status: ReleaseStatus,
    pub blocked_reason: Option<ProposalBlockedReason>,
    pub recordable: bool,
    pub provenance: TransportProvenance,
    pub claims: EvidenceClaims,
}

impl FeatureReleaseResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &FeatureReleaseProposalRequest,
        registration_digest: &Digest,
        flag: FlagSnapshot,
        dry_run_evidence: DryRunEvidence,
        approval_status: Option<ApprovalStatus>,
        approval: Option<ApprovalEvidence>,
        audit_fence: AuditFence,
        status: ReleaseStatus,
        blocked_reason: Option<ProposalBlockedReason>,
        provenance: TransportProvenance,
    ) -> Self {
        let provider_fence = FeatureReleaseProviderFence::from_flag(
            &flag,
            request.scope_digest.clone(),
            registration_digest.clone(),
        );
        let proposal = Self {
            proposal_digest: Digest::from_text("pending"),
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            registration_digest: registration_digest.clone(),
            provider_fence: Some(provider_fence),
            mission_id: request.mission_id.clone(),
            project_id: request.project_id.clone(),
            work_product_id: request.work_product_id.clone(),
            consent_revision: request.consent_revision,
            policy_revision: request.policy_revision,
            patch: request.patch.clone(),
            base_flag_version: flag.flag_version,
            base_flag: Some(flag),
            dry_run: request.dry_run,
            dry_run_evidence,
            approval_status,
            approval,
            audit_fence,
            status,
            blocked_reason,
            recordable: !request.dry_run
                && matches!(status, ReleaseStatus::Approved)
                && matches!(
                    provenance,
                    TransportProvenance::Recording | TransportProvenance::Loopback
                ),
            provenance,
            claims: EvidenceClaims::layer_one(),
        };
        let proposal_digest = Digest::from_serialized(&proposal_without_digest(&proposal));
        Self {
            proposal_digest,
            ..proposal
        }
    }

    fn unavailable(
        request: &FeatureReleaseProposalRequest,
        registration_digest: &Digest,
        dry_run_evidence: DryRunEvidence,
        availability: EvidenceAvailability,
        provenance: TransportProvenance,
    ) -> Result<Self, FeatureReleaseError> {
        let (status, blocked_reason) = match availability {
            EvidenceAvailability::ProviderUnknown => (
                ReleaseStatus::ProviderUnknown,
                Some(ProposalBlockedReason::ProviderUnknown),
            ),
            EvidenceAvailability::BlockedEnv => (
                ReleaseStatus::BlockedEnv,
                Some(ProposalBlockedReason::BlockedEnv),
            ),
            EvidenceAvailability::Complete => {
                return Err(FeatureReleaseError::InvalidInput(
                    "complete evidence has no missing flag".into(),
                ));
            }
        };
        let proposal = Self {
            proposal_digest: Digest::from_text("pending"),
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            registration_digest: registration_digest.clone(),
            provider_fence: None,
            mission_id: request.mission_id.clone(),
            project_id: request.project_id.clone(),
            work_product_id: request.work_product_id.clone(),
            consent_revision: request.consent_revision,
            policy_revision: request.policy_revision,
            patch: request.patch.clone(),
            base_flag: None,
            base_flag_version: request.patch.base_flag_version,
            dry_run: request.dry_run,
            dry_run_evidence,
            approval_status: None,
            approval: None,
            audit_fence: AuditFence {
                entry_count: 0,
                entry_ids: Vec::new(),
                entry_digests: Vec::new(),
                bounded: true,
            },
            status,
            blocked_reason,
            recordable: false,
            provenance,
            claims: EvidenceClaims::layer_one(),
        };
        let proposal_digest = Digest::from_serialized(&proposal_without_digest(&proposal));
        Ok(Self {
            proposal_digest,
            ..proposal
        })
    }

    fn validate_digest(&self) -> Result<(), FeatureReleaseError> {
        self.claims.validate()?;
        self.patch.validate_digest()?;
        if let Some(fence) = &self.provider_fence
            && (fence.provider_id != PROVIDER_ID
                || fence.flag_version == 0
                || !valid_digest(&fence.scope_digest)
                || !valid_digest(&fence.registration_digest))
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        if matches!(
            self.provenance,
            TransportProvenance::Fixture | TransportProvenance::BlockedEnv
        ) && (self.recordable || self.status == ReleaseStatus::Approved)
        {
            return Err(FeatureReleaseError::ProvenanceForbidden);
        }
        let expected_recordable = !self.dry_run
            && self.status == ReleaseStatus::Approved
            && matches!(
                self.provenance,
                TransportProvenance::Recording | TransportProvenance::Loopback
            );
        if self.recordable != expected_recordable {
            return Err(FeatureReleaseError::ProvenanceForbidden);
        }
        if let Some(approval) = &self.approval {
            approval.validate()?;
        }
        if !valid_digest(&self.proposal_digest)
            || self.proposal_digest != Digest::from_serialized(&proposal_without_digest(self))
        {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        Ok(())
    }
}

fn proposal_without_digest(proposal: &FeatureReleaseResultProposal) -> serde_json::Value {
    serde_json::json!({
        "requestDigest": &proposal.request_digest,
        "scopeDigest": &proposal.scope_digest,
        "registrationDigest": &proposal.registration_digest,
        "providerFence": &proposal.provider_fence,
        "missionId": &proposal.mission_id,
        "projectId": &proposal.project_id,
        "workProductId": &proposal.work_product_id,
        "consentRevision": &proposal.consent_revision,
        "policyRevision": &proposal.policy_revision,
        "patch": &proposal.patch,
        "baseFlag": &proposal.base_flag,
        "baseFlagVersion": &proposal.base_flag_version,
        "dryRun": &proposal.dry_run,
        "dryRunEvidence": &proposal.dry_run_evidence,
        "approvalStatus": &proposal.approval_status,
        "approval": &proposal.approval,
        "auditFence": &proposal.audit_fence,
        "status": &proposal.status,
        "blockedReason": &proposal.blocked_reason,
        "recordable": &proposal.recordable,
        "provenance": &proposal.provenance,
        "claims": &proposal.claims
    })
}

/// Exact post-change read-back evidence. Constructing this type does not
/// mutate LaunchDarkly and does not assert a native provider receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseReadBack {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_fence: FeatureReleaseProviderFence,
    pub flag: FlagSnapshot,
    pub audit_entries: Vec<AuditEvidence>,
    pub provenance: TransportProvenance,
    pub claims: EvidenceClaims,
    pub readback_digest: Digest,
}

impl ReleaseReadBack {
    pub fn new(
        scope: &FeatureReleaseScope,
        registration_digest: Digest,
        flag: FlagSnapshot,
        audit_entries: Vec<AuditEvidence>,
        provenance: TransportProvenance,
    ) -> Result<Self, FeatureReleaseError> {
        if matches!(
            provenance,
            TransportProvenance::Fixture | TransportProvenance::BlockedEnv
        ) {
            return Err(FeatureReleaseError::ProvenanceForbidden);
        }
        flag.validate_for_scope(scope)?;
        if audit_entries.is_empty() || audit_entries.len() > usize::from(MAX_AUDIT_ENTRIES) {
            return Err(FeatureReleaseError::AuditMissing);
        }
        for audit in &audit_entries {
            audit.validate_for_scope(scope)?;
        }
        ensure_unique_audits(&audit_entries)?;
        let provider_fence = FeatureReleaseProviderFence::from_flag(
            &flag,
            scope.scope_digest(),
            registration_digest.clone(),
        );
        let mut readback = Self {
            scope_digest: scope.scope_digest(),
            registration_digest,
            provider_fence,
            flag,
            audit_entries,
            provenance,
            claims: EvidenceClaims::layer_one(),
            readback_digest: Digest::from_text("pending"),
        };
        let readback_digest = Digest::from_serialized(&readback_without_digest(&readback));
        readback.readback_digest = readback_digest;
        Ok(readback)
    }

    fn validate_fence(
        &self,
        scope: &FeatureReleaseScope,
        registration_digest: &Digest,
    ) -> Result<(), FeatureReleaseError> {
        self.claims.validate()?;
        if self.scope_digest != scope.scope_digest()
            || self.registration_digest != *registration_digest
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        if matches!(
            self.provenance,
            TransportProvenance::Fixture | TransportProvenance::BlockedEnv
        ) {
            return Err(FeatureReleaseError::ProvenanceForbidden);
        }
        if self.readback_digest != Digest::from_serialized(&readback_without_digest(self)) {
            return Err(FeatureReleaseError::InvalidDigest);
        }
        self.flag.validate_for_scope(scope)?;
        self.provider_fence.validate_for_scope(
            scope,
            registration_digest,
            Some(self.flag.flag_version),
        )?;
        for audit in &self.audit_entries {
            audit.validate_for_scope(scope)?;
        }
        ensure_unique_audits(&self.audit_entries)
    }
}

fn readback_without_digest(readback: &ReleaseReadBack) -> impl Serialize + '_ {
    (
        &readback.scope_digest,
        &readback.registration_digest,
        &readback.provider_fence,
        &readback.flag,
        &readback.audit_entries,
        &readback.provenance,
        &readback.claims,
    )
}

/// Recording-only durable receipt. `write_effect` is always false; this type
/// records exact read-back evidence supplied by a caller and never comes from
/// a write operation in this crate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub approval_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_fence: FeatureReleaseProviderFence,
    pub before_flag_version: u64,
    pub after_flag_version: u64,
    pub after_flag_digest: Digest,
    pub audit_entry_id: String,
    pub audit_entry_digest: Digest,
    pub observed_at: u64,
    pub recording_only: bool,
    pub write_effect: bool,
    pub provenance: TransportProvenance,
    pub claims: EvidenceClaims,
}

impl ReleaseReceipt {
    fn new(
        proposal: &FeatureReleaseResultProposal,
        readback: &ReleaseReadBack,
        audit: &AuditEvidence,
    ) -> Result<Self, FeatureReleaseError> {
        let approval_digest = proposal
            .approval
            .as_ref()
            .map(|approval| approval.evidence_digest.clone())
            .ok_or(FeatureReleaseError::ApprovalNotApproved)?;
        let receipt = Self {
            receipt_digest: Digest::from_text("pending"),
            proposal_digest: proposal.proposal_digest.clone(),
            approval_digest,
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_fence: readback.provider_fence.clone(),
            before_flag_version: proposal.base_flag_version,
            after_flag_version: readback.flag.flag_version,
            after_flag_digest: readback.flag.fingerprint(),
            audit_entry_id: audit.entry_id.clone(),
            audit_entry_digest: audit.fingerprint(),
            observed_at: readback.flag.observed_at,
            recording_only: true,
            write_effect: false,
            provenance: readback.provenance,
            claims: EvidenceClaims::layer_one(),
        };
        let receipt_digest = Digest::from_serialized(&release_receipt_without_digest(&receipt));
        Ok(Self {
            receipt_digest,
            ..receipt
        })
    }

    fn validate(&self) -> Result<(), FeatureReleaseError> {
        self.claims.validate()?;
        if !self.recording_only
            || self.write_effect
            || self.before_flag_version >= self.after_flag_version
        {
            return Err(FeatureReleaseError::ReceiptTampered);
        }
        if matches!(
            self.provenance,
            TransportProvenance::Fixture | TransportProvenance::BlockedEnv
        ) {
            return Err(FeatureReleaseError::ProvenanceForbidden);
        }
        if self.provider_fence.provider_id != PROVIDER_ID
            || self.provider_fence.flag_version != self.after_flag_version
            || self.provider_fence.registration_digest != self.registration_digest
            || self.provider_fence.scope_digest != self.scope_digest
        {
            return Err(FeatureReleaseError::ReceiptTampered);
        }
        if !valid_digest(&self.approval_digest) {
            return Err(FeatureReleaseError::ReceiptTampered);
        }
        if !valid_digest(&self.receipt_digest)
            || self.receipt_digest != Digest::from_serialized(&release_receipt_without_digest(self))
        {
            return Err(FeatureReleaseError::ReceiptTampered);
        }
        Ok(())
    }
}

fn release_receipt_without_digest(receipt: &ReleaseReceipt) -> impl Serialize + '_ {
    (
        &receipt.proposal_digest,
        &receipt.approval_digest,
        &receipt.scope_digest,
        &receipt.registration_digest,
        &receipt.provider_fence,
        &receipt.before_flag_version,
        &receipt.after_flag_version,
        &receipt.after_flag_digest,
        &receipt.audit_entry_id,
        &receipt.audit_entry_digest,
        &receipt.observed_at,
        &receipt.recording_only,
        &receipt.write_effect,
        &receipt.provenance,
        &receipt.claims,
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedReleaseResult {
    pub verified: bool,
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub readback_digest: Digest,
    pub status: ReleaseStatus,
    pub claims: EvidenceClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOperation {
    DescribeRelease,
    ReadFlagEvidence,
    CompileReleaseProposal,
    RecordReleaseReceipt,
    VerifyReleaseResult,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMode {
    ReadProposalRecord,
}

/// Typed service definition used by registration and inspection. It is not a
/// catalog entry and is owned by the service instance that registers it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct FeatureReleaseServiceDefinition {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub operations: Vec<CapabilityOperation>,
    pub mode: ServiceMode,
    pub effect_authority: bool,
    pub consent_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub native_evidence: bool,
}

impl FeatureReleaseServiceDefinition {
    pub fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID.into(),
            provider_id: PROVIDER_ID.into(),
            consumer_id: CONSUMER_ID.into(),
            plugin_id: PLUGIN_ID.into(),
            plugin_version: PluginVersion::new(1, 0, 0),
            contract_version: CONTRACT_VERSION.into(),
            contract_digest: contract_digest(),
            operations: vec![
                CapabilityOperation::DescribeRelease,
                CapabilityOperation::ReadFlagEvidence,
                CapabilityOperation::CompileReleaseProposal,
                CapabilityOperation::RecordReleaseReceipt,
                CapabilityOperation::VerifyReleaseResult,
            ],
            mode: ServiceMode::ReadProposalRecord,
            effect_authority: false,
            consent_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            native_evidence: false,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContractCapabilityPayload {
    service_id: String,
    provider_id: String,
    consumer_id: String,
    operations: Vec<CapabilityOperation>,
    mode: ServiceMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContractEvidencePayload {
    flag: FlagSnapshot,
    approval: Vec<ApprovalEvidence>,
    audit: Vec<AuditEvidence>,
    claims: EvidenceClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContractBoundariesPayload {
    forbidden_operations: Vec<String>,
    forbidden_authorities: Vec<String>,
    blocked_environment_status: String,
    audit_description: String,
    targeting: String,
    secret_material: String,
}

/// Canonical payload validated against the versioned JSON Schema. This is the
/// executable schema/serde seam; a typed Rust value is not accepted merely
/// because its individual fields happen to deserialize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureReleaseContractPayload {
    schema_version: String,
    capability: ContractCapabilityPayload,
    scope: FeatureReleaseScope,
    registration: RegistrationReceipt,
    evidence: ContractEvidencePayload,
    boundaries: ContractBoundariesPayload,
}

impl FeatureReleaseContractPayload {
    pub fn from_evidence(
        scope: &FeatureReleaseScope,
        registration: &RegistrationReceipt,
        evidence: &ReleaseReadEvidence,
    ) -> Result<Self, FeatureReleaseError> {
        registration.validate_digest()?;
        if registration.contract_digest != contract_digest()
            || registration.scope_digest != scope.scope_digest()
            || registration.lifecycle != RegistrationLifecycle::Active
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        evidence.claims.validate()?;
        if evidence.availability != EvidenceAvailability::Complete
            || evidence.scope_digest != scope.scope_digest()
            || evidence.registration_digest != registration.registration_digest
            || evidence.evidence_digest
                != Digest::from_serialized(&evidence_without_digest(evidence))
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        ensure_complete_provenance(evidence.provenance)?;
        let flag = evidence
            .flag
            .clone()
            .ok_or(FeatureReleaseError::ProviderUnknown)?;
        flag.validate_for_scope(scope)?;
        for approval in &evidence.approvals {
            approval.validate_for_scope(scope)?;
        }
        for audit in &evidence.audit_entries {
            audit.validate_for_scope(scope)?;
        }
        ensure_unique_approvals(&evidence.approvals)?;
        ensure_unique_audits(&evidence.audit_entries)?;
        let payload = Self {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            capability: ContractCapabilityPayload {
                service_id: SERVICE_ID.into(),
                provider_id: PROVIDER_ID.into(),
                consumer_id: CONSUMER_ID.into(),
                operations: vec![
                    CapabilityOperation::DescribeRelease,
                    CapabilityOperation::ReadFlagEvidence,
                    CapabilityOperation::CompileReleaseProposal,
                    CapabilityOperation::RecordReleaseReceipt,
                    CapabilityOperation::VerifyReleaseResult,
                ],
                mode: ServiceMode::ReadProposalRecord,
            },
            scope: scope.clone(),
            registration: registration.clone(),
            evidence: ContractEvidencePayload {
                flag,
                approval: evidence.approvals.clone(),
                audit: evidence.audit_entries.clone(),
                claims: evidence.claims,
            },
            boundaries: ContractBoundariesPayload {
                forbidden_operations: vec![
                    "patch_flag".into(),
                    "toggle_flag".into(),
                    "create_flag".into(),
                    "delete_flag".into(),
                    "create_approval".into(),
                    "review_approval".into(),
                    "apply_approval".into(),
                    "schedule_change".into(),
                    "evaluate_context".into(),
                    "ingest_event".into(),
                ],
                forbidden_authorities: [
                    "Truth",
                    "Consent",
                    "Effect",
                    "Receipt",
                    "Verification",
                    "Outcome",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                blocked_environment_status: "BLOCKED_ENV".into(),
                audit_description: "digest_only_bounded".into(),
                targeting: "digest_only_no_context_attributes".into(),
                secret_material: "never_serialized".into(),
            },
        };
        payload.validate_schema()?;
        Ok(payload)
    }

    pub fn validate_schema(&self) -> Result<(), FeatureReleaseError> {
        let instance =
            serde_json::to_value(self).map_err(|_| FeatureReleaseError::SchemaValidation)?;
        validate_contract_json(&instance)
    }
}

pub fn validate_contract_json(instance: &serde_json::Value) -> Result<(), FeatureReleaseError> {
    let schema = serde_json::from_str::<serde_json::Value>(CONTRACT_SCHEMA)
        .map_err(|_| FeatureReleaseError::SchemaValidation)?;
    let validator: Validator =
        jsonschema::validator_for(&schema).map_err(|_| FeatureReleaseError::SchemaValidation)?;
    if validator.validate(instance).is_err() {
        return Err(FeatureReleaseError::SchemaValidation);
    }
    Ok(())
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_SCHEMA.as_bytes())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationLifecycle {
    Active,
    Revoked,
    Unregistered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_digest: Digest,
    pub adapter_revision: String,
    pub api_revision: String,
    pub service_definition_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub secret_reference_digest: Digest,
    pub approval_policy_revision: u64,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub lifecycle: RegistrationLifecycle,
    pub registration_digest: Digest,
}

impl RegistrationReceipt {
    fn validate_digest(&self) -> Result<(), FeatureReleaseError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PluginVersion::new(1, 0, 0)
            || !valid_digest(&self.contract_digest)
            || !valid_bounded_text(&self.adapter_revision)
            || !valid_bounded_text(&self.api_revision)
            || !valid_digest(&self.service_definition_digest)
            || !valid_digest(&self.permission_snapshot_digest)
            || !valid_digest(&self.secret_reference_digest)
            || !valid_revision(self.approval_policy_revision)
            || !valid_digest(&self.scope_digest)
            || !valid_revision(self.registration_revision)
            || !valid_digest(&self.registration_digest)
            || self.registration_digest
                != Digest::from_serialized(&registration_receipt_without_digest(self))
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FeatureReleaseRegistration {
    scope_digest: Digest,
    plugin_version: PluginVersion,
    contract_digest: Digest,
    adapter_revision: String,
    api_revision: String,
    service_definition_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    secret_reference_digest: Digest,
    registration_revision: u64,
    lifecycle: RegistrationLifecycle,
    receipt: RegistrationReceipt,
}

impl FeatureReleaseRegistration {
    pub fn new(
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
        plugin_version: PluginVersion,
        adapter_revision: impl Into<String>,
        api_revision: impl Into<String>,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self, FeatureReleaseError> {
        scope.validate()?;
        secret_reference.validate()?;
        if secret_reference.is_revoked() {
            return Err(FeatureReleaseError::SecretReferenceRevoked);
        }
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(FeatureReleaseError::SecretReferenceScopeMismatch);
        }
        permission_snapshot.validate_for_scope(scope)?;
        let adapter_revision = adapter_revision.into();
        let api_revision = api_revision.into();
        if !valid_bounded_text(&adapter_revision) || !valid_bounded_text(&api_revision) {
            return Err(FeatureReleaseError::InvalidInput(
                "adapter and API revisions must be bounded single-line text".into(),
            ));
        }
        let definition = FeatureReleaseServiceDefinition::layer_one();
        if plugin_version != definition.plugin_version {
            return Err(FeatureReleaseError::InvalidInput(
                "unsupported plugin version".into(),
            ));
        }
        let registration = Self {
            scope_digest: scope.scope_digest(),
            plugin_version,
            contract_digest: definition.contract_digest.clone(),
            adapter_revision,
            api_revision,
            service_definition_digest: definition.digest(),
            permission_snapshot,
            secret_reference_digest: secret_reference.reference_digest(),
            registration_revision: 1,
            lifecycle: RegistrationLifecycle::Active,
            receipt: RegistrationReceipt {
                plugin_id: PLUGIN_ID.into(),
                plugin_version,
                contract_digest: definition.contract_digest,
                adapter_revision: String::new(),
                api_revision: String::new(),
                service_definition_digest: Digest::from_text("pending"),
                permission_snapshot_digest: Digest::from_text("pending"),
                secret_reference_digest: Digest::from_text("pending"),
                approval_policy_revision: scope.policy_revision,
                scope_digest: scope.scope_digest(),
                registration_revision: 1,
                lifecycle: RegistrationLifecycle::Active,
                registration_digest: Digest::from_text("pending"),
            },
        };
        Ok(registration.with_receipt())
    }

    fn with_receipt(mut self) -> Self {
        self.receipt = self.make_receipt();
        self
    }

    fn make_receipt(&self) -> RegistrationReceipt {
        let mut receipt = RegistrationReceipt {
            plugin_id: PLUGIN_ID.into(),
            plugin_version: self.plugin_version,
            contract_digest: self.contract_digest.clone(),
            adapter_revision: self.adapter_revision.clone(),
            api_revision: self.api_revision.clone(),
            service_definition_digest: self.service_definition_digest.clone(),
            permission_snapshot_digest: self.permission_snapshot.digest(),
            secret_reference_digest: self.secret_reference_digest.clone(),
            approval_policy_revision: self.permission_snapshot.approval_policy_revision,
            scope_digest: self.scope_digest.clone(),
            registration_revision: self.registration_revision,
            lifecycle: self.lifecycle,
            registration_digest: Digest::from_text("pending"),
        };
        let registration_digest =
            Digest::from_serialized(&registration_receipt_without_digest(&receipt));
        receipt.registration_digest = registration_digest;
        receipt
    }

    pub fn receipt(&self) -> &RegistrationReceipt {
        &self.receipt
    }

    pub fn lifecycle(&self) -> RegistrationLifecycle {
        self.lifecycle
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn validate_active(
        &self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<(), FeatureReleaseError> {
        secret_reference.validate()?;
        self.receipt.validate_digest()?;
        match self.lifecycle {
            RegistrationLifecycle::Active => {}
            RegistrationLifecycle::Revoked => return Err(FeatureReleaseError::RegistrationRevoked),
            RegistrationLifecycle::Unregistered => {
                return Err(FeatureReleaseError::RegistrationUnregistered);
            }
        }
        if self.scope_digest != scope.scope_digest()
            || secret_reference.scope_digest() != &scope.scope_digest()
            || secret_reference.is_revoked()
            || secret_reference.reference_digest() != self.secret_reference_digest
            || self.receipt.lifecycle != RegistrationLifecycle::Active
            || self.receipt.secret_reference_digest != self.secret_reference_digest
            || self.receipt.registration_digest
                != Digest::from_serialized(&registration_receipt_without_digest(&self.receipt))
        {
            return if secret_reference.is_revoked() {
                Err(FeatureReleaseError::SecretReferenceRevoked)
            } else {
                Err(FeatureReleaseError::RegistrationFenceMismatch)
            };
        }
        self.permission_snapshot.validate_for_scope(scope)
    }

    pub fn revoke(&mut self) -> Result<RegistrationReceipt, FeatureReleaseError> {
        if self.lifecycle == RegistrationLifecycle::Revoked {
            return Ok(self.receipt.clone());
        }
        self.lifecycle = RegistrationLifecycle::Revoked;
        self.receipt = self.make_receipt();
        Ok(self.receipt.clone())
    }

    pub fn unregister(&mut self) -> Result<RegistrationReceipt, FeatureReleaseError> {
        if self.lifecycle == RegistrationLifecycle::Unregistered {
            return Ok(self.receipt.clone());
        }
        self.lifecycle = RegistrationLifecycle::Unregistered;
        self.receipt = self.make_receipt();
        Ok(self.receipt.clone())
    }

    pub fn reregister(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<RegistrationReceipt, FeatureReleaseError> {
        secret_reference.validate()?;
        if self.lifecycle == RegistrationLifecycle::Active {
            return Ok(self.receipt.clone());
        }
        if secret_reference.is_revoked() {
            return Err(FeatureReleaseError::SecretReferenceRevoked);
        }
        if self.scope_digest != scope.scope_digest()
            || secret_reference.scope_digest() != &self.scope_digest
            || secret_reference.reference_digest() != self.secret_reference_digest
        {
            return Err(FeatureReleaseError::SecretReferenceScopeMismatch);
        }
        self.permission_snapshot.validate_for_scope(scope)?;
        self.registration_revision =
            self.registration_revision
                .checked_add(1)
                .ok_or(FeatureReleaseError::InvalidInput(
                    "registration revision overflow".into(),
                ))?;
        self.lifecycle = RegistrationLifecycle::Active;
        self.receipt = self.make_receipt();
        Ok(self.receipt.clone())
    }
}

fn registration_receipt_without_digest(receipt: &RegistrationReceipt) -> impl Serialize + '_ {
    (
        &receipt.plugin_id,
        &receipt.plugin_version,
        &receipt.contract_digest,
        &receipt.adapter_revision,
        &receipt.api_revision,
        &receipt.service_definition_digest,
        &receipt.permission_snapshot_digest,
        &receipt.secret_reference_digest,
        &receipt.approval_policy_revision,
        &receipt.scope_digest,
        &receipt.registration_revision,
        &receipt.lifecycle,
    )
}

/// Read-only provider transport. There is intentionally no patch/toggle/write
/// method, and callers receive only an opaque SecretReference.
pub trait LaunchDarklyReleaseTransport {
    fn provenance(&self) -> TransportProvenance;

    fn read_flag(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<FlagSnapshot, TransportError>;

    fn read_approvals(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<Vec<ApprovalEvidence>, TransportError>;

    fn read_audit_log(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
        limit: u8,
    ) -> Result<Vec<AuditEvidence>, TransportError>;
}

fn pop_script<T: Clone>(
    script: &mut VecDeque<Result<T, TransportError>>,
) -> Result<T, TransportError> {
    script
        .pop_front()
        .ok_or_else(|| TransportError::unknown("recording-script-exhausted"))?
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    flag_script: VecDeque<Result<FlagSnapshot, TransportError>>,
    approval_script: VecDeque<Result<Vec<ApprovalEvidence>, TransportError>>,
    audit_script: VecDeque<Result<Vec<AuditEvidence>, TransportError>>,
}

impl RecordingTransport {
    pub fn new(
        flag: FlagSnapshot,
        approvals: Vec<ApprovalEvidence>,
        audits: Vec<AuditEvidence>,
    ) -> Self {
        Self::from_results(
            vec![Ok(flag)],
            vec![Ok(approvals)],
            vec![Ok(audits)],
            TransportProvenance::Recording,
        )
    }

    pub fn from_results(
        flag_script: Vec<Result<FlagSnapshot, TransportError>>,
        approval_script: Vec<Result<Vec<ApprovalEvidence>, TransportError>>,
        audit_script: Vec<Result<Vec<AuditEvidence>, TransportError>>,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            provenance,
            flag_script: flag_script.into(),
            approval_script: approval_script.into(),
            audit_script: audit_script.into(),
        }
    }
}

impl LaunchDarklyReleaseTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read_flag(
        &mut self,
        _scope: &FeatureReleaseScope,
        _secret_reference: &SecretReference,
    ) -> Result<FlagSnapshot, TransportError> {
        pop_script(&mut self.flag_script)
    }

    fn read_approvals(
        &mut self,
        _scope: &FeatureReleaseScope,
        _secret_reference: &SecretReference,
    ) -> Result<Vec<ApprovalEvidence>, TransportError> {
        pop_script(&mut self.approval_script)
    }

    fn read_audit_log(
        &mut self,
        _scope: &FeatureReleaseScope,
        _secret_reference: &SecretReference,
        _limit: u8,
    ) -> Result<Vec<AuditEvidence>, TransportError> {
        pop_script(&mut self.audit_script)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport(RecordingTransport);

impl FixtureTransport {
    pub fn new(
        flag: FlagSnapshot,
        approvals: Vec<ApprovalEvidence>,
        audits: Vec<AuditEvidence>,
    ) -> Self {
        Self(RecordingTransport::from_results(
            vec![Ok(flag)],
            vec![Ok(approvals)],
            vec![Ok(audits)],
            TransportProvenance::Fixture,
        ))
    }
}

impl LaunchDarklyReleaseTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.0.provenance()
    }

    fn read_flag(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<FlagSnapshot, TransportError> {
        self.0.read_flag(scope, secret_reference)
    }

    fn read_approvals(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<Vec<ApprovalEvidence>, TransportError> {
        self.0.read_approvals(scope, secret_reference)
    }

    fn read_audit_log(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
        limit: u8,
    ) -> Result<Vec<AuditEvidence>, TransportError> {
        self.0.read_audit_log(scope, secret_reference, limit)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport(RecordingTransport);

impl LoopbackTransport {
    pub fn new(
        flag: FlagSnapshot,
        approvals: Vec<ApprovalEvidence>,
        audits: Vec<AuditEvidence>,
    ) -> Self {
        Self(RecordingTransport::from_results(
            vec![Ok(flag)],
            vec![Ok(approvals)],
            vec![Ok(audits)],
            TransportProvenance::Loopback,
        ))
    }
}

impl LaunchDarklyReleaseTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.0.provenance()
    }

    fn read_flag(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<FlagSnapshot, TransportError> {
        self.0.read_flag(scope, secret_reference)
    }

    fn read_approvals(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
    ) -> Result<Vec<ApprovalEvidence>, TransportError> {
        self.0.read_approvals(scope, secret_reference)
    }

    fn read_audit_log(
        &mut self,
        scope: &FeatureReleaseScope,
        secret_reference: &SecretReference,
        limit: u8,
    ) -> Result<Vec<AuditEvidence>, TransportError> {
        self.0.read_audit_log(scope, secret_reference, limit)
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvTransport {
    code: String,
}

impl BlockedEnvTransport {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: bounded_code(code.into()),
        }
    }

    fn error(&self) -> TransportError {
        TransportError::blocked_env(self.code.clone())
    }
}

impl LaunchDarklyReleaseTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_flag(
        &mut self,
        _scope: &FeatureReleaseScope,
        _secret_reference: &SecretReference,
    ) -> Result<FlagSnapshot, TransportError> {
        Err(self.error())
    }

    fn read_approvals(
        &mut self,
        _scope: &FeatureReleaseScope,
        _secret_reference: &SecretReference,
    ) -> Result<Vec<ApprovalEvidence>, TransportError> {
        Err(self.error())
    }

    fn read_audit_log(
        &mut self,
        _scope: &FeatureReleaseScope,
        _secret_reference: &SecretReference,
        _limit: u8,
    ) -> Result<Vec<AuditEvidence>, TransportError> {
        Err(self.error())
    }
}

/// Provider implementing the typed Layer 1 feature-release service. It owns
/// one exact registration and one read-only transport; no parallel registry is
/// consulted.
pub struct LaunchDarklyReleaseProvider<T> {
    scope: FeatureReleaseScope,
    secret_reference: SecretReference,
    registration: FeatureReleaseRegistration,
    transport: T,
    retry_policy: RetryPolicy,
}

impl<T: LaunchDarklyReleaseTransport> fmt::Debug for LaunchDarklyReleaseProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchDarklyReleaseProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration.receipt())
            .field("transport_provenance", &self.transport.provenance())
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl<T: LaunchDarklyReleaseTransport> LaunchDarklyReleaseProvider<T> {
    pub fn new(
        transport: T,
        scope: FeatureReleaseScope,
        secret_reference: SecretReference,
        plugin_version: PluginVersion,
        adapter_revision: impl Into<String>,
        api_revision: impl Into<String>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, FeatureReleaseError> {
        retry_policy.validate()?;
        let permission_snapshot = PermissionSnapshot::read_only(&scope);
        let registration = FeatureReleaseRegistration::new(
            &scope,
            &secret_reference,
            plugin_version,
            adapter_revision,
            api_revision,
            permission_snapshot,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            registration,
            transport,
            retry_policy,
        })
    }

    pub fn with_defaults(
        transport: T,
        scope: FeatureReleaseScope,
        secret_reference: SecretReference,
    ) -> Result<Self, FeatureReleaseError> {
        Self::new(
            transport,
            scope,
            secret_reference,
            PluginVersion::new(1, 0, 0),
            DEFAULT_ADAPTER_REVISION,
            DEFAULT_API_REVISION,
            RetryPolicy::default(),
        )
    }

    pub fn service_definition(&self) -> FeatureReleaseServiceDefinition {
        FeatureReleaseServiceDefinition::layer_one()
    }

    pub fn scope(&self) -> &FeatureReleaseScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), FeatureReleaseError> {
        self.secret_reference.revoke();
        Ok(())
    }

    pub fn registration(&self) -> &FeatureReleaseRegistration {
        &self.registration
    }

    pub fn registration_receipt(&self) -> &RegistrationReceipt {
        self.registration.receipt()
    }

    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn describe_release(&self) -> ReleaseDescription {
        let availability = match self.registration.lifecycle() {
            RegistrationLifecycle::Active
                if self.transport.provenance() == TransportProvenance::BlockedEnv =>
            {
                EvidenceAvailability::BlockedEnv
            }
            RegistrationLifecycle::Active => EvidenceAvailability::Complete,
            RegistrationLifecycle::Revoked | RegistrationLifecycle::Unregistered => {
                EvidenceAvailability::ProviderUnknown
            }
        };
        ReleaseDescription {
            service_definition: self.service_definition(),
            scope: self.scope.clone(),
            secret_reference: self.secret_reference.clone(),
            registration: self.registration.receipt().clone(),
            availability,
            provenance: self.transport.provenance(),
            claims: EvidenceClaims::layer_one(),
        }
    }

    fn ensure_active(&self) -> Result<(), FeatureReleaseError> {
        self.registration
            .validate_active(&self.scope, &self.secret_reference)
    }

    fn retry_read<R, F>(&mut self, mut operation: F) -> Result<(R, u8), FeatureReleaseError>
    where
        F: FnMut(&mut T, &FeatureReleaseScope, &SecretReference) -> Result<R, TransportError>,
    {
        self.retry_policy.validate()?;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match operation(&mut self.transport, &self.scope, &self.secret_reference) {
                Ok(value) => return Ok((value, attempts)),
                Err(error) if error.is_retryable() && attempts < self.retry_policy.max_attempts => {
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Read exact flag, approval, and bounded audit evidence.
    pub fn read_flag_evidence(&mut self) -> Result<ReleaseReadEvidence, FeatureReleaseError> {
        self.ensure_active()?;
        let (flag, flag_attempts) = self.retry_read(LaunchDarklyReleaseTransport::read_flag)?;
        flag.validate_for_scope(&self.scope)?;
        let (approvals, approval_attempts) =
            self.retry_read(LaunchDarklyReleaseTransport::read_approvals)?;
        if approvals.len() > usize::from(MAX_APPROVAL_ENTRIES) {
            return Err(FeatureReleaseError::AuditUnbounded);
        }
        let (audits, audit_attempts) = self.retry_read(|transport, scope, secret| {
            transport.read_audit_log(scope, secret, MAX_AUDIT_ENTRIES)
        })?;
        if audits.len() > usize::from(MAX_AUDIT_ENTRIES) {
            return Err(FeatureReleaseError::AuditUnbounded);
        }
        let evidence = ReleaseReadEvidence::complete(
            &self.scope,
            self.registration.receipt().registration_digest.clone(),
            flag,
            approvals,
            audits,
            self.transport.provenance(),
            RetrySummary::new(
                self.retry_policy,
                flag_attempts,
                approval_attempts,
                audit_attempts,
            ),
        )?;
        FeatureReleaseContractPayload::from_evidence(
            &self.scope,
            self.registration.receipt(),
            &evidence,
        )?;
        Ok(evidence)
    }

    /// Compile a local semantic-patch proposal against a read fence and local
    /// dry-run validation. No provider mutation is possible here.
    pub fn compile_release_proposal(
        &self,
        request: &FeatureReleaseProposalRequest,
        evidence: &ReleaseReadEvidence,
        dry_run_evidence: &DryRunEvidence,
    ) -> Result<FeatureReleaseResultProposal, FeatureReleaseError> {
        self.ensure_active()?;
        request.validate(&self.scope)?;
        if evidence.scope_digest != self.scope.scope_digest()
            || evidence.registration_digest != self.registration.receipt().registration_digest
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        if evidence.availability != EvidenceAvailability::Complete {
            return FeatureReleaseResultProposal::unavailable(
                request,
                &self.registration.receipt().registration_digest,
                dry_run_evidence.clone(),
                evidence.availability,
                evidence.provenance,
            );
        }
        evidence.validate_fence(
            &self.scope,
            &self.registration.receipt().registration_digest,
        )?;
        let flag = evidence
            .flag
            .clone()
            .ok_or(FeatureReleaseError::ProviderUnknown)?;
        flag.validate_for_scope(&self.scope)?;
        let provider_fence = FeatureReleaseProviderFence::from_flag(
            &flag,
            self.scope.scope_digest(),
            self.registration.receipt().registration_digest.clone(),
        );
        provider_fence.validate_for_scope(
            &self.scope,
            &self.registration.receipt().registration_digest,
            Some(self.scope.flag_version),
        )?;
        request.patch.validate_against(&self.scope, &flag)?;
        dry_run_evidence.validate_for(&self.scope, &flag, &request.patch)?;
        let (approval_status, approval) = select_approval(&self.scope, &evidence.approvals);
        let audit_fence = AuditFence::from_entries(&evidence.audit_entries)?;
        let audit_status = audit_status(&evidence.audit_entries);
        let (status, blocked_reason) = match audit_status {
            Some(ReleaseStatus::Failed) => (
                ReleaseStatus::Failed,
                Some(ProposalBlockedReason::AuditNotApplied),
            ),
            Some(ReleaseStatus::Scheduled) => (
                ReleaseStatus::Scheduled,
                Some(ProposalBlockedReason::AuditNotApplied),
            ),
            Some(ReleaseStatus::Applied) => (ReleaseStatus::Applied, None),
            Some(_) | None => match approval_status {
                Some(ApprovalStatus::Approved) => (ReleaseStatus::Approved, None),
                Some(ApprovalStatus::Declined) => (
                    ReleaseStatus::Declined,
                    Some(ProposalBlockedReason::ApprovalDeclined),
                ),
                Some(ApprovalStatus::Conflicted) => (
                    ReleaseStatus::Conflicted,
                    Some(ProposalBlockedReason::ApprovalConflict),
                ),
                Some(ApprovalStatus::Stale) => (
                    ReleaseStatus::Stale,
                    Some(ProposalBlockedReason::ApprovalStale),
                ),
                Some(ApprovalStatus::Unknown) => (
                    ReleaseStatus::ProviderUnknown,
                    Some(ProposalBlockedReason::ProviderUnknown),
                ),
                Some(ApprovalStatus::Pending) | None => (
                    ReleaseStatus::Pending,
                    Some(ProposalBlockedReason::ApprovalPending),
                ),
            },
        };
        Ok(FeatureReleaseResultProposal::new(
            request,
            &self.registration.receipt().registration_digest,
            flag,
            dry_run_evidence.clone(),
            approval_status,
            approval,
            audit_fence,
            status,
            blocked_reason,
            evidence.provenance,
        ))
    }

    /// Record exact post-change read-back as a recording-only receipt. This
    /// method never calls a write endpoint and rejects dry-run proposals.
    pub fn record_release_receipt(
        &self,
        proposal: &FeatureReleaseResultProposal,
        readback: &ReleaseReadBack,
    ) -> Result<ReleaseReceipt, FeatureReleaseError> {
        self.ensure_active()?;
        proposal.validate_digest()?;
        if proposal.dry_run {
            return Err(FeatureReleaseError::DryRunReceiptForbidden);
        }
        if !proposal.recordable || proposal.status != ReleaseStatus::Approved {
            return Err(FeatureReleaseError::ApprovalNotApproved);
        }
        self.validate_proposal_fence(proposal)?;
        readback.validate_fence(
            &self.scope,
            &self.registration.receipt().registration_digest,
        )?;
        let proposal_fence = proposal
            .provider_fence
            .as_ref()
            .ok_or(FeatureReleaseError::RegistrationFenceMismatch)?;
        if !proposal_fence.same_target(&readback.provider_fence) {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        if readback.flag.flag_version <= proposal.base_flag_version {
            return Err(FeatureReleaseError::ReadBackVersionNotNewer);
        }
        let audit = matching_applied_audit(proposal, readback)?;
        ReleaseReceipt::new(proposal, readback, audit)
    }

    /// Verify an existing recording-only receipt against a new exact read-back.
    pub fn verify_release_result(
        &self,
        receipt: &ReleaseReceipt,
        readback: &ReleaseReadBack,
    ) -> Result<VerifiedReleaseResult, FeatureReleaseError> {
        self.ensure_active()?;
        receipt.validate()?;
        if receipt.scope_digest != self.scope.scope_digest()
            || receipt.registration_digest != self.registration.receipt().registration_digest
        {
            return Err(FeatureReleaseError::ReceiptRegistrationStale);
        }
        readback.validate_fence(
            &self.scope,
            &self.registration.receipt().registration_digest,
        )?;
        if !receipt.provider_fence.same_target(&readback.provider_fence) {
            return Err(FeatureReleaseError::ReadBackFlagMismatch);
        }
        if readback.flag.flag_version != receipt.after_flag_version {
            return Err(FeatureReleaseError::VersionDrift {
                expected: receipt.after_flag_version,
                actual: readback.flag.flag_version,
            });
        }
        if readback.flag.fingerprint() != receipt.after_flag_digest {
            return Err(FeatureReleaseError::ReadBackFlagMismatch);
        }
        let matches = readback
            .audit_entries
            .iter()
            .filter(|audit| audit.entry_id == receipt.audit_entry_id)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(FeatureReleaseError::AuditMissing);
        }
        if matches.len() != 1
            || matches[0].fingerprint() != receipt.audit_entry_digest
            || matches[0].related_proposal_digest.as_ref() != Some(&receipt.proposal_digest)
            || matches[0].related_approval_digest.as_ref() != Some(&receipt.approval_digest)
        {
            return Err(FeatureReleaseError::AuditMismatch);
        }
        if matches[0].event_kind != AuditEventKind::ChangeApplied
            || matches[0].flag_version != receipt.after_flag_version
        {
            return Err(FeatureReleaseError::AuditMismatch);
        }
        Ok(VerifiedReleaseResult {
            verified: true,
            receipt_digest: receipt.receipt_digest.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            readback_digest: readback.readback_digest.clone(),
            status: ReleaseStatus::Applied,
            claims: EvidenceClaims::layer_one(),
        })
    }

    fn validate_proposal_fence(
        &self,
        proposal: &FeatureReleaseResultProposal,
    ) -> Result<(), FeatureReleaseError> {
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.registration_digest != self.registration.receipt().registration_digest
        {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        }
        proposal
            .provider_fence
            .as_ref()
            .ok_or(FeatureReleaseError::RegistrationFenceMismatch)?
            .validate_for_scope(
                &self.scope,
                &self.registration.receipt().registration_digest,
                Some(proposal.base_flag_version),
            )?;
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationReceipt, FeatureReleaseError> {
        self.registration.revoke()
    }

    pub fn unregister(&mut self) -> Result<RegistrationReceipt, FeatureReleaseError> {
        self.registration.unregister()
    }

    pub fn reregister(&mut self) -> Result<RegistrationReceipt, FeatureReleaseError> {
        self.registration
            .reregister(&self.scope, &self.secret_reference)
    }
}

fn select_approval(
    scope: &FeatureReleaseScope,
    approvals: &[ApprovalEvidence],
) -> (Option<ApprovalStatus>, Option<ApprovalEvidence>) {
    let matching = approvals
        .iter()
        .filter(|approval| approval.flag_version == scope.flag_version)
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return (Some(ApprovalStatus::Conflicted), None);
    }
    let Some(approval) = matching.first() else {
        return (
            if scope.approval_policy.required {
                Some(ApprovalStatus::Pending)
            } else {
                Some(ApprovalStatus::Approved)
            },
            None,
        );
    };
    if approval.policy_revision != scope.policy_revision {
        return (Some(ApprovalStatus::Stale), Some((*approval).clone()));
    }
    (Some(approval.status), Some((*approval).clone()))
}

fn audit_status(audits: &[AuditEvidence]) -> Option<ReleaseStatus> {
    if audits
        .iter()
        .any(|audit| audit.event_kind == AuditEventKind::ChangeFailed)
    {
        Some(ReleaseStatus::Failed)
    } else if audits
        .iter()
        .any(|audit| audit.event_kind == AuditEventKind::ChangeScheduled)
    {
        Some(ReleaseStatus::Scheduled)
    } else if audits
        .iter()
        .any(|audit| audit.event_kind == AuditEventKind::ChangeApplied)
    {
        Some(ReleaseStatus::Applied)
    } else {
        None
    }
}

fn matching_applied_audit<'a>(
    proposal: &FeatureReleaseResultProposal,
    readback: &'a ReleaseReadBack,
) -> Result<&'a AuditEvidence, FeatureReleaseError> {
    let matches = readback
        .audit_entries
        .iter()
        .filter(|audit| {
            audit.event_kind == AuditEventKind::ChangeApplied
                && audit.flag_version == readback.flag.flag_version
                && audit
                    .related_proposal_digest
                    .as_ref()
                    .is_some_and(|digest| digest == &proposal.proposal_digest)
                && proposal.approval.as_ref().is_some_and(|approval| {
                    audit.related_approval_id.as_deref() == Some(approval.request_id.as_str())
                        && audit.related_approval_digest.as_ref() == Some(&approval.evidence_digest)
                })
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(FeatureReleaseError::AuditMissing),
        [audit] => Ok(audit),
        _ => Err(FeatureReleaseError::AuditDuplicate),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseDescription {
    pub service_definition: FeatureReleaseServiceDefinition,
    pub scope: FeatureReleaseScope,
    pub secret_reference: SecretReference,
    pub registration: RegistrationReceipt,
    pub availability: EvidenceAvailability,
    pub provenance: TransportProvenance,
    pub claims: EvidenceClaims,
}

/// Typed service facade exposed to Mission composition.
pub struct FeatureReleaseService<T> {
    provider: LaunchDarklyReleaseProvider<T>,
}

impl<T: LaunchDarklyReleaseTransport> fmt::Debug for FeatureReleaseService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeatureReleaseService")
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: LaunchDarklyReleaseTransport> FeatureReleaseService<T> {
    pub fn new(provider: LaunchDarklyReleaseProvider<T>) -> Self {
        Self { provider }
    }

    pub fn provider(&self) -> &LaunchDarklyReleaseProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut LaunchDarklyReleaseProvider<T> {
        &mut self.provider
    }

    pub fn describe_release(&self) -> ReleaseDescription {
        self.provider.describe_release()
    }

    pub fn read_flag_evidence(&mut self) -> Result<ReleaseReadEvidence, FeatureReleaseError> {
        self.provider.read_flag_evidence()
    }

    pub fn compile_release_proposal(
        &self,
        request: &FeatureReleaseProposalRequest,
        evidence: &ReleaseReadEvidence,
        dry_run_evidence: &DryRunEvidence,
    ) -> Result<FeatureReleaseResultProposal, FeatureReleaseError> {
        self.provider
            .compile_release_proposal(request, evidence, dry_run_evidence)
    }

    pub fn record_release_receipt(
        &self,
        proposal: &FeatureReleaseResultProposal,
        readback: &ReleaseReadBack,
    ) -> Result<ReleaseReceipt, FeatureReleaseError> {
        self.provider.record_release_receipt(proposal, readback)
    }

    pub fn verify_release_result(
        &self,
        receipt: &ReleaseReceipt,
        readback: &ReleaseReadBack,
    ) -> Result<VerifiedReleaseResult, FeatureReleaseError> {
        self.provider.verify_release_result(receipt, readback)
    }
}

/// Mission consumer that projects a release proposal without claiming an
/// Outcome or invoking kernel authority.
#[derive(Clone, Debug)]
pub struct MissionFeatureReleaseConsumer {
    scope: FeatureReleaseScope,
    provider_fence: FeatureReleaseProviderFence,
}

impl MissionFeatureReleaseConsumer {
    pub fn for_scope(scope: &FeatureReleaseScope, registration_digest: Digest) -> Self {
        Self {
            scope: scope.clone(),
            provider_fence: FeatureReleaseProviderFence::for_scope(scope, registration_digest),
        }
    }

    pub fn consume(
        &self,
        proposal: &FeatureReleaseResultProposal,
    ) -> Result<MissionFeatureReleaseProposal, FeatureReleaseError> {
        proposal.validate_digest()?;
        proposal.claims.validate()?;
        if proposal.mission_id != self.scope.mission_id
            || proposal.project_id != self.scope.project_id
            || proposal.work_product_id != self.scope.work_product_id
            || proposal.consent_revision != self.scope.consent_revision
            || proposal.policy_revision != self.scope.policy_revision
        {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        let Some(provider_fence) = &proposal.provider_fence else {
            return Err(FeatureReleaseError::RegistrationFenceMismatch);
        };
        if provider_fence != &self.provider_fence {
            return Err(FeatureReleaseError::ScopeMismatch);
        }
        provider_fence.validate_for_scope(
            &self.scope,
            &self.provider_fence.registration_digest,
            Some(self.scope.flag_version),
        )?;
        if matches!(
            proposal.provenance,
            TransportProvenance::Fixture | TransportProvenance::BlockedEnv
        ) {
            return Err(FeatureReleaseError::ProvenanceForbidden);
        }
        let mission = MissionFeatureReleaseProposal {
            consumer_id: CONSUMER_ID.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            provider_fence: provider_fence.clone(),
            mission_id: self.scope.mission_id.clone(),
            project_id: self.scope.project_id.clone(),
            work_product_id: self.scope.work_product_id.clone(),
            consent_revision: self.scope.consent_revision,
            policy_revision: self.scope.policy_revision,
            status: proposal.status,
            adoptable: proposal.recordable && proposal.status == ReleaseStatus::Approved,
            authority_boundary: AuthorityBoundary::layer_one(),
            claims: EvidenceClaims::layer_one(),
        };
        Ok(mission)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AuthorityBoundary {
    pub truth: bool,
    pub consent: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
}

impl AuthorityBoundary {
    pub const fn layer_one() -> Self {
        Self {
            truth: false,
            consent: false,
            effect: false,
            receipt: false,
            verification: false,
            outcome: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionFeatureReleaseProposal {
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub provider_fence: FeatureReleaseProviderFence,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub status: ReleaseStatus,
    pub adoptable: bool,
    pub authority_boundary: AuthorityBoundary,
    pub claims: EvidenceClaims,
}

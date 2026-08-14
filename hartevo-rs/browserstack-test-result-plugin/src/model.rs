//! Bounded BrowserStack test-result data model.
//!
//! Only normalized metadata is serializable from this module. BrowserStack
//! username/access-key references and short-lived credential leases are kept
//! in the provider module and deliberately do not implement `Serialize`.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    BROWSERSTACK_CONTRACT_VERSION, BROWSERSTACK_MAX_OUTCOME_COUNT, BROWSERSTACK_MAX_PAGE_SIZE,
    BROWSERSTACK_MAX_PAGES, BROWSERSTACK_MAX_RECEIPTS, BROWSERSTACK_MAX_RESPONSE_BYTES,
    BROWSERSTACK_MAX_SESSIONS, BROWSERSTACK_PLUGIN_VERSION_TEXT, BROWSERSTACK_PROVIDER_ID,
    BROWSERSTACK_PROVIDER_REVISION, BROWSERSTACK_SCHEMA_VERSION, BROWSERSTACK_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_STATUS_BYTES: usize = 128;
pub const MAX_TIMESTAMP_BYTES: usize = 128;
pub const MAX_FAILURES: usize = 16;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or unsafe whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds the Layer-1 bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} is already revoked")]
    AlreadyRevoked { field: &'static str },
    #[error("{field} digest is inconsistent")]
    DigestMismatch { field: &'static str },
}

fn validate_text(
    value: &str,
    field: &'static str,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidText { field });
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

fn validate_digest(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, false)?;
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
    };
}

identifier_type!(AccountId, "BrowserStack account id");
identifier_type!(GroupId, "BrowserStack group id");
identifier_type!(BrowserStackProjectId, "BrowserStack project id");
identifier_type!(BuildId, "BrowserStack build id");
identifier_type!(SessionId, "BrowserStack session id");
identifier_type!(HartevoProjectId, "Hartevo project id");
identifier_type!(MissionId, "Mission id");
identifier_type!(WorkProductId, "Work Product id");
identifier_type!(ArtifactId, "BrowserStack artifact id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        validate_digest(&value, "SHA-256 digest")?;
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domain.as_bytes());
        bytes.push(0);
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        Self::from_bytes(&bytes)
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStackProduct {
    Automate,
    AppAutomate,
}

impl BrowserStackProduct {
    pub const ALL: [Self; 2] = [Self::Automate, Self::AppAutomate];

    pub const fn api_area(self) -> &'static str {
        match self {
            Self::Automate => "automate",
            Self::AppAutomate => "app-automate",
        }
    }

    pub const fn api_origin(self) -> &'static str {
        match self {
            Self::Automate => crate::BROWSERSTACK_AUTOMATE_API_ORIGIN,
            Self::AppAutomate => crate::BROWSERSTACK_APP_AUTOMATE_API_ORIGIN,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HartevoProjectScope {
    id: HartevoProjectId,
    revision: Revision,
}

impl HartevoProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: HartevoProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: MissionId,
    revision: Revision,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PermissionSnapshot {
    account_read: bool,
    group_read: bool,
    project_read: bool,
    build_read: bool,
    session_read: bool,
    revision: Revision,
    digest: Digest,
}

impl PermissionSnapshot {
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn new(
        revision: u64,
        account_read: bool,
        group_read: bool,
        project_read: bool,
        build_read: bool,
        session_read: bool,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(revision)?;
        let digest = digest_serializable(&(
            account_read,
            group_read,
            project_read,
            build_read,
            session_read,
            revision,
        ))?;
        Ok(Self {
            account_read,
            group_read,
            project_read,
            build_read,
            session_read,
            revision,
            digest,
        })
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(revision, true, true, true, true, true)
    }

    pub const fn account_read(&self) -> bool {
        self.account_read
    }

    pub const fn group_read(&self) -> bool {
        self.group_read
    }

    pub const fn project_read(&self) -> bool {
        self.project_read
    }

    pub const fn build_read(&self) -> bool {
        self.build_read
    }

    pub const fn session_read(&self) -> bool {
        self.session_read
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn allows_product(&self, _product: BrowserStackProduct) -> bool {
        self.account_read
            && self.group_read
            && self.project_read
            && self.build_read
            && self.session_read
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = digest_serializable(&(
            self.account_read,
            self.group_read,
            self.project_read,
            self.build_read,
            self.session_read,
            self.revision,
        ))?;
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch {
                field: "permission snapshot",
            })
        }
    }
}

/// This reference is intentionally opaque and does not implement `Serialize`
/// or `Deserialize`. It retains only digests of host-keyring handles, never a
/// BrowserStack username or access key and never credential material.
pub struct SecretReference {
    username_reference_digest: Digest,
    access_key_reference_digest: Digest,
    reference_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            username_reference_digest: self.username_reference_digest.clone(),
            access_key_reference_digest: self.access_key_reference_digest.clone(),
            reference_digest: self.reference_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("username_reference_digest", &self.username_reference_digest)
            .field(
                "access_key_reference_digest",
                &self.access_key_reference_digest,
            )
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.username_reference_digest == other.username_reference_digest
            && self.access_key_reference_digest == other.access_key_reference_digest
            && self.reference_digest == other.reference_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        username_reference: impl Into<String>,
        access_key_reference: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let username_reference = username_reference.into();
        let access_key_reference = access_key_reference.into();
        validate_text(
            &username_reference,
            "BrowserStack username secret reference",
            false,
        )?;
        validate_text(
            &access_key_reference,
            "BrowserStack access-key secret reference",
            false,
        )?;
        let credential_revision = Revision::new(credential_revision)?;
        let username_reference_digest = Digest::from_fields(
            "browserstack-username-secret-reference/v1",
            &[username_reference],
        );
        let access_key_reference_digest = Digest::from_fields(
            "browserstack-access-key-secret-reference/v1",
            &[access_key_reference],
        );
        let reference_digest = Digest::from_fields(
            "browserstack-secret-reference/v1",
            &[
                username_reference_digest.as_str().to_owned(),
                access_key_reference_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            username_reference_digest,
            access_key_reference_digest,
            reference_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn username_reference_digest(&self) -> &Digest {
        &self.username_reference_digest
    }

    pub fn access_key_reference_digest(&self) -> &Digest {
        &self.access_key_reference_digest
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked {
                field: "BrowserStack SecretReference",
            })
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

pub type BrowserStackSecretReference = SecretReference;
pub type BrowserStackPermissionSnapshot = PermissionSnapshot;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitReference {
    value: String,
}

impl CommitReference {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "commit reference", false)?;
        if value.len() < 7
            || value.len() > 128
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ModelError::Invalid {
                field: "commit reference",
            });
        }
        Ok(Self { value })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactReference {
    id: ArtifactId,
}

impl ArtifactReference {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self {
            id: ArtifactId::new(value)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackScopeInput {
    pub account_id: String,
    pub group_id: String,
    pub browserstack_project_id: String,
    pub product: BrowserStackProduct,
    pub build_id: String,
    pub session_id: Option<String>,
    pub build_revision: u64,
    pub session_revision: Option<u64>,
    pub commit: Option<String>,
    pub artifact: Option<String>,
    pub hartevo_project_id: String,
    pub hartevo_project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub permission: PermissionSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrowserStackScope {
    account_id: AccountId,
    group_id: GroupId,
    browserstack_project_id: BrowserStackProjectId,
    product: BrowserStackProduct,
    build_id: BuildId,
    session_id: Option<SessionId>,
    build_revision: Revision,
    session_revision: Option<Revision>,
    commit: Option<CommitReference>,
    artifact: Option<ArtifactReference>,
    hartevo_project: HartevoProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    permission: PermissionSnapshot,
    scope_digest: Digest,
}

impl BrowserStackScope {
    pub fn new(input: BrowserStackScopeInput) -> Result<Self, ModelError> {
        let session_id = input.session_id.map(SessionId::new).transpose()?;
        let session_revision = input.session_revision.map(Revision::new).transpose()?;
        if session_id.is_some() != session_revision.is_some() {
            return Err(ModelError::Invalid {
                field: "session id and session revision pair",
            });
        }
        let permission = input.permission;
        permission.validate()?;
        let scope = Self {
            account_id: AccountId::new(input.account_id)?,
            group_id: GroupId::new(input.group_id)?,
            browserstack_project_id: BrowserStackProjectId::new(input.browserstack_project_id)?,
            product: input.product,
            build_id: BuildId::new(input.build_id)?,
            session_id,
            build_revision: Revision::new(input.build_revision)?,
            session_revision,
            commit: input.commit.map(CommitReference::new).transpose()?,
            artifact: input.artifact.map(ArtifactReference::new).transpose()?,
            hartevo_project: HartevoProjectScope::new(
                input.hartevo_project_id,
                input.hartevo_project_revision,
            )?,
            mission: MissionScope::new(input.mission_id, input.mission_revision)?,
            work_product: WorkProductScope::new(
                input.work_product_id,
                input.work_product_revision,
            )?,
            permission,
            scope_digest: Digest::from_text("pending"),
        };
        let scope_digest = digest_serializable(&(
            &scope.account_id,
            &scope.group_id,
            &scope.browserstack_project_id,
            scope.product,
            &scope.build_id,
            &scope.session_id,
            scope.build_revision,
            &scope.session_revision,
            &scope.commit,
            &scope.artifact,
            &scope.hartevo_project,
            &scope.mission,
            &scope.work_product,
            &scope.permission,
        ))?;
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    pub fn account_id(&self) -> &str {
        self.account_id.as_str()
    }

    pub fn group_id(&self) -> &str {
        self.group_id.as_str()
    }

    pub fn browserstack_project_id(&self) -> &str {
        self.browserstack_project_id.as_str()
    }

    pub const fn product(&self) -> BrowserStackProduct {
        self.product
    }

    pub fn build_id(&self) -> &str {
        self.build_id.as_str()
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_ref().map(SessionId::as_str)
    }

    pub const fn build_revision(&self) -> Revision {
        self.build_revision
    }

    pub const fn session_revision(&self) -> Option<Revision> {
        self.session_revision
    }

    pub fn commit(&self) -> Option<&str> {
        self.commit.as_ref().map(CommitReference::as_str)
    }

    pub fn artifact(&self) -> Option<&str> {
        self.artifact.as_ref().map(ArtifactReference::id)
    }

    pub fn hartevo_project(&self) -> &HartevoProjectScope {
        &self.hartevo_project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackReadRequest {
    pub expected_build_revision: Option<u64>,
    pub expected_session_revision: Option<u64>,
}

impl BrowserStackReadRequest {
    pub fn new() -> Self {
        Self {
            expected_build_revision: None,
            expected_session_revision: None,
        }
    }

    pub fn with_expected_build_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "expected build revision")?;
        self.expected_build_revision = Some(revision);
        Ok(self)
    }

    pub fn with_expected_session_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "expected session revision")?;
        self.expected_session_revision = Some(revision);
        Ok(self)
    }
}

impl Default for BrowserStackReadRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    ProductionRead,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
    Expired,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    RateLimited,
    PageBound,
    Timeout,
    MissingSessionDetail,
    Redacted,
    Retention,
    ProviderError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    Transport,
    BlockedEnv,
    Deleted,
    AccessLoss,
    Retention,
    Partial,
    ScopeMismatch,
    RevisionMismatch,
    ArtifactMismatch,
    CommitMismatch,
    Tamper,
    Redaction,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderFailure {
    pub class: FailureClass,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
}

impl ProviderFailure {
    pub fn new(
        class: FailureClass,
        status_code: Option<u16>,
        retryable: bool,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            class,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackMatrixEntry {
    pub device: Option<String>,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub operating_system: Option<String>,
    pub operating_system_version: Option<String>,
}

impl BrowserStackMatrixEntry {
    pub fn new(
        device: Option<String>,
        browser: Option<String>,
        browser_version: Option<String>,
        operating_system: Option<String>,
        operating_system_version: Option<String>,
    ) -> Result<Self, ModelError> {
        for value in [
            device.as_deref(),
            browser.as_deref(),
            browser_version.as_deref(),
            operating_system.as_deref(),
            operating_system_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_text(value, "device/browser/OS matrix value", true)?;
        }
        Ok(Self {
            device,
            browser,
            browser_version,
            operating_system,
            operating_system_version,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeCounts {
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub timed_out: u32,
    pub unknown: u32,
}

impl OutcomeCounts {
    pub fn new(
        total: u32,
        passed: u32,
        failed: u32,
        skipped: u32,
        timed_out: u32,
        unknown: u32,
    ) -> Result<Self, ModelError> {
        let value = Self {
            total,
            passed,
            failed,
            skipped,
            timed_out,
            unknown,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn add(&mut self, other: Self) -> Result<(), ModelError> {
        self.total = self
            .total
            .checked_add(other.total)
            .ok_or(ModelError::BoundExceeded {
                field: "outcome count",
            })?;
        self.passed = self
            .passed
            .checked_add(other.passed)
            .ok_or(ModelError::BoundExceeded {
                field: "passed outcome count",
            })?;
        self.failed = self
            .failed
            .checked_add(other.failed)
            .ok_or(ModelError::BoundExceeded {
                field: "failed outcome count",
            })?;
        self.skipped =
            self.skipped
                .checked_add(other.skipped)
                .ok_or(ModelError::BoundExceeded {
                    field: "skipped outcome count",
                })?;
        self.timed_out =
            self.timed_out
                .checked_add(other.timed_out)
                .ok_or(ModelError::BoundExceeded {
                    field: "timed-out outcome count",
                })?;
        self.unknown =
            self.unknown
                .checked_add(other.unknown)
                .ok_or(ModelError::BoundExceeded {
                    field: "unknown outcome count",
                })?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.total > BROWSERSTACK_MAX_OUTCOME_COUNT
            || self.passed > BROWSERSTACK_MAX_OUTCOME_COUNT
            || self.failed > BROWSERSTACK_MAX_OUTCOME_COUNT
            || self.skipped > BROWSERSTACK_MAX_OUTCOME_COUNT
            || self.timed_out > BROWSERSTACK_MAX_OUTCOME_COUNT
            || self.unknown > BROWSERSTACK_MAX_OUTCOME_COUNT
        {
            return Err(ModelError::BoundExceeded {
                field: "outcome count",
            });
        }
        let categorized = self
            .passed
            .saturating_add(self.failed)
            .saturating_add(self.skipped)
            .saturating_add(self.timed_out)
            .saturating_add(self.unknown);
        if categorized > self.total {
            return Err(ModelError::Invalid {
                field: "outcome count total",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackBuildPayload {
    pub id: String,
    pub revision: Revision,
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub status: String,
    pub duration_seconds: Option<u64>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub commit: Option<String>,
    pub artifact: Option<String>,
    pub session_count: Option<u32>,
    pub product: BrowserStackProduct,
}

impl BrowserStackBuildPayload {
    pub fn new(
        id: impl Into<String>,
        product: BrowserStackProduct,
        status: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let status = status.into();
        validate_text(&status, "build status", true)?;
        Ok(Self {
            id: id.into(),
            revision: Revision::new(revision)?,
            project_id: None,
            name: None,
            status,
            duration_seconds: None,
            started_at: None,
            finished_at: None,
            commit: None,
            artifact: None,
            session_count: None,
            product,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(&self.id, "build id", false)?;
        validate_text(&self.status, "build status", true)?;
        if self.status.len() > MAX_STATUS_BYTES {
            return Err(ModelError::TooLong {
                field: "build status",
            });
        }
        if let Some(value) = self.session_count
            && usize::try_from(value).unwrap_or(usize::MAX) > BROWSERSTACK_MAX_SESSIONS
        {
            return Err(ModelError::BoundExceeded {
                field: "session count",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackSessionPayload {
    pub id: String,
    pub revision: Revision,
    pub build_id: String,
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub status: String,
    pub duration_seconds: Option<u64>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub matrix: BrowserStackMatrixEntry,
    pub commit: Option<String>,
    pub artifact: Option<String>,
    pub outcomes: OutcomeCounts,
    pub product: BrowserStackProduct,
}

impl BrowserStackSessionPayload {
    pub fn new(
        id: impl Into<String>,
        build_id: impl Into<String>,
        product: BrowserStackProduct,
        status: impl Into<String>,
        revision: u64,
        matrix: BrowserStackMatrixEntry,
        outcomes: OutcomeCounts,
    ) -> Result<Self, ModelError> {
        let status = status.into();
        validate_text(&status, "session status", true)?;
        outcomes.validate()?;
        Ok(Self {
            id: id.into(),
            revision: Revision::new(revision)?,
            build_id: build_id.into(),
            project_id: None,
            name: None,
            status,
            duration_seconds: None,
            started_at: None,
            finished_at: None,
            matrix,
            commit: None,
            artifact: None,
            outcomes,
            product,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(&self.id, "session id", false)?;
        validate_text(&self.build_id, "session build id", false)?;
        validate_text(&self.status, "session status", true)?;
        self.outcomes.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum BrowserStackResponseBody {
    Build(BrowserStackBuildPayload),
    Sessions(Vec<BrowserStackSessionPayload>),
    Session(BrowserStackSessionPayload),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackResponseReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub endpoint: String,
    pub product: BrowserStackProduct,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: String,
    pub offset: Option<u32>,
    pub limit: Option<u16>,
    pub raw_payload_retained: bool,
    pub raw_logs_retained: bool,
    pub raw_network_retained: bool,
    pub raw_har_retained: bool,
    pub raw_video_retained: bool,
    pub raw_screenshots_retained: bool,
    pub arbitrary_capabilities_retained: bool,
    pub credential_material_retained: bool,
    pub observed_at: DateTime<Utc>,
}

impl BrowserStackResponseReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(self.request_digest.as_str(), "request digest")?;
        validate_digest(self.response_digest.as_str(), "response digest")?;
        validate_text(&self.endpoint, "response endpoint", true)?;
        validate_text(&self.provider_revision, "provider revision", false)?;
        if self.response_size > BROWSERSTACK_MAX_RESPONSE_BYTES
            || self.raw_payload_retained
            || self.raw_logs_retained
            || self.raw_network_retained
            || self.raw_har_retained
            || self.raw_video_retained
            || self.raw_screenshots_retained
            || self.arbitrary_capabilities_retained
            || self.credential_material_retained
        {
            return Err(ModelError::Invalid {
                field: "response receipt safety fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackBuildProjection {
    pub id: String,
    pub revision: Revision,
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub status: String,
    pub duration_seconds: Option<u64>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub commit: Option<String>,
    pub artifact: Option<String>,
    pub session_count: Option<u32>,
    pub product: BrowserStackProduct,
}

impl From<BrowserStackBuildPayload> for BrowserStackBuildProjection {
    fn from(payload: BrowserStackBuildPayload) -> Self {
        Self {
            id: payload.id,
            revision: payload.revision,
            project_id: payload.project_id,
            name: payload.name,
            status: payload.status,
            duration_seconds: payload.duration_seconds,
            started_at: payload.started_at,
            finished_at: payload.finished_at,
            commit: payload.commit,
            artifact: payload.artifact,
            session_count: payload.session_count,
            product: payload.product,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackSessionProjection {
    pub id: String,
    pub revision: Revision,
    pub build_id: String,
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub status: String,
    pub duration_seconds: Option<u64>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub matrix: BrowserStackMatrixEntry,
    pub commit: Option<String>,
    pub artifact: Option<String>,
    pub outcomes: OutcomeCounts,
    pub product: BrowserStackProduct,
}

impl From<BrowserStackSessionPayload> for BrowserStackSessionProjection {
    fn from(payload: BrowserStackSessionPayload) -> Self {
        Self {
            id: payload.id,
            revision: payload.revision,
            build_id: payload.build_id,
            project_id: payload.project_id,
            name: payload.name,
            status: payload.status,
            duration_seconds: payload.duration_seconds,
            started_at: payload.started_at,
            finished_at: payload.finished_at,
            matrix: payload.matrix,
            commit: payload.commit,
            artifact: payload.artifact,
            outcomes: payload.outcomes,
            product: payload.product,
        }
    }
}

pub type BuildProjection = BrowserStackBuildProjection;
pub type SessionProjection = BrowserStackSessionProjection;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct Authority {
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub truth: bool,
    pub consent: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub build_digest: Digest,
    pub sessions_digest: Digest,
    pub matrix_digest: Digest,
    pub outcome_digest: Digest,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackTestResultEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: TransportProvenance,
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub build: Option<BrowserStackBuildProjection>,
    pub sessions: Vec<BrowserStackSessionProjection>,
    pub matrix: Vec<BrowserStackMatrixEntry>,
    pub outcome_counts: OutcomeCounts,
    pub failures: Vec<ProviderFailure>,
    pub receipts: Vec<BrowserStackResponseReceipt>,
    pub redaction_applied: bool,
    pub authority: Authority,
    pub digests: EvidenceDigests,
    pub evidence_digest: Digest,
}

impl BrowserStackTestResultEvidence {
    pub(crate) fn new(
        contract_digest: Digest,
        provider_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        registration_digest: Digest,
        provenance: TransportProvenance,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        build: Option<BrowserStackBuildProjection>,
        sessions: Vec<BrowserStackSessionProjection>,
        failures: Vec<ProviderFailure>,
        receipts: Vec<BrowserStackResponseReceipt>,
    ) -> Result<Self, ModelError> {
        if sessions.len() > BROWSERSTACK_MAX_SESSIONS {
            return Err(ModelError::BoundExceeded {
                field: "session evidence",
            });
        }
        if failures.len() > MAX_FAILURES || receipts.len() > BROWSERSTACK_MAX_RECEIPTS {
            return Err(ModelError::BoundExceeded {
                field: "evidence receipt/failure count",
            });
        }
        let mut matrix = Vec::new();
        for session in &sessions {
            if !matrix.contains(&session.matrix) {
                matrix.push(session.matrix.clone());
            }
        }
        let mut outcome_counts = OutcomeCounts::default();
        for session in &sessions {
            outcome_counts.add(session.outcomes)?;
        }
        let digests = EvidenceDigests {
            build_digest: digest_serializable(&build)?,
            sessions_digest: digest_serializable(&sessions)?,
            matrix_digest: digest_serializable(&matrix)?,
            outcome_digest: digest_serializable(&outcome_counts)?,
            response_digest: digest_serializable(&receipts)?,
        };
        let mut evidence = Self {
            schema_version: BROWSERSTACK_SCHEMA_VERSION.to_owned(),
            contract_version: BROWSERSTACK_CONTRACT_VERSION.to_owned(),
            plugin_version: BROWSERSTACK_PLUGIN_VERSION_TEXT.to_owned(),
            service_id: BROWSERSTACK_SERVICE_ID.to_owned(),
            provider_id: BROWSERSTACK_PROVIDER_ID.to_owned(),
            provider_revision: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
            contract_digest,
            provider_digest,
            scope_digest,
            permission_digest,
            registration_digest,
            provenance,
            status,
            partial_reason,
            build,
            sessions,
            matrix,
            outcome_counts,
            failures,
            receipts,
            redaction_applied: true,
            authority: Authority::default(),
            digests,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.compute_digest()?;
        evidence.validate()?;
        Ok(evidence)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&EvidenceDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provenance: self.provenance,
            status: self.status,
            partial_reason: self.partial_reason,
            build: &self.build,
            sessions: &self.sessions,
            matrix: &self.matrix,
            outcome_counts: &self.outcome_counts,
            failures: &self.failures,
            receipts: &self.receipts,
            redaction_applied: self.redaction_applied,
            authority: self.authority,
            digests: &self.digests,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        if self.compute_digest()? != self.evidence_digest {
            return Err(ModelError::DigestMismatch { field: "evidence" });
        }
        let expected = EvidenceDigests {
            build_digest: digest_serializable(&self.build)?,
            sessions_digest: digest_serializable(&self.sessions)?,
            matrix_digest: digest_serializable(&self.matrix)?,
            outcome_digest: digest_serializable(&self.outcome_counts)?,
            response_digest: digest_serializable(&self.receipts)?,
        };
        if expected != self.digests {
            return Err(ModelError::DigestMismatch {
                field: "evidence component",
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != BROWSERSTACK_SCHEMA_VERSION
            || self.contract_version != BROWSERSTACK_CONTRACT_VERSION
            || self.plugin_version != BROWSERSTACK_PLUGIN_VERSION_TEXT
            || self.service_id != BROWSERSTACK_SERVICE_ID
            || self.provider_id != BROWSERSTACK_PROVIDER_ID
            || self.provider_revision != BROWSERSTACK_PROVIDER_REVISION
            || !self.redaction_applied
            || self.authority != Authority::default()
            || self.sessions.len() > BROWSERSTACK_MAX_SESSIONS
            || self.failures.len() > MAX_FAILURES
            || self.receipts.len() > BROWSERSTACK_MAX_RECEIPTS
        {
            return Err(ModelError::Invalid {
                field: "evidence authority or metadata",
            });
        }
        self.outcome_counts.validate()?;
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        for session in &self.sessions {
            session.validate()?;
        }
        self.verify_integrity()
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    plugin_version: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    provider_revision: &'a str,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    registration_digest: &'a Digest,
    provenance: TransportProvenance,
    status: EvidenceStatus,
    partial_reason: Option<PartialReason>,
    build: &'a Option<BrowserStackBuildProjection>,
    sessions: &'a Vec<BrowserStackSessionProjection>,
    matrix: &'a Vec<BrowserStackMatrixEntry>,
    outcome_counts: &'a OutcomeCounts,
    failures: &'a Vec<ProviderFailure>,
    receipts: &'a Vec<BrowserStackResponseReceipt>,
    redaction_applied: bool,
    authority: Authority,
    digests: &'a EvidenceDigests,
}

impl BrowserStackSessionProjection {
    fn validate(&self) -> Result<(), ModelError> {
        validate_text(&self.id, "session id", false)?;
        validate_text(&self.build_id, "session build id", false)?;
        validate_text(&self.status, "session status", true)?;
        self.outcomes.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackReadProposal {
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub request: BrowserStackReadRequest,
    pub bounds: RequestBounds,
    pub request_digest: Digest,
    pub proposal_digest: Digest,
}

impl BrowserStackReadProposal {
    pub(crate) fn new(
        scope: &BrowserStackScope,
        request: BrowserStackReadRequest,
        bounds: RequestBounds,
        registration_digest: Digest,
        provider_digest: Digest,
    ) -> Result<Self, ModelError> {
        let request_digest = digest_serializable(&(scope.digest(), &request, bounds))?;
        let mut proposal = Self {
            contract_version: BROWSERSTACK_CONTRACT_VERSION.to_owned(),
            plugin_version: BROWSERSTACK_PLUGIN_VERSION_TEXT.to_owned(),
            service_id: BROWSERSTACK_SERVICE_ID.to_owned(),
            provider_id: BROWSERSTACK_PROVIDER_ID.to_owned(),
            provider_revision: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            scope_digest: scope.digest().clone(),
            permission_digest: scope.permission().digest().clone(),
            registration_digest,
            request,
            bounds,
            request_digest,
            proposal_digest: Digest::from_text("pending"),
        };
        proposal.proposal_digest = proposal.compute_digest()?;
        Ok(proposal)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.contract_version,
            &self.plugin_version,
            &self.service_id,
            &self.provider_id,
            &self.provider_revision,
            &self.contract_digest,
            &self.provider_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.registration_digest,
            &self.request,
            self.bounds,
            &self.request_digest,
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        if self.compute_digest()? == self.proposal_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch { field: "proposal" })
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_sessions: usize,
    pub max_outcome_count: u32,
    pub max_receipts: usize,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: BROWSERSTACK_MAX_RESPONSE_BYTES,
            max_pages: BROWSERSTACK_MAX_PAGES,
            page_size: BROWSERSTACK_MAX_PAGE_SIZE,
            max_sessions: BROWSERSTACK_MAX_SESSIONS,
            max_outcome_count: BROWSERSTACK_MAX_OUTCOME_COUNT,
            max_receipts: BROWSERSTACK_MAX_RECEIPTS,
        }
    }
}

impl RequestBounds {
    pub fn new(
        max_response_bytes: usize,
        max_pages: u16,
        page_size: u16,
        max_sessions: usize,
        max_outcome_count: u32,
        max_receipts: usize,
    ) -> Result<Self, ModelError> {
        if max_response_bytes == 0
            || max_response_bytes > BROWSERSTACK_MAX_RESPONSE_BYTES
            || max_pages == 0
            || max_pages > BROWSERSTACK_MAX_PAGES
            || page_size == 0
            || page_size > BROWSERSTACK_MAX_PAGE_SIZE
            || max_sessions == 0
            || max_sessions > BROWSERSTACK_MAX_SESSIONS
            || max_outcome_count == 0
            || max_outcome_count > BROWSERSTACK_MAX_OUTCOME_COUNT
            || max_receipts == 0
            || max_receipts > BROWSERSTACK_MAX_RECEIPTS
        {
            return Err(ModelError::Invalid {
                field: "BrowserStack request bounds",
            });
        }
        Ok(Self {
            max_response_bytes,
            max_pages,
            page_size,
            max_sessions,
            max_outcome_count,
            max_receipts,
        })
    }
}

//! Typed, bounded CloudWatch Logs scope and digest-only evidence primitives.
//!
//! There is intentionally no raw log-event, message, stack-trace, request-body,
//! PII, `@ptr`, or arbitrary query-string type in this module. Values crossing
//! the provider boundary are either typed metadata or one-way digests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_LOG_GROUPS: usize = 64;
pub const MAX_QUERY_TEMPLATES: usize = 16;
pub const MAX_PARAMETERS: usize = 16;
pub const MAX_PAGES: u8 = 4;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_RESULTS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_ERROR_CLASSES: usize = 32;
pub const MAX_CORRELATION_FINGERPRINTS: usize = 128;
pub const MAX_FIELD_NAMES: usize = 16;
pub const MAX_RETRIES: u8 = 2;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} does not match the bound query")]
    QueryMismatch { field: &'static str },
    #[error("secret reference is already revoked")]
    AlreadyRevoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@#*$".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
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
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
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

bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(ServiceRevisionId, "service revision id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(LogGroupName, "CloudWatch log group name");
bounded_identifier!(QueryTemplateId, "query template id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded CloudWatch Logs values serialize");
    Digest::from_bytes(&bytes)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRevision {
    pub id: ServiceRevisionId,
    pub revision: Revision,
}

impl ServiceRevision {
    pub const fn new(id: ServiceRevisionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        let window = Self { start, end };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.end <= self.start {
            return Err(ModelError::Invalid {
                field: "time window",
            });
        }
        if self.duration_seconds() > MAX_WINDOW_SECONDS {
            return Err(ModelError::Invalid {
                field: "time window bound",
            });
        }
        Ok(())
    }

    pub fn duration_seconds(&self) -> i64 {
        (self.end - self.start).num_seconds()
    }

    pub fn contains(&self, other: &Self) -> bool {
        other.start >= self.start && other.end <= self.end
    }

    pub fn bounded_from(start: DateTime<Utc>, seconds: i64) -> Result<Self, ModelError> {
        if !(1..=MAX_WINDOW_SECONDS).contains(&seconds) {
            return Err(ModelError::Invalid {
                field: "time window seconds",
            });
        }
        Self::new(start, start + Duration::seconds(seconds))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsScope {
    pub deployment: DeploymentBinding,
    pub service_revision: ServiceRevision,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub log_groups: BTreeSet<LogGroupName>,
    pub query_templates: BTreeSet<QueryTemplateId>,
    pub time_window: TimeWindow,
    pub permission_digest: Digest,
}

impl AwsCloudWatchLogsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        service_revision: ServiceRevision,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AccountId,
        region: AwsRegion,
        log_groups: impl IntoIterator<Item = LogGroupName>,
        query_templates: impl IntoIterator<Item = QueryTemplateId>,
        time_window: TimeWindow,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let log_groups = log_groups.into_iter().collect::<BTreeSet<_>>();
        if log_groups.is_empty() {
            return Err(ModelError::Empty {
                field: "log group allowlist",
            });
        }
        if log_groups.len() > MAX_LOG_GROUPS {
            return Err(ModelError::TooMany {
                field: "log group allowlist",
            });
        }
        let query_templates = query_templates.into_iter().collect::<BTreeSet<_>>();
        if query_templates.is_empty() {
            return Err(ModelError::Empty {
                field: "query template allowlist",
            });
        }
        if query_templates.len() > MAX_QUERY_TEMPLATES {
            return Err(ModelError::TooMany {
                field: "query template allowlist",
            });
        }
        if permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        time_window.validate()?;
        Ok(Self {
            deployment,
            service_revision,
            mission,
            project,
            work_product,
            account_id,
            region,
            log_groups,
            query_templates,
            time_window,
            permission_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.log_groups.is_empty() || self.query_templates.is_empty() {
            return Err(ModelError::Invalid {
                field: "scope allowlists",
            });
        }
        if self.log_groups.len() > MAX_LOG_GROUPS
            || self.query_templates.len() > MAX_QUERY_TEMPLATES
        {
            return Err(ModelError::TooMany {
                field: "scope allowlists",
            });
        }
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        self.time_window.validate()
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn allows_log_group(&self, log_group: &LogGroupName) -> bool {
        self.log_groups.contains(log_group)
    }

    pub fn allows_query_template(&self, template: &QueryTemplateId) -> bool {
        self.query_templates.contains(template)
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission.id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project.id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product.id
    }

    pub fn work_product_revision(&self) -> Revision {
        self.work_product.revision
    }
}

/// A SigV4 reference is reduced to a digest before entering the service.
/// Neither the caller's reference nor credential material is retained, and
/// this type intentionally does not implement `Serialize`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    scope_digest: Digest,
    region: AwsRegion,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference: impl AsRef<str>,
        scope: &AwsCloudWatchLogsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::for_cloudwatch_logs(reference, scope, credential_revision)
    }

    pub fn for_cloudwatch_logs(
        reference: impl AsRef<str>,
        scope: &AwsCloudWatchLogsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        validate_identifier(reference, "SigV4 secret reference")?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let region = scope.region.clone();
        let digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-sigv4-secret/v1",
            &[
                "logs".to_owned(),
                region.as_str().to_owned(),
                scope_digest.to_string(),
                reference.to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            digest,
            scope_digest,
            region,
            credential_revision,
            revoked: false,
        })
    }

    pub fn new_with_revision(
        reference: impl AsRef<str>,
        scope: &AwsCloudWatchLogsScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_cloudwatch_logs(reference, scope, credential_revision.get())
    }

    pub fn for_sigv4(
        reference: impl AsRef<str>,
        scope: &AwsCloudWatchLogsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::for_cloudwatch_logs(reference, scope, credential_revision)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn signing_service(&self) -> &'static str {
        "logs"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &self.signing_service())
            .field("signing_region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("digest", &self.digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(ModelError::Invalid {
                field: "opaque next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-logs-next-token/v1",
                &[value.to_owned()],
            ),
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

    pub fn digest(&self) -> Digest {
        self.token_digest.clone()
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
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

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 2)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("tokenDigest", &self.token_digest)?;
        value.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct QueryId {
    digest: Digest,
}

impl QueryId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_identifier(value, "CloudWatch query id")?;
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-logs-query-id/v1",
                &[value.to_owned()],
            ),
        })
    }

    pub fn from_digest(digest: Digest) -> Self {
        Self { digest }
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

impl fmt::Debug for QueryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryId")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for QueryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("QueryId", 1)?;
        value.serialize_field("digest", &self.digest)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    StartQuery,
    GetQueryResults,
    DescribeQueries,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::StartQuery,
                PermissionAction::GetQueryResults,
                PermissionAction::DescribeQueries,
            ],
        )
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(Self {
            id,
            revision,
            allowed_actions,
        })
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QueryExecutionStatus {
    Scheduled,
    Running,
    Complete,
    Failed,
    Cancelled,
    Timeout,
    Unknown,
}

impl QueryExecutionStatus {
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Scheduled | Self::Running)
    }

    pub const fn is_expired(self) -> bool {
        matches!(self, Self::Timeout)
    }

    pub const fn is_terminal(self) -> bool {
        !self.is_running()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Running,
    Partial,
    Expired,
    AccessLoss,
    ProviderUnknown,
    Failed,
    Replay,
    Tampered,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    ResultBudget,
    ResponseTooLarge,
    MissingPageToken,
    QueryStillRunning,
    Timeout,
    ProviderError,
    FilterDrift,
    QueryDrift,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Application,
    Authorization,
    Dependency,
    Throttling,
    Timeout,
    Validation,
    Unknown,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct FieldName(String);

impl FieldName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "result field name", 64)?;
        if !matches!(
            value.as_str(),
            "@timestamp"
                | "@logStream"
                | "level"
                | "errorClass"
                | "serviceRevision"
                | "requestFingerprint"
                | "count"
                | "bin"
        ) || value.eq_ignore_ascii_case("@message")
            || value.eq_ignore_ascii_case("@ptr")
        {
            return Err(ModelError::Unsupported {
                field: "result field name",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FieldName").field(&self.0).finish()
    }
}

impl fmt::Display for FieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSummary {
    pub field_names: Vec<FieldName>,
    pub event_count: u64,
    pub bytes_scanned: u64,
    pub error_class_counts: BTreeMap<ErrorClass, u64>,
    pub correlation_fingerprint_digests: Vec<Digest>,
    pub summary_digest: Digest,
}

impl ResultSummary {
    pub fn new(
        mut field_names: Vec<FieldName>,
        event_count: u64,
        bytes_scanned: u64,
        error_class_counts: BTreeMap<ErrorClass, u64>,
        mut correlation_fingerprint_digests: Vec<Digest>,
    ) -> Result<Self, ModelError> {
        if field_names.is_empty() || field_names.len() > MAX_FIELD_NAMES {
            return Err(ModelError::Invalid {
                field: "result field names",
            });
        }
        field_names.sort();
        field_names.dedup();
        if error_class_counts.len() > MAX_ERROR_CLASSES {
            return Err(ModelError::TooMany {
                field: "error class counts",
            });
        }
        if correlation_fingerprint_digests.len() > MAX_CORRELATION_FINGERPRINTS {
            return Err(ModelError::TooMany {
                field: "correlation fingerprints",
            });
        }
        correlation_fingerprint_digests.sort();
        correlation_fingerprint_digests.dedup();
        let mut summary = Self {
            field_names,
            event_count,
            bytes_scanned,
            error_class_counts,
            correlation_fingerprint_digests,
            summary_digest: Digest::zero(),
        };
        summary.summary_digest = summary.recomputed_digest();
        Ok(summary)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&SummaryBody {
            field_names: &self.field_names,
            event_count: self.event_count,
            bytes_scanned: self.bytes_scanned,
            error_class_counts: &self.error_class_counts,
            correlation_fingerprint_digests: &self.correlation_fingerprint_digests,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.field_names.is_empty()
            || self.field_names.len() > MAX_FIELD_NAMES
            || self.error_class_counts.len() > MAX_ERROR_CLASSES
            || self.correlation_fingerprint_digests.len() > MAX_CORRELATION_FINGERPRINTS
            || self.summary_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "result summary",
            });
        }
        if self.field_names.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ModelError::Duplicate {
                field: "result field names",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryBody<'a> {
    field_names: &'a [FieldName],
    event_count: u64,
    bytes_scanned: u64,
    error_class_counts: &'a BTreeMap<ErrorClass, u64>,
    correlation_fingerprint_digests: &'a [Digest],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub error_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    MalformedResponse,
    BlockedEnv,
    Unknown,
}

impl ProviderErrorKind {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited => Some(429),
            Self::ServerFailure => Some(500),
            Self::Timeout | Self::MalformedResponse | Self::BlockedEnv | Self::Unknown => None,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::ServerFailure | Self::Timeout
        )
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }
}

#[derive(Clone, Eq, Error, PartialEq)]
#[error("CloudWatch Logs provider returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportError")
            .field("kind", &self.kind)
            .field("status_code", &self.status_code)
            .field("retryable", &self.retryable)
            .field("blocked_env", &self.blocked_env)
            .field("diagnostic_digest", &self.diagnostic_digest)
            .finish()
    }
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retryable: kind.retryable(),
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn from_status(status_code: u16) -> Self {
        let kind = match status_code {
            400 => ProviderErrorKind::BadRequest,
            401 => ProviderErrorKind::Unauthorized,
            403 => ProviderErrorKind::Forbidden,
            404 => ProviderErrorKind::NotFound,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), format!("http-{status_code}"))
    }

    pub fn bad_request() -> Self {
        Self::from_status(400)
    }

    pub fn unauthorized() -> Self {
        Self::from_status(401)
    }

    pub fn forbidden() -> Self {
        Self::from_status(403)
    }

    pub fn not_found() -> Self {
        Self::from_status(404)
    }

    pub fn rate_limited() -> Self {
        Self::from_status(429)
    }

    pub fn server_failure() -> Self {
        Self::from_status(500)
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn malformed_response() -> Self {
        Self::new(ProviderErrorKind::MalformedResponse, None, "malformed")
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind,
            status_code: self.status_code,
            retryable: self.retryable,
            error_digest: self.diagnostic_digest.clone(),
        }
    }
}

impl ProviderErrorEvidence {
    pub fn from_error(error: &TransportError) -> Self {
        Self {
            kind: error.kind,
            status_code: error.status_code,
            retryable: error.retryable,
            error_digest: error.diagnostic_digest().clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

pub type AwsAccountId = AccountId;
pub type AwsLogGroupName = LogGroupName;
pub type AwsQueryId = QueryId;
pub type AwsCloudWatchLogsScopeModel = AwsCloudWatchLogsScope;
pub type AwsCloudWatchLogsEvidenceState = EvidenceState;
pub type QueryStatus = QueryExecutionStatus;

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

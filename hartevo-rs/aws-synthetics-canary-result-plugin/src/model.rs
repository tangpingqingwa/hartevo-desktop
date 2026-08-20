//! Typed Layer-1 scope, request, run, and evidence models for AWS Synthetics.
//!
//! Raw canary configuration, endpoint URLs, provider payloads, credentials, and
//! pagination tokens are intentionally not representable in the retained
//! evidence types.  An endpoint is represented by a host-owned identifier and
//! digest; a provider cursor is represented only by a digest.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_RUNS_PER_PAGE: usize = 50;
pub const MAX_RUNS: usize = 128;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
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
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
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
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
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

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
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

bounded_identifier!(DeploymentId, "Deployment id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(CanaryName, "canary name");
bounded_identifier!(EndpointId, "endpoint id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(RunId, "canary run id");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    let encoded = serde_json::to_vec(value).expect("typed Layer-1 values must serialize");
    sha256_digest(&encoded)
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsTarget {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub canary_name: CanaryName,
    pub canary_revision: Revision,
    pub endpoint_id: EndpointId,
    pub endpoint_digest: Digest,
}

impl AwsSyntheticsTarget {
    pub fn new(
        account_id: AccountId,
        region: AwsRegion,
        canary_name: CanaryName,
        canary_revision: Revision,
        endpoint_id: EndpointId,
        endpoint_digest: Digest,
    ) -> Result<Self, ModelError> {
        if endpoint_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "endpoint digest",
            });
        }
        Ok(Self {
            account_id,
            region,
            canary_name,
            canary_revision,
            endpoint_id,
            endpoint_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.endpoint_digest == Digest::zero() {
            Err(ModelError::Invalid {
                field: "endpoint digest",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    GetCanaryRuns,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id,
            revision,
            allowed_actions: [PermissionAction::GetCanaryRuns].into_iter().collect(),
        })
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub target: AwsSyntheticsTarget,
    pub permission_digest: Digest,
}

impl AwsSyntheticsScope {
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        target: AwsSyntheticsTarget,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            target,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.target.validate()?;
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

/// A SigV4 keyring reference is reduced to a digest immediately.  Neither the
/// supplied reference nor signing material is retained or serializable.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
}

impl SecretReference {
    pub fn for_synthetics(
        reference: impl AsRef<str>,
        target: &AwsSyntheticsTarget,
    ) -> Result<Self, ModelError> {
        let value = reference.as_ref();
        validate_text(value, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        let region = target.region.clone();
        let digest = Digest::from_parts(
            "hartevo-aws-synthetics-sigv4-secret/v1",
            &[
                "synthetics".to_owned(),
                region.as_str().to_owned(),
                target.account_id.as_str().to_owned(),
                value.to_owned(),
            ],
        );
        Ok(Self { digest, region })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn signing_service(&self) -> &'static str {
        "synthetics"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque", &true)
            .field("digest", &self.digest)
            .field("signing_region", &self.region)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

/// Provider pagination is bound to a query digest but the token itself never
/// crosses the serialization boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor {
                field: "provider cursor",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-synthetics-provider-cursor/v1",
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

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("opaque", &true)
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
        let mut state = serializer.serialize_struct("OpaqueCursor", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    AccessDenied,
    NotFound,
    Throttled,
    Timeout,
    BlockedEnv,
    Malformed,
    Replay,
    RevisionMismatch,
}

impl ProviderErrorKind {
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Throttled | Self::Timeout)
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::AccessDenied | Self::NotFound)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub retryable: bool,
    pub provenance: TransportProvenance,
    pub provider_revision: ProviderRevision,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        provenance: TransportProvenance,
        provider_revision: ProviderRevision,
    ) -> Self {
        let error_digest = Digest::from_parts(
            "hartevo-aws-synthetics-provider-error/v1",
            &[
                format!("{kind:?}"),
                format!("{provenance:?}"),
                provider_revision.to_string(),
            ],
        );
        Self {
            kind,
            retryable: kind.retryable(),
            provenance,
            provider_revision,
            error_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryRunOutcome {
    Passed,
    Failed,
    Running,
    Stopped,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Passed,
    Failed,
    Running,
    Stopped,
    Unknown,
    Partial,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    RunBudget,
    ResponseBudget,
    CursorReplay,
    PaginationLoop,
    ScopeMismatch,
    StaleRevision,
    AccessLoss,
    Throttled,
    Timeout,
    BlockedEnv,
    ProviderError,
    MalformedPage,
    MissingRuns,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryRun {
    pub run_id: RunId,
    pub canary_name: CanaryName,
    pub canary_revision: Revision,
    pub endpoint_digest: Digest,
    pub run_revision: Revision,
    pub outcome: CanaryRunOutcome,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub run_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CanaryRunBody<'a> {
    run_id: &'a RunId,
    canary_name: &'a CanaryName,
    canary_revision: Revision,
    endpoint_digest: &'a Digest,
    run_revision: Revision,
    outcome: CanaryRunOutcome,
    started_at: &'a DateTime<Utc>,
    completed_at: &'a Option<DateTime<Utc>>,
}

impl CanaryRun {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: RunId,
        canary_name: CanaryName,
        canary_revision: Revision,
        endpoint_digest: Digest,
        run_revision: Revision,
        outcome: CanaryRunOutcome,
        started_at: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<Self, ModelError> {
        if endpoint_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "run endpoint digest",
            });
        }
        if completed_at.is_some_and(|completed| completed < started_at) {
            return Err(ModelError::Invalid {
                field: "run completion timestamp",
            });
        }
        let mut run = Self {
            run_id,
            canary_name,
            canary_revision,
            endpoint_digest,
            run_revision,
            outcome,
            started_at,
            completed_at,
            run_digest: Digest::zero(),
        };
        run.run_digest = run.recomputed_digest();
        Ok(run)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&CanaryRunBody {
            run_id: &self.run_id,
            canary_name: &self.canary_name,
            canary_revision: self.canary_revision,
            endpoint_digest: &self.endpoint_digest,
            run_revision: self.run_revision,
            outcome: self.outcome,
            started_at: &self.started_at,
            completed_at: &self.completed_at,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.endpoint_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "run endpoint digest",
            });
        }
        if self
            .completed_at
            .is_some_and(|completed| completed < self.started_at)
        {
            return Err(ModelError::Invalid {
                field: "run completion timestamp",
            });
        }
        if self.run_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "run digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryReadOperation {
    GetCanaryRuns,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryReadRequest {
    pub operation: CanaryReadOperation,
    pub scope_digest: Digest,
    pub canary_name: CanaryName,
    pub canary_revision: Revision,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_retries: u8,
    pub max_response_bytes: usize,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CanaryReadQueryBody<'a> {
    operation: CanaryReadOperation,
    scope_digest: &'a Digest,
    canary_name: &'a CanaryName,
    canary_revision: Revision,
    page_size: u16,
    max_pages: u16,
    max_retries: u8,
    max_response_bytes: usize,
}

impl CanaryReadRequest {
    pub fn for_scope(
        scope: &AwsSyntheticsScope,
        page_size: u16,
        max_pages: u16,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE {
            return Err(ModelError::Invalid {
                field: "canary page size",
            });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "canary page budget",
            });
        }
        let mut request = Self {
            operation: CanaryReadOperation::GetCanaryRuns,
            scope_digest: scope.digest(),
            canary_name: scope.target.canary_name.clone(),
            canary_revision: scope.target.canary_revision,
            page_size,
            max_pages,
            max_retries: MAX_RETRIES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            cursor: None,
            query_digest: Digest::zero(),
        };
        request.query_digest = request.recomputed_query_digest();
        Ok(request)
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Result<Self, ModelError> {
        if let Some(cursor) = cursor {
            if cursor
                .binding_digest()
                .is_some_and(|binding| binding != &self.query_digest)
            {
                return Err(ModelError::ScopeMismatch {
                    field: "cursor query binding",
                });
            }
            self.cursor = Some(cursor.bind(&self.query_digest));
        } else {
            self.cursor = None;
        }
        Ok(self)
    }

    pub fn validate_against(
        &self,
        scope: &AwsSyntheticsScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        if self.operation != CanaryReadOperation::GetCanaryRuns
            || self.scope_digest != scope.digest()
            || self.canary_name != scope.target.canary_name
            || self.canary_revision != scope.target.canary_revision
        {
            return Err(ModelError::ScopeMismatch {
                field: "canary read request scope",
            });
        }
        if scope.permission_digest != permission.digest()
            || !permission.allows(PermissionAction::GetCanaryRuns)
        {
            return Err(ModelError::ScopeMismatch {
                field: "canary read permission",
            });
        }
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_retries > MAX_RETRIES
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::Invalid {
                field: "canary read bounds",
            });
        }
        if self.query_digest != self.recomputed_query_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "canary query digest",
            });
        }
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.binding_digest() != Some(&self.query_digest))
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        Ok(())
    }

    fn recomputed_query_digest(&self) -> Digest {
        digest_serialized(&CanaryReadQueryBody {
            operation: self.operation,
            scope_digest: &self.scope_digest,
            canary_name: &self.canary_name,
            canary_revision: self.canary_revision,
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_retries: self.max_retries,
            max_response_bytes: self.max_response_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryRunPage {
    pub page_number: u16,
    pub runs: Vec<CanaryRun>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CanaryRunPageBody<'a> {
    page_number: u16,
    runs: &'a [CanaryRun],
    next_token_digest: Option<&'a Digest>,
    next_binding_digest: Option<&'a Digest>,
    response_bytes: usize,
    provider_revision: &'a ProviderRevision,
}

impl CanaryRunPage {
    pub fn new(
        page_number: u16,
        runs: Vec<CanaryRun>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if page_number == 0 {
            return Err(ModelError::MustBePositive {
                field: "canary page number",
            });
        }
        if runs.len() > MAX_RUNS_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "canary runs per page",
            });
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooMany {
                field: "canary response bytes",
            });
        }
        let mut run_ids = BTreeSet::new();
        for run in &runs {
            run.validate()?;
            if !run_ids.insert(run.run_id.clone()) {
                return Err(ModelError::Duplicate {
                    field: "canary run id",
                });
            }
        }
        let mut page = Self {
            page_number,
            runs,
            next_cursor,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn recomputed_digest(&self) -> Digest {
        let (next_token_digest, next_binding_digest) =
            self.next_cursor.as_ref().map_or((None, None), |cursor| {
                (Some(cursor.token_digest()), cursor.binding_digest())
            });
        digest_serialized(&CanaryRunPageBody {
            page_number: self.page_number,
            runs: &self.runs,
            next_token_digest,
            next_binding_digest,
            response_bytes: self.response_bytes,
            provider_revision: &self.provider_revision,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "canary page digest",
            });
        }
        if self.runs.len() > MAX_RUNS_PER_PAGE || self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooMany {
                field: "canary page bounds",
            });
        }
        for run in &self.runs {
            run.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryEvidence {
    pub operation: CanaryReadOperation,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provenance: TransportProvenance,
    pub state: EvidenceState,
    pub runs: Vec<CanaryRun>,
    pub page_digests: Vec<Digest>,
    pub pages_read: u16,
    pub requests_made: u16,
    pub retries: u8,
    pub truncated: bool,
    pub partial_reason: Option<PartialReason>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub evidence_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CanaryEvidenceBody<'a> {
    operation: CanaryReadOperation,
    query_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    provenance: TransportProvenance,
    state: EvidenceState,
    runs: &'a [CanaryRun],
    page_digests: &'a [Digest],
    pages_read: u16,
    requests_made: u16,
    retries: u8,
    truncated: bool,
    partial_reason: Option<PartialReason>,
    provider_errors: &'a [ProviderErrorEvidence],
}

impl CanaryEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: CanaryReadOperation,
        query_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        api_digest: Digest,
        contract_digest: Digest,
        provenance: TransportProvenance,
        runs: Vec<CanaryRun>,
        page_digests: Vec<Digest>,
        pages_read: u16,
        requests_made: u16,
        retries: u8,
        truncated: bool,
        partial_reason: Option<PartialReason>,
        provider_errors: Vec<ProviderErrorEvidence>,
    ) -> Result<Self, ModelError> {
        if runs.len() > MAX_RUNS {
            return Err(ModelError::TooMany {
                field: "canary evidence runs",
            });
        }
        if page_digests.len() > usize::from(MAX_PAGES)
            || usize::from(pages_read) != page_digests.len()
            || pages_read > MAX_PAGES
            || requests_made == 0
            || requests_made > MAX_REQUESTS_PER_READ
            || retries > MAX_RETRIES
            || usize::from(retries) > usize::from(requests_made)
            || usize::from(pages_read) > usize::from(requests_made)
            || provider_errors.len() > usize::from(requests_made)
            || (partial_reason.is_some() && !truncated)
        {
            return Err(ModelError::Invalid {
                field: "canary evidence bounds",
            });
        }
        if query_digest == Digest::zero()
            || scope_digest == Digest::zero()
            || permission_digest == Digest::zero()
            || provider_digest == Digest::zero()
            || api_digest == Digest::zero()
            || contract_digest == Digest::zero()
        {
            return Err(ModelError::Invalid {
                field: "canary evidence digest binding",
            });
        }
        let state = evidence_state(&runs, partial_reason, &provider_errors);
        let mut evidence = Self {
            operation,
            query_digest,
            scope_digest,
            permission_digest,
            provider_digest,
            provider_revision,
            api_digest,
            contract_digest,
            provenance,
            state,
            runs,
            page_digests,
            pages_read,
            requests_made,
            retries,
            truncated,
            partial_reason,
            provider_errors,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        Ok(evidence)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&CanaryEvidenceBody {
            operation: self.operation,
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            provenance: self.provenance,
            state: self.state,
            runs: &self.runs,
            page_digests: &self.page_digests,
            pages_read: self.pages_read,
            requests_made: self.requests_made,
            retries: self.retries,
            truncated: self.truncated,
            partial_reason: self.partial_reason,
            provider_errors: &self.provider_errors,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.runs.len() > MAX_RUNS
            || self.page_digests.len() > usize::from(MAX_PAGES)
            || usize::from(self.pages_read) != self.page_digests.len()
            || self.pages_read > MAX_PAGES
            || self.requests_made == 0
            || self.requests_made > MAX_REQUESTS_PER_READ
            || self.retries > MAX_RETRIES
            || usize::from(self.retries) > usize::from(self.requests_made)
            || usize::from(self.pages_read) > usize::from(self.requests_made)
            || self.provider_errors.len() > usize::from(self.requests_made)
            || (self.partial_reason.is_some() && !self.truncated)
            || self.query_digest == Digest::zero()
            || self.scope_digest == Digest::zero()
            || self.permission_digest == Digest::zero()
            || self.provider_digest == Digest::zero()
            || self.api_digest == Digest::zero()
            || self.contract_digest == Digest::zero()
        {
            return Err(ModelError::Invalid {
                field: "canary evidence binding",
            });
        }
        for run in &self.runs {
            run.validate()?;
        }
        if self.state != evidence_state(&self.runs, self.partial_reason, &self.provider_errors)
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "canary evidence digest or state",
            });
        }
        Ok(())
    }
}

pub fn sort_runs(runs: &mut [CanaryRun]) {
    runs.sort_by(|left, right| {
        right
            .started_at
            .cmp(&left.started_at)
            .then_with(|| right.run_revision.cmp(&left.run_revision))
            .then_with(|| left.run_id.cmp(&right.run_id))
    });
}

pub fn evidence_state(
    runs: &[CanaryRun],
    partial_reason: Option<PartialReason>,
    provider_errors: &[ProviderErrorEvidence],
) -> EvidenceState {
    if let Some(reason) = partial_reason {
        return match reason {
            PartialReason::AccessLoss => EvidenceState::AccessLoss,
            PartialReason::Throttled => EvidenceState::Throttled,
            PartialReason::Timeout => EvidenceState::Timeout,
            PartialReason::BlockedEnv => EvidenceState::ProviderUnknown,
            PartialReason::ProviderError
                if provider_errors
                    .first()
                    .is_some_and(|error| error.kind == ProviderErrorKind::Replay) =>
            {
                EvidenceState::ProviderUnknown
            }
            _ => EvidenceState::Partial,
        };
    }
    if runs.is_empty() {
        if let Some(error) = provider_errors.first() {
            return match error.kind {
                ProviderErrorKind::AccessDenied | ProviderErrorKind::NotFound => {
                    EvidenceState::AccessLoss
                }
                ProviderErrorKind::Throttled => EvidenceState::Throttled,
                ProviderErrorKind::Timeout => EvidenceState::Timeout,
                _ => EvidenceState::ProviderUnknown,
            };
        }
        return EvidenceState::ProviderUnknown;
    }
    if runs
        .iter()
        .any(|run| run.outcome == CanaryRunOutcome::Failed)
    {
        return EvidenceState::Failed;
    }
    if runs
        .iter()
        .any(|run| run.outcome == CanaryRunOutcome::Running)
    {
        return EvidenceState::Running;
    }
    if runs
        .iter()
        .any(|run| run.outcome == CanaryRunOutcome::Stopped)
    {
        return EvidenceState::Stopped;
    }
    if runs
        .iter()
        .any(|run| run.outcome == CanaryRunOutcome::Unknown)
    {
        return EvidenceState::Unknown;
    }
    EvidenceState::Passed
}

pub type AwsSyntheticsCanaryScope = AwsSyntheticsScope;
pub type AwsSyntheticsCanaryRun = CanaryRun;
pub type AwsSyntheticsCanaryRunPage = CanaryRunPage;
pub type AwsSyntheticsCanaryEvidence = CanaryEvidence;
pub type AwsSyntheticsReadRequest = CanaryReadRequest;
pub type AwsSyntheticsReadOperation = CanaryReadOperation;
pub type AwsSyntheticsRunOutcome = CanaryRunOutcome;
pub type AwsSyntheticsEvidenceState = EvidenceState;

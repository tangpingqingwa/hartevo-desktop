//! Bounded, digest-bound values for the GitGuardian Layer-1 boundary.
//!
//! Provider text that could contain a secret, source content, a raw path, or
//! a raw cursor is hashed at the boundary. The model deliberately has no
//! field in which API-key material, service-account material, or occurrence
//! content can be retained.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{CONTRACT_VERSION, EVIDENCE_POLICY_INPUT, PROVIDER_API_REVISION, PROVIDER_ID};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 16;
pub const MAX_INCIDENTS: usize = 64;
pub const MAX_OCCURRENCES: usize = 128;
pub const MAX_DETECTORS: usize = 64;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_REQUESTS_PER_READ: usize = 8;
pub const MAX_PROVIDER_ERRORS: usize = 8;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 86_400;

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
    #[error("repository identity is invalid")]
    InvalidRepository,
    #[error("Git ref must be an exact refs/ value")]
    InvalidRef,
    #[error("commit SHA is invalid")]
    InvalidCommit,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("permission snapshot is empty, duplicated, or contains a write")]
    InvalidPermissions,
    #[error("query is invalid")]
    InvalidQuery,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("opaque cursor is invalid")]
    InvalidCursor,
    #[error("incident evidence is invalid")]
    InvalidIncident,
    #[error("occurrence evidence is invalid")]
    InvalidOccurrence,
    #[error("detector evidence is invalid")]
    InvalidDetector,
    #[error("redacted receipt is invalid")]
    InvalidReceipt,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or SecretReference is already revoked")]
    AlreadyRevoked,
    #[error("registration is not reversible in its current state")]
    NotReversible,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts<I, S>(domain: &str, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field.as_ref());
        }
        Self::from_bytes(&bytes)
    }

    #[must_use]
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

    #[must_use]
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    #[must_use]
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

macro_rules! identifier_type {
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

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
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

identifier_type!(WorkspaceId);
identifier_type!(PerimeterId);
identifier_type!(IncidentId);
identifier_type!(OccurrenceId);
identifier_type!(DetectorId);
identifier_type!(ProjectId);
identifier_type!(MissionId);
identifier_type!(WorkProductId);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryIdentity {
    owner: String,
    name: String,
}

impl RepositoryIdentity {
    pub fn from_parts(
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let owner = owner.into();
        let name = name.into();
        if valid_identifier(&owner)
            && valid_identifier(&name)
            && !owner.contains('/')
            && !name.contains('/')
        {
            Ok(Self { owner, name })
        } else {
            Err(ModelError::InvalidRepository)
        }
    }

    pub fn from_full_name(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some((owner, name)) = value.split_once('/') else {
            return Err(ModelError::InvalidRepository);
        };
        Self::from_parts(owner, name)
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gitguardian-repository/v1",
            [self.owner.clone(), self.name.clone()],
        )
    }
}

impl fmt::Display for RepositoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.owner, self.name)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RefName(String);

impl RefName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_text(&value, MAX_IDENTIFIER_BYTES, false) && value.starts_with("refs/") {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRef)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let valid_length = (7..=64).contains(&value.len());
        let valid_hex = value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if valid_length && valid_hex {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidCommit)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
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
        if project_revision.get() == 0
            || mission_revision.get() == 0
            || work_product_revision.get() == 0
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitGuardianAuthKind {
    ApiKey,
    ServiceAccount,
}

impl GitGuardianAuthKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::ServiceAccount => "service_account",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitGuardianPermission {
    IncidentsRead,
    OccurrencesRead,
    DetectorsRead,
    StatusRead,
}

impl GitGuardianPermission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IncidentsRead => "incidents:read",
            Self::OccurrencesRead => "occurrences:read",
            Self::DetectorsRead => "detectors:read",
            Self::StatusRead => "status:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PermissionSnapshot(BTreeSet<GitGuardianPermission>);

impl PermissionSnapshot {
    pub fn new<I>(permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = GitGuardianPermission>,
    {
        let permissions: Vec<_> = permissions.into_iter().collect();
        let set: BTreeSet<_> = permissions.iter().copied().collect();
        if permissions.is_empty() || permissions.len() != set.len() {
            return Err(ModelError::InvalidPermissions);
        }
        Ok(Self(set))
    }

    #[must_use]
    pub fn least_privilege() -> Self {
        Self(
            [
                GitGuardianPermission::IncidentsRead,
                GitGuardianPermission::OccurrencesRead,
                GitGuardianPermission::DetectorsRead,
                GitGuardianPermission::StatusRead,
            ]
            .into_iter()
            .collect(),
        )
    }

    #[must_use]
    pub fn contains(&self, permission: GitGuardianPermission) -> bool {
        self.0.contains(&permission)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<GitGuardianPermission> {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.0.is_empty() || self.0.len() > 4 {
            return Err(ModelError::InvalidPermissions);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentStatus {
    Open,
    Resolved,
    Ignored,
    Unknown,
}

impl IncidentStatus {
    #[must_use]
    pub const fn as_api_value(self) -> &'static str {
        match self {
            Self::Open => "TRIGGERED",
            Self::Resolved => "RESOLVED",
            Self::Ignored => "IGNORED",
            Self::Unknown => "UNKNOWN",
        }
    }

    #[must_use]
    pub const fn evidence_state(self) -> EvidenceStatus {
        match self {
            Self::Open => EvidenceStatus::Open,
            Self::Resolved => EvidenceStatus::Resolved,
            Self::Ignored => EvidenceStatus::Ignored,
            Self::Unknown => EvidenceStatus::Unknown,
        }
    }
}

pub type GitGuardianIncidentStatus = IncidentStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityStatus {
    Valid,
    Invalid,
    FailedToCheck,
    NoChecker,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    Specific,
    Generic,
    Custom,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrencePresence {
    Present,
    Removed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Open,
    Resolved,
    Ignored,
    Unknown,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

pub type GitGuardianResultState = EvidenceStatus;
pub type GitGuardianEvidenceState = EvidenceStatus;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueCursor {
    token_digest: Digest,
}

impl OpaqueCursor {
    pub fn new(raw_cursor: impl Into<String>) -> Result<Self, ModelError> {
        let raw_cursor = raw_cursor.into();
        if !valid_text(&raw_cursor, MAX_CURSOR_BYTES, false) {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token_digest: Digest::from_text(raw_cursor),
        })
    }

    pub fn from_digest(token_digest: Digest) -> Result<Self, ModelError> {
        token_digest
            .validate()
            .map_err(|_| ModelError::InvalidCursor)?;
        Ok(Self { token_digest })
    }

    #[must_use]
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.token_digest
            .validate()
            .map_err(|_| ModelError::InvalidCursor)
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianQuery {
    pub statuses: BTreeSet<IncidentStatus>,
    pub severity_allowlist: BTreeSet<Severity>,
    pub validity_allowlist: BTreeSet<ValidityStatus>,
    pub include_occurrences: bool,
    pub include_detector: bool,
    pub page_size: u16,
    pub max_pages: u16,
}

impl GitGuardianQuery {
    #[must_use]
    pub fn all() -> Self {
        Self {
            statuses: [
                IncidentStatus::Open,
                IncidentStatus::Resolved,
                IncidentStatus::Ignored,
                IncidentStatus::Unknown,
            ]
            .into_iter()
            .collect(),
            severity_allowlist: [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
                Severity::Unknown,
            ]
            .into_iter()
            .collect(),
            validity_allowlist: [
                ValidityStatus::Valid,
                ValidityStatus::Invalid,
                ValidityStatus::FailedToCheck,
                ValidityStatus::NoChecker,
                ValidityStatus::Unknown,
            ]
            .into_iter()
            .collect(),
            include_occurrences: true,
            include_detector: true,
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
        }
    }

    pub fn new(
        statuses: impl IntoIterator<Item = IncidentStatus>,
        severity_allowlist: impl IntoIterator<Item = Severity>,
        validity_allowlist: impl IntoIterator<Item = ValidityStatus>,
        page_size: u16,
        max_pages: u16,
    ) -> Result<Self, ModelError> {
        let query = Self {
            statuses: statuses.into_iter().collect(),
            severity_allowlist: severity_allowlist.into_iter().collect(),
            validity_allowlist: validity_allowlist.into_iter().collect(),
            include_occurrences: true,
            include_detector: true,
            page_size,
            max_pages,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.statuses.is_empty()
            || self.severity_allowlist.is_empty()
            || self.validity_allowlist.is_empty()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            Err(ModelError::InvalidQuery)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    #[must_use]
    pub fn query_digest_for_request(&self, page: u16, cursor: Option<&OpaqueCursor>) -> Digest {
        Digest::from_serialized(&(self, page, self.page_size, cursor))
    }

    #[must_use]
    pub fn allows(&self, status: IncidentStatus) -> bool {
        self.statuses.contains(&status)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedRateReceipt {
    pub limited: bool,
    pub retry_after_seconds: Option<u32>,
    pub limit_digest: Digest,
    pub remaining_digest: Digest,
}

impl RedactedRateReceipt {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            limited: false,
            retry_after_seconds: None,
            limit_digest: Digest::zero(),
            remaining_digest: Digest::zero(),
        }
    }

    pub fn new(
        limited: bool,
        retry_after_seconds: Option<u32>,
        limit: impl AsRef<str>,
        remaining: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        if retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS) {
            return Err(ModelError::InvalidReceipt);
        }
        Ok(Self {
            limited,
            retry_after_seconds,
            limit_digest: Digest::from_text(limit.as_ref().as_bytes()),
            remaining_digest: Digest::from_text(remaining.as_ref().as_bytes()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedRequestReceipt {
    pub method: String,
    pub endpoint_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_status: Option<u16>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
}

impl RedactedRequestReceipt {
    pub fn new(
        method: impl Into<String>,
        endpoint_digest: Digest,
        request_digest: Digest,
        response_digest: Digest,
        response_status: Option<u16>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        let method = method.into();
        if method != "GET"
            || endpoint_digest.validate().is_err()
            || request_digest.validate().is_err()
            || response_digest.validate().is_err()
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::InvalidReceipt);
        }
        Ok(Self {
            method,
            endpoint_digest,
            request_digest,
            response_digest,
            response_status,
            response_bytes,
            provenance,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianDetector {
    pub detector_name_digest: Digest,
    pub category_digest: Digest,
    pub kind: DetectorKind,
    pub status: DetectorStatus,
    pub active: bool,
    pub open_incidents_count: u32,
    pub ignored_incidents_count: u32,
    pub resolved_incidents_count: u32,
    pub detector_digest: Digest,
}

impl GitGuardianDetector {
    pub fn from_provider_text(
        detector_name: impl AsRef<str>,
        category: impl AsRef<str>,
        kind: DetectorKind,
        status: DetectorStatus,
        active: bool,
        open_incidents_count: u32,
        ignored_incidents_count: u32,
        resolved_incidents_count: u32,
    ) -> Result<Self, ModelError> {
        let detector_name_digest = Digest::from_text(detector_name.as_ref().as_bytes());
        let category_digest = Digest::from_text(category.as_ref().as_bytes());
        let detector_digest = Digest::from_serialized(&(
            &detector_name_digest,
            &category_digest,
            kind,
            status,
            active,
            open_incidents_count,
            ignored_incidents_count,
            resolved_incidents_count,
        ));
        Ok(Self {
            detector_name_digest,
            category_digest,
            kind,
            status,
            active,
            open_incidents_count,
            ignored_incidents_count,
            resolved_incidents_count,
            detector_digest,
        })
    }

    pub fn validate_for_scope(&self, scope: &GitGuardianScope) -> Result<(), ModelError> {
        if self.detector_name_digest != scope.detector_id.digest()
            || self.detector_digest != self.computed_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.detector_name_digest,
            &self.category_digest,
            self.kind,
            self.status,
            self.active,
            self.open_incidents_count,
            self.ignored_incidents_count,
            self.resolved_incidents_count,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianIncidentInput {
    pub incident_id: IncidentId,
    pub status: IncidentStatus,
    pub severity: Severity,
    pub validity: ValidityStatus,
    pub detector_digest: Digest,
    pub workspace_digest: Digest,
    pub perimeter_digest: Digest,
    pub repository_digest: Digest,
    pub commit_digest: Digest,
    pub occurrence_count: u16,
    pub opened_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub has_more_occurrences: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianIncident {
    pub incident_id: IncidentId,
    pub status: IncidentStatus,
    pub severity: Severity,
    pub validity: ValidityStatus,
    pub detector_digest: Digest,
    pub workspace_digest: Digest,
    pub perimeter_digest: Digest,
    pub repository_digest: Digest,
    pub commit_digest: Digest,
    pub occurrence_count: u16,
    pub opened_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub has_more_occurrences: bool,
    pub incident_digest: Digest,
}

impl GitGuardianIncident {
    pub fn new(input: GitGuardianIncidentInput) -> Result<Self, ModelError> {
        for digest in [
            &input.detector_digest,
            &input.workspace_digest,
            &input.perimeter_digest,
            &input.repository_digest,
            &input.commit_digest,
        ] {
            digest.validate()?;
        }
        if input.occurrence_count as usize > MAX_OCCURRENCES
            || input.status == IncidentStatus::Resolved && input.resolved_at.is_none()
            || input.status == IncidentStatus::Open && input.resolved_at.is_some()
        {
            return Err(ModelError::InvalidIncident);
        }
        let incident_digest = Digest::from_serialized(&input);
        Ok(Self {
            incident_id: input.incident_id,
            status: input.status,
            severity: input.severity,
            validity: input.validity,
            detector_digest: input.detector_digest,
            workspace_digest: input.workspace_digest,
            perimeter_digest: input.perimeter_digest,
            repository_digest: input.repository_digest,
            commit_digest: input.commit_digest,
            occurrence_count: input.occurrence_count,
            opened_at: input.opened_at,
            resolved_at: input.resolved_at,
            has_more_occurrences: input.has_more_occurrences,
            incident_digest,
        })
    }

    pub fn validate_for_scope(&self, scope: &GitGuardianScope) -> Result<(), ModelError> {
        if self.incident_id != scope.incident_id
            || self.detector_digest != scope.detector_id.digest()
            || self.workspace_digest != scope.workspace_id.digest()
            || self.perimeter_digest != scope.perimeter_id.digest()
            || self.repository_digest != scope.repository.digest()
            || self.commit_digest != scope.commit.digest()
            || self.incident_digest != self.computed_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&GitGuardianIncidentInput {
            incident_id: self.incident_id.clone(),
            status: self.status,
            severity: self.severity,
            validity: self.validity,
            detector_digest: self.detector_digest.clone(),
            workspace_digest: self.workspace_digest.clone(),
            perimeter_digest: self.perimeter_digest.clone(),
            repository_digest: self.repository_digest.clone(),
            commit_digest: self.commit_digest.clone(),
            occurrence_count: self.occurrence_count,
            opened_at: self.opened_at,
            resolved_at: self.resolved_at,
            has_more_occurrences: self.has_more_occurrences,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianOccurrenceInput {
    pub occurrence_id: OccurrenceId,
    pub incident_digest: Digest,
    pub detector_digest: Digest,
    pub workspace_digest: Digest,
    pub perimeter_digest: Digest,
    pub repository_digest: Digest,
    pub commit_digest: Digest,
    pub status: IncidentStatus,
    pub presence: OccurrencePresence,
    pub location_digest: Digest,
    pub first_seen_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianOccurrence {
    pub occurrence_id: OccurrenceId,
    pub incident_digest: Digest,
    pub detector_digest: Digest,
    pub workspace_digest: Digest,
    pub perimeter_digest: Digest,
    pub repository_digest: Digest,
    pub commit_digest: Digest,
    pub status: IncidentStatus,
    pub presence: OccurrencePresence,
    pub location_digest: Digest,
    pub first_seen_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub occurrence_digest: Digest,
}

impl GitGuardianOccurrence {
    pub fn new(input: GitGuardianOccurrenceInput) -> Result<Self, ModelError> {
        for digest in [
            &input.incident_digest,
            &input.detector_digest,
            &input.workspace_digest,
            &input.perimeter_digest,
            &input.repository_digest,
            &input.commit_digest,
            &input.location_digest,
        ] {
            digest.validate()?;
        }
        let occurrence_digest = Digest::from_serialized(&input);
        Ok(Self {
            occurrence_id: input.occurrence_id,
            incident_digest: input.incident_digest,
            detector_digest: input.detector_digest,
            workspace_digest: input.workspace_digest,
            perimeter_digest: input.perimeter_digest,
            repository_digest: input.repository_digest,
            commit_digest: input.commit_digest,
            status: input.status,
            presence: input.presence,
            location_digest: input.location_digest,
            first_seen_at: input.first_seen_at,
            last_seen_at: input.last_seen_at,
            occurrence_digest,
        })
    }

    pub fn validate_for_scope(&self, scope: &GitGuardianScope) -> Result<(), ModelError> {
        if self.occurrence_id != scope.occurrence_id
            || self.detector_digest != scope.detector_id.digest()
            || self.workspace_digest != scope.workspace_id.digest()
            || self.perimeter_digest != scope.perimeter_id.digest()
            || self.repository_digest != scope.repository.digest()
            || self.commit_digest != scope.commit.digest()
            || self.occurrence_digest != self.computed_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&GitGuardianOccurrenceInput {
            occurrence_id: self.occurrence_id.clone(),
            incident_digest: self.incident_digest.clone(),
            detector_digest: self.detector_digest.clone(),
            workspace_digest: self.workspace_digest.clone(),
            perimeter_digest: self.perimeter_digest.clone(),
            repository_digest: self.repository_digest.clone(),
            commit_digest: self.commit_digest.clone(),
            status: self.status,
            presence: self.presence,
            location_digest: self.location_digest.clone(),
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianScope {
    pub workspace_id: WorkspaceId,
    pub perimeter_id: PerimeterId,
    pub incident_id: IncidentId,
    pub occurrence_id: OccurrenceId,
    pub detector_id: DetectorId,
    pub repository: RepositoryIdentity,
    pub commit: CommitSha,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permissions: PermissionSnapshot,
    pub query: GitGuardianQuery,
    pub evidence_policy_digest: Digest,
    scope_digest: Digest,
}

pub type GitGuardianSecretResultScope = GitGuardianScope;
pub type SecretResultScope = GitGuardianScope;

impl GitGuardianScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        perimeter_id: PerimeterId,
        incident_id: IncidentId,
        occurrence_id: OccurrenceId,
        detector_id: DetectorId,
        repository: RepositoryIdentity,
        commit: CommitSha,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permissions: PermissionSnapshot,
        query: GitGuardianQuery,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            workspace_id,
            perimeter_id,
            incident_id,
            occurrence_id,
            detector_id,
            repository,
            commit,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            permissions,
            query,
            evidence_policy_digest: Digest::from_text(EVIDENCE_POLICY_INPUT),
            scope_digest: Digest::zero(),
        };
        let mut scope = scope;
        scope.scope_digest = scope.computed_digest();
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        workspace_id: WorkspaceId,
        perimeter_id: PerimeterId,
        incident_id: IncidentId,
        occurrence_id: OccurrenceId,
        detector_id: DetectorId,
        repository: RepositoryIdentity,
        commit: CommitSha,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permissions: PermissionSnapshot,
        query: GitGuardianQuery,
    ) -> Result<Self, ModelError> {
        Self::new(
            workspace_id,
            perimeter_id,
            incident_id,
            occurrence_id,
            detector_id,
            repository,
            commit,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            permissions,
            query,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permissions.validate()?;
        self.query.validate()?;
        self.evidence_policy_digest.validate()?;
        for revision in [
            self.project_revision,
            self.mission_revision,
            self.work_product_revision,
        ] {
            if revision.get() == 0 {
                return Err(ModelError::InvalidScope);
            }
        }
        if self.scope_digest != self.computed_digest() {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> Digest {
        self.query.digest()
    }

    #[must_use]
    pub fn workspace_digest(&self) -> Digest {
        self.workspace_id.digest()
    }

    #[must_use]
    pub fn perimeter_digest(&self) -> Digest {
        self.perimeter_id.digest()
    }

    #[must_use]
    pub fn evidence_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "gitguardian-evidence-binding/v1",
            [
                self.scope_digest.to_string(),
                self.query_digest().to_string(),
                self.evidence_policy_digest.to_string(),
                CONTRACT_VERSION.to_owned(),
            ],
        )
    }

    #[must_use]
    pub fn mission_binding(&self) -> MissionScopeBinding {
        MissionScopeBinding {
            project_id: self.project_id.clone(),
            project_revision: self.project_revision,
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision,
            work_product_id: self.work_product_id.clone(),
            work_product_revision: self.work_product_revision,
        }
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.workspace_id,
            &self.perimeter_id,
            &self.incident_id,
            &self.occurrence_id,
            &self.detector_id,
            &self.repository,
            &self.commit,
            &self.project_id,
            self.project_revision,
            &self.mission_id,
            self.mission_revision,
            &self.work_product_id,
            self.work_product_revision,
            &self.permissions,
            &self.query,
            &self.evidence_policy_digest,
        ))
    }
}

/// Opaque credential boundary. The constructor hashes the caller-provided
/// reference and then drops the raw value; this type intentionally does not
/// implement `Serialize` or `Deserialize`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    auth_kind: GitGuardianAuthKind,
    revoked: bool,
}

pub type GitGuardianSecretReference = SecretReference;

impl SecretReference {
    pub fn new(
        raw_reference: impl Into<String>,
        scope: &GitGuardianScope,
        revision: Revision,
        auth_kind: GitGuardianAuthKind,
    ) -> Result<Self, ModelError> {
        let raw_reference = raw_reference.into();
        if !valid_text(&raw_reference, MAX_SECRET_REFERENCE_BYTES, false) {
            return Err(ModelError::InvalidSecretReference);
        }
        scope.validate()?;
        Ok(Self {
            reference_digest: Digest::from_parts(
                "gitguardian-secret-reference/v1",
                [
                    raw_reference,
                    scope.scope_digest.to_string(),
                    revision.get().to_string(),
                    auth_kind.as_str().to_owned(),
                ],
            ),
            scope_digest: scope.digest(),
            revision,
            auth_kind,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn auth_kind(&self) -> GitGuardianAuthKind {
        self.auth_kind
    }

    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate_for_scope(&self, scope: &GitGuardianScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.scope_digest == *scope.scope_digest()
            && self.reference_digest.validate().is_ok()
            && self.revision.get() > 0
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
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
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianEvidence {
    pub state: EvidenceStatus,
    pub scope_digest: Digest,
    pub incident: GitGuardianIncident,
    pub occurrence: Option<GitGuardianOccurrence>,
    pub detector: Option<GitGuardianDetector>,
    pub response_receipts: Vec<RedactedRequestReceipt>,
    pub rate_receipts: Vec<RedactedRateReceipt>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub partial: bool,
    pub evidence_digest: Digest,
}

pub type GitGuardianSecretResultEvidence = GitGuardianEvidence;

impl GitGuardianEvidence {
    pub fn new(
        scope: &GitGuardianScope,
        incident: GitGuardianIncident,
        occurrence: Option<GitGuardianOccurrence>,
        detector: Option<GitGuardianDetector>,
        response_receipts: Vec<RedactedRequestReceipt>,
        rate_receipts: Vec<RedactedRateReceipt>,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        incident.validate_for_scope(scope)?;
        if response_receipts.len() > MAX_REQUESTS_PER_READ
            || response_receipts
                .iter()
                .any(|receipt| receipt.response_bytes > MAX_RESPONSE_BYTES)
            || rate_receipts.len() > MAX_PROVIDER_ERRORS
        {
            return Err(ModelError::InvalidReceipt);
        }
        if let Some(occurrence) = &occurrence {
            occurrence.validate_for_scope(scope)?;
            if occurrence.incident_digest != incident.incident_digest {
                return Err(ModelError::DigestMismatch);
            }
        }
        if let Some(detector) = &detector {
            detector.validate_for_scope(scope)?;
            if detector.detector_name_digest != incident.detector_digest {
                return Err(ModelError::DigestMismatch);
            }
        }
        let partial = occurrence.is_none() || detector.is_none() || incident.has_more_occurrences;
        let state = if partial {
            EvidenceStatus::Partial
        } else {
            incident.status.evidence_state()
        };
        let mut evidence = Self {
            state,
            scope_digest: scope.digest(),
            incident,
            occurrence,
            detector,
            response_receipts,
            rate_receipts,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            partial,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    pub fn validate_integrity(&self, scope: &GitGuardianScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.evidence_digest != self.computed_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        self.incident.validate_for_scope(scope)?;
        if let Some(occurrence) = &self.occurrence {
            occurrence.validate_for_scope(scope)?;
            if occurrence.incident_digest != self.incident.incident_digest {
                return Err(ModelError::DigestMismatch);
            }
        }
        if let Some(detector) = &self.detector {
            detector.validate_for_scope(scope)?;
            if detector.detector_name_digest != self.incident.detector_digest {
                return Err(ModelError::DigestMismatch);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.state,
            &self.scope_digest,
            &self.incident,
            &self.occurrence,
            &self.detector,
            &self.response_receipts,
            &self.rate_receipts,
            self.provenance,
            self.connected,
            self.native,
            self.first_party,
            self.partial,
        ))
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

impl fmt::Display for GitGuardianEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitGuardian evidence state={:?} evidence_digest={}",
            self.state, self.evidence_digest
        )
    }
}

// Keep these imports in the model module so the provider and service can use
// a single provenance vocabulary without adding another authority boundary.
#[allow(dead_code)]
const _PROVIDER_BOUNDARY_MARKER: (&str, &str) = (PROVIDER_ID, PROVIDER_API_REVISION);

//! Typed OneTrust consent scope, redacted evidence, and registration models.
//!
//! Provider payloads are deliberately not represented here. Only allowlisted
//! consent metadata, opaque subject hashes, bounded cursor digests, and
//! cryptographic request/response receipts cross the provider boundary.

use std::{
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    ONETRUST_CONSENT_WINDOW_HOURS, ONETRUST_CONTRACT_VERSION, ONETRUST_MAX_CONSENT_WINDOW_HOURS,
    ONETRUST_MAX_OBSERVATIONS, ONETRUST_MAX_PAGES, ONETRUST_MAX_RESPONSE_BYTES, ONETRUST_PAGE_SIZE,
    ONETRUST_PLUGIN_VERSION_TEXT, ONETRUST_PROVIDER_ID, ONETRUST_PROVIDER_REVISION_TEXT,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 4_096;
pub const MAX_CURSOR_BYTES: usize = 256;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OneTrustModelError {
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
    #[error("{field} is not a valid opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} exceeds the bounded list size")]
    TooMany { field: &'static str },
    #[error("consent window must be positive and no longer than 24 hours")]
    InvalidConsentWindow,
    #[error("cannot serialize canonical OneTrust value: {0}")]
    Serialization(String),
    #[error("provider response is not a bounded allowlisted shape: {0}")]
    InvalidResponse(String),
    #[error("provider policy revision is stale")]
    StalePolicyRevision,
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), OneTrustModelError> {
    if value.is_empty() {
        return Err(OneTrustModelError::Empty { field });
    }
    if value.len() > max {
        return Err(OneTrustModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(OneTrustModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(OneTrustModelError::InvalidCharacters { field });
    }
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || "-_.:/@".contains(character)
            || allow_internal_whitespace && character.is_whitespace())
    }) {
        return Err(OneTrustModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_secret_material(value: &str) -> Result<(), OneTrustModelError> {
    if value.is_empty() {
        return Err(OneTrustModelError::Empty {
            field: "secret reference",
        });
    }
    if value.len() > MAX_SECRET_REFERENCE_BYTES {
        return Err(OneTrustModelError::TooLong {
            field: "secret reference",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(OneTrustModelError::ControlCharacter {
            field: "secret reference",
        });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), OneTrustModelError> {
    if value == 0 {
        Err(OneTrustModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, OneTrustModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES, $whitespace)?;
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
            type Err = OneTrustModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(TenantId, "tenant id", false);
bounded_identifier!(Region, "region", false);
bounded_identifier!(PurposeId, "purpose id", false);
bounded_identifier!(PurposeVersion, "purpose version", false);
bounded_identifier!(CollectionPointId, "collection point", false);
bounded_identifier!(PolicyRevision, "policy revision", false);
bounded_identifier!(MissionId, "Mission id", false);
bounded_identifier!(ProjectId, "Project id", false);
bounded_identifier!(ConsentId, "consent id", false);
bounded_identifier!(WorkProductId, "Work Product id", false);
bounded_identifier!(ProviderRevision, "provider revision", false);

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hasher = Sha256::new();
        for field in fields {
            let value = field.as_ref();
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        Self(hex_encode(hasher.finalize().as_slice()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, OneTrustModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(OneTrustModelError::InvalidDigest { field: "digest" });
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, OneTrustModelError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| OneTrustModelError::Serialization(error.to_string()))?;
    Ok(sha256_digest(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, OneTrustModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An opaque provider-secret handle. The supplied value is hashed immediately
/// and is never retained, serialized, displayed, or passed to a transport.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
}

impl SecretReference {
    pub fn new(value: impl AsRef<str>) -> Result<Self, OneTrustModelError> {
        let value = value.as_ref();
        validate_secret_material(value)?;
        Ok(Self {
            digest: Digest::from_fields(["hartevo-onetrust-secret-v1", value]),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

/// A salted subject-reference digest bound to a scope fence. The subject and
/// salt are intentionally not retained after construction.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectReferenceHash {
    scope_digest: Digest,
    subject_hash: Digest,
}

impl SubjectReferenceHash {
    pub fn new(
        scope_digest: &Digest,
        salt: impl AsRef<str>,
        subject_reference: impl AsRef<str>,
    ) -> Result<Self, OneTrustModelError> {
        validate_secret_material(salt.as_ref())?;
        validate_secret_material(subject_reference.as_ref())?;
        Ok(Self {
            scope_digest: scope_digest.clone(),
            subject_hash: Digest::from_fields([
                "hartevo-onetrust-subject-v1",
                scope_digest.as_str(),
                salt.as_ref(),
                subject_reference.as_ref(),
            ]),
        })
    }

    pub fn from_subject(
        scope_digest: &Digest,
        salt: impl AsRef<str>,
        subject_reference: impl AsRef<str>,
    ) -> Result<Self, OneTrustModelError> {
        Self::new(scope_digest, salt, subject_reference)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.subject_hash
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SubjectReferenceHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubjectReferenceHash")
            .field("scope_digest", &self.scope_digest)
            .field("subject_hash", &"<opaque>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl ConsentWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, OneTrustModelError> {
        let window = Self { start, end };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), OneTrustModelError> {
        if self.end <= self.start
            || self.end - self.start > Duration::hours(ONETRUST_MAX_CONSENT_WINDOW_HOURS)
        {
            return Err(OneTrustModelError::InvalidConsentWindow);
        }
        Ok(())
    }

    pub fn contains(&self, instant: DateTime<Utc>) -> bool {
        instant >= self.start && instant <= self.end
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub id: ConsentId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ConsentBinding {
    pub fn new(id: ConsentId, revision: Revision, digest: Digest) -> Self {
        Self {
            id,
            revision,
            digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustConsentScope {
    pub tenant: TenantId,
    pub region: Region,
    pub purpose_id: PurposeId,
    pub purpose_version: PurposeVersion,
    pub collection_point: CollectionPointId,
    pub consent_window: ConsentWindow,
    pub subject_reference: SubjectReferenceHash,
    pub policy_revision: PolicyRevision,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub consent: ConsentBinding,
    pub work_product: WorkProductBinding,
    pub permission_digest: Digest,
}

impl OneTrustConsentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        region: Region,
        purpose_id: PurposeId,
        purpose_version: PurposeVersion,
        collection_point: CollectionPointId,
        consent_window: ConsentWindow,
        subject_reference: SubjectReferenceHash,
        policy_revision: PolicyRevision,
        mission: MissionBinding,
        project: ProjectBinding,
        consent: ConsentBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, OneTrustModelError> {
        let scope = Self {
            tenant,
            region,
            purpose_id,
            purpose_version,
            collection_point,
            consent_window,
            subject_reference,
            policy_revision,
            mission,
            project,
            consent,
            work_product,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), OneTrustModelError> {
        self.consent_window.validate()?;
        if !self.subject_reference.is_opaque()
            || self.subject_reference.scope_digest().as_str() == Digest::zero().as_str()
        {
            return Err(OneTrustModelError::Invalid {
                field: "scope-bound subject reference hash",
            });
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_fields([
            self.tenant.as_str().to_owned(),
            self.region.as_str().to_owned(),
            self.purpose_id.as_str().to_owned(),
            self.purpose_version.as_str().to_owned(),
            self.collection_point.as_str().to_owned(),
            self.consent_window.start.to_rfc3339(),
            self.consent_window.end.to_rfc3339(),
            self.subject_reference.scope_digest().as_str().to_owned(),
            self.subject_reference.digest().as_str().to_owned(),
            self.policy_revision.as_str().to_owned(),
            self.mission.id.as_str().to_owned(),
            self.mission.revision.get().to_string(),
            self.project.id.as_str().to_owned(),
            self.project.revision.get().to_string(),
            self.consent.id.as_str().to_owned(),
            self.consent.revision.get().to_string(),
            self.consent.digest.as_str().to_owned(),
            self.work_product.id.as_str().to_owned(),
            self.work_product.revision.get().to_string(),
            self.permission_digest.as_str().to_owned(),
        ])
    }

    pub fn subject_scope_digest(&self) -> &Digest {
        self.subject_reference.scope_digest()
    }

    pub fn expected_endpoints(&self) -> [OneTrustEndpoint; 3] {
        [
            OneTrustEndpoint::DataSubjectDetailsV4,
            OneTrustEndpoint::RealtimePreferencesV2,
            OneTrustEndpoint::TransactionsV2,
        ]
    }

    pub fn mission_revision(&self) -> Revision {
        self.mission.revision
    }

    pub fn project_revision(&self) -> Revision {
        self.project.revision
    }

    pub fn consent_revision(&self) -> Revision {
        self.consent.revision
    }

    pub fn work_product_revision(&self) -> Revision {
        self.work_product.revision
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentEvidenceStatus {
    Granted,
    Denied,
    Pending,
    Withdrawn,
    Expired,
    NoRecord,
    Partial,
    AccessLost,
    Stale,
    ProviderUnknown,
}

pub type ConsentStatus = ConsentEvidenceStatus;
pub type ConsentState = ConsentEvidenceStatus;

impl ConsentEvidenceStatus {
    pub const fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::Partial
                | Self::AccessLost
                | Self::Expired
                | Self::NoRecord
                | Self::Stale
                | Self::ProviderUnknown
                | Self::Denied
                | Self::Withdrawn
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OneTrustEndpoint {
    DataSubjectDetailsV4,
    RealtimePreferencesV2,
    TransactionsV2,
}

impl OneTrustEndpoint {
    pub const ALL: [Self; 3] = [
        Self::DataSubjectDetailsV4,
        Self::RealtimePreferencesV2,
        Self::TransactionsV2,
    ];

    pub const fn operation_name(self) -> &'static str {
        match self {
            Self::DataSubjectDetailsV4 => "get_datasubject_details_v4",
            Self::RealtimePreferencesV2 => "get_realtime_preferences_v2",
            Self::TransactionsV2 => "get_transactions_v2",
        }
    }

    pub const fn method(self) -> &'static str {
        match self {
            Self::TransactionsV2 => "POST",
            Self::DataSubjectDetailsV4 | Self::RealtimePreferencesV2 => "GET",
        }
    }

    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::DataSubjectDetailsV4 => "/rest/api/consent/v4/datasubjects/details",
            Self::RealtimePreferencesV2 => "/v2/preferences",
            Self::TransactionsV2 => "/api/consent/v2/transactions",
        }
    }

    pub const fn is_transaction_read(self) -> bool {
        matches!(self, Self::TransactionsV2)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, OneTrustModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(OneTrustModelError::InvalidCursor { field: "cursor" });
        }
        if value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "-_.~:/".contains(character)))
        {
            return Err(OneTrustModelError::InvalidCursor { field: "cursor" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(["hartevo-onetrust-cursor-v1", self.as_str()])
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("cursorDigest", &self.digest())?;
        value.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustReadRequest {
    pub endpoint: OneTrustEndpoint,
    pub scope_digest: Digest,
    pub tenant: TenantId,
    pub region: Region,
    pub subject_reference: SubjectReferenceHash,
    pub purpose_id: PurposeId,
    pub purpose_version: PurposeVersion,
    pub collection_point: CollectionPointId,
    pub policy_revision: PolicyRevision,
    pub consent_window: ConsentWindow,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub observed_at: DateTime<Utc>,
}

impl OneTrustReadRequest {
    pub fn new(
        endpoint: OneTrustEndpoint,
        scope: &OneTrustConsentScope,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, OneTrustModelError> {
        if page_size == 0
            || page_size > ONETRUST_PAGE_SIZE
            || max_pages == 0
            || max_pages > ONETRUST_MAX_PAGES
        {
            return Err(OneTrustModelError::Invalid {
                field: "read bounds",
            });
        }
        Ok(Self {
            endpoint,
            scope_digest: scope.scope_digest(),
            tenant: scope.tenant.clone(),
            region: scope.region.clone(),
            subject_reference: scope.subject_reference.clone(),
            purpose_id: scope.purpose_id.clone(),
            purpose_version: scope.purpose_version.clone(),
            collection_point: scope.collection_point.clone(),
            policy_revision: scope.policy_revision.clone(),
            consent_window: scope.consent_window.clone(),
            page_size,
            max_pages,
            cursor: None,
            observed_at,
        })
    }

    #[must_use]
    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Self {
        let mut request = self.clone();
        request.cursor = cursor;
        request
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustHttpRequest {
    pub method: String,
    pub origin: String,
    pub path_and_query: String,
    pub endpoint: OneTrustEndpoint,
    pub scope_digest: Digest,
    pub tenant: TenantId,
    pub region: Region,
    pub subject_reference: SubjectReferenceHash,
    pub purpose_id: PurposeId,
    pub purpose_version: PurposeVersion,
    pub collection_point: CollectionPointId,
    pub policy_revision: PolicyRevision,
    pub consent_window: ConsentWindow,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub body_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl OneTrustHttpRequest {
    pub fn from_read(request: &OneTrustReadRequest) -> Result<Self, OneTrustModelError> {
        let cursor_digest = request.cursor.as_ref().map(OpaqueCursor::digest);
        let mut path_and_query = format!(
            "{}?pageSize={}",
            request.endpoint.relative_path(),
            request.page_size
        );
        if let Some(cursor) = &request.cursor {
            path_and_query.push_str("&pageCursor=");
            path_and_query.push_str(cursor.as_str());
        }
        let origin = match request.endpoint {
            OneTrustEndpoint::RealtimePreferencesV2 => {
                "https://consent-api.onetrust.com".to_owned()
            }
            OneTrustEndpoint::DataSubjectDetailsV4 | OneTrustEndpoint::TransactionsV2 => {
                format!("https://{}.onetrust.com", request.tenant.as_str())
            }
        };
        let body_digest = request.endpoint.is_transaction_read().then(|| {
            Digest::from_fields([
                "hartevo-onetrust-transactions-body-v1",
                request.subject_reference.digest().as_str(),
                request.purpose_id.as_str(),
                request.purpose_version.as_str(),
                request.collection_point.as_str(),
                &request.consent_window.start.to_rfc3339(),
                &request.consent_window.end.to_rfc3339(),
                &request.page_size.to_string(),
                cursor_digest.as_ref().map_or("", Digest::as_str),
            ])
        });
        let request_digest = Digest::from_fields([
            "hartevo-onetrust-request-v1",
            request.endpoint.operation_name(),
            request.endpoint.method(),
            &origin,
            &path_and_query,
            request.tenant.as_str(),
            request.region.as_str(),
            request.scope_digest.as_str(),
            request.subject_reference.digest().as_str(),
            body_digest.as_ref().map_or("", Digest::as_str),
        ]);
        Ok(Self {
            method: request.endpoint.method().to_owned(),
            origin,
            path_and_query,
            endpoint: request.endpoint,
            scope_digest: request.scope_digest.clone(),
            tenant: request.tenant.clone(),
            region: request.region.clone(),
            subject_reference: request.subject_reference.clone(),
            purpose_id: request.purpose_id.clone(),
            purpose_version: request.purpose_version.clone(),
            collection_point: request.collection_point.clone(),
            policy_revision: request.policy_revision.clone(),
            consent_window: request.consent_window.clone(),
            page_size: request.page_size,
            cursor_digest,
            body_digest,
            request_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustRequestReceipt {
    pub method: String,
    pub origin: String,
    pub path_and_query: String,
    pub request_digest: Digest,
    pub body_digest: Option<Digest>,
    pub raw_subject_identifier_retained: bool,
    pub raw_jwt_retained: bool,
}

impl OneTrustRequestReceipt {
    pub fn from_request(request: &OneTrustHttpRequest) -> Self {
        Self {
            method: request.method.clone(),
            origin: request.origin.clone(),
            path_and_query: request.path_and_query.clone(),
            request_digest: request.request_digest.clone(),
            body_digest: request.body_digest.clone(),
            raw_subject_identifier_retained: false,
            raw_jwt_retained: false,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }

    pub fn validate(&self) -> Result<(), OneTrustModelError> {
        if self.request_digest.as_str() == Digest::zero().as_str()
            || self.raw_subject_identifier_retained
            || self.raw_jwt_retained
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust request receipt",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustResponseReceipt {
    pub status_code: u16,
    pub response_size_bytes: usize,
    pub response_digest: Digest,
    pub request_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub raw_provider_payload_retained: bool,
    pub raw_preference_payload_retained: bool,
    pub raw_pii_retained: bool,
    pub raw_jwt_retained: bool,
}

impl OneTrustResponseReceipt {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }

    pub fn validate(&self) -> Result<(), OneTrustModelError> {
        if self.response_size_bytes > ONETRUST_MAX_RESPONSE_BYTES
            || self.request_digest.as_str() == Digest::zero().as_str()
            || self.response_digest.as_str() == Digest::zero().as_str()
            || self.raw_provider_payload_retained
            || self.raw_preference_payload_retained
            || self.raw_pii_retained
            || self.raw_jwt_retained
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust response receipt",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OneTrustProviderErrorKind {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    CursorLoop,
    Tampered,
    StalePolicyRevision,
    Partial,
    InvalidResponse,
    BlockedEnv,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustProviderErrorEvidence {
    pub operation: String,
    pub kind: OneTrustProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retry_after_seconds: Option<u64>,
}

impl OneTrustProviderErrorEvidence {
    pub fn new(
        operation: impl Into<String>,
        kind: OneTrustProviderErrorKind,
        status_code: Option<u16>,
        detail: impl AsRef<str>,
        retry_after_seconds: Option<u64>,
    ) -> Self {
        Self {
            operation: operation.into(),
            kind,
            status_code,
            error_digest: Digest::from_fields(["hartevo-onetrust-error-v1", detail.as_ref()]),
            retry_after_seconds,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustConsentObservation {
    pub purpose_id: PurposeId,
    pub purpose_version: PurposeVersion,
    pub status: ConsentEvidenceStatus,
    pub consented_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub collection_point: CollectionPointId,
    pub transaction_id_digest: Option<Digest>,
    pub policy_revision: PolicyRevision,
    pub subject_reference: SubjectReferenceHash,
    pub source_digest: Digest,
    pub result_digest: Digest,
}

impl OneTrustConsentObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purpose_id: PurposeId,
        purpose_version: PurposeVersion,
        status: ConsentEvidenceStatus,
        consented_at: Option<DateTime<Utc>>,
        withdrawn_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
        collection_point: CollectionPointId,
        transaction_id_digest: Option<Digest>,
        policy_revision: PolicyRevision,
        subject_reference: SubjectReferenceHash,
        source_digest: Digest,
    ) -> Self {
        let result_digest = digest_serializable(&(
            &purpose_id,
            &purpose_version,
            status,
            consented_at,
            withdrawn_at,
            expires_at,
            &collection_point,
            &transaction_id_digest,
            &policy_revision,
            &subject_reference,
            &source_digest,
        ))
        .unwrap_or_else(|_| Digest::zero());
        Self {
            purpose_id,
            purpose_version,
            status,
            consented_at,
            withdrawn_at,
            expires_at,
            collection_point,
            transaction_id_digest,
            policy_revision,
            subject_reference,
            source_digest,
            result_digest,
        }
    }

    pub fn from_transaction_id(
        purpose_id: PurposeId,
        purpose_version: PurposeVersion,
        status: ConsentEvidenceStatus,
        collection_point: CollectionPointId,
        transaction_id: Option<&str>,
        policy_revision: PolicyRevision,
        subject_reference: SubjectReferenceHash,
        source_digest: Digest,
    ) -> Result<Self, OneTrustModelError> {
        if let Some(transaction_id) = transaction_id {
            validate_secret_material(transaction_id)?;
        }
        Ok(Self::new(
            purpose_id,
            purpose_version,
            status,
            None,
            None,
            None,
            collection_point,
            transaction_id
                .map(|value| Digest::from_fields(["hartevo-onetrust-transaction-v1", value])),
            policy_revision,
            subject_reference,
            source_digest,
        ))
    }

    pub fn validate_against(&self, scope: &OneTrustConsentScope) -> Result<(), OneTrustModelError> {
        if self.purpose_id != scope.purpose_id
            || self.purpose_version != scope.purpose_version
            || self.collection_point != scope.collection_point
            || self.subject_reference != scope.subject_reference
        {
            return Err(OneTrustModelError::Invalid {
                field: "consent evidence scope",
            });
        }
        if self.policy_revision != scope.policy_revision {
            return Err(OneTrustModelError::StalePolicyRevision);
        }
        self.validate_against_window(&scope.consent_window)?;
        let recomputed = digest_serializable(&(
            &self.purpose_id,
            &self.purpose_version,
            self.status,
            self.consented_at,
            self.withdrawn_at,
            self.expires_at,
            &self.collection_point,
            &self.transaction_id_digest,
            &self.policy_revision,
            &self.subject_reference,
            &self.source_digest,
        ))?;
        if recomputed != self.result_digest {
            return Err(OneTrustModelError::Invalid {
                field: "consent evidence result digest",
            });
        }
        Ok(())
    }

    pub fn validate_against_window(
        &self,
        window: &ConsentWindow,
    ) -> Result<(), OneTrustModelError> {
        if [self.consented_at, self.withdrawn_at, self.expires_at]
            .into_iter()
            .flatten()
            .any(|instant| !window.contains(instant))
        {
            return Err(OneTrustModelError::Invalid {
                field: "consent evidence event window",
            });
        }
        Ok(())
    }

    pub fn event_at(&self) -> Option<DateTime<Utc>> {
        self.withdrawn_at.or(self.consented_at).or(self.expires_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustResponseBody {
    pub observations: Vec<OneTrustConsentObservation>,
}

impl OneTrustResponseBody {
    pub fn new(observations: Vec<OneTrustConsentObservation>) -> Result<Self, OneTrustModelError> {
        if observations.len() > ONETRUST_MAX_OBSERVATIONS {
            return Err(OneTrustModelError::TooMany {
                field: "consent observations",
            });
        }
        Ok(Self { observations })
    }

    pub fn empty() -> Self {
        Self {
            observations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustHttpResponse {
    pub status_code: u16,
    pub body: OneTrustResponseBody,
    pub next_cursor: Option<OpaqueCursor>,
    pub receipt: OneTrustResponseReceipt,
}

impl OneTrustHttpResponse {
    pub fn from_body(
        request: &OneTrustHttpRequest,
        status_code: u16,
        body: OneTrustResponseBody,
        provider_revision: ProviderRevision,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, OneTrustModelError> {
        let encoded = serde_json::to_vec(&body)
            .map_err(|error| OneTrustModelError::Serialization(error.to_string()))?;
        if encoded.len() > ONETRUST_MAX_RESPONSE_BYTES {
            return Err(OneTrustModelError::TooLong {
                field: "provider response",
            });
        }
        Ok(Self {
            status_code,
            body,
            next_cursor,
            receipt: OneTrustResponseReceipt {
                status_code,
                response_size_bytes: encoded.len(),
                response_digest: sha256_digest(&encoded),
                request_digest: request.request_digest.clone(),
                provider_revision,
                raw_provider_payload_retained: false,
                raw_preference_payload_retained: false,
                raw_pii_retained: false,
                raw_jwt_retained: false,
            },
        })
    }

    pub fn body(&self) -> &OneTrustResponseBody {
        &self.body
    }

    pub fn receipt(&self) -> &OneTrustResponseReceipt {
        &self.receipt
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustReadEvidence {
    pub endpoint: OneTrustEndpoint,
    pub scope_digest: Digest,
    pub subject_reference: SubjectReferenceHash,
    pub observations: Vec<OneTrustConsentObservation>,
    pub pages_observed: u16,
    pub page_cursor_digests: Vec<Digest>,
    pub request_receipt_digests: Vec<Digest>,
    pub response_receipt_digests: Vec<Digest>,
    pub failures: Vec<OneTrustProviderErrorEvidence>,
    pub source_digest: Digest,
    pub result_digest: Digest,
    pub provenance: TransportProvenance,
}

impl OneTrustReadEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: OneTrustEndpoint,
        scope_digest: Digest,
        subject_reference: SubjectReferenceHash,
        observations: Vec<OneTrustConsentObservation>,
        pages_observed: u16,
        page_cursor_digests: Vec<Digest>,
        request_receipt_digests: Vec<Digest>,
        response_receipt_digests: Vec<Digest>,
        failures: Vec<OneTrustProviderErrorEvidence>,
        provenance: TransportProvenance,
    ) -> Result<Self, OneTrustModelError> {
        if observations.len() > ONETRUST_MAX_OBSERVATIONS {
            return Err(OneTrustModelError::TooMany {
                field: "consent observations",
            });
        }
        let source_digest = digest_serializable(&(
            endpoint,
            &scope_digest,
            &subject_reference,
            &request_receipt_digests,
            &response_receipt_digests,
            &failures,
            provenance,
        ))?;
        let result_digest = digest_serializable(&(
            &observations,
            &page_cursor_digests,
            pages_observed,
            &source_digest,
        ))?;
        let evidence = Self {
            endpoint,
            scope_digest,
            subject_reference,
            observations,
            pages_observed,
            page_cursor_digests,
            request_receipt_digests,
            response_receipt_digests,
            failures,
            source_digest,
            result_digest,
            provenance,
        };
        evidence.validate_integrity()?;
        Ok(evidence)
    }

    pub fn recompute_source_digest(&self) -> Result<Digest, OneTrustModelError> {
        digest_serializable(&(
            self.endpoint,
            &self.scope_digest,
            &self.subject_reference,
            &self.request_receipt_digests,
            &self.response_receipt_digests,
            &self.failures,
            self.provenance,
        ))
    }

    pub fn recompute_result_digest(&self) -> Result<Digest, OneTrustModelError> {
        let source_digest = self.recompute_source_digest()?;
        digest_serializable(&(
            &self.observations,
            &self.page_cursor_digests,
            self.pages_observed,
            &source_digest,
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), OneTrustModelError> {
        if self.pages_observed == 0
            || self.pages_observed > ONETRUST_MAX_PAGES
            || self.observations.len() > ONETRUST_MAX_OBSERVATIONS
            || self.request_receipt_digests.len() != usize::from(self.pages_observed)
            || self.response_receipt_digests.len() != usize::from(self.pages_observed)
            || self.page_cursor_digests.len() > usize::from(self.pages_observed)
            || self
                .page_cursor_digests
                .iter()
                .any(|digest| digest.as_str() == Digest::zero().as_str())
            || self
                .request_receipt_digests
                .iter()
                .chain(self.response_receipt_digests.iter())
                .any(|digest| digest.as_str() == Digest::zero().as_str())
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust read receipt digest fence",
            });
        }
        if self.source_digest != self.recompute_source_digest()? {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust read source digest",
            });
        }
        if self.result_digest != self.recompute_result_digest()? {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust read result digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustEvidenceBundle {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub reads: Vec<OneTrustReadEvidence>,
    pub failures: Vec<OneTrustProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
}

impl OneTrustEvidenceBundle {
    pub fn new(
        scope: &OneTrustConsentScope,
        registration_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        reads: Vec<OneTrustReadEvidence>,
        failures: Vec<OneTrustProviderErrorEvidence>,
        provenance: TransportProvenance,
    ) -> Result<Self, OneTrustModelError> {
        if reads.len() > OneTrustEndpoint::ALL.len() {
            return Err(OneTrustModelError::TooMany {
                field: "provider reads",
            });
        }
        let mut reads = reads;
        reads.sort_by_key(|read| read.endpoint);
        if reads
            .windows(2)
            .any(|pair| pair[0].endpoint == pair[1].endpoint)
        {
            return Err(OneTrustModelError::Invalid {
                field: "duplicate provider read endpoint",
            });
        }
        let scope_digest = scope.scope_digest();
        for read in &reads {
            if read.scope_digest != scope_digest
                || read.subject_reference != scope.subject_reference
            {
                return Err(OneTrustModelError::Invalid {
                    field: "evidence scope fence",
                });
            }
            read.validate_integrity()?;
            for observation in &read.observations {
                observation.validate_against(scope)?;
            }
        }
        let evidence_digest = digest_serializable(&(
            &scope_digest,
            &registration_digest,
            &provider_digest,
            &provider_revision,
            &reads,
            &failures,
            provenance,
        ))?;
        Ok(Self {
            scope_digest,
            registration_digest,
            provider_digest,
            provider_revision,
            reads,
            failures,
            provenance,
            evidence_digest,
        })
    }

    pub fn observation_count(&self) -> usize {
        self.reads.iter().map(|read| read.observations.len()).sum()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustConsentEvidence {
    pub status: ConsentEvidenceStatus,
    pub scope_digest: Digest,
    pub subject_reference: SubjectReferenceHash,
    pub policy_revision: PolicyRevision,
    pub observed_at: DateTime<Utc>,
    pub observations: Vec<OneTrustConsentObservation>,
    pub pages_observed: u16,
    pub read_count: usize,
    pub page_cursor_digests: Vec<Digest>,
    pub request_receipt_digests: Vec<Digest>,
    pub response_receipt_digests: Vec<Digest>,
    pub failures: Vec<OneTrustProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub source_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub raw_preference_payload_retained: bool,
    pub raw_subject_identifier_retained: bool,
    pub raw_jwt_retained: bool,
    pub raw_pii_retained: bool,
}

impl OneTrustConsentEvidence {
    pub fn recompute_source_digest(&self) -> Result<Digest, OneTrustModelError> {
        digest_serializable(&(
            "hartevo-onetrust-evidence-source-v2",
            &self.scope_digest,
            self.status,
            self.observed_at,
            &self.observations,
            self.pages_observed,
            self.read_count,
            &self.page_cursor_digests,
            &self.request_receipt_digests,
            &self.response_receipt_digests,
            &self.failures,
            self.provenance,
        ))
    }

    pub fn recompute_result_digest(&self) -> Result<Digest, OneTrustModelError> {
        let source_digest = self.recompute_source_digest()?;
        digest_serializable(&(
            "hartevo-onetrust-evidence-result-v2",
            &self.scope_digest,
            self.status,
            self.observed_at,
            &self.observations,
            self.pages_observed,
            self.read_count,
            &self.page_cursor_digests,
            &self.request_receipt_digests,
            &self.response_receipt_digests,
            &self.failures,
            &source_digest,
        ))
    }

    pub fn recompute_evidence_digest(&self) -> Result<Digest, OneTrustModelError> {
        let source_digest = self.recompute_source_digest()?;
        let result_digest = self.recompute_result_digest()?;
        digest_serializable(&(
            "hartevo-onetrust-evidence-v2",
            &self.scope_digest,
            self.status,
            self.observed_at,
            self.pages_observed,
            self.read_count,
            &source_digest,
            &result_digest,
            self.read_only,
            self.proposal_only,
            self.native,
            self.connected,
            self.raw_preference_payload_retained,
            self.raw_subject_identifier_retained,
            self.raw_jwt_retained,
            self.raw_pii_retained,
        ))
    }

    pub fn validate_integrity(
        &self,
        scope: &OneTrustConsentScope,
    ) -> Result<(), OneTrustModelError> {
        let pages_observed = usize::from(self.pages_observed);
        let has_reads = self.read_count != 0;
        if self.scope_digest != scope.scope_digest()
            || self.subject_reference != scope.subject_reference
            || self.policy_revision != scope.policy_revision
            || self.observations.len() > ONETRUST_MAX_OBSERVATIONS
            || self.read_count > OneTrustEndpoint::ALL.len()
            || (has_reads
                && (pages_observed == 0
                    || pages_observed > usize::from(ONETRUST_MAX_PAGES) * self.read_count))
            || (has_reads
                && (self.request_receipt_digests.len() != pages_observed
                    || self.response_receipt_digests.len() != pages_observed))
            || (!has_reads
                && (pages_observed != 0
                    || !self.observations.is_empty()
                    || !self.page_cursor_digests.is_empty()
                    || !self.request_receipt_digests.is_empty()
                    || !self.response_receipt_digests.is_empty()))
            || self.page_cursor_digests.len() > pages_observed
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.raw_preference_payload_retained
            || self.raw_subject_identifier_retained
            || self.raw_jwt_retained
            || self.raw_pii_retained
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust evidence authority or scope fence",
            });
        }
        for observation in &self.observations {
            observation.validate_against(scope)?;
        }
        if self
            .request_receipt_digests
            .iter()
            .chain(self.response_receipt_digests.iter())
            .any(|digest| digest.as_str() == Digest::zero().as_str())
            || self
                .page_cursor_digests
                .iter()
                .any(|digest| digest.as_str() == Digest::zero().as_str())
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust evidence receipt digest fence",
            });
        }
        if self.source_digest != self.recompute_source_digest()?
            || self.result_digest != self.recompute_result_digest()?
            || self.evidence_digest != self.recompute_evidence_digest()?
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust evidence digest fence",
            });
        }
        Ok(())
    }
}

/// Monotonic live-use fence shared by a registration and every Mission
/// consumer created from it. It is intentionally process-lifecycle bounded:
/// the serde-skipped atomics do not claim restart-durable revocation state.
#[derive(Debug)]
pub(crate) struct RegistrationUseFence {
    generation: AtomicU64,
}

impl Default for RegistrationUseFence {
    fn default() -> Self {
        Self {
            generation: AtomicU64::new(1),
        }
    }
}

impl PartialEq for RegistrationUseFence {
    fn eq(&self, other: &Self) -> bool {
        self.generation.load(Ordering::Acquire) == other.generation.load(Ordering::Acquire)
    }
}

impl Eq for RegistrationUseFence {}

impl RegistrationUseFence {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn is_active(&self) -> bool {
        self.generation.load(Ordering::Acquire) == 1
    }

    fn revoke(&self) {
        let _ = self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                Some(generation.saturating_add(1))
            });
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

fn default_registration_provenance() -> TransportProvenance {
    TransportProvenance::Fixture
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustRegistration {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub service_implementation: String,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    #[serde(default = "default_registration_provenance")]
    pub provenance: TransportProvenance,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub consent_revision: Revision,
    pub work_product_revision: Revision,
    pub secret_reference_digest: Digest,
    pub evidence_digest_fence: Digest,
    pub state: RegistrationState,
    #[serde(skip)]
    active_use_fence: Arc<RegistrationUseFence>,
}

impl OneTrustRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &OneTrustConsentScope,
        secret_reference: &SecretReference,
        provider_id: impl Into<String>,
        provider_implementation: impl Into<String>,
        provider_version: impl Into<String>,
        provider_revision: ProviderRevision,
        provider_digest: Digest,
        contract_digest: Digest,
    ) -> Result<Self, OneTrustModelError> {
        Self::new_with_provenance(
            scope,
            secret_reference,
            provider_id,
            provider_implementation,
            provider_version,
            provider_revision,
            provider_digest,
            contract_digest,
            TransportProvenance::Fixture,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_provenance(
        scope: &OneTrustConsentScope,
        secret_reference: &SecretReference,
        provider_id: impl Into<String>,
        provider_implementation: impl Into<String>,
        provider_version: impl Into<String>,
        provider_revision: ProviderRevision,
        provider_digest: Digest,
        contract_digest: Digest,
        provenance: TransportProvenance,
    ) -> Result<Self, OneTrustModelError> {
        let evidence_digest_fence = Digest::from_fields([
            "hartevo-onetrust-registration-evidence-fence-v1",
            scope.scope_digest().as_str(),
            provider_digest.as_str(),
            contract_digest.as_str(),
        ]);
        let mut registration = Self {
            registration_digest: Digest::zero(),
            registration_revision: Revision::new(1)?,
            plugin_version: ONETRUST_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: ONETRUST_CONTRACT_VERSION.to_owned(),
            contract_digest,
            service_id: crate::ONETRUST_SERVICE_ID.to_owned(),
            service_implementation: crate::ONETRUST_SERVICE_NAME.to_owned(),
            provider_id: provider_id.into(),
            provider_implementation: provider_implementation.into(),
            provider_version: provider_version.into(),
            provider_revision,
            provider_digest,
            provenance,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest.clone(),
            mission_revision: scope.mission.revision,
            project_revision: scope.project.revision,
            consent_revision: scope.consent.revision,
            work_product_revision: scope.work_product.revision,
            secret_reference_digest: secret_reference.digest().clone(),
            evidence_digest_fence,
            state: RegistrationState::Active,
            active_use_fence: RegistrationUseFence::new(),
        };
        registration.registration_digest = registration.recompute_digest()?;
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active && self.active_use_fence.is_active()
    }

    pub fn revoke(&mut self) -> Result<(), OneTrustModelError> {
        if !self.is_active() {
            return Err(OneTrustModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.active_use_fence.revoke();
        Ok(())
    }

    pub(crate) fn active_use_fence(&self) -> Arc<RegistrationUseFence> {
        self.active_use_fence.clone()
    }

    pub fn recompute_digest(&self) -> Result<Digest, OneTrustModelError> {
        Ok(Digest::from_fields([
            self.registration_revision.get().to_string(),
            self.plugin_version.clone(),
            self.contract_version.clone(),
            self.contract_digest.as_str().to_owned(),
            self.service_id.clone(),
            self.service_implementation.clone(),
            self.provider_id.clone(),
            self.provider_implementation.clone(),
            self.provider_version.clone(),
            self.provider_revision.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            format!("{:?}", self.provenance),
            self.scope_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.mission_revision.get().to_string(),
            self.project_revision.get().to_string(),
            self.consent_revision.get().to_string(),
            self.work_product_revision.get().to_string(),
            self.secret_reference_digest.as_str().to_owned(),
            self.evidence_digest_fence.as_str().to_owned(),
            format!("{:?}", self.state),
        ]))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        scope: &OneTrustConsentScope,
        secret_reference: &SecretReference,
        provider_id: &str,
        provider_implementation: &str,
        provider_version: &str,
        provider_revision: &ProviderRevision,
        provider_digest: &Digest,
        contract_digest: &Digest,
    ) -> Result<(), OneTrustModelError> {
        self.validate_with_provenance(
            scope,
            secret_reference,
            provider_id,
            provider_implementation,
            provider_version,
            provider_revision,
            provider_digest,
            contract_digest,
            self.provenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_with_provenance(
        &self,
        scope: &OneTrustConsentScope,
        secret_reference: &SecretReference,
        provider_id: &str,
        provider_implementation: &str,
        provider_version: &str,
        provider_revision: &ProviderRevision,
        provider_digest: &Digest,
        contract_digest: &Digest,
        provenance: TransportProvenance,
    ) -> Result<(), OneTrustModelError> {
        if self
            .validate_identity(
                scope,
                provider_id,
                provider_implementation,
                provider_version,
                provider_revision,
                provider_digest,
                contract_digest,
                provenance,
            )
            .is_err()
            || self.secret_reference_digest != *secret_reference.digest()
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust registration fence",
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_identity(
        &self,
        scope: &OneTrustConsentScope,
        provider_id: &str,
        provider_implementation: &str,
        provider_version: &str,
        provider_revision: &ProviderRevision,
        provider_digest: &Digest,
        contract_digest: &Digest,
        provenance: TransportProvenance,
    ) -> Result<(), OneTrustModelError> {
        let expected_evidence_digest_fence = Digest::from_fields([
            "hartevo-onetrust-registration-evidence-fence-v1",
            scope.scope_digest().as_str(),
            provider_digest.as_str(),
            contract_digest.as_str(),
        ]);
        if self.registration_digest != self.recompute_digest()?
            || self.plugin_version != ONETRUST_PLUGIN_VERSION_TEXT
            || self.contract_version != ONETRUST_CONTRACT_VERSION
            || &self.contract_digest != contract_digest
            || self.service_id != crate::ONETRUST_SERVICE_ID
            || self.service_implementation != crate::ONETRUST_SERVICE_NAME
            || self.provider_id != provider_id
            || self.provider_implementation != provider_implementation
            || self.provider_version != provider_version
            || &self.provider_revision != provider_revision
            || &self.provider_digest != provider_digest
            || self.provenance != provenance
            || self.scope_digest != scope.scope_digest()
            || self.permission_digest != scope.permission_digest
            || self.mission_revision != scope.mission.revision
            || self.project_revision != scope.project.revision
            || self.consent_revision != scope.consent.revision
            || self.work_product_revision != scope.work_product.revision
            || self.evidence_digest_fence != expected_evidence_digest_fence
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust registration identity fence",
            });
        }
        Ok(())
    }

    pub(crate) fn revoke_active_use(&self) {
        self.active_use_fence.revoke();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustConsentProjection {
    pub status: ConsentEvidenceStatus,
    pub observed_record_count: usize,
    pub read_count: usize,
    pub partial: bool,
    pub fail_closed: bool,
    pub rationale_digest: Digest,
}

impl OneTrustConsentProjection {
    pub fn recompute_rationale_digest(&self, evidence: &OneTrustConsentEvidence) -> Digest {
        Digest::from_fields([
            "hartevo-onetrust-projection-v2".to_owned(),
            evidence.scope_digest.as_str().to_owned(),
            format!("{:?}", self.status),
            self.observed_record_count.to_string(),
            self.read_count.to_string(),
            self.partial.to_string(),
            self.fail_closed.to_string(),
            evidence.evidence_digest.as_str().to_owned(),
            evidence.result_digest.as_str().to_owned(),
        ])
    }

    pub fn validate_integrity(
        &self,
        evidence: &OneTrustConsentEvidence,
    ) -> Result<(), OneTrustModelError> {
        let partial = evidence
            .failures
            .iter()
            .any(|failure| failure.kind == OneTrustProviderErrorKind::Partial);
        if self.status != evidence.status
            || self.observed_record_count != evidence.observations.len()
            || self.read_count != evidence.read_count
            || self.partial != partial
            || self.fail_closed != (self.status != ConsentEvidenceStatus::Granted || partial)
            || self.rationale_digest != self.recompute_rationale_digest(evidence)
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust projection fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustEvidenceProposal {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub consent_revision: Revision,
    pub work_product_revision: Revision,
    pub projection: OneTrustConsentProjection,
    pub evidence: OneTrustConsentEvidence,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub consent_receipt_created: bool,
    pub consent_withdrawn: bool,
    pub preference_updated: bool,
    pub adopted_by_kernel: bool,
    pub proposal_digest: Digest,
}

impl OneTrustEvidenceProposal {
    pub fn recompute_digest(&self) -> Result<Digest, OneTrustModelError> {
        Ok(Digest::from_fields([
            self.plugin_version.clone(),
            self.contract_version.clone(),
            self.contract_digest.as_str().to_owned(),
            self.provider_id.clone(),
            self.provider_implementation.clone(),
            self.provider_version.clone(),
            self.provider_revision.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            self.registration_digest.as_str().to_owned(),
            self.registration_revision.get().to_string(),
            self.scope_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.mission_revision.get().to_string(),
            self.project_revision.get().to_string(),
            self.consent_revision.get().to_string(),
            self.work_product_revision.get().to_string(),
            format!("{:?}", self.projection.status),
            self.projection.observed_record_count.to_string(),
            self.projection.read_count.to_string(),
            self.projection.partial.to_string(),
            self.projection.fail_closed.to_string(),
            self.projection.rationale_digest.as_str().to_owned(),
            self.evidence.evidence_digest.as_str().to_owned(),
            self.evidence.result_digest.as_str().to_owned(),
            format!("{:?}", self.provenance),
            format!("read_only:{}", self.read_only),
            format!("proposal_only:{}", self.proposal_only),
            format!("native:{}", self.native),
            format!("connected:{}", self.connected),
            format!("consent_receipt_created:{}", self.consent_receipt_created),
            format!("consent_withdrawn:{}", self.consent_withdrawn),
            format!("preference_updated:{}", self.preference_updated),
            format!("adopted_by_kernel:{}", self.adopted_by_kernel),
        ]))
    }

    pub fn validate_integrity(
        &self,
        scope: &OneTrustConsentScope,
    ) -> Result<(), OneTrustModelError> {
        self.evidence.validate_integrity(scope)?;
        if self.plugin_version != ONETRUST_PLUGIN_VERSION_TEXT
            || self.scope_digest != scope.scope_digest()
            || self.permission_digest != scope.permission_digest
            || self.mission_revision != scope.mission.revision
            || self.project_revision != scope.project.revision
            || self.consent_revision != scope.consent.revision
            || self.work_product_revision != scope.work_product.revision
            || self.evidence.scope_digest != self.scope_digest
            || self.evidence.provenance != self.provenance
            || self.evidence.status != self.projection.status
            || self.evidence.read_only != self.read_only
            || self.evidence.proposal_only != self.proposal_only
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust proposal scope or authority fence",
            });
        }
        self.projection.validate_integrity(&self.evidence)
    }

    pub fn replay_digest(&self, scope: &OneTrustConsentScope) -> Digest {
        Digest::from_fields([
            "hartevo-onetrust-record-replay-v1".to_owned(),
            self.contract_version.clone(),
            self.contract_digest.as_str().to_owned(),
            self.provider_id.clone(),
            self.provider_implementation.clone(),
            self.provider_version.clone(),
            self.provider_revision.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            format!("{:?}", self.provenance),
            self.registration_digest.as_str().to_owned(),
            self.registration_revision.get().to_string(),
            scope.tenant.as_str().to_owned(),
            scope.region.as_str().to_owned(),
            scope.purpose_id.as_str().to_owned(),
            scope.purpose_version.as_str().to_owned(),
            scope.collection_point.as_str().to_owned(),
            scope.consent_window.start.to_rfc3339(),
            scope.consent_window.end.to_rfc3339(),
            scope.subject_reference.scope_digest().as_str().to_owned(),
            scope.subject_reference.digest().as_str().to_owned(),
            scope.policy_revision.as_str().to_owned(),
            scope.mission.id.as_str().to_owned(),
            scope.mission.revision.get().to_string(),
            scope.project.id.as_str().to_owned(),
            scope.project.revision.get().to_string(),
            scope.consent.id.as_str().to_owned(),
            scope.consent.revision.get().to_string(),
            scope.consent.digest.as_str().to_owned(),
            scope.work_product.id.as_str().to_owned(),
            scope.work_product.revision.get().to_string(),
            scope.permission_digest.as_str().to_owned(),
            self.evidence.observed_at.to_rfc3339(),
            self.evidence.pages_observed.to_string(),
            self.evidence.read_count.to_string(),
            self.evidence.source_digest.as_str().to_owned(),
            self.evidence.result_digest.as_str().to_owned(),
            self.evidence.evidence_digest.as_str().to_owned(),
            self.proposal_digest.as_str().to_owned(),
        ])
    }

    pub fn status(&self) -> ConsentEvidenceStatus {
        self.projection.status
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustRecordingReceipt {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub consent_id: ConsentId,
    pub consent_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub replay_digest: Digest,
    pub recorded: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_subject_identifier_retained: bool,
    pub raw_jwt_retained: bool,
    pub consent_receipt_created: bool,
    pub preference_updated: bool,
    pub native: bool,
    pub connected: bool,
}

impl OneTrustRecordingReceipt {
    pub fn validate(
        &self,
        scope: &OneTrustConsentScope,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<(), OneTrustModelError> {
        if self.contract_version != proposal.contract_version
            || self.contract_digest != proposal.contract_digest
            || self.provider_id != proposal.provider_id
            || self.provider_implementation != proposal.provider_implementation
            || self.provider_version != proposal.provider_version
            || self.provider_revision != proposal.provider_revision
            || self.provider_digest != proposal.provider_digest
            || self.registration_digest != proposal.registration_digest
            || self.registration_revision != proposal.registration_revision
            || self.scope_digest != scope.scope_digest()
            || self.mission_id != scope.mission.id
            || self.mission_revision != scope.mission.revision
            || self.project_id != scope.project.id
            || self.project_revision != scope.project.revision
            || self.consent_id != scope.consent.id
            || self.consent_revision != scope.consent.revision
            || self.work_product_id != scope.work_product.id
            || self.work_product_revision != scope.work_product.revision
            || self.proposal_digest != proposal.proposal_digest
            || self.evidence_digest != proposal.evidence.evidence_digest
            || self.provenance != proposal.provenance
            || self.replay_digest != proposal.replay_digest(scope)
            || !self.recorded
            || self.raw_provider_payload_retained
            || self.raw_subject_identifier_retained
            || self.raw_jwt_retained
            || self.consent_receipt_created
            || self.preference_updated
            || self.native
            || self.connected
        {
            return Err(OneTrustModelError::Invalid {
                field: "OneTrust recording receipt fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustVerification {
    pub verified: bool,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub kernel_authority: bool,
}

/// A compile-time tripwire that keeps the source-level constants aligned with
/// the contract values used by the typed models.
pub fn contract_bounds_tripwire() -> bool {
    ONETRUST_MAX_PAGES == 4
        && ONETRUST_PAGE_SIZE == 50
        && ONETRUST_MAX_RESPONSE_BYTES == 1_048_576
        && ONETRUST_MAX_OBSERVATIONS == 256
        && ONETRUST_MAX_CONSENT_WINDOW_HOURS == ONETRUST_CONSENT_WINDOW_HOURS
        && ONETRUST_PROVIDER_ID == "onetrust.consent"
        && ONETRUST_PROVIDER_REVISION_TEXT == "onetrust-consent-v4-r1"
}

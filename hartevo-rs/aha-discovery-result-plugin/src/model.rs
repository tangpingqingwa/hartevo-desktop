//! Bounded, redacted Aha! Discovery contract models.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AHA_DISCOVERY_MAX_BOUNDED_COUNT, AHA_DISCOVERY_MAX_CURSOR_BYTES, AHA_DISCOVERY_MAX_PAGE_SIZE,
    AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;

/// Errors raised when a Layer-1 contract value cannot be constructed or verified.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum AhaDiscoveryResultError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("value is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope hierarchy is invalid")]
    InvalidScope,
    #[error("scope digest does not match")]
    ScopeMismatch,
    #[error("secret reference is not bound to this scope")]
    SecretScopeMismatch,
    #[error("Layer-1 permission snapshot is not read-only and redacted")]
    InvalidPermission,
    #[error("evidence fence is invalid")]
    InvalidEvidenceFence,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    RegistrationAlreadyRevoked,
    #[error("registration is already active")]
    RegistrationAlreadyActive,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration was not found")]
    RegistrationNotFound,
    #[error("registration identifier is already registered")]
    DuplicateRegistration,
    #[error("page size must be between one and the Layer-1 maximum")]
    InvalidPageSize,
    #[error("opaque cursor is empty, malformed, or too long")]
    InvalidCursor,
    #[error("page exceeds its bounded item limit")]
    PageBoundExceeded,
    #[error("projection resource does not match the requested resource")]
    ResourceMismatch,
    #[error("projection is not deterministically redacted")]
    ProjectionNotRedacted,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
    #[error("request digest does not match immutable fields")]
    RequestDigestMismatch,
    #[error("redacted text is empty, unsafe, or exceeds its bound")]
    InvalidRedactedText,
    #[error("metadata count exceeds its bound")]
    BoundExceeded,
    #[error("idempotency key is empty, malformed, or too long")]
    InvalidIdempotencyKey,
    #[error("recording key was reused for a different proposal")]
    RecordingConflict,
    #[error("provider definition is invalid")]
    InvalidProviderDefinition,
    #[error("provider transport is unavailable in Layer 1")]
    TransportUnavailable,
    #[error("recorded provider page is not available")]
    PageNotFound,
    #[error("evidence was tampered")]
    TamperedEvidence,
}

/// A lowercase SHA-256 digest used as an evidence, scope, and replay fence.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AhaDiscoveryResultError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AhaDiscoveryResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (key, value) in fields {
            append_field(&mut bytes, key);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub(crate) fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AhaDiscoveryResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AhaDiscoveryResultError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(AhaDiscoveryResultError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
            }

            pub(crate) fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
                if valid_identifier(self.as_str()) {
                    Ok(())
                } else {
                    Err(AhaDiscoveryResultError::InvalidIdentifier)
                }
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
    };
}

string_identifier!(AccountId);
string_identifier!(WorkspaceId);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(StudyId);
string_identifier!(InterviewId);
string_identifier!(QuestionId);
string_identifier!(ResponseId);
string_identifier!(HighlightId);
string_identifier!(LinkedRecordId);

/// A positive monotonic source or registration revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, AhaDiscoveryResultError> {
        if value == 0 {
            Err(AhaDiscoveryResultError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An opaque, bounded pagination cursor. Layer 1 never decodes or constructs a native cursor.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PageCursor(String);

impl PageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, AhaDiscoveryResultError> {
        let value = value.into();
        if !valid_cursor(&value) {
            return Err(AhaDiscoveryResultError::InvalidCursor);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if valid_cursor(self.as_str()) {
            Ok(())
        } else {
            Err(AhaDiscoveryResultError::InvalidCursor)
        }
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PageCursor")
            .field(&"<opaque>")
            .finish()
    }
}

fn valid_cursor(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= AHA_DISCOVERY_MAX_CURSOR_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

/// Text retained by Layer 1 after deterministic email/phone-like redaction.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RedactedText(String);

impl RedactedText {
    pub fn new(value: impl AsRef<str>) -> Result<Self, AhaDiscoveryResultError> {
        let value = value.as_ref();
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(AhaDiscoveryResultError::InvalidRedactedText);
        }
        let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.is_empty() || normalized.len() > AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES {
            return Err(AhaDiscoveryResultError::InvalidRedactedText);
        }
        let redacted = normalized
            .split(' ')
            .map(redact_token)
            .collect::<Vec<_>>()
            .join(" ");
        if redacted.is_empty() || redacted.len() > AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES {
            return Err(AhaDiscoveryResultError::InvalidRedactedText);
        }
        Ok(Self(redacted))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }

    pub(crate) fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if self.0.is_empty()
            || self.0.len() > AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES
            || self.0.bytes().any(|byte| byte.is_ascii_control())
            || self.0.split_whitespace().any(looks_like_sensitive_token)
        {
            Err(AhaDiscoveryResultError::InvalidRedactedText)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for RedactedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedText")
            .field("digest", &self.digest())
            .finish()
    }
}

fn redact_token(token: &str) -> String {
    if token.chars().any(|character| character == '@') && looks_like_email(token) {
        "[REDACTED_EMAIL]".to_owned()
    } else if token.chars().filter(char::is_ascii_digit).count() >= 7 {
        "[REDACTED_NUMBER]".to_owned()
    } else {
        token.to_owned()
    }
}

fn looks_like_sensitive_token(token: &str) -> bool {
    looks_like_email(token) || token.chars().filter(char::is_ascii_digit).count() >= 7
}

fn looks_like_email(token: &str) -> bool {
    let Some(at) = token.find('@') else {
        return false;
    };
    at > 0 && token[at + 1..].contains('.')
}

/// Explicit redaction guarantees attached to every projection and proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub projection_redacted: bool,
    pub raw_transcript_exposed: bool,
    pub raw_media_exposed: bool,
    pub participant_pii_exposed: bool,
    pub credentials_exposed: bool,
    pub mutation_authority_exposed: bool,
}

impl RedactionSummary {
    pub const fn layer1() -> Self {
        Self {
            projection_redacted: true,
            raw_transcript_exposed: false,
            raw_media_exposed: false,
            participant_pii_exposed: false,
            credentials_exposed: false,
            mutation_authority_exposed: false,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-redaction/v1",
            &[
                ("projection_redacted", self.projection_redacted.to_string()),
                ("raw_transcript", self.raw_transcript_exposed.to_string()),
                ("raw_media", self.raw_media_exposed.to_string()),
                ("participant_pii", self.participant_pii_exposed.to_string()),
                ("credentials", self.credentials_exposed.to_string()),
                (
                    "mutation_authority",
                    self.mutation_authority_exposed.to_string(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if *self == Self::layer1() {
            Ok(())
        } else {
            Err(AhaDiscoveryResultError::ProjectionNotRedacted)
        }
    }
}

/// Lifecycle/evidence state used for both individual metadata and result proposals.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InsightState {
    Present,
    Partial,
    Archived,
    AccessLost,
    ProviderUnknown,
    Stale,
    Tampered,
    Revoked,
}

impl InsightState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "PRESENT",
            Self::Partial => "PARTIAL",
            Self::Archived => "ARCHIVED",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Stale => "STALE",
            Self::Tampered => "TAMPERED",
            Self::Revoked => "REVOKED",
        }
    }
}

/// Resource families that can be inspected. No mutation operation exists in Layer 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryResource {
    Studies,
    Interviews,
    Questions,
    Responses,
    Highlights,
    LinkedRecords,
}

impl DiscoveryResource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Studies => "studies",
            Self::Interviews => "interviews",
            Self::Questions => "questions",
            Self::Responses => "responses",
            Self::Highlights => "highlights",
            Self::LinkedRecords => "linked_records",
        }
    }
}

/// Exact Project/Mission/Work Product scope plus optional exact Discovery resource fences.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaDiscoveryScope {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub study_id: Option<StudyId>,
    pub interview_id: Option<InterviewId>,
    pub question_id: Option<QuestionId>,
    pub response_id: Option<ResponseId>,
    pub highlight_id: Option<HighlightId>,
    pub linked_record_id: Option<LinkedRecordId>,
}

impl AhaDiscoveryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        study_id: Option<StudyId>,
        interview_id: Option<InterviewId>,
        question_id: Option<QuestionId>,
        response_id: Option<ResponseId>,
        highlight_id: Option<HighlightId>,
        linked_record_id: Option<LinkedRecordId>,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let scope = Self {
            account_id,
            workspace_id,
            project_id,
            mission_id,
            work_product_id,
            study_id,
            interview_id,
            question_id,
            response_id,
            highlight_id,
            linked_record_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-scope/v1",
            &[
                ("account", self.account_id.as_str().to_owned()),
                ("workspace", self.workspace_id.as_str().to_owned()),
                ("project", self.project_id.as_str().to_owned()),
                ("mission", self.mission_id.as_str().to_owned()),
                ("work_product", self.work_product_id.as_str().to_owned()),
                (
                    "study",
                    self.study_id
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
                (
                    "interview",
                    self.interview_id
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
                (
                    "question",
                    self.question_id
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
                (
                    "response",
                    self.response_id
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
                (
                    "highlight",
                    self.highlight_id
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
                (
                    "linked_record",
                    self.linked_record_id
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.account_id.validate()?;
        self.workspace_id.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        for identifier in [
            self.study_id.as_ref().map(StudyId::as_str),
            self.interview_id.as_ref().map(InterviewId::as_str),
            self.question_id.as_ref().map(QuestionId::as_str),
            self.response_id.as_ref().map(ResponseId::as_str),
            self.highlight_id.as_ref().map(HighlightId::as_str),
            self.linked_record_id.as_ref().map(LinkedRecordId::as_str),
        ]
        .into_iter()
        .flatten()
        {
            if !valid_identifier(identifier) {
                return Err(AhaDiscoveryResultError::InvalidIdentifier);
            }
        }
        if self.interview_id.is_some() && self.study_id.is_none()
            || self.question_id.is_some() && self.interview_id.is_none()
            || self.response_id.is_some() && self.question_id.is_none()
            || self.highlight_id.is_some() && self.response_id.is_none()
        {
            return Err(AhaDiscoveryResultError::InvalidScope);
        }
        Ok(())
    }
}

/// Revision and digest fence for source, transcript, and highlight evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceFence {
    pub source_revision: Revision,
    pub transcript_digest: Digest,
    pub highlight_digest: Digest,
}

impl EvidenceFence {
    pub fn new(
        source_revision: Revision,
        transcript_digest: Digest,
        highlight_digest: Digest,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let fence = Self {
            source_revision,
            transcript_digest,
            highlight_digest,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-evidence-fence/v1",
            &[
                ("source_revision", self.source_revision.get().to_string()),
                ("transcript", self.transcript_digest.as_str().to_owned()),
                ("highlight", self.highlight_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if self.source_revision.get() == 0 {
            return Err(AhaDiscoveryResultError::InvalidEvidenceFence);
        }
        self.transcript_digest.validate()?;
        self.highlight_digest.validate()?;
        Ok(())
    }
}

/// Layer-1 permission snapshot. It can read only bounded metadata and redacted projections.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub metadata_read: bool,
    pub redacted_projection: bool,
    pub recording: bool,
    pub raw_transcript_access: bool,
    pub raw_media_access: bool,
    pub participant_pii_access: bool,
    pub credential_resolution: bool,
    pub mutation_authority: bool,
}

impl PermissionSnapshot {
    pub const fn layer1_read_only() -> Self {
        Self {
            metadata_read: true,
            redacted_projection: true,
            recording: true,
            raw_transcript_access: false,
            raw_media_access: false,
            participant_pii_access: false,
            credential_resolution: false,
            mutation_authority: false,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-permission/v1",
            &[
                ("metadata_read", self.metadata_read.to_string()),
                ("redacted_projection", self.redacted_projection.to_string()),
                ("recording", self.recording.to_string()),
                (
                    "raw_transcript_access",
                    self.raw_transcript_access.to_string(),
                ),
                ("raw_media_access", self.raw_media_access.to_string()),
                (
                    "participant_pii_access",
                    self.participant_pii_access.to_string(),
                ),
                (
                    "credential_resolution",
                    self.credential_resolution.to_string(),
                ),
                ("mutation_authority", self.mutation_authority.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if *self == Self::layer1_read_only() {
            Ok(())
        } else {
            Err(AhaDiscoveryResultError::InvalidPermission)
        }
    }
}

/// Aggregate digests exposed on proposals and recordings; no source content is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub scope_digest: Digest,
    pub source_revision: Revision,
    pub transcript_digest: Digest,
    pub highlight_digest: Digest,
    pub projection_digest: Digest,
}

impl EvidenceDigests {
    pub fn from_page(scope: &AhaDiscoveryScope, page: &AhaDiscoveryPage) -> Self {
        Self {
            scope_digest: scope.digest(),
            source_revision: page.fence.source_revision,
            transcript_digest: page.fence.transcript_digest.clone(),
            highlight_digest: page.fence.highlight_digest.clone(),
            projection_digest: page.page_digest.clone(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-evidence-digests/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("source_revision", self.source_revision.get().to_string()),
                ("transcript", self.transcript_digest.as_str().to_owned()),
                ("highlight", self.highlight_digest.as_str().to_owned()),
                ("projection", self.projection_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.scope_digest.validate()?;
        if self.source_revision.get() == 0 {
            return Err(AhaDiscoveryResultError::InvalidEvidenceFence);
        }
        self.transcript_digest.validate()?;
        self.highlight_digest.validate()?;
        self.projection_digest.validate()
    }
}

macro_rules! projection_common {
    ($value:expr) => {{
        $value.revision.get() != 0
            && $value.redaction.validate().is_ok()
            && $value.evidence_digest.validate().is_ok()
    }};
}

/// Allowlisted study metadata with a redacted label and no transcript/media field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StudyProjection {
    pub study_id: StudyId,
    pub redacted_label: RedactedText,
    pub revision: Revision,
    pub state: InsightState,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

impl StudyProjection {
    pub fn new(
        study_id: StudyId,
        redacted_label: RedactedText,
        revision: Revision,
        state: InsightState,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let mut projection = Self {
            study_id,
            redacted_label,
            revision,
            state,
            redaction: RedactionSummary::layer1(),
            evidence_digest: Digest::from_text("unsealed-aha-study"),
        };
        projection.evidence_digest = projection.calculate_digest();
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.study_id.validate()?;
        self.redacted_label.validate()?;
        if !projection_common!(self) || self.evidence_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-study-projection/v1",
            &[
                ("id", self.study_id.as_str().to_owned()),
                ("label", self.redacted_label.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("state", self.state.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
            ],
        )
    }
}

/// Allowlisted interview metadata; response bodies and participant identity are absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterviewProjection {
    pub study_id: StudyId,
    pub interview_id: InterviewId,
    pub redacted_label: RedactedText,
    pub bounded_response_count: u16,
    pub revision: Revision,
    pub state: InsightState,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

impl InterviewProjection {
    pub fn new(
        study_id: StudyId,
        interview_id: InterviewId,
        redacted_label: RedactedText,
        bounded_response_count: u16,
        revision: Revision,
        state: InsightState,
    ) -> Result<Self, AhaDiscoveryResultError> {
        if bounded_response_count > AHA_DISCOVERY_MAX_BOUNDED_COUNT {
            return Err(AhaDiscoveryResultError::BoundExceeded);
        }
        let mut projection = Self {
            study_id,
            interview_id,
            redacted_label,
            bounded_response_count,
            revision,
            state,
            redaction: RedactionSummary::layer1(),
            evidence_digest: Digest::from_text("unsealed-aha-interview"),
        };
        projection.evidence_digest = projection.calculate_digest();
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.study_id.validate()?;
        self.interview_id.validate()?;
        self.redacted_label.validate()?;
        if self.bounded_response_count > AHA_DISCOVERY_MAX_BOUNDED_COUNT {
            return Err(AhaDiscoveryResultError::BoundExceeded);
        }
        if !projection_common!(self) || self.evidence_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-interview-projection/v1",
            &[
                ("study", self.study_id.as_str().to_owned()),
                ("id", self.interview_id.as_str().to_owned()),
                ("label", self.redacted_label.digest().as_str().to_owned()),
                ("response_count", self.bounded_response_count.to_string()),
                ("revision", self.revision.get().to_string()),
                ("state", self.state.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
            ],
        )
    }
}

/// Allowlisted script-question metadata; only an ordinal and prompt digest are retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionProjection {
    pub interview_id: InterviewId,
    pub question_id: QuestionId,
    pub ordinal: u16,
    pub prompt_digest: Digest,
    pub revision: Revision,
    pub state: InsightState,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

impl QuestionProjection {
    pub fn new(
        interview_id: InterviewId,
        question_id: QuestionId,
        ordinal: u16,
        prompt_digest: Digest,
        revision: Revision,
        state: InsightState,
    ) -> Result<Self, AhaDiscoveryResultError> {
        if ordinal == 0 || ordinal > AHA_DISCOVERY_MAX_BOUNDED_COUNT {
            return Err(AhaDiscoveryResultError::BoundExceeded);
        }
        let mut projection = Self {
            interview_id,
            question_id,
            ordinal,
            prompt_digest,
            revision,
            state,
            redaction: RedactionSummary::layer1(),
            evidence_digest: Digest::from_text("unsealed-aha-question"),
        };
        projection.evidence_digest = projection.calculate_digest();
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.interview_id.validate()?;
        self.question_id.validate()?;
        self.prompt_digest.validate()?;
        if self.ordinal == 0 || self.ordinal > AHA_DISCOVERY_MAX_BOUNDED_COUNT {
            return Err(AhaDiscoveryResultError::BoundExceeded);
        }
        if !projection_common!(self) || self.evidence_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-question-projection/v1",
            &[
                ("interview", self.interview_id.as_str().to_owned()),
                ("id", self.question_id.as_str().to_owned()),
                ("ordinal", self.ordinal.to_string()),
                ("prompt", self.prompt_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("state", self.state.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
            ],
        )
    }
}

/// Allowlisted response metadata; answer content is represented only by a digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseProjection {
    pub interview_id: InterviewId,
    pub question_id: QuestionId,
    pub response_id: ResponseId,
    pub answer_digest: Digest,
    pub bounded_highlight_count: u16,
    pub revision: Revision,
    pub state: InsightState,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

impl ResponseProjection {
    pub fn new(
        interview_id: InterviewId,
        question_id: QuestionId,
        response_id: ResponseId,
        answer_digest: Digest,
        bounded_highlight_count: u16,
        revision: Revision,
        state: InsightState,
    ) -> Result<Self, AhaDiscoveryResultError> {
        if bounded_highlight_count > AHA_DISCOVERY_MAX_BOUNDED_COUNT {
            return Err(AhaDiscoveryResultError::BoundExceeded);
        }
        let mut projection = Self {
            interview_id,
            question_id,
            response_id,
            answer_digest,
            bounded_highlight_count,
            revision,
            state,
            redaction: RedactionSummary::layer1(),
            evidence_digest: Digest::from_text("unsealed-aha-response"),
        };
        projection.evidence_digest = projection.calculate_digest();
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.interview_id.validate()?;
        self.question_id.validate()?;
        self.response_id.validate()?;
        self.answer_digest.validate()?;
        if self.bounded_highlight_count > AHA_DISCOVERY_MAX_BOUNDED_COUNT {
            return Err(AhaDiscoveryResultError::BoundExceeded);
        }
        if !projection_common!(self) || self.evidence_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-response-projection/v1",
            &[
                ("interview", self.interview_id.as_str().to_owned()),
                ("question", self.question_id.as_str().to_owned()),
                ("id", self.response_id.as_str().to_owned()),
                ("answer", self.answer_digest.as_str().to_owned()),
                ("highlight_count", self.bounded_highlight_count.to_string()),
                ("revision", self.revision.get().to_string()),
                ("state", self.state.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
            ],
        )
    }
}

/// Allowlisted highlight metadata; the highlight quote is represented only by a digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HighlightProjection {
    pub response_id: ResponseId,
    pub highlight_id: HighlightId,
    pub redacted_label: RedactedText,
    pub quote_digest: Digest,
    pub revision: Revision,
    pub state: InsightState,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

impl HighlightProjection {
    pub fn new(
        response_id: ResponseId,
        highlight_id: HighlightId,
        redacted_label: RedactedText,
        quote_digest: Digest,
        revision: Revision,
        state: InsightState,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let mut projection = Self {
            response_id,
            highlight_id,
            redacted_label,
            quote_digest,
            revision,
            state,
            redaction: RedactionSummary::layer1(),
            evidence_digest: Digest::from_text("unsealed-aha-highlight"),
        };
        projection.evidence_digest = projection.calculate_digest();
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.response_id.validate()?;
        self.highlight_id.validate()?;
        self.redacted_label.validate()?;
        self.quote_digest.validate()?;
        if !projection_common!(self) || self.evidence_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-highlight-projection/v1",
            &[
                ("response", self.response_id.as_str().to_owned()),
                ("id", self.highlight_id.as_str().to_owned()),
                ("label", self.redacted_label.digest().as_str().to_owned()),
                ("quote", self.quote_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("state", self.state.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
            ],
        )
    }
}

/// Linked records are represented by an allowlisted kind and opaque digest only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedRecordKind {
    Project,
    Mission,
    WorkProduct,
    Study,
    Interview,
}

impl LinkedRecordKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Mission => "mission",
            Self::WorkProduct => "work_product",
            Self::Study => "study",
            Self::Interview => "interview",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedRecordProjection {
    pub linked_record_id: LinkedRecordId,
    pub record_kind: LinkedRecordKind,
    pub record_digest: Digest,
    pub revision: Revision,
    pub state: InsightState,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

impl LinkedRecordProjection {
    pub fn new(
        linked_record_id: LinkedRecordId,
        record_kind: LinkedRecordKind,
        record_digest: Digest,
        revision: Revision,
        state: InsightState,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let mut projection = Self {
            linked_record_id,
            record_kind,
            record_digest,
            revision,
            state,
            redaction: RedactionSummary::layer1(),
            evidence_digest: Digest::from_text("unsealed-aha-linked-record"),
        };
        projection.evidence_digest = projection.calculate_digest();
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.linked_record_id.validate()?;
        self.record_digest.validate()?;
        if !projection_common!(self) || self.evidence_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-linked-record-projection/v1",
            &[
                ("id", self.linked_record_id.as_str().to_owned()),
                ("kind", self.record_kind.as_str().to_owned()),
                ("record", self.record_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("state", self.state.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
            ],
        )
    }
}

/// A tagged union keeps pagination typed while retaining only allowlisted projections.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "metadata", rename_all = "snake_case")]
pub enum AhaDiscoveryProjection {
    Study(StudyProjection),
    Interview(InterviewProjection),
    Question(QuestionProjection),
    Response(ResponseProjection),
    Highlight(HighlightProjection),
    LinkedRecord(LinkedRecordProjection),
}

impl AhaDiscoveryProjection {
    pub const fn resource(&self) -> DiscoveryResource {
        match self {
            Self::Study(_) => DiscoveryResource::Studies,
            Self::Interview(_) => DiscoveryResource::Interviews,
            Self::Question(_) => DiscoveryResource::Questions,
            Self::Response(_) => DiscoveryResource::Responses,
            Self::Highlight(_) => DiscoveryResource::Highlights,
            Self::LinkedRecord(_) => DiscoveryResource::LinkedRecords,
        }
    }

    pub fn digest(&self) -> &Digest {
        match self {
            Self::Study(value) => value.evidence_digest(),
            Self::Interview(value) => value.evidence_digest(),
            Self::Question(value) => value.evidence_digest(),
            Self::Response(value) => value.evidence_digest(),
            Self::Highlight(value) => value.evidence_digest(),
            Self::LinkedRecord(value) => value.evidence_digest(),
        }
    }

    pub fn validate(&self, scope: &AhaDiscoveryScope) -> Result<(), AhaDiscoveryResultError> {
        scope.validate()?;
        match self {
            Self::Study(value) => {
                value.validate()?;
                if let Some(study_id) = &scope.study_id
                    && study_id != &value.study_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
            }
            Self::Interview(value) => {
                value.validate()?;
                if let Some(study_id) = &scope.study_id
                    && study_id != &value.study_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
                if let Some(interview_id) = &scope.interview_id
                    && interview_id != &value.interview_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
            }
            Self::Question(value) => {
                value.validate()?;
                if let Some(interview_id) = &scope.interview_id
                    && interview_id != &value.interview_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
                if let Some(question_id) = &scope.question_id
                    && question_id != &value.question_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
            }
            Self::Response(value) => {
                value.validate()?;
                if let Some(interview_id) = &scope.interview_id
                    && interview_id != &value.interview_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
                if let Some(question_id) = &scope.question_id
                    && question_id != &value.question_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
                if let Some(response_id) = &scope.response_id
                    && response_id != &value.response_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
            }
            Self::Highlight(value) => {
                value.validate()?;
                if let Some(response_id) = &scope.response_id
                    && response_id != &value.response_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
                if let Some(highlight_id) = &scope.highlight_id
                    && highlight_id != &value.highlight_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
            }
            Self::LinkedRecord(value) => {
                value.validate()?;
                if let Some(linked_record_id) = &scope.linked_record_id
                    && linked_record_id != &value.linked_record_id
                {
                    return Err(AhaDiscoveryResultError::ScopeMismatch);
                }
            }
        }
        Ok(())
    }

    fn sort_key(&self) -> String {
        let (kind, id) = match self {
            Self::Study(value) => ("study", value.study_id.as_str()),
            Self::Interview(value) => ("interview", value.interview_id.as_str()),
            Self::Question(value) => ("question", value.question_id.as_str()),
            Self::Response(value) => ("response", value.response_id.as_str()),
            Self::Highlight(value) => ("highlight", value.highlight_id.as_str()),
            Self::LinkedRecord(value) => ("linked_record", value.linked_record_id.as_str()),
        };
        format!("{kind}:{id}")
    }
}

/// A bounded deterministic page returned by a fixture/recording transport.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaDiscoveryPage {
    pub scope: AhaDiscoveryScope,
    pub resource: DiscoveryResource,
    pub page_size: u16,
    pub request_digest: Digest,
    pub cursor: Option<PageCursor>,
    pub next_cursor: Option<PageCursor>,
    pub fence: EvidenceFence,
    pub items: Vec<AhaDiscoveryProjection>,
    pub redaction: RedactionSummary,
    pub page_digest: Digest,
}

impl AhaDiscoveryPage {
    pub fn new(
        request: &AhaDiscoveryRequest,
        next_cursor: Option<PageCursor>,
        mut items: Vec<AhaDiscoveryProjection>,
    ) -> Result<Self, AhaDiscoveryResultError> {
        request.validate()?;
        if items.len() > usize::from(request.page_size) {
            return Err(AhaDiscoveryResultError::PageBoundExceeded);
        }
        items.sort_by_key(AhaDiscoveryProjection::sort_key);
        let mut page = Self {
            scope: request.scope.clone(),
            resource: request.resource,
            page_size: request.page_size,
            request_digest: request.request_digest.clone(),
            cursor: request.cursor.clone(),
            next_cursor,
            fence: request.expected_fence.clone(),
            items,
            redaction: RedactionSummary::layer1(),
            page_digest: Digest::from_text("unsealed-aha-page"),
        };
        page.page_digest = page.calculate_digest();
        page.validate()?;
        Ok(page)
    }

    pub fn empty(request: &AhaDiscoveryRequest) -> Result<Self, AhaDiscoveryResultError> {
        Self::new(request, None, Vec::new())
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.scope.validate()?;
        self.fence.validate()?;
        self.request_digest.validate()?;
        if self.page_size == 0 || self.page_size > AHA_DISCOVERY_MAX_PAGE_SIZE {
            return Err(AhaDiscoveryResultError::InvalidPageSize);
        }
        if self.items.len() > usize::from(self.page_size)
            || self.items.len() > usize::from(AHA_DISCOVERY_MAX_PAGE_SIZE)
        {
            return Err(AhaDiscoveryResultError::PageBoundExceeded);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate()?;
        }
        self.redaction.validate()?;
        for item in &self.items {
            if item.resource() != self.resource {
                return Err(AhaDiscoveryResultError::ResourceMismatch);
            }
            item.validate(&self.scope)?;
        }
        if self.page_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::DigestMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.page_digest
    }

    fn calculate_digest(&self) -> Digest {
        let mut fields = vec![
            ("scope", self.scope.digest().as_str().to_owned()),
            ("resource", self.resource.as_str().to_owned()),
            ("page_size", self.page_size.to_string()),
            ("request", self.request_digest.as_str().to_owned()),
            (
                "cursor",
                self.cursor
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
            ),
            (
                "next_cursor",
                self.next_cursor
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
            ),
            ("fence", self.fence.digest().as_str().to_owned()),
            ("redaction", self.redaction.digest().as_str().to_owned()),
        ];
        fields.extend(
            self.items
                .iter()
                .enumerate()
                .map(|(index, item)| ("item", format!("{index}:{}", item.digest().as_str()))),
        );
        Digest::from_parts("aha-discovery-page/v1", &fields)
    }
}

/// Read-only request carrying an exact scope, opaque cursor, and expected evidence fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaDiscoveryRequest {
    pub scope: AhaDiscoveryScope,
    pub resource: DiscoveryResource,
    pub page_size: u16,
    pub cursor: Option<PageCursor>,
    pub expected_fence: EvidenceFence,
    pub request_digest: Digest,
}

impl AhaDiscoveryRequest {
    pub fn new(
        scope: AhaDiscoveryScope,
        resource: DiscoveryResource,
        page_size: u16,
        cursor: Option<PageCursor>,
        expected_fence: EvidenceFence,
    ) -> Result<Self, AhaDiscoveryResultError> {
        if page_size == 0 || page_size > AHA_DISCOVERY_MAX_PAGE_SIZE {
            return Err(AhaDiscoveryResultError::InvalidPageSize);
        }
        scope.validate()?;
        expected_fence.validate()?;
        if let Some(cursor) = &cursor {
            cursor.validate()?;
        }
        let mut request = Self {
            scope,
            resource,
            page_size,
            cursor,
            expected_fence,
            request_digest: Digest::from_text("unsealed-aha-request"),
        };
        request.request_digest = request.calculate_digest();
        request.validate()?;
        Ok(request)
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.scope.validate()?;
        self.expected_fence.validate()?;
        if self.page_size == 0 || self.page_size > AHA_DISCOVERY_MAX_PAGE_SIZE {
            return Err(AhaDiscoveryResultError::InvalidPageSize);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        if self.request_digest != self.calculate_digest() {
            return Err(AhaDiscoveryResultError::RequestDigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-request/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                ("resource", self.resource.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |value| value.as_str().to_owned()),
                ),
                ("fence", self.expected_fence.digest().as_str().to_owned()),
            ],
        )
    }
}

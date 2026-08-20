//! Typed, bounded Slack decision scope and redacted evidence models.
//!
//! Raw Slack payloads, message text, attachments, member identifiers and
//! credentials intentionally have no representation in this module.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SLACK_DECISION_API_REVISION, SLACK_DECISION_CONTRACT_VERSION, SLACK_DECISION_PLUGIN_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_MESSAGES: usize = 256;
pub const MAX_REPLIES: usize = 256;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

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
    #[error("{field} is not an opaque bounded cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} contains a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} is not permitted in a Layer-1 read scope")]
    Unsupported { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), ModelError> {
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

    pub fn from_parts(domain: &str, parts: &[String]) -> Self {
        let mut encoded = Vec::new();
        append_digest_part(&mut encoded, domain);
        for part in parts {
            append_digest_part(&mut encoded, part);
        }
        Self::from_bytes(&encoded)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest { field: "digest" })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == "0".repeat(64)
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

fn append_digest_part(bytes: &mut Vec<u8>, part: &str) {
    bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
    bytes.extend_from_slice(part.as_bytes());
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    match serde_json::to_vec(value) {
        Ok(bytes) => Digest::from_bytes(&bytes),
        Err(_) => Digest::zero(),
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

bounded_identifier!(WorkspaceId, "workspace id");
bounded_identifier!(TeamId, "team id");
bounded_identifier!(ChannelId, "channel id");
bounded_identifier!(ThreadId, "thread id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ServiceId, "service id");
bounded_identifier!(ConsumerId, "consumer id");

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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DecisionFingerprint(Digest);

impl DecisionFingerprint {
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(Digest::from_parts(
            "hartevo-slack-decision-fingerprint/v1",
            &[String::from_utf8_lossy(value.as_ref()).into_owned()],
        ))
    }

    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self::from_text(value)
    }

    pub fn from_digest(digest: Digest) -> Result<Self, ModelError> {
        if digest.is_zero() {
            return Err(ModelError::InvalidDigest {
                field: "decision fingerprint",
            });
        }
        Ok(Self(digest))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for DecisionFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let digest = Digest::deserialize(deserializer)?;
        Self::from_digest(digest).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        if end < start {
            return Err(ModelError::Invalid {
                field: "time window",
            });
        }
        if (end - start).num_seconds() > MAX_WINDOW_SECONDS {
            return Err(ModelError::TooLong {
                field: "time window",
            });
        }
        Ok(Self { start, end })
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

pub type TimestampWindow = TimeWindow;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionScope {
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
}

impl MissionScope {
    pub fn new(
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
    ) -> Self {
        Self {
            mission,
            project,
            work_product,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TokenScope {
    scopes: BTreeSet<String>,
}

impl TokenScope {
    pub fn new<I, S>(scopes: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut normalized = BTreeSet::new();
        for scope in scopes {
            let scope = scope.into();
            validate_text(&scope, "token scope", MAX_IDENTIFIER_BYTES)?;
            if !matches!(
                scope.as_str(),
                "channels:history" | "groups:history" | "channels:read" | "groups:read"
            ) {
                return Err(ModelError::Unsupported {
                    field: "token scope",
                });
            }
            if !normalized.insert(scope) {
                return Err(ModelError::Duplicate {
                    field: "token scope",
                });
            }
        }
        if normalized.is_empty() {
            return Err(ModelError::Empty {
                field: "token scope",
            });
        }
        Ok(Self { scopes: normalized })
    }

    pub fn read_only() -> Self {
        Self::new([
            "channels:history",
            "channels:read",
            "groups:history",
            "groups:read",
        ])
        .expect("canonical Slack read-only scopes are valid")
    }

    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scopes.iter().map(String::as_str)
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

pub type PermissionFence = TokenScope;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Bot,
    User,
}

pub type SlackSecretKind = SecretKind;

/// Opaque reference into a host-owned secret store.
///
/// The reference id and credential material are never retained. Serialization
/// deliberately emits only an opacity marker, and Debug contains only digests.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
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
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("SecretReference", 1)?;
        output.serialize_field("opaque", &true)?;
        output.end()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        kind: SecretKind,
        scope_digest: Digest,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "secret reference", MAX_IDENTIFIER_BYTES)?;
        if scope_digest.is_zero() {
            return Err(ModelError::InvalidDigest {
                field: "secret scope digest",
            });
        }
        let reference_digest = Digest::from_parts(
            "hartevo-slack-secret-reference/v1",
            &[
                reference_id,
                format!("{kind:?}"),
                scope_digest.to_string(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn for_bot(
        reference_id: impl Into<String>,
        scope: &SlackDecisionScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            SecretKind::Bot,
            scope.digest(),
            Revision::new(1)?,
        )
    }

    pub fn for_user(
        reference_id: impl Into<String>,
        scope: &SlackDecisionScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            SecretKind::User,
            scope.digest(),
            Revision::new(1)?,
        )
    }

    pub fn for_bot_at_revision(
        reference_id: impl Into<String>,
        scope: &SlackDecisionScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, SecretKind::Bot, scope.digest(), revision)
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SlackDecisionScope {
    pub workspace: WorkspaceId,
    pub team: TeamId,
    pub channel: ChannelId,
    pub thread: ThreadId,
    pub time_window: TimeWindow,
    pub decision_fingerprint: DecisionFingerprint,
    pub mission: MissionScope,
    pub token_scope: TokenScope,
}

impl SlackDecisionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: WorkspaceId,
        team: TeamId,
        channel: ChannelId,
        thread: ThreadId,
        time_window: TimeWindow,
        decision_fingerprint: DecisionFingerprint,
        mission: MissionScope,
        token_scope: TokenScope,
    ) -> Result<Self, ModelError> {
        if decision_fingerprint.digest().is_zero() {
            return Err(ModelError::InvalidDigest {
                field: "decision fingerprint",
            });
        }
        if !token_scope.contains("channels:history") && !token_scope.contains("groups:history") {
            return Err(ModelError::Unsupported {
                field: "history token scope",
            });
        }
        Ok(Self {
            workspace,
            team,
            channel,
            thread,
            time_window,
            decision_fingerprint,
            mission,
            token_scope,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.decision_fingerprint.digest().is_zero() {
            return Err(ModelError::InvalidDigest {
                field: "decision fingerprint",
            });
        }
        if !self.token_scope.contains("channels:history")
            && !self.token_scope.contains("groups:history")
        {
            return Err(ModelError::Unsupported {
                field: "history token scope",
            });
        }
        Ok(())
    }

    pub fn mission_scope(&self) -> &MissionScope {
        &self.mission
    }

    pub fn token_scope_digest(&self) -> Digest {
        self.token_scope.digest()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlackReadOperation {
    ConversationsHistory,
    ConversationsReplies,
}

impl SlackReadOperation {
    pub const HISTORY: Self = Self::ConversationsHistory;
    pub const REPLIES: Self = Self::ConversationsReplies;

    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ConversationsHistory => "conversations.history",
            Self::ConversationsReplies => "conversations.replies",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Digest,
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("OpaqueCursor", 1)?;
        output.serialize_field("opaque", &true)?;
        output.end()
    }
}

impl OpaqueCursor {
    pub fn new(raw_cursor: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let raw_cursor = raw_cursor.as_ref();
        if raw_cursor.is_empty() || raw_cursor.len() > MAX_CURSOR_BYTES {
            return Err(ModelError::InvalidCursor { field: "cursor" });
        }
        if raw_cursor.iter().any(u8::is_ascii_control) {
            return Err(ModelError::InvalidCursor { field: "cursor" });
        }
        Ok(Self {
            token_digest: Digest::from_bytes(raw_cursor),
            binding_digest: Digest::zero(),
        })
    }

    pub fn bind(&self, request_binding: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: request_binding.clone(),
        }
    }

    pub fn is_bound(&self) -> bool {
        !self.binding_digest.is_zero()
    }

    pub fn is_bound_to(&self, request_binding: &Digest) -> bool {
        self.binding_digest == *request_binding
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }
}

impl fmt::Display for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque-cursor>")
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SlackReadRequest {
    pub operation: SlackReadOperation,
    pub scope_digest: Digest,
    pub channel: ChannelId,
    pub thread: ThreadId,
    pub time_window: TimeWindow,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
}

impl SlackReadRequest {
    pub fn new(
        scope: &SlackDecisionScope,
        operation: SlackReadOperation,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid { field: "max pages" });
        }
        let request_binding = Digest::from_parts(
            "hartevo-slack-read-binding/v1",
            &[
                operation.api_name().to_owned(),
                scope.digest().to_string(),
                scope.channel.to_string(),
                scope.thread.to_string(),
                scope.time_window.digest().to_string(),
                page_size.to_string(),
                max_pages.to_string(),
            ],
        );
        let cursor = cursor.map(|cursor| {
            if cursor.is_bound() {
                cursor
            } else {
                cursor.bind(&request_binding)
            }
        });
        if cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.is_bound_to(&request_binding))
        {
            return Err(ModelError::ScopeMismatch { field: "cursor" });
        }
        let mut request = Self {
            operation,
            scope_digest: scope.digest(),
            channel: scope.channel.clone(),
            thread: scope.thread.clone(),
            time_window: scope.time_window.clone(),
            page_size,
            max_pages,
            cursor,
            request_digest: Digest::zero(),
        };
        request.request_digest = request.recomputed_digest();
        Ok(request)
    }

    pub fn history(
        scope: &SlackDecisionScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            SlackReadOperation::ConversationsHistory,
            page_size,
            max_pages,
            cursor,
        )
    }

    pub fn replies(
        scope: &SlackDecisionScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            SlackReadOperation::ConversationsReplies,
            page_size,
            max_pages,
            cursor,
        )
    }

    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Result<Self, ModelError> {
        let binding = self.binding_digest();
        let cursor = cursor.map(|cursor| {
            if cursor.is_bound() {
                cursor
            } else {
                cursor.bind(&binding)
            }
        });
        if cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.is_bound_to(&binding))
        {
            return Err(ModelError::ScopeMismatch { field: "cursor" });
        }
        self.cursor = cursor;
        self.request_digest = self.recomputed_digest();
        Ok(self)
    }

    pub fn binding_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-slack-read-binding/v1",
            &[
                self.operation.api_name().to_owned(),
                self.scope_digest.to_string(),
                self.channel.to_string(),
                self.thread.to_string(),
                self.time_window.digest().to_string(),
                self.page_size.to_string(),
                self.max_pages.to_string(),
            ],
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RequestDigestBody {
            operation: self.operation,
            scope_digest: &self.scope_digest,
            channel: &self.channel,
            thread: &self.thread,
            time_window: &self.time_window,
            page_size: self.page_size,
            max_pages: self.max_pages,
            cursor_digest: self.cursor.as_ref().map(OpaqueCursor::token_digest),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestDigestBody<'a> {
    operation: SlackReadOperation,
    scope_digest: &'a Digest,
    channel: &'a ChannelId,
    thread: &'a ThreadId,
    time_window: &'a TimeWindow,
    page_size: u16,
    max_pages: u16,
    cursor_digest: Option<&'a Digest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantClass {
    Bot,
    User,
    Mixed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SlackMessageProjection {
    pub timestamp: DateTime<Utc>,
    pub message_digest: Digest,
    pub content_fingerprint: Digest,
    pub reaction_digest: Digest,
    pub decision_marker_digest: Option<Digest>,
    pub reply_count: u16,
    pub participant_class: ParticipantClass,
}

impl SlackMessageProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp: DateTime<Utc>,
        message_digest: Digest,
        content_fingerprint: Digest,
        reaction_digest: Digest,
        decision_marker_digest: Option<Digest>,
        reply_count: u16,
        participant_class: ParticipantClass,
    ) -> Result<Self, ModelError> {
        if message_digest.is_zero() || content_fingerprint.is_zero() || reaction_digest.is_zero() {
            return Err(ModelError::InvalidDigest {
                field: "redacted message projection",
            });
        }
        if decision_marker_digest.as_ref().is_some_and(Digest::is_zero) {
            return Err(ModelError::InvalidDigest {
                field: "decision marker digest",
            });
        }
        Ok(Self {
            timestamp,
            message_digest,
            content_fingerprint,
            reaction_digest,
            decision_marker_digest,
            reply_count,
            participant_class,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionState {
    WithinWindow,
    Expired,
    Unavailable,
    Unknown,
}

impl RetentionState {
    pub const fn is_safe(self) -> bool {
        matches!(self, Self::WithinWindow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    Redacted,
    Unredacted,
    Unknown,
}

impl RedactionState {
    pub const fn is_safe(self) -> bool {
        matches!(self, Self::Redacted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
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

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SlackReadPage {
    pub operation: SlackReadOperation,
    pub request_digest: Digest,
    pub page_number: u16,
    pub messages: Vec<SlackMessageProjection>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub retention: RetentionState,
    pub redaction: RedactionState,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
}

impl SlackReadPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &SlackReadRequest,
        page_number: u16,
        messages: Vec<SlackMessageProjection>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        retention: RetentionState,
        redaction: RedactionState,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > request.max_pages {
            return Err(ModelError::Invalid {
                field: "page number",
            });
        }
        if messages.len() > usize::from(request.page_size)
            || messages.len() > MAX_PAGE_SIZE as usize
        {
            return Err(ModelError::TooMany {
                field: "messages per page",
            });
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "response bytes",
            });
        }
        if let Some(cursor) = &next_cursor
            && cursor.is_bound()
            && !cursor.is_bound_to(&request.binding_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "next cursor",
            });
        }
        if messages
            .iter()
            .any(|message| !request.time_window.contains(message.timestamp))
        {
            return Err(ModelError::ScopeMismatch {
                field: "message time",
            });
        }
        let mut page = Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            page_number,
            messages,
            next_cursor,
            response_bytes,
            retention,
            redaction,
            provenance,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&PageDigestBody {
            operation: self.operation,
            request_digest: &self.request_digest,
            page_number: self.page_number,
            messages: &self.messages,
            next_cursor_digest: self.next_cursor.as_ref().map(OpaqueCursor::token_digest),
            response_bytes: self.response_bytes,
            retention: self.retention,
            redaction: self.redaction,
            provenance: self.provenance,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "page digest",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PageDigestBody<'a> {
    operation: SlackReadOperation,
    request_digest: &'a Digest,
    page_number: u16,
    messages: &'a [SlackMessageProjection],
    next_cursor_digest: Option<&'a Digest>,
    response_bytes: usize,
    retention: RetentionState,
    redaction: RedactionState,
    provenance: TransportProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    RateLimited,
    PermissionDenied,
    Timeout,
    RetentionUnavailable,
    ProviderUnknown,
    ScopeDrift,
    RedactionLoss,
    CursorReplay,
    CursorLoop,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("Slack transport is blocked in Layer-1 environment")]
    BlockedEnv,
    #[error("Slack provider returned a bounded error state: {0:?}")]
    Provider(ProviderErrorKind),
    #[error("Slack transport response is invalid: {0}")]
    InvalidResponse(String),
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::BlockedEnv => ProviderErrorKind::ProviderUnknown,
            Self::Provider(kind) => *kind,
            Self::InvalidResponse(_) => ProviderErrorKind::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(error: &TransportError) -> Self {
        let kind = error.kind();
        Self {
            kind,
            digest: Digest::from_parts("hartevo-slack-provider-error/v1", &[format!("{kind:?}")]),
        }
    }
}

pub(crate) fn evidence_policy_digest() -> Digest {
    Digest::from_parts(
        "hartevo-slack-evidence-policy/v1",
        &[
            SLACK_DECISION_PLUGIN_VERSION.to_owned(),
            SLACK_DECISION_CONTRACT_VERSION.to_owned(),
            SLACK_DECISION_API_REVISION.to_owned(),
            MAX_PAGE_SIZE.to_string(),
            MAX_PAGES.to_string(),
            MAX_MESSAGES.to_string(),
            MAX_REPLIES.to_string(),
            "raw-message-text-excluded".to_owned(),
            "raw-attachments-excluded".to_owned(),
            "member-pii-excluded".to_owned(),
        ],
    )
}

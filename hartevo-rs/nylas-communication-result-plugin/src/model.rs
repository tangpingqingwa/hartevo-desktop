use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_ITEMS: usize = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_BACKOFF_SECONDS: u32 = 300;
pub const MAX_ATTEMPTS: u8 = 5;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded Nylas value serializes");
    sha256_digest(&bytes)
}

pub(crate) fn validate_digest(value: &str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@+%/~$-".contains(&byte))
}

fn valid_secret_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SECRET_REFERENCE_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_revision(value: u64, label: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("Nylas permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Nylas secret reference is invalid")]
    InvalidSecretReference,
    #[error("Nylas scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Nylas request is invalid or outside its exact scope")]
    InvalidRequest,
    #[error("Nylas metadata aggregate is invalid or exceeds the Layer-1 bound")]
    InvalidAggregate,
    #[error("Nylas pagination cursor is invalid or not bound to its request")]
    InvalidCursor,
    #[error("Nylas selected field set is invalid")]
    InvalidFieldSelection,
    #[error("Nylas registration is already revoked")]
    AlreadyRevoked,
    #[error("Nylas registration or secret is not revoked")]
    NotRevoked,
    #[error("Nylas registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An identifier is retained only inside the provider boundary and serializes
/// as its deterministic digest. This keeps mailbox/grant/resource identifiers
/// out of evidence and debug output while still allowing fixture transports to
/// bind requests to exact scope.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueIdentifier(String);

impl OpaqueIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(ModelError::InvalidIdentifier {
                label: "identifier",
            });
        }
        Ok(Self(value))
    }

    pub fn from_digest(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_digest(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(format!("nylas-identifier/v1|{}", self.0).as_bytes())
    }

    #[must_use]
    pub fn redacted(&self) -> String {
        format!("identifier:{}", &self.digest()[..16])
    }

    pub(crate) fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        if valid_identifier(&self.0) {
            Ok(())
        } else {
            Err(ModelError::InvalidIdentifier { label })
        }
    }
}

impl Serialize for OpaqueIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.digest())
    }
}

impl fmt::Debug for OpaqueIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueIdentifier")
            .field(&self.redacted())
            .finish()
    }
}

pub type NylasApplicationId = OpaqueIdentifier;
pub type NylasGrantId = OpaqueIdentifier;
pub type NylasMailboxId = OpaqueIdentifier;
pub type NylasCalendarId = OpaqueIdentifier;
pub type NylasThreadId = OpaqueIdentifier;
pub type NylasMessageId = OpaqueIdentifier;
pub type NylasEventId = OpaqueIdentifier;
pub type ProjectId = OpaqueIdentifier;
pub type MissionId = OpaqueIdentifier;
pub type WorkProductId = OpaqueIdentifier;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeBinding {
    id: OpaqueIdentifier,
    revision: Revision,
}

impl ScopeBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let binding = Self {
            id: OpaqueIdentifier::new(id)?,
            revision: Revision::new(revision)?,
        };
        binding.validate("binding")?;
        Ok(binding)
    }

    #[must_use]
    pub fn id(&self) -> &OpaqueIdentifier {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        self.id.validate(label)?;
        validate_revision(self.revision.get(), label)
    }
}

pub type ProjectBinding = ScopeBinding;
pub type MissionBinding = ScopeBinding;
pub type WorkProductBinding = ScopeBinding;
pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

/// A secret reference contains no key/token bytes and deliberately has no
/// `Serialize` implementation. Only a stable reference digest crosses a
/// registration or evidence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(reference: impl AsRef<str>, credential_revision: u64) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if !valid_secret_reference(reference) {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: sha256_digest(
                format!("nylas-secret-reference/v1|{reference}").as_bytes(),
            ),
            credential_revision: Revision::new(credential_revision)?,
            revoked: false,
        })
    }

    pub fn api_key(
        reference: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference, credential_revision)
    }

    pub fn access_token(
        reference: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference, credential_revision)
    }

    pub fn from_digest(
        reference_digest: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_digest = reference_digest.into();
        validate_digest(&reference_digest)?;
        Ok(Self {
            reference_digest,
            credential_revision: Revision::new(credential_revision)?,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "nylas-secret-reference/v1|{}|{}",
                self.reference_digest,
                self.credential_revision.get()
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference", &"<redacted>")
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasPermission {
    ApplicationRead,
    GrantRead,
    MailboxRead,
    CalendarRead,
    ThreadRead,
    MessageRead,
    EventRead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasPermissionSnapshot {
    permissions: BTreeSet<NylasPermission>,
    revision: Revision,
    read_only: bool,
}

impl NylasPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = NylasPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let snapshot = Self {
            permissions: permissions.into_iter().collect(),
            revision: Revision::new(revision)?,
            read_only: true,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                NylasPermission::ApplicationRead,
                NylasPermission::GrantRead,
                NylasPermission::MailboxRead,
                NylasPermission::CalendarRead,
                NylasPermission::ThreadRead,
                NylasPermission::MessageRead,
                NylasPermission::EventRead,
            ],
            revision,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_revision(self.revision.get(), "permission")?;
        if !self.read_only || self.permissions.is_empty() {
            return Err(ModelError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn has(&self, permission: NylasPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<NylasPermission> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationScopeSpec {
    pub application: NylasApplicationId,
    pub grant: NylasGrantId,
    pub mailbox: NylasMailboxId,
    pub calendar: NylasCalendarId,
    pub thread: NylasThreadId,
    pub message: NylasMessageId,
    pub event: NylasEventId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permissions: NylasPermissionSnapshot,
    pub scope_revision: Revision,
}

#[allow(clippy::too_many_arguments)]
impl NylasCommunicationScopeSpec {
    pub fn new(
        application: NylasApplicationId,
        grant: NylasGrantId,
        mailbox: NylasMailboxId,
        calendar: NylasCalendarId,
        thread: NylasThreadId,
        message: NylasMessageId,
        event: NylasEventId,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permissions: NylasPermissionSnapshot,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let spec = Self {
            application,
            grant,
            mailbox,
            calendar,
            thread,
            message,
            event,
            project,
            mission,
            work_product,
            permissions,
            scope_revision: Revision::new(scope_revision)?,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.application.validate("application")?;
        self.grant.validate("grant")?;
        self.mailbox.validate("mailbox")?;
        self.calendar.validate("calendar")?;
        self.thread.validate("thread")?;
        self.message.validate("message")?;
        self.event.validate("event")?;
        self.project.validate("project")?;
        self.mission.validate("mission")?;
        self.work_product.validate("work product")?;
        self.permissions.validate()?;
        validate_revision(self.scope_revision.get(), "scope")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationScope {
    spec: NylasCommunicationScopeSpec,
    scope_digest: Digest,
    revision_digest: Digest,
}

impl NylasCommunicationScope {
    pub fn new(spec: NylasCommunicationScopeSpec) -> Result<Self, ModelError> {
        spec.validate()?;
        let scope_digest = canonical_digest(&("nylas-scope/v1", &spec));
        let revision_digest = canonical_digest(&(
            "nylas-revision-fence/v1",
            spec.scope_revision,
            spec.permissions.revision(),
            spec.project.revision(),
            spec.mission.revision(),
            spec.work_product.revision(),
        ));
        Ok(Self {
            spec,
            scope_digest,
            revision_digest,
        })
    }

    #[must_use]
    pub fn spec(&self) -> &NylasCommunicationScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn application(&self) -> &NylasApplicationId {
        &self.spec.application
    }

    #[must_use]
    pub fn grant(&self) -> &NylasGrantId {
        &self.spec.grant
    }

    #[must_use]
    pub fn mailbox(&self) -> &NylasMailboxId {
        &self.spec.mailbox
    }

    #[must_use]
    pub fn calendar(&self) -> &NylasCalendarId {
        &self.spec.calendar
    }

    #[must_use]
    pub fn thread(&self) -> &NylasThreadId {
        &self.spec.thread
    }

    #[must_use]
    pub fn message(&self) -> &NylasMessageId {
        &self.spec.message
    }

    #[must_use]
    pub fn event(&self) -> &NylasEventId {
        &self.spec.event
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.spec.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.spec.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.spec.work_product
    }

    #[must_use]
    pub fn permissions(&self) -> &NylasPermissionSnapshot {
        &self.spec.permissions
    }

    #[must_use]
    pub const fn scope_revision(&self) -> Revision {
        self.spec.scope_revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permissions().digest()
    }

    #[must_use]
    pub fn resource_digest(&self, resource: NylasResourceKind) -> Digest {
        match resource {
            NylasResourceKind::Application => self.application().digest(),
            NylasResourceKind::Grant => self.grant().digest(),
            NylasResourceKind::Mailbox => self.mailbox().digest(),
            NylasResourceKind::Calendar => self.calendar().digest(),
            NylasResourceKind::Thread => self.thread().digest(),
            NylasResourceKind::Message => self.message().digest(),
            NylasResourceKind::Event => self.event().digest(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.spec.validate()?;
        if self.scope_digest != canonical_digest(&("nylas-scope/v1", &self.spec))
            || self.revision_digest
                != canonical_digest(&(
                    "nylas-revision-fence/v1",
                    self.spec.scope_revision,
                    self.spec.permissions.revision(),
                    self.spec.project.revision(),
                    self.spec.mission.revision(),
                    self.spec.work_product.revision(),
                ))
        {
            return Err(ModelError::InvalidScope("scope or revision digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasResourceKind {
    Application,
    Grant,
    Mailbox,
    Calendar,
    Thread,
    Message,
    Event,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasReadOperation {
    Messages,
    Message,
    Threads,
    Thread,
    Calendars,
    Calendar,
    Events,
    Event,
}

pub type NylasOperation = NylasReadOperation;

impl NylasReadOperation {
    #[must_use]
    pub const fn resource_kind(self) -> NylasResourceKind {
        match self {
            Self::Messages | Self::Message => NylasResourceKind::Message,
            Self::Threads | Self::Thread => NylasResourceKind::Thread,
            Self::Calendars | Self::Calendar => NylasResourceKind::Calendar,
            Self::Events | Self::Event => NylasResourceKind::Event,
        }
    }

    #[must_use]
    pub const fn permission(self) -> NylasPermission {
        match self {
            Self::Messages | Self::Message => NylasPermission::MessageRead,
            Self::Threads | Self::Thread => NylasPermission::ThreadRead,
            Self::Calendars | Self::Calendar => NylasPermission::CalendarRead,
            Self::Events | Self::Event => NylasPermission::EventRead,
        }
    }

    #[must_use]
    pub const fn is_collection(self) -> bool {
        matches!(
            self,
            Self::Messages | Self::Threads | Self::Calendars | Self::Events
        )
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Messages => "/v3/grants/{grant_id}/messages",
            Self::Message => "/v3/grants/{grant_id}/messages/{message_id}",
            Self::Threads => "/v3/grants/{grant_id}/threads",
            Self::Thread => "/v3/grants/{grant_id}/threads/{thread_id}",
            Self::Calendars => "/v3/grants/{grant_id}/calendars",
            Self::Calendar => "/v3/grants/{grant_id}/calendars/{calendar_id}",
            Self::Events => "/v3/grants/{grant_id}/events",
            Self::Event => "/v3/grants/{grant_id}/events/{event_id}",
        }
    }

    #[must_use]
    pub const fn expected_kind(self) -> NylasRecordKind {
        match self {
            Self::Messages | Self::Message => NylasRecordKind::Message,
            Self::Threads | Self::Thread => NylasRecordKind::Thread,
            Self::Calendars | Self::Calendar => NylasRecordKind::Calendar,
            Self::Events | Self::Event => NylasRecordKind::Event,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdempotencyKey {
    digest: Digest,
}

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            digest: sha256_digest(format!("nylas-idempotency-key/v1|{value}").as_bytes()),
        })
    }

    pub fn from_digest(digest: impl Into<String>) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest)?;
        Ok(Self { digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueCursor {
    digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            digest: sha256_digest(format!("nylas-cursor/v1|{value}").as_bytes()),
            binding_digest: None,
        })
    }

    pub fn bound(
        value: impl AsRef<str>,
        binding_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let mut cursor = Self::new(value)?;
        let binding_digest = binding_digest.into();
        validate_digest(&binding_digest)?;
        cursor.binding_digest = Some(binding_digest);
        Ok(cursor)
    }

    pub fn from_digest(
        digest: impl Into<String>,
        binding_digest: Option<String>,
    ) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest)?;
        if let Some(binding) = &binding_digest {
            validate_digest(binding)?;
        }
        Ok(Self {
            digest,
            binding_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasSelectedField {
    Object,
    Id,
    GrantId,
    ThreadId,
    CalendarId,
    EventId,
    Date,
    UpdatedAt,
    SubjectDigest,
    Status,
    HasAttachments,
    Unread,
    Starred,
    Busy,
    Cancelled,
    ParticipantCount,
    MessageCount,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasFieldSelection {
    fields: BTreeSet<NylasSelectedField>,
}

impl NylasFieldSelection {
    pub fn new(fields: impl IntoIterator<Item = NylasSelectedField>) -> Result<Self, ModelError> {
        let selection = Self {
            fields: fields.into_iter().collect(),
        };
        selection.validate()?;
        Ok(selection)
    }

    #[must_use]
    pub fn metadata() -> Self {
        Self {
            fields: [
                NylasSelectedField::Object,
                NylasSelectedField::Id,
                NylasSelectedField::GrantId,
                NylasSelectedField::ThreadId,
                NylasSelectedField::CalendarId,
                NylasSelectedField::EventId,
                NylasSelectedField::Date,
                NylasSelectedField::UpdatedAt,
                NylasSelectedField::SubjectDigest,
                NylasSelectedField::Status,
                NylasSelectedField::HasAttachments,
                NylasSelectedField::Unread,
                NylasSelectedField::Starred,
                NylasSelectedField::Busy,
                NylasSelectedField::Cancelled,
                NylasSelectedField::ParticipantCount,
                NylasSelectedField::MessageCount,
            ]
            .into_iter()
            .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.fields.is_empty() {
            Err(ModelError::InvalidFieldSelection)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn contains(&self, field: NylasSelectedField) -> bool {
        self.fields.contains(&field)
    }

    #[must_use]
    pub fn fields(&self) -> &BTreeSet<NylasSelectedField> {
        &self.fields
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl Default for NylasFieldSelection {
    fn default() -> Self {
        Self::metadata()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationRequest {
    operation: NylasReadOperation,
    target_id_digest: Option<Digest>,
    page_token_digest: Option<Digest>,
    cursor_binding_digest: Option<Digest>,
    field_selection: NylasFieldSelection,
    page_size: u16,
    scope_digest: Digest,
    revision_digest: Digest,
    permission_digest: Digest,
    idempotency_key_digest: Digest,
}

impl NylasCommunicationRequest {
    pub fn new(
        scope: &NylasCommunicationScope,
        operation: NylasReadOperation,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let target_id_digest =
            (!operation.is_collection()).then(|| scope.resource_digest(operation.resource_kind()));
        Ok(Self {
            operation,
            target_id_digest,
            page_token_digest: None,
            cursor_binding_digest: None,
            field_selection: NylasFieldSelection::metadata(),
            page_size: MAX_PAGE_SIZE,
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            permission_digest: scope.permission_digest(),
            idempotency_key_digest: idempotency_key.digest().clone(),
        })
    }

    pub fn messages(
        scope: &NylasCommunicationScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, NylasReadOperation::Messages, key)
    }

    pub fn threads(
        scope: &NylasCommunicationScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, NylasReadOperation::Threads, key)
    }

    pub fn calendars(
        scope: &NylasCommunicationScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, NylasReadOperation::Calendars, key)
    }

    pub fn events(
        scope: &NylasCommunicationScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(scope, NylasReadOperation::Events, key)
    }

    pub fn with_page_size(mut self, page_size: u16) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidRequest);
        }
        self.page_size = page_size;
        Ok(self)
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: &OpaqueCursor) -> Self {
        let binding = cursor
            .binding_digest()
            .cloned()
            .unwrap_or_else(|| self.cursor_binding_digest());
        self.page_token_digest = Some(cursor.digest().clone());
        self.cursor_binding_digest = Some(binding);
        self
    }

    #[must_use]
    pub fn with_fields(mut self, fields: NylasFieldSelection) -> Self {
        self.field_selection = fields;
        self
    }

    #[must_use]
    pub const fn operation(&self) -> NylasReadOperation {
        self.operation
    }

    #[must_use]
    pub fn target_id_digest(&self) -> Option<&Digest> {
        self.target_id_digest.as_ref()
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<&Digest> {
        self.page_token_digest.as_ref()
    }

    #[must_use]
    pub fn cursor_binding_digest(&self) -> Digest {
        canonical_digest(&(
            "nylas-cursor-binding/v1",
            self.operation,
            &self.target_id_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.permission_digest,
            &self.field_selection.digest(),
            self.page_size,
        ))
    }

    #[must_use]
    pub fn cursor_binding(&self) -> Option<&Digest> {
        self.cursor_binding_digest.as_ref()
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn field_selection(&self) -> &NylasFieldSelection {
        &self.field_selection
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn idempotency_key_digest(&self) -> &Digest {
        &self.idempotency_key_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self, scope: &NylasCommunicationScope) -> Result<(), ModelError> {
        scope.validate()?;
        self.field_selection.validate()?;
        if self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || validate_digest(&self.idempotency_key_digest).is_err()
            || self
                .target_id_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
            || self
                .page_token_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(ModelError::InvalidRequest);
        }
        let expected_target = (!self.operation.is_collection())
            .then(|| scope.resource_digest(self.operation.resource_kind()));
        if self.target_id_digest != expected_target {
            return Err(ModelError::InvalidRequest);
        }
        match (&self.page_token_digest, &self.cursor_binding_digest) {
            (None, None) => Ok(()),
            (Some(_), Some(binding)) if binding == &self.cursor_binding_digest() => Ok(()),
            _ => Err(ModelError::InvalidCursor),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasRecordKind {
    Message,
    Thread,
    Calendar,
    Event,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasDeliveryStatus {
    Sent,
    Delivered,
    Bounced,
    Failed,
    Cancelled,
    Updated,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasMetadataRecord {
    pub kind: NylasRecordKind,
    pub id_digest: Digest,
    pub grant_id_digest: Option<Digest>,
    pub thread_id_digest: Option<Digest>,
    pub calendar_id_digest: Option<Digest>,
    pub event_id_digest: Option<Digest>,
    pub message_digest: Option<Digest>,
    pub thread_digest: Option<Digest>,
    pub event_digest: Option<Digest>,
    pub occurred_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub subject_digest: Option<Digest>,
    pub status: Option<NylasDeliveryStatus>,
    pub has_attachments: Option<bool>,
    pub unread: Option<bool>,
    pub starred: Option<bool>,
    pub busy: Option<bool>,
    pub cancelled: Option<bool>,
    pub participant_count: Option<u16>,
    pub message_count: Option<u16>,
    pub selected_fields_digest: Digest,
    pub record_digest: Digest,
}

impl NylasMetadataRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kind: NylasRecordKind,
        id_digest: Digest,
        grant_id_digest: Option<Digest>,
        thread_id_digest: Option<Digest>,
        calendar_id_digest: Option<Digest>,
        event_id_digest: Option<Digest>,
        occurred_at: Option<i64>,
        updated_at: Option<i64>,
        subject_digest: Option<Digest>,
        status: Option<NylasDeliveryStatus>,
        has_attachments: Option<bool>,
        unread: Option<bool>,
        starred: Option<bool>,
        busy: Option<bool>,
        cancelled: Option<bool>,
        participant_count: Option<u16>,
        message_count: Option<u16>,
        selected_fields_digest: Digest,
        message_digest: Option<Digest>,
        thread_digest: Option<Digest>,
        event_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        validate_digest(&id_digest)?;
        for digest in [
            grant_id_digest.as_ref(),
            thread_id_digest.as_ref(),
            calendar_id_digest.as_ref(),
            event_id_digest.as_ref(),
            subject_digest.as_ref(),
            message_digest.as_ref(),
            thread_digest.as_ref(),
            event_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest)?;
        }
        validate_digest(&selected_fields_digest)?;
        let mut record = Self {
            kind,
            id_digest,
            grant_id_digest,
            thread_id_digest,
            calendar_id_digest,
            event_id_digest,
            message_digest,
            thread_digest,
            event_digest,
            occurred_at,
            updated_at,
            subject_digest,
            status,
            has_attachments,
            unread,
            starred,
            busy,
            cancelled,
            participant_count,
            message_count,
            selected_fields_digest,
            record_digest: String::new(),
        };
        record.record_digest = record.compute_digest();
        Ok(record)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.record_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.id_digest)?;
        validate_digest(&self.selected_fields_digest)?;
        if self.record_digest != self.compute_digest() {
            return Err(ModelError::InvalidAggregate);
        }
        for digest in [
            self.grant_id_digest.as_ref(),
            self.thread_id_digest.as_ref(),
            self.calendar_id_digest.as_ref(),
            self.event_id_digest.as_ref(),
            self.message_digest.as_ref(),
            self.thread_digest.as_ref(),
            self.event_digest.as_ref(),
            self.subject_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest)?;
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.record_digest.clear();
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasMetadataPage {
    pub operation: NylasReadOperation,
    pub records: Vec<NylasMetadataRecord>,
    pub item_count: u16,
    pub total_count: Option<u32>,
    pub partial: bool,
    pub next_cursor_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl NylasMetadataPage {
    pub(crate) fn new(
        operation: NylasReadOperation,
        mut records: Vec<NylasMetadataRecord>,
        total_count: Option<u32>,
        partial: bool,
        next_cursor_digest: Option<Digest>,
        cursor_binding_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if records.len() > MAX_ITEMS {
            return Err(ModelError::InvalidAggregate);
        }
        if next_cursor_digest.is_some() != cursor_binding_digest.is_some() {
            return Err(ModelError::InvalidAggregate);
        }
        if let Some(cursor) = &next_cursor_digest {
            validate_digest(cursor)?;
        }
        if let Some(binding) = &cursor_binding_digest {
            validate_digest(binding)?;
        }
        for record in &records {
            record.validate()?;
            if record.kind != operation.expected_kind() {
                return Err(ModelError::InvalidAggregate);
            }
        }
        records.sort_by_key(|record| record.record_digest.clone());
        let item_count = u16::try_from(records.len()).map_err(|_| ModelError::InvalidAggregate)?;
        if total_count.is_some_and(|total| total < u32::from(item_count)) {
            return Err(ModelError::InvalidAggregate);
        }
        let mut page = Self {
            operation,
            records,
            item_count,
            total_count,
            partial,
            next_cursor_digest,
            cursor_binding_digest,
            page_digest: String::new(),
        };
        page.page_digest = page.compute_digest();
        Ok(page)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.page_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.records.len() > MAX_ITEMS
            || self.item_count != self.records.len() as u16
            || self.next_cursor_digest.is_some() != self.cursor_binding_digest.is_some()
            || self.page_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidAggregate);
        }
        for record in &self.records {
            record.validate()?;
            if record.kind != self.operation.expected_kind() {
                return Err(ModelError::InvalidAggregate);
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.page_digest.clear();
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub backoff_seconds: u32,
    pub attempt: u8,
    pub throttled: bool,
}

impl Default for NylasRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: Some(MAX_REQUESTS_PER_MINUTE - 1),
            retry_after_seconds: None,
            backoff_seconds: 0,
            attempt: 1,
            throttled: false,
        }
    }
}

impl NylasRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        backoff_seconds: u32,
        attempt: u8,
        throttled: bool,
    ) -> Result<Self, ModelError> {
        let receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            backoff_seconds,
            attempt,
            throttled,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || self
                .remaining
                .is_some_and(|remaining| remaining > self.limit_per_minute)
            || self
                .retry_after_seconds
                .is_some_and(|seconds| seconds > MAX_RETRY_AFTER_SECONDS)
            || self.backoff_seconds > MAX_BACKOFF_SECONDS
            || self.attempt == 0
            || self.attempt > MAX_ATTEMPTS
        {
            Err(ModelError::InvalidAggregate)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasTransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl NylasTransportProvenance {
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
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NylasEvidenceState {
    Sent,
    Delivered,
    Bounced,
    Failed,
    Cancelled,
    Updated,
    Complete,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    BlockedEnv,
    Tamper,
    Stale,
    Revoked,
    Timeout,
    RateLimited,
}

pub type NylasCommunicationState = NylasEvidenceState;
pub type NylasCommunicationResultState = NylasEvidenceState;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl NylasRegistration {
    #[must_use]
    pub fn bind(
        scope: &NylasCommunicationScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::PLUGIN_VERSION.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_digest: provider_digest.clone(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            evidence_digest: canonical_digest(&(
                "nylas-evidence-contract/v1",
                crate::CONTRACT_VERSION,
                &provider_digest,
                scope.permission_digest(),
                scope.scope_digest(),
                scope.revision_digest(),
            )),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: Revision::new(1).expect("registration revision is non-zero"),
            registration_digest: String::new(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    pub fn validate(
        &self,
        scope: &NylasCommunicationScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        let expected_evidence_digest = canonical_digest(&(
            "nylas-evidence-contract/v1",
            crate::CONTRACT_VERSION,
            provider_digest,
            scope.permission_digest(),
            scope.scope_digest(),
            scope.revision_digest(),
        ));
        if self.plugin_version != crate::PLUGIN_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.evidence_digest != expected_evidence_digest
            || self.secret_reference_digest != secret_reference.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if !self.revocable || self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.reversible {
            return Err(ModelError::InvalidScope("registration is not reversible"));
        }
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.registration_digest.clear();
        canonical_digest(&copy)
    }
}

pub type NylasProviderRegistration = NylasRegistration;
pub type NylasScope = NylasCommunicationScope;
pub type NylasScopeSpec = NylasCommunicationScopeSpec;
pub type NylasPageToken = OpaqueCursor;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_response_dropped: bool,
    pub raw_api_key_dropped: bool,
    pub raw_access_token_dropped: bool,
    pub raw_message_body_dropped: bool,
    pub raw_calendar_body_dropped: bool,
    pub raw_attachment_dropped: bool,
    pub raw_recipient_pii_dropped: bool,
    pub webhook_material_dropped: bool,
}

impl RedactionSummary {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            raw_response_dropped: true,
            raw_api_key_dropped: true,
            raw_access_token_dropped: true,
            raw_message_body_dropped: true,
            raw_calendar_body_dropped: true,
            raw_attachment_dropped: true,
            raw_recipient_pii_dropped: true,
            webhook_material_dropped: true,
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.raw_response_dropped
            && self.raw_api_key_dropped
            && self.raw_access_token_dropped
            && self.raw_message_body_dropped
            && self.raw_calendar_body_dropped
            && self.raw_attachment_dropped
            && self.raw_recipient_pii_dropped
            && self.webhook_material_dropped
    }
}

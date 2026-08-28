#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 Intercom conversation-result evidence plugin."]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::needless_pass_by_value)]

//! A bounded, read/proposal/recording boundary for one Intercom conversation.
//!
//! The crate intentionally has no HTTP client, native credential resolver,
//! reply sender, conversation mutator, webhook registration, Inbox authority,
//! durable provider receipt, or Kernel Outcome adoption authority. Recording,
//! fake, loopback, and `BLOCKED_ENV` transports are deterministic evidence
//! sources and are never reported as Connected, native, or first-party.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.intercom-conversation-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-INTERCOM-01-L1/v1";
pub const PLUGIN_ID: &str = "intercom.conversation-result";
pub const SERVICE_ID: &str = "IntercomConversationResultService";
pub const PROVIDER_ID: &str = "IntercomProvider";
pub const CONSUMER_ID: &str = "MissionIntercomConversationConsumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const INTERCOM_API_PATH: &str = "/";
pub const WORKSPACE_PATH: &str = "/me";
pub const CONVERSATION_PATH: &str = "/conversations/{conversation_id}";
pub const CONVERSATION_PARTS_PATH: &str = "/conversations/{conversation_id}/parts";
pub const CONVERSATION_REPLIES_PATH: &str = CONVERSATION_PARTS_PATH;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_CURSOR_AGE_SECONDS: u64 = 900;
pub const MAX_PAGE_ITEMS: usize = 100;
pub const MAX_PAGES: usize = 32;
pub const MAX_PARTS: usize = 1_024;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/intercom-conversation-result/service.v1.json");

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

pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);

/// A lowercase SHA-256 digest. Raw provider data and credential material are
/// never represented by this type's input-bearing API.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
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
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum IntercomError {
    #[error("invalid Layer-1 Intercom input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("Intercom workspace does not match the bound scope")]
    WorkspaceMismatch,
    #[error("Intercom workspace revision drifted")]
    WorkspaceRevisionDrift,
    #[error("Intercom conversation does not match the bound scope")]
    ConversationMismatch,
    #[error("Intercom conversation revision drifted")]
    RevisionDrift,
    #[error("customer-conversation objective does not match the bound scope")]
    ObjectiveMismatch,
    #[error("Mission, Project, or Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("required Intercom read permission is missing or drifted")]
    PermissionDrift,
    #[error("opaque SecretReference is not bound to this scope")]
    SecretScopeMismatch,
    #[error("opaque SecretReference has been revoked")]
    SecretRevoked,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration has been revoked or reversed")]
    RegistrationRevoked,
    #[error("registration binding or digest drifted")]
    RegistrationDrift,
    #[error("consumer is inactive")]
    ConsumerInactive,
    #[error("conversation recording was replayed with different evidence")]
    DuplicateConversation,
    #[error("conversation part was replayed with different content")]
    DuplicatePart,
    #[error("invalid conversation state transition")]
    InvalidStateTransition,
    #[error("pagination cursor repeated")]
    PaginationRepeatedCursor,
    #[error("pagination cursor expired")]
    PaginationExpired,
    #[error("pagination cursor was issued from the future")]
    PaginationCursorFromFuture,
    #[error("pagination cursor or page digest was tampered")]
    PaginationTampered,
    #[error("pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider returned a malformed response")]
    MalformedResponse,
    #[error("provider returned a partial response")]
    PartialResponse,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider response retained forbidden raw data")]
    RedactionViolation,
    #[error("provider payload or evidence digest was tampered")]
    EvidenceTampered,
    #[error("conversation result proposal digest or binding was tampered")]
    ProposalTampered,
    #[error("recording digest or binding was tampered")]
    RecordingTampered,
    #[error("provider is unavailable in the blocked environment")]
    BlockedEnv,
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("provider returned an unknown transport error")]
    ProviderUnknown,
    #[error("recording transport has no response queued")]
    MissingRecordedResponse,
    #[error("invalid read limits")]
    InvalidLimits,
}

impl IntercomError {
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn projection(&self) -> IntercomConversationState {
        match self {
            Self::HttpStatus {
                status: 401 | 403, ..
            }
            | Self::SecretRevoked
            | Self::SecretScopeMismatch
            | Self::RegistrationRevoked
            | Self::RegistrationInactive => IntercomConversationState::AccessLoss,
            Self::PartialResponse
            | Self::MalformedResponse
            | Self::ResponseTooLarge
            | Self::RedactionViolation
            | Self::EvidenceTampered
            | Self::ProposalTampered
            | Self::RecordingTampered
            | Self::RevisionDrift
            | Self::PaginationTampered
            | Self::PaginationExpired
            | Self::PaginationCursorFromFuture
            | Self::PaginationRepeatedCursor
            | Self::PaginationLimit => IntercomConversationState::Partial,
            Self::Timeout
            | Self::ProviderUnknown
            | Self::BlockedEnv
            | Self::HttpStatus {
                status: 404 | 409 | 429 | 500..=599,
                ..
            } => IntercomConversationState::ProviderUnknown,
            _ => IntercomConversationState::Unknown,
        }
    }
}

fn validate_text(field: &'static str, value: &str, max_bytes: usize) -> Result<(), IntercomError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(IntercomError::InvalidInput(field));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), IntercomError> {
    validate_text(field, value, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(IntercomError::InvalidInput(field));
    }
    Ok(())
}

fn validate_cursor(value: &str) -> Result<(), IntercomError> {
    validate_text("cursor", value, MAX_CURSOR_BYTES)
}

fn validate_revision(revision: u64) -> Result<(), IntercomError> {
    if revision == 0 {
        Err(IntercomError::InvalidInput("revision"))
    } else {
        Ok(())
    }
}

fn validate_digest(digest: &Digest) -> Result<(), IntercomError> {
    if digest.is_valid() {
        Ok(())
    } else {
        Err(IntercomError::InvalidDigest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomWorkspaceIdentity {
    pub workspace_id: String,
    pub revision: u64,
}

impl IntercomWorkspaceIdentity {
    pub fn new(workspace_id: impl Into<String>, revision: u64) -> Result<Self, IntercomError> {
        let identity = Self {
            workspace_id: workspace_id.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        validate_identifier("workspace id", &self.workspace_id)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationIdentity {
    pub conversation_id: String,
    pub revision: u64,
}

impl IntercomConversationIdentity {
    pub fn new(conversation_id: impl Into<String>, revision: u64) -> Result<Self, IntercomError> {
        let identity = Self {
            conversation_id: conversation_id.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        validate_identifier("conversation id", &self.conversation_id)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeBinding {
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub policy_digest: Digest,
    pub consent_digest: Digest,
}

impl MissionScopeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        project_revision: u64,
        mission_revision: u64,
        work_product_revision: u64,
        policy_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, IntercomError> {
        let binding = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            work_product_id: work_product_id.into(),
            project_revision,
            mission_revision,
            work_product_revision,
            policy_digest,
            consent_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        validate_identifier("Project", &self.project_id)?;
        validate_identifier("Mission", &self.mission_id)?;
        validate_identifier("Work Product", &self.work_product_id)?;
        validate_revision(self.project_revision)?;
        validate_revision(self.mission_revision)?;
        validate_revision(self.work_product_revision)?;
        validate_digest(&self.policy_digest)?;
        validate_digest(&self.consent_digest)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationResolutionObjective {
    pub objective_id: String,
    pub revision: u64,
    pub objective_digest: Digest,
}

impl ConversationResolutionObjective {
    pub fn new(objective_id: impl Into<String>, revision: u64) -> Result<Self, IntercomError> {
        let objective_id = objective_id.into();
        validate_identifier("customer-conversation objective", &objective_id)?;
        validate_revision(revision)?;
        Ok(Self {
            objective_digest: Digest::from_serializable(&(objective_id.as_str(), revision)),
            objective_id,
            revision,
        })
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        validate_identifier("customer-conversation objective", &self.objective_id)?;
        validate_revision(self.revision)?;
        if self.objective_digest
            != Digest::from_serializable(&(self.objective_id.as_str(), self.revision))
        {
            return Err(IntercomError::ObjectiveMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

pub type CustomerConversationObjective = ConversationResolutionObjective;
pub type CustomerResolutionObjective = ConversationResolutionObjective;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntercomPermission {
    WorkspaceRead,
    ConversationRead,
    ConversationPartsRead,
    PartsRead,
    RepliesRead,
    AssignmentRead,
    MissionScope,
}

impl IntercomPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceRead => "workspace:read",
            Self::ConversationRead => "conversation:read",
            Self::ConversationPartsRead | Self::PartsRead | Self::RepliesRead => {
                "conversation:parts:read"
            }
            Self::AssignmentRead => "assignment:read",
            Self::MissionScope => "mission:scope",
        }
    }

    pub const fn is_parts_read(self) -> bool {
        matches!(
            self,
            Self::ConversationPartsRead | Self::PartsRead | Self::RepliesRead
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationScope {
    pub workspace: IntercomWorkspaceIdentity,
    pub conversation: IntercomConversationIdentity,
    pub objective: ConversationResolutionObjective,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<IntercomPermission>,
}

impl IntercomConversationScope {
    pub fn new<I>(
        workspace: IntercomWorkspaceIdentity,
        conversation: IntercomConversationIdentity,
        objective: ConversationResolutionObjective,
        mission: MissionScopeBinding,
        permissions: I,
    ) -> Result<Self, IntercomError>
    where
        I: IntoIterator<Item = IntercomPermission>,
    {
        let scope = Self {
            workspace,
            conversation,
            objective,
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn read_permissions() -> BTreeSet<IntercomPermission> {
        [
            IntercomPermission::WorkspaceRead,
            IntercomPermission::ConversationRead,
            IntercomPermission::ConversationPartsRead,
            IntercomPermission::AssignmentRead,
            IntercomPermission::MissionScope,
        ]
        .into_iter()
        .collect()
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        self.workspace.validate()?;
        self.conversation.validate()?;
        self.objective.validate()?;
        self.mission.validate()?;
        if !self
            .permissions
            .contains(&IntercomPermission::WorkspaceRead)
            || !self
                .permissions
                .contains(&IntercomPermission::ConversationRead)
            || !self
                .permissions
                .iter()
                .any(|permission| permission.is_parts_read())
            || !self
                .permissions
                .contains(&IntercomPermission::AssignmentRead)
            || !self.permissions.contains(&IntercomPermission::MissionScope)
        {
            return Err(IntercomError::PermissionDrift);
        }
        if self.permissions.is_empty() {
            return Err(IntercomError::PermissionDrift);
        }
        Ok(())
    }

    pub fn workspace_digest(&self) -> Digest {
        self.workspace.digest()
    }

    pub fn conversation_digest(&self) -> Digest {
        self.conversation.digest()
    }

    pub fn objective_digest(&self) -> Digest {
        self.objective.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        let permissions: Vec<&str> = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect();
        Digest::from_serializable(&permissions)
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    AccessToken,
}

/// An opaque credential handle. The caller-provided reference is reduced to a
/// digest immediately and is never stored, serialized, formatted, or sent to
/// a transport.
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl fmt::Display for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretReference(opaque)")
    }
}

impl SecretReference {
    pub fn new(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &IntercomConversationScope,
        credential_revision: u64,
    ) -> Result<Self, IntercomError> {
        let reference = opaque_reference.as_ref();
        validate_text("SecretReference", reference, MAX_IDENTIFIER_BYTES)?;
        validate_revision(credential_revision)?;
        Ok(Self {
            kind,
            reference_digest: Digest::from_text(reference),
            scope_digest: scope.scope_digest(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &IntercomConversationScope,
        credential_revision: u64,
    ) -> Result<Self, IntercomError> {
        Self::new(
            SecretReferenceKind::OAuth,
            opaque_reference,
            scope,
            credential_revision,
        )
    }

    pub fn access_token(
        opaque_reference: impl AsRef<str>,
        scope: &IntercomConversationScope,
        credential_revision: u64,
    ) -> Result<Self, IntercomError> {
        Self::new(
            SecretReferenceKind::AccessToken,
            opaque_reference,
            scope,
            credential_revision,
        )
    }

    pub fn api_token(
        opaque_reference: impl AsRef<str>,
        scope: &IntercomConversationScope,
        credential_revision: u64,
    ) -> Result<Self, IntercomError> {
        Self::access_token(opaque_reference, scope, credential_revision)
    }

    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomRegistration {
    pub status: RegistrationStatus,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub workspace_digest: Digest,
    pub conversation_digest: Digest,
    pub objective_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
    pub transition: RegistrationTransitionEvidence,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub transition: RegistrationTransitionEvidence,
    pub secret_revoked: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl IntercomRegistration {
    pub fn new(
        scope: &IntercomConversationScope,
        secret: &SecretReference,
    ) -> Result<Self, IntercomError> {
        scope.validate()?;
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(IntercomError::SecretScopeMismatch);
        }
        let mut registration = Self {
            status: RegistrationStatus::Active,
            version_digest: Digest::from_serializable(&PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: Digest::from_text(PROVIDER_ID),
            workspace_digest: scope.workspace_digest(),
            conversation_digest: scope.conversation_digest(),
            objective_digest: scope.objective_digest(),
            mission_digest: scope.mission_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            credential_digest: secret.reference_digest().clone(),
            registration_digest: Digest::from_text("unsealed-registration"),
            reversible: true,
            revocable: true,
        };
        registration.seal();
        Ok(registration)
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            CONTRACT_SCHEMA,
            self.status,
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.workspace_digest,
            &self.conversation_digest,
            &self.objective_digest,
            &self.mission_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.credential_digest,
            self.reversible,
            self.revocable,
        ))
    }

    fn seal(&mut self) {
        self.registration_digest = self.expected_digest();
    }

    pub fn validate_binding(
        &self,
        scope: &IntercomConversationScope,
        secret: &SecretReference,
    ) -> Result<(), IntercomError> {
        if self.registration_digest != self.expected_digest()
            || self.version_digest != Digest::from_serializable(&PLUGIN_VERSION)
            || self.contract_digest != contract_digest()
            || self.provider_digest != Digest::from_text(PROVIDER_ID)
            || self.workspace_digest != scope.workspace_digest()
            || self.conversation_digest != scope.conversation_digest()
            || self.objective_digest != scope.objective_digest()
            || self.mission_digest != scope.mission_digest()
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != scope.scope_digest()
            || self.credential_digest != *secret.reference_digest()
            || secret.scope_digest() != &scope.scope_digest()
        {
            return Err(IntercomError::RegistrationDrift);
        }
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence, IntercomError> {
        if self.status != RegistrationStatus::Active || !self.reversible {
            return Err(IntercomError::RegistrationInactive);
        }
        Ok(self.transition(RegistrationStatus::Unmounted))
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence, IntercomError> {
        if self.status != RegistrationStatus::Unmounted || !self.reversible {
            return Err(IntercomError::RegistrationInactive);
        }
        Ok(self.transition(RegistrationStatus::Active))
    }

    pub fn revoke(
        &mut self,
        secret: &mut SecretReference,
    ) -> Result<RevocationReceipt, IntercomError> {
        if !self.revocable
            || matches!(
                self.status,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            )
        {
            return Err(IntercomError::RegistrationRevoked);
        }
        let transition = self.transition(RegistrationStatus::Revoked);
        secret.revoke();
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            transition,
            secret_revoked: secret.is_revoked(),
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, IntercomError> {
        if self.status != RegistrationStatus::Revoked || !self.reversible {
            return Err(IntercomError::RegistrationRevoked);
        }
        Ok(self.transition(RegistrationStatus::Reversed))
    }

    fn transition(&mut self, to: RegistrationStatus) -> RegistrationTransitionEvidence {
        let from = self.status;
        self.status = to;
        self.seal();
        RegistrationTransitionEvidence {
            from,
            to,
            transition_digest: Digest::from_serializable(&(
                CONTRACT_SCHEMA,
                from,
                to,
                &self.registration_digest,
            )),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct IntercomRegistrationRegistry {
    registrations: BTreeMap<String, IntercomRegistration>,
}

impl IntercomRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: IntercomRegistration,
    ) -> Result<RegistrationReceipt, IntercomError> {
        let id = registration.registration_digest.as_str().to_owned();
        if self.registrations.contains_key(&id) {
            return Err(IntercomError::RevisionDrift);
        }
        let status = registration.status;
        self.registrations.insert(id.clone(), registration);
        Ok(RegistrationReceipt {
            registration_digest: Digest(id),
            status,
            transition: RegistrationTransitionEvidence {
                from: RegistrationStatus::Unmounted,
                to: status,
                transition_digest: Digest::from_text("registration-created"),
            },
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn get(&self, digest: &Digest) -> Option<&IntercomRegistration> {
        self.registrations.get(digest.as_str())
    }

    pub fn get_mut(&mut self, digest: &Digest) -> Option<&mut IntercomRegistration> {
        self.registrations.get_mut(digest.as_str())
    }

    pub fn restore(
        &mut self,
        digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence, IntercomError> {
        self.registrations
            .get_mut(digest.as_str())
            .ok_or(IntercomError::RevisionDrift)?
            .remount()
    }

    pub fn revoke(
        &mut self,
        digest: &Digest,
        secret: &mut SecretReference,
    ) -> Result<RevocationReceipt, IntercomError> {
        self.registrations
            .get_mut(digest.as_str())
            .ok_or(IntercomError::RevisionDrift)?
            .revoke(secret)
    }

    pub fn reverse(
        &mut self,
        digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence, IntercomError> {
        self.registrations
            .get_mut(digest.as_str())
            .ok_or(IntercomError::RevisionDrift)?
            .reverse()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntercomConversationState {
    Open,
    Closed,
    Reopened,
    AssignmentChanged,
    Unknown,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

impl IntercomConversationState {
    pub fn can_follow(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Open => matches!(
                next,
                Self::Closed
                    | Self::Reopened
                    | Self::AssignmentChanged
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Closed => matches!(
                next,
                Self::Reopened
                    | Self::AssignmentChanged
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Reopened | Self::AssignmentChanged => matches!(
                next,
                Self::Open
                    | Self::Closed
                    | Self::Reopened
                    | Self::AssignmentChanged
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Unknown | Self::Partial | Self::AccessLoss | Self::ProviderUnknown => true,
        }
    }

    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

pub type IntercomConversationStatus = IntercomConversationState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntercomPriority {
    Low,
    Normal,
    High,
    Urgent,
    Unknown,
}

pub type ConversationPriority = IntercomPriority;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntercomPartKind {
    Reply,
    Note,
    AssignmentChange,
    StateChange,
    System,
    Unknown,
}

pub type IntercomConversationPartKind = IntercomPartKind;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub raw_names_retained: bool,
    pub raw_emails_retained: bool,
    pub raw_phone_numbers_retained: bool,
    pub raw_message_bodies_retained: bool,
    pub raw_comments_retained: bool,
    pub raw_attachments_retained: bool,
    pub raw_response_retained: bool,
    pub raw_pii_retained: bool,
}

impl RedactionEvidence {
    pub fn validate(&self) -> Result<(), IntercomError> {
        if self.raw_names_retained
            || self.raw_emails_retained
            || self.raw_phone_numbers_retained
            || self.raw_message_bodies_retained
            || self.raw_comments_retained
            || self.raw_attachments_retained
            || self.raw_response_retained
            || self.raw_pii_retained
        {
            return Err(IntercomError::RedactionViolation);
        }
        Ok(())
    }

    pub const fn is_clean(&self) -> bool {
        !self.raw_names_retained
            && !self.raw_emails_retained
            && !self.raw_phone_numbers_retained
            && !self.raw_message_bodies_retained
            && !self.raw_comments_retained
            && !self.raw_attachments_retained
            && !self.raw_response_retained
            && !self.raw_pii_retained
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomAssignment {
    pub assignee_id: Option<String>,
    pub team_id: Option<String>,
    pub revision: u64,
    pub assignment_digest: Digest,
}

impl IntercomAssignment {
    pub fn new(
        assignee_id: Option<String>,
        team_id: Option<String>,
        revision: u64,
    ) -> Result<Self, IntercomError> {
        let assignment = Self {
            assignee_id,
            team_id,
            revision,
            assignment_digest: Digest::from_text("unsealed-assignment"),
        };
        assignment.validate_shape()?;
        Ok(Self {
            assignment_digest: assignment.expected_digest(),
            ..assignment
        })
    }

    pub fn unassigned(revision: u64) -> Result<Self, IntercomError> {
        Self::new(None, None, revision)
    }

    fn validate_shape(&self) -> Result<(), IntercomError> {
        for (field, value) in [
            ("assignee id", self.assignee_id.as_deref()),
            ("team id", self.team_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_identifier(field, value)?;
            }
        }
        validate_revision(self.revision)
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.assignee_id, &self.team_id, self.revision))
    }

    pub fn reseal(&mut self) {
        self.assignment_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        self.validate_shape()?;
        if self.assignment_digest != self.expected_digest() {
            return Err(IntercomError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.assignment_digest.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationSnapshot {
    pub workspace: IntercomWorkspaceIdentity,
    pub conversation: IntercomConversationIdentity,
    pub state: IntercomConversationState,
    pub priority: IntercomPriority,
    pub assignee_id: Option<String>,
    pub team_id: Option<String>,
    pub assignment_revision: u64,
    pub created_at_epoch_seconds: u64,
    pub updated_at_epoch_seconds: u64,
    pub first_response_at_epoch_seconds: Option<u64>,
    pub resolution_at_epoch_seconds: Option<u64>,
    pub content_digest: Digest,
    pub redaction: RedactionEvidence,
    pub complete: bool,
    pub assignment_changed: bool,
    pub conversation_digest: Digest,
}

impl IntercomConversationSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: IntercomWorkspaceIdentity,
        conversation: IntercomConversationIdentity,
        state: IntercomConversationState,
        priority: IntercomPriority,
        assignee_id: Option<String>,
        team_id: Option<String>,
        created_at_epoch_seconds: u64,
        updated_at_epoch_seconds: u64,
        first_response_at_epoch_seconds: Option<u64>,
        resolution_at_epoch_seconds: Option<u64>,
        content_digest: Digest,
        redaction: RedactionEvidence,
    ) -> Result<Self, IntercomError> {
        let snapshot = Self {
            assignment_revision: conversation.revision,
            workspace,
            conversation,
            state,
            priority,
            assignee_id,
            team_id,
            created_at_epoch_seconds,
            updated_at_epoch_seconds,
            first_response_at_epoch_seconds,
            resolution_at_epoch_seconds,
            content_digest,
            redaction,
            complete: true,
            assignment_changed: false,
            conversation_digest: Digest::from_text("unsealed-conversation"),
        };
        snapshot.validate_shape()?;
        Ok(Self {
            conversation_digest: snapshot.expected_digest(),
            ..snapshot
        })
    }

    pub fn for_scope(scope: &IntercomConversationScope, state: IntercomConversationState) -> Self {
        Self::new(
            scope.workspace.clone(),
            scope.conversation.clone(),
            state,
            IntercomPriority::Normal,
            Some("fixture-assignee".into()),
            Some("fixture-team".into()),
            1_750_000_000,
            1_750_000_060,
            Some(1_750_000_010),
            state.is_closed().then_some(1_750_000_060),
            Digest::from_text("redacted-conversation-content"),
            RedactionEvidence::default(),
        )
        .expect("scope fixture is valid")
    }

    pub fn minimal(scope: &IntercomConversationScope) -> Self {
        Self::for_scope(scope, IntercomConversationState::Open)
    }

    #[must_use]
    pub fn with_assignment(mut self, assignee_id: Option<String>, team_id: Option<String>) -> Self {
        self.assignee_id = assignee_id;
        self.team_id = team_id;
        self.state = IntercomConversationState::AssignmentChanged;
        self.assignment_changed = true;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_timestamps(
        mut self,
        created_at_epoch_seconds: u64,
        updated_at_epoch_seconds: u64,
        first_response_at_epoch_seconds: Option<u64>,
        resolution_at_epoch_seconds: Option<u64>,
    ) -> Self {
        self.created_at_epoch_seconds = created_at_epoch_seconds;
        self.updated_at_epoch_seconds = updated_at_epoch_seconds;
        self.first_response_at_epoch_seconds = first_response_at_epoch_seconds;
        self.resolution_at_epoch_seconds = resolution_at_epoch_seconds;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_content_digest(mut self, content_digest: Digest) -> Self {
        self.content_digest = content_digest;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionEvidence) -> Self {
        self.redaction = redaction;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.reseal();
        self
    }

    #[must_use]
    pub fn mark_assignment_changed(mut self) -> Self {
        self.assignment_changed = true;
        self.reseal();
        self
    }

    fn validate_shape(&self) -> Result<(), IntercomError> {
        self.workspace.validate()?;
        self.conversation.validate()?;
        for (field, value) in [
            ("assignee id", self.assignee_id.as_deref()),
            ("team id", self.team_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_identifier(field, value)?;
            }
        }
        validate_revision(self.assignment_revision)?;
        if self.updated_at_epoch_seconds < self.created_at_epoch_seconds {
            return Err(IntercomError::InvalidInput("conversation timestamp"));
        }
        for value in [
            self.first_response_at_epoch_seconds,
            self.resolution_at_epoch_seconds,
        ]
        .into_iter()
        .flatten()
        {
            if value < self.created_at_epoch_seconds {
                return Err(IntercomError::InvalidInput(
                    "conversation lifecycle timestamp",
                ));
            }
        }
        if let (Some(first), Some(resolution)) = (
            self.first_response_at_epoch_seconds,
            self.resolution_at_epoch_seconds,
        ) && resolution < first
        {
            return Err(IntercomError::InvalidInput(
                "conversation resolution timestamp",
            ));
        }
        validate_digest(&self.content_digest)?;
        self.redaction.validate()
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.workspace,
            &self.conversation,
            self.state,
            self.priority,
            &self.assignee_id,
            &self.team_id,
            self.assignment_revision,
            self.created_at_epoch_seconds,
            self.updated_at_epoch_seconds,
            self.first_response_at_epoch_seconds,
            self.resolution_at_epoch_seconds,
            &self.content_digest,
            &self.redaction,
            self.complete,
            self.assignment_changed,
        ))
    }

    pub fn reseal(&mut self) {
        self.conversation_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        self.validate_shape()?;
        if self.conversation_digest != self.expected_digest() {
            return Err(IntercomError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn assignment(&self) -> Result<IntercomAssignment, IntercomError> {
        IntercomAssignment::new(
            self.assignee_id.clone(),
            self.team_id.clone(),
            self.assignment_revision,
        )
    }

    pub const fn created_at(&self) -> u64 {
        self.created_at_epoch_seconds
    }

    pub const fn updated_at(&self) -> u64 {
        self.updated_at_epoch_seconds
    }

    pub const fn first_response_at(&self) -> Option<u64> {
        self.first_response_at_epoch_seconds
    }

    pub const fn resolution_at(&self) -> Option<u64> {
        self.resolution_at_epoch_seconds
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationPart {
    pub part_id: String,
    pub conversation: IntercomConversationIdentity,
    pub kind: IntercomPartKind,
    pub created_at_epoch_seconds: u64,
    pub content_digest: Digest,
    pub redaction: RedactionEvidence,
    pub complete: bool,
    pub part_digest: Digest,
}

impl IntercomConversationPart {
    pub fn new(
        part_id: impl Into<String>,
        conversation: IntercomConversationIdentity,
        kind: IntercomPartKind,
        created_at_epoch_seconds: u64,
        content_digest: Digest,
        redaction: RedactionEvidence,
    ) -> Result<Self, IntercomError> {
        let part = Self {
            part_id: part_id.into(),
            conversation,
            kind,
            created_at_epoch_seconds,
            content_digest,
            redaction,
            complete: true,
            part_digest: Digest::from_text("unsealed-part"),
        };
        part.validate_shape()?;
        Ok(Self {
            part_digest: part.expected_digest(),
            ..part
        })
    }

    pub fn for_scope(
        scope: &IntercomConversationScope,
        part_id: impl Into<String>,
        kind: IntercomPartKind,
    ) -> Self {
        Self::new(
            part_id,
            scope.conversation.clone(),
            kind,
            1_750_000_020,
            Digest::from_text("redacted-part-content"),
            RedactionEvidence::default(),
        )
        .expect("scope fixture is valid")
    }

    pub fn reply(
        scope: &IntercomConversationScope,
        part_id: impl Into<String>,
        content_digest: Digest,
    ) -> Result<Self, IntercomError> {
        Self::new(
            part_id,
            scope.conversation.clone(),
            IntercomPartKind::Reply,
            1_750_000_020,
            content_digest,
            RedactionEvidence::default(),
        )
    }

    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionEvidence) -> Self {
        self.redaction = redaction;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.reseal();
        self
    }

    fn validate_shape(&self) -> Result<(), IntercomError> {
        validate_identifier("conversation part id", &self.part_id)?;
        self.conversation.validate()?;
        validate_digest(&self.content_digest)?;
        self.redaction.validate()
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.part_id,
            &self.conversation,
            self.kind,
            self.created_at_epoch_seconds,
            &self.content_digest,
            &self.redaction,
            self.complete,
        ))
    }

    pub fn reseal(&mut self) {
        self.part_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        self.validate_shape()?;
        if self.part_digest != self.expected_digest() {
            return Err(IntercomError::EvidenceTampered);
        }
        Ok(())
    }
}

pub type IntercomReply = IntercomConversationPart;
pub type IntercomPart = IntercomConversationPart;
pub type IntercomConversationReply = IntercomConversationPart;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadLimits {
    pub max_identifier_bytes: usize,
    pub max_cursor_bytes: usize,
    pub max_cursor_age_seconds: u64,
    pub max_page_items: usize,
    pub max_pages: usize,
    pub max_parts: usize,
    pub max_response_bytes: usize,
    pub max_metadata_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_identifier_bytes: MAX_IDENTIFIER_BYTES,
            max_cursor_bytes: MAX_CURSOR_BYTES,
            max_cursor_age_seconds: MAX_CURSOR_AGE_SECONDS,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGES,
            max_parts: MAX_PARTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_metadata_bytes: MAX_METADATA_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(self) -> Result<Self, IntercomError> {
        if self.max_identifier_bytes == 0
            || self.max_identifier_bytes > MAX_IDENTIFIER_BYTES
            || self.max_cursor_bytes == 0
            || self.max_cursor_bytes > MAX_CURSOR_BYTES
            || self.max_cursor_age_seconds == 0
            || self.max_cursor_age_seconds > MAX_CURSOR_AGE_SECONDS
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_parts == 0
            || self.max_parts > MAX_PARTS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > MAX_METADATA_BYTES
        {
            return Err(IntercomError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntercomOperation {
    DescribeWorkspace,
    ReadConversation,
    ReadConversationParts,
    ReadConversationReplies,
}

impl IntercomOperation {
    pub const fn is_parts_read(self) -> bool {
        matches!(
            self,
            Self::ReadConversationParts | Self::ReadConversationReplies
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedPayloadMetadata {
    pub response_bytes: usize,
    pub complete: bool,
    pub redaction: RedactionEvidence,
    pub payload_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomPayload<T> {
    pub operation: IntercomOperation,
    pub value: T,
    pub response_bytes: usize,
    pub complete: bool,
    pub redaction: RedactionEvidence,
    pub payload_digest: Digest,
}

impl<T: Serialize> IntercomPayload<T> {
    pub fn new(operation: IntercomOperation, value: T) -> Self {
        let response_bytes = serde_json::to_vec(&value).map_or(0, |bytes| bytes.len());
        let mut payload = Self {
            operation,
            value,
            response_bytes,
            complete: true,
            redaction: RedactionEvidence::default(),
            payload_digest: Digest::from_text("unsealed-payload"),
        };
        payload.payload_digest = payload.expected_digest();
        payload
    }

    #[must_use]
    pub fn with_metadata(
        mut self,
        response_bytes: usize,
        complete: bool,
        redaction: RedactionEvidence,
    ) -> Self {
        self.response_bytes = response_bytes;
        self.complete = complete;
        self.redaction = redaction;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionEvidence) -> Self {
        self.redaction = redaction;
        self.reseal();
        self
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            &self.value,
            self.response_bytes,
            self.complete,
            &self.redaction,
        ))
    }

    pub fn reseal(&mut self) {
        self.payload_digest = self.expected_digest();
    }

    pub fn verify(&self, limits: &ReadLimits) -> Result<(), IntercomError> {
        if self.response_bytes > limits.max_response_bytes {
            return Err(IntercomError::ResponseTooLarge);
        }
        if !self.complete {
            return Err(IntercomError::PartialResponse);
        }
        self.redaction.validate()?;
        if self.payload_digest != self.expected_digest() {
            return Err(IntercomError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn metadata(&self) -> RedactedPayloadMetadata {
        RedactedPayloadMetadata {
            response_bytes: self.response_bytes,
            complete: self.complete,
            redaction: self.redaction.clone(),
            payload_digest: self.payload_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomPage<T> {
    pub operation: IntercomOperation,
    pub page_index: usize,
    pub cursor_in: Option<String>,
    pub next_cursor: Option<String>,
    pub cursor_issued_at_epoch_seconds: Option<u64>,
    pub items: Vec<T>,
    pub complete: bool,
    pub response_bytes: usize,
    pub redaction: RedactionEvidence,
    pub page_digest: Digest,
}

impl<T: Serialize> IntercomPage<T> {
    pub fn new(
        operation: IntercomOperation,
        page_index: usize,
        cursor_in: Option<String>,
        next_cursor: Option<String>,
        items: Vec<T>,
    ) -> Self {
        let response_bytes = serde_json::to_vec(&items).map_or(0, |bytes| bytes.len());
        let mut page = Self {
            operation,
            page_index,
            cursor_in,
            next_cursor,
            cursor_issued_at_epoch_seconds: None,
            items,
            complete: true,
            response_bytes,
            redaction: RedactionEvidence::default(),
            page_digest: Digest::from_text("unsealed-page"),
        };
        page.page_digest = page.expected_digest();
        page
    }

    #[must_use]
    pub fn with_cursor_issued_at(mut self, issued_at_epoch_seconds: u64) -> Self {
        self.cursor_issued_at_epoch_seconds = Some(issued_at_epoch_seconds);
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_metadata(
        mut self,
        response_bytes: usize,
        complete: bool,
        redaction: RedactionEvidence,
    ) -> Self {
        self.response_bytes = response_bytes;
        self.complete = complete;
        self.redaction = redaction;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionEvidence) -> Self {
        self.redaction = redaction;
        self.reseal();
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.reseal();
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            self.page_index,
            &self.cursor_in,
            &self.next_cursor,
            self.cursor_issued_at_epoch_seconds,
            &self.items,
            self.complete,
            self.response_bytes,
            &self.redaction,
        ))
    }

    pub fn reseal(&mut self) {
        self.page_digest = self.expected_digest();
    }

    pub fn validate(
        &self,
        limits: &ReadLimits,
        observed_at_epoch_seconds: u64,
        expected_cursor: Option<&str>,
        expected_page_index: usize,
    ) -> Result<(), IntercomError> {
        if self.page_index != expected_page_index || self.cursor_in.as_deref() != expected_cursor {
            return Err(IntercomError::PaginationTampered);
        }
        if self.items.len() > limits.max_page_items {
            return Err(IntercomError::PaginationLimit);
        }
        if self.response_bytes > limits.max_response_bytes {
            return Err(IntercomError::ResponseTooLarge);
        }
        if self.next_cursor.as_deref().is_some_and(|cursor| {
            validate_cursor(cursor).is_err() || cursor.len() > limits.max_cursor_bytes
        }) || self
            .cursor_in
            .as_deref()
            .is_some_and(|cursor| validate_cursor(cursor).is_err())
        {
            return Err(IntercomError::PaginationTampered);
        }
        if let Some(issued_at) = self.cursor_issued_at_epoch_seconds {
            if issued_at > observed_at_epoch_seconds {
                return Err(IntercomError::PaginationCursorFromFuture);
            }
            if observed_at_epoch_seconds - issued_at > limits.max_cursor_age_seconds {
                return Err(IntercomError::PaginationExpired);
            }
        }
        self.redaction.validate()?;
        if self.page_digest != self.expected_digest() {
            return Err(IntercomError::PaginationTampered);
        }
        if self.next_cursor.is_none() && !self.complete {
            return Err(IntercomError::PartialResponse);
        }
        Ok(())
    }
}

pub type IntercomConversationPage<T> = IntercomPage<T>;
pub type IntercomConversationPartsPage<T> = IntercomPage<T>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomReadRequest {
    pub workspace_id: String,
    pub conversation_id: String,
    pub conversation_revision: u64,
    pub observed_at_epoch_seconds: u64,
    pub cursor: Option<String>,
    pub incremental_since_epoch_seconds: Option<u64>,
}

impl IntercomReadRequest {
    pub fn new(
        workspace_id: impl Into<String>,
        conversation_id: impl Into<String>,
        conversation_revision: u64,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, IntercomError> {
        let request = Self {
            workspace_id: workspace_id.into(),
            conversation_id: conversation_id.into(),
            conversation_revision,
            observed_at_epoch_seconds,
            cursor: None,
            incremental_since_epoch_seconds: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn for_scope(scope: &IntercomConversationScope, observed_at_epoch_seconds: u64) -> Self {
        Self::new(
            scope.workspace.workspace_id.clone(),
            scope.conversation.conversation_id.clone(),
            scope.conversation.revision,
            observed_at_epoch_seconds,
        )
        .expect("scope request is valid")
    }

    pub fn validate(&self) -> Result<(), IntercomError> {
        validate_identifier("workspace id", &self.workspace_id)?;
        validate_identifier("conversation id", &self.conversation_id)?;
        validate_revision(self.conversation_revision)?;
        if let Some(cursor) = &self.cursor {
            validate_cursor(cursor)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    #[must_use]
    pub fn incremental_since(mut self, start_time_epoch_seconds: u64) -> Self {
        self.incremental_since_epoch_seconds = Some(start_time_epoch_seconds);
        self
    }
}

pub type IntercomConversationReadRequest = IntercomReadRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum IntercomTransportError {
    #[error("HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("timeout")]
    Timeout,
    #[error("blocked environment")]
    BlockedEnv,
    #[error("missing response")]
    MissingResponse,
    #[error("provider unknown")]
    ProviderUnknown,
}

impl From<IntercomTransportError> for IntercomError {
    fn from(error: IntercomTransportError) -> Self {
        match error {
            IntercomTransportError::HttpStatus {
                status,
                retry_after_seconds,
            } => Self::HttpStatus {
                status,
                retry_after_seconds,
            },
            IntercomTransportError::Timeout => Self::Timeout,
            IntercomTransportError::BlockedEnv => Self::BlockedEnv,
            IntercomTransportError::MissingResponse => Self::MissingRecordedResponse,
            IntercomTransportError::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

pub trait IntercomTransport {
    fn provenance(&self) -> TransportProvenance;

    fn describe_workspace(
        &mut self,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<IntercomPayload<IntercomWorkspaceIdentity>, IntercomTransportError>;

    fn read_conversation(
        &mut self,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<IntercomPayload<IntercomConversationSnapshot>, IntercomTransportError>;

    fn read_parts_page(
        &mut self,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<IntercomPage<IntercomConversationPart>, IntercomTransportError> {
        self.read_conversation_parts(request, secret)
    }

    fn read_conversation_parts(
        &mut self,
        _request: &IntercomReadRequest,
        _secret: &SecretReference,
    ) -> Result<IntercomPage<IntercomConversationPart>, IntercomTransportError> {
        Err(IntercomTransportError::ProviderUnknown)
    }

    fn read_replies_page(
        &mut self,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<IntercomPage<IntercomConversationPart>, IntercomTransportError> {
        self.read_parts_page(request, secret)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingIntercomTransport {
    provenance: TransportProvenance,
    workspace_responses:
        VecDeque<Result<IntercomPayload<IntercomWorkspaceIdentity>, IntercomTransportError>>,
    conversation_responses:
        VecDeque<Result<IntercomPayload<IntercomConversationSnapshot>, IntercomTransportError>>,
    part_pages: VecDeque<Result<IntercomPage<IntercomConversationPart>, IntercomTransportError>>,
    failure: Option<IntercomTransportError>,
}

impl RecordingIntercomTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            workspace_responses: VecDeque::new(),
            conversation_responses: VecDeque::new(),
            part_pages: VecDeque::new(),
            failure: None,
        }
    }

    pub fn recording() -> Self {
        Self::new(TransportProvenance::Recording)
    }

    pub fn fake() -> Self {
        Self::new(TransportProvenance::Fake)
    }

    pub fn loopback() -> Self {
        Self::new(TransportProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportProvenance::BlockedEnv).with_failure(IntercomTransportError::BlockedEnv)
    }

    #[must_use]
    pub fn with_failure(mut self, failure: IntercomTransportError) -> Self {
        self.failure = Some(failure);
        self
    }

    pub fn fail_with(&mut self, failure: IntercomTransportError) {
        self.failure = Some(failure);
    }

    pub fn push_workspace_response(
        &mut self,
        response: Result<IntercomPayload<IntercomWorkspaceIdentity>, IntercomTransportError>,
    ) {
        self.workspace_responses.push_back(response);
    }

    pub fn push_conversation_response(
        &mut self,
        response: Result<IntercomPayload<IntercomConversationSnapshot>, IntercomTransportError>,
    ) {
        self.conversation_responses.push_back(response);
    }

    pub fn push_parts_page(
        &mut self,
        response: Result<IntercomPage<IntercomConversationPart>, IntercomTransportError>,
    ) {
        self.part_pages.push_back(response);
    }

    pub fn push_conversation_parts_page(
        &mut self,
        response: Result<IntercomPage<IntercomConversationPart>, IntercomTransportError>,
    ) {
        self.push_parts_page(response);
    }

    pub fn push_replies_page(
        &mut self,
        response: Result<IntercomPage<IntercomConversationPart>, IntercomTransportError>,
    ) {
        self.push_parts_page(response);
    }

    fn pop<T>(
        queue: &mut VecDeque<Result<T, IntercomTransportError>>,
        failure: Option<&IntercomTransportError>,
    ) -> Result<T, IntercomTransportError> {
        queue.pop_front().unwrap_or_else(|| {
            failure
                .copied()
                .map_or(Err(IntercomTransportError::MissingResponse), Err)
        })
    }
}

impl IntercomTransport for RecordingIntercomTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_workspace(
        &mut self,
        _request: &IntercomReadRequest,
        _secret: &SecretReference,
    ) -> Result<IntercomPayload<IntercomWorkspaceIdentity>, IntercomTransportError> {
        Self::pop(&mut self.workspace_responses, self.failure.as_ref())
    }

    fn read_conversation(
        &mut self,
        _request: &IntercomReadRequest,
        _secret: &SecretReference,
    ) -> Result<IntercomPayload<IntercomConversationSnapshot>, IntercomTransportError> {
        Self::pop(&mut self.conversation_responses, self.failure.as_ref())
    }

    fn read_parts_page(
        &mut self,
        _request: &IntercomReadRequest,
        _secret: &SecretReference,
    ) -> Result<IntercomPage<IntercomConversationPart>, IntercomTransportError> {
        Self::pop(&mut self.part_pages, self.failure.as_ref())
    }
}

pub type FakeIntercomTransport = RecordingIntercomTransport;
pub type LoopbackIntercomTransport = RecordingIntercomTransport;
pub type BlockedEnvTransport = RecordingIntercomTransport;

#[derive(Clone, Debug)]
pub struct IntercomProvider<T> {
    transport: T,
    limits: ReadLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationEvidenceComponents {
    pub conversation: IntercomConversationSnapshot,
    pub parts: Vec<IntercomConversationPart>,
    pub pages_read: u16,
    pub duplicate_parts_dropped: u32,
    pub complete: bool,
}

impl<T: IntercomTransport> IntercomProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ReadLimits::default(),
        }
    }

    pub fn with_limits(transport: T, limits: ReadLimits) -> Result<Self, IntercomError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn limits(&self) -> &ReadLimits {
        &self.limits
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn ensure_secret(
        scope: &IntercomConversationScope,
        secret: &SecretReference,
    ) -> Result<(), IntercomError> {
        if secret.is_revoked() {
            return Err(IntercomError::SecretRevoked);
        }
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(IntercomError::SecretScopeMismatch);
        }
        Ok(())
    }

    fn validate_request(
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
    ) -> Result<(), IntercomError> {
        request.validate()?;
        if request.workspace_id != scope.workspace.workspace_id {
            return Err(IntercomError::WorkspaceMismatch);
        }
        if request.conversation_id != scope.conversation.conversation_id {
            return Err(IntercomError::ConversationMismatch);
        }
        if request.conversation_revision != scope.conversation.revision {
            return Err(IntercomError::RevisionDrift);
        }
        Ok(())
    }

    pub fn describe_workspace(
        &mut self,
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<IntercomWorkspaceIdentity, IntercomError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let payload = self
            .transport
            .describe_workspace(request, secret)
            .map_err(IntercomError::from)?;
        payload.verify(&self.limits)?;
        if payload.operation != IntercomOperation::DescribeWorkspace {
            return Err(IntercomError::MalformedResponse);
        }
        let workspace = payload.value;
        workspace.validate()?;
        if workspace != scope.workspace {
            return Err(if workspace.workspace_id == scope.workspace.workspace_id {
                IntercomError::WorkspaceRevisionDrift
            } else {
                IntercomError::WorkspaceMismatch
            });
        }
        Ok(workspace)
    }

    pub fn read_conversation(
        &mut self,
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<IntercomConversationSnapshot, IntercomError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let payload = self
            .transport
            .read_conversation(request, secret)
            .map_err(IntercomError::from)?;
        payload.verify(&self.limits)?;
        if payload.operation != IntercomOperation::ReadConversation {
            return Err(IntercomError::MalformedResponse);
        }
        let conversation = payload.value;
        conversation.validate()?;
        if !conversation.complete {
            return Err(IntercomError::PartialResponse);
        }
        if !payload.redaction.is_clean() {
            return Err(IntercomError::RedactionViolation);
        }
        Self::validate_conversation_binding(scope, &conversation).map(|()| conversation)
    }

    pub fn read_conversation_parts(
        &mut self,
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<(Vec<IntercomConversationPart>, usize, usize), IntercomError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let mut cursor = request.cursor.clone();
        let mut pages_read = 0usize;
        let mut duplicate_parts_dropped = 0usize;
        let mut parts = BTreeMap::<String, IntercomConversationPart>::new();
        let mut seen_cursors = BTreeSet::new();
        loop {
            if pages_read >= self.limits.max_pages {
                return Err(IntercomError::PaginationLimit);
            }
            let mut page_request = request.clone();
            page_request.cursor.clone_from(&cursor);
            let page = self
                .transport
                .read_parts_page(&page_request, secret)
                .map_err(IntercomError::from)?;
            page.validate(
                &self.limits,
                request.observed_at_epoch_seconds,
                cursor.as_deref(),
                pages_read,
            )?;
            if !page.operation.is_parts_read() {
                return Err(IntercomError::MalformedResponse);
            }
            for part in page.items {
                part.validate()?;
                Self::validate_part_binding(scope, &part)?;
                if let Some(existing) = parts.get(&part.part_id) {
                    if existing != &part {
                        return Err(IntercomError::DuplicatePart);
                    }
                    duplicate_parts_dropped += 1;
                } else {
                    if parts.len() >= self.limits.max_parts {
                        return Err(IntercomError::PaginationLimit);
                    }
                    parts.insert(part.part_id.clone(), part);
                }
            }
            pages_read += 1;
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            validate_cursor(&next_cursor)?;
            if !seen_cursors.insert(next_cursor.clone()) {
                return Err(IntercomError::PaginationRepeatedCursor);
            }
            cursor = Some(next_cursor);
        }
        Ok((
            parts.into_values().collect(),
            pages_read,
            duplicate_parts_dropped,
        ))
    }

    pub fn read_parts(
        &mut self,
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<Vec<IntercomConversationPart>, IntercomError> {
        self.read_conversation_parts(scope, request, secret)
            .map(|(parts, _, _)| parts)
    }

    pub fn read_conversation_components(
        &mut self,
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<ConversationEvidenceComponents, IntercomError> {
        let conversation = self.read_conversation(scope, request, secret)?;
        let (parts, pages_read, duplicate_parts_dropped) =
            self.read_conversation_parts(scope, request, secret)?;
        let complete = conversation.complete && pages_read > 0;
        Ok(ConversationEvidenceComponents {
            conversation,
            parts,
            pages_read: u16::try_from(pages_read).map_err(|_| IntercomError::PaginationLimit)?,
            duplicate_parts_dropped: u32::try_from(duplicate_parts_dropped)
                .map_err(|_| IntercomError::PaginationLimit)?,
            complete,
        })
    }

    pub fn read_conversation_result_components(
        &mut self,
        scope: &IntercomConversationScope,
        request: &IntercomReadRequest,
        secret: &SecretReference,
    ) -> Result<ConversationEvidenceComponents, IntercomError> {
        self.read_conversation_components(scope, request, secret)
    }

    fn validate_conversation_binding(
        scope: &IntercomConversationScope,
        conversation: &IntercomConversationSnapshot,
    ) -> Result<(), IntercomError> {
        if conversation.workspace.workspace_id != scope.workspace.workspace_id {
            return Err(IntercomError::WorkspaceMismatch);
        }
        if conversation.workspace != scope.workspace {
            return Err(IntercomError::WorkspaceRevisionDrift);
        }
        if conversation.conversation.conversation_id != scope.conversation.conversation_id {
            return Err(IntercomError::ConversationMismatch);
        }
        if conversation.conversation != scope.conversation {
            return Err(IntercomError::RevisionDrift);
        }
        Ok(())
    }

    fn validate_part_binding(
        scope: &IntercomConversationScope,
        part: &IntercomConversationPart,
    ) -> Result<(), IntercomError> {
        if part.conversation.conversation_id != scope.conversation.conversation_id {
            return Err(IntercomError::ConversationMismatch);
        }
        if part.conversation != scope.conversation {
            return Err(IntercomError::RevisionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub transport: TransportProvenance,
    pub response_digest: Digest,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub raw_names_retained: bool,
    pub raw_emails_retained: bool,
    pub raw_phone_numbers_retained: bool,
    pub raw_message_bodies_retained: bool,
    pub raw_attachments_retained: bool,
}

impl EvidenceProvenance {
    fn for_components(
        transport: TransportProvenance,
        conversation: &IntercomConversationSnapshot,
        parts: &[IntercomConversationPart],
    ) -> Self {
        Self {
            transport,
            response_digest: Digest::from_serializable(&(
                &conversation.conversation_digest,
                parts
                    .iter()
                    .map(|part| &part.part_digest)
                    .collect::<Vec<_>>(),
            )),
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            raw_names_retained: false,
            raw_emails_retained: false,
            raw_phone_numbers_retained: false,
            raw_message_bodies_retained: false,
            raw_attachments_retained: false,
        }
    }

    fn validate(&self) -> Result<(), IntercomError> {
        if !self.recording_only
            || self.connected
            || self.native
            || self.first_party
            || self.raw_names_retained
            || self.raw_emails_retained
            || self.raw_phone_numbers_retained
            || self.raw_message_bodies_retained
            || self.raw_attachments_retained
        {
            return Err(IntercomError::RedactionViolation);
        }
        validate_digest(&self.response_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub objective_digest: Digest,
    pub mission: MissionScopeBinding,
    pub observed_at_epoch_seconds: u64,
    pub conversation: IntercomConversationSnapshot,
    pub parts: Vec<IntercomConversationPart>,
    pub state: IntercomConversationState,
    pub status: IntercomConversationState,
    pub priority: IntercomPriority,
    pub assignee_id: Option<String>,
    pub team_id: Option<String>,
    pub created_at_epoch_seconds: u64,
    pub updated_at_epoch_seconds: u64,
    pub first_response_at_epoch_seconds: Option<u64>,
    pub resolution_at_epoch_seconds: Option<u64>,
    pub complete: bool,
    pub partial: bool,
    pub pages_read: u16,
    pub parts_read: u32,
    pub duplicate_parts_dropped: u32,
    pub conversation_digest: Digest,
    pub parts_digest: Digest,
    pub content_digest: Digest,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    objective_digest: &'a Digest,
    mission: &'a MissionScopeBinding,
    observed_at_epoch_seconds: u64,
    conversation: &'a IntercomConversationSnapshot,
    parts: &'a [IntercomConversationPart],
    state: IntercomConversationState,
    status: IntercomConversationState,
    priority: IntercomPriority,
    assignee_id: &'a Option<String>,
    team_id: &'a Option<String>,
    created_at_epoch_seconds: u64,
    updated_at_epoch_seconds: u64,
    first_response_at_epoch_seconds: Option<u64>,
    resolution_at_epoch_seconds: Option<u64>,
    complete: bool,
    partial: bool,
    pages_read: u16,
    parts_read: u32,
    duplicate_parts_dropped: u32,
    conversation_digest: &'a Digest,
    parts_digest: &'a Digest,
    content_digest: &'a Digest,
    provenance: &'a EvidenceProvenance,
}

impl IntercomConversationEvidence {
    fn new(
        scope: &IntercomConversationScope,
        registration: &IntercomRegistration,
        components: ConversationEvidenceComponents,
        observed_at_epoch_seconds: u64,
        transport: TransportProvenance,
    ) -> Result<Self, IntercomError> {
        let conversation = components.conversation;
        let parts = components.parts;
        let parts_digest = Digest::from_serializable(
            &parts
                .iter()
                .map(|part| &part.part_digest)
                .collect::<Vec<_>>(),
        );
        let provenance = EvidenceProvenance::for_components(transport, &conversation, &parts);
        let state = conversation.state;
        let evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: registration.registration_digest.clone(),
            objective_digest: scope.objective_digest(),
            mission: scope.mission.clone(),
            observed_at_epoch_seconds,
            state,
            status: state,
            priority: conversation.priority,
            assignee_id: conversation.assignee_id.clone(),
            team_id: conversation.team_id.clone(),
            created_at_epoch_seconds: conversation.created_at_epoch_seconds,
            updated_at_epoch_seconds: conversation.updated_at_epoch_seconds,
            first_response_at_epoch_seconds: conversation.first_response_at_epoch_seconds,
            resolution_at_epoch_seconds: conversation.resolution_at_epoch_seconds,
            complete: components.complete,
            partial: !components.complete,
            pages_read: components.pages_read,
            parts_read: u32::try_from(parts.len()).map_err(|_| IntercomError::PaginationLimit)?,
            duplicate_parts_dropped: components.duplicate_parts_dropped,
            conversation_digest: conversation.conversation_digest.clone(),
            content_digest: conversation.content_digest.clone(),
            parts_digest,
            conversation,
            parts,
            provenance,
            evidence_digest: Digest::from_text("unsealed-evidence"),
        };
        let mut evidence = evidence;
        evidence.evidence_digest = evidence.expected_digest();
        evidence.validate(scope, registration)?;
        Ok(evidence)
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            objective_digest: &self.objective_digest,
            mission: &self.mission,
            observed_at_epoch_seconds: self.observed_at_epoch_seconds,
            conversation: &self.conversation,
            parts: &self.parts,
            state: self.state,
            status: self.status,
            priority: self.priority,
            assignee_id: &self.assignee_id,
            team_id: &self.team_id,
            created_at_epoch_seconds: self.created_at_epoch_seconds,
            updated_at_epoch_seconds: self.updated_at_epoch_seconds,
            first_response_at_epoch_seconds: self.first_response_at_epoch_seconds,
            resolution_at_epoch_seconds: self.resolution_at_epoch_seconds,
            complete: self.complete,
            partial: self.partial,
            pages_read: self.pages_read,
            parts_read: self.parts_read,
            duplicate_parts_dropped: self.duplicate_parts_dropped,
            conversation_digest: &self.conversation_digest,
            parts_digest: &self.parts_digest,
            content_digest: &self.content_digest,
            provenance: &self.provenance,
        })
    }

    pub fn validate(
        &self,
        scope: &IntercomConversationScope,
        registration: &IntercomRegistration,
    ) -> Result<(), IntercomError> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.objective_digest != scope.objective_digest()
            || self.mission != scope.mission
            || self.state != self.conversation.state
            || self.status != self.state
            || self.priority != self.conversation.priority
            || self.assignee_id != self.conversation.assignee_id
            || self.team_id != self.conversation.team_id
            || self.created_at_epoch_seconds != self.conversation.created_at_epoch_seconds
            || self.updated_at_epoch_seconds != self.conversation.updated_at_epoch_seconds
            || self.first_response_at_epoch_seconds
                != self.conversation.first_response_at_epoch_seconds
            || self.resolution_at_epoch_seconds != self.conversation.resolution_at_epoch_seconds
            || self.partial == self.complete
            || self.pages_read == 0
            || self.parts_read != u32::try_from(self.parts.len()).unwrap_or(u32::MAX)
            || self.conversation_digest != self.conversation.conversation_digest
            || self.content_digest != self.conversation.content_digest
            || !self.evidence_digest.is_valid()
            || self.evidence_digest != self.expected_digest()
        {
            return Err(IntercomError::EvidenceTampered);
        }
        IntercomProvider::<RecordingIntercomTransport>::validate_conversation_binding(
            scope,
            &self.conversation,
        )?;
        self.conversation.validate()?;
        if self.parts.len() > MAX_PARTS {
            return Err(IntercomError::PaginationLimit);
        }
        let mut expected_part_ids = BTreeSet::new();
        for part in &self.parts {
            part.validate()?;
            IntercomProvider::<RecordingIntercomTransport>::validate_part_binding(scope, part)?;
            if !expected_part_ids.insert(&part.part_id) {
                return Err(IntercomError::DuplicatePart);
            }
        }
        let expected_parts_digest = Digest::from_serializable(
            &self
                .parts
                .iter()
                .map(|part| &part.part_digest)
                .collect::<Vec<_>>(),
        );
        if self.parts_digest != expected_parts_digest {
            return Err(IntercomError::EvidenceTampered);
        }
        self.provenance.validate()
    }

    pub fn assignment(&self) -> Result<IntercomAssignment, IntercomError> {
        self.conversation.assignment()
    }
}

pub type IntercomConversationResultEvidence = IntercomConversationEvidence;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationDecisionDisposition {
    ReviewNextMissionDecision,
    Layer2AdoptionRequired,
    BlockedByProjection,
}

pub type IntercomDecisionDisposition = ConversationDecisionDisposition;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub objective_digest: Digest,
    pub mission: MissionScopeBinding,
    pub workspace_id: String,
    pub conversation_id: String,
    pub conversation_revision: u64,
    pub state: IntercomConversationState,
    pub status: IntercomConversationState,
    pub priority: IntercomPriority,
    pub assignee_id: Option<String>,
    pub team_id: Option<String>,
    pub created_at_epoch_seconds: u64,
    pub updated_at_epoch_seconds: u64,
    pub first_response_at_epoch_seconds: Option<u64>,
    pub resolution_at_epoch_seconds: Option<u64>,
    pub conversation_digest: Digest,
    pub parts_digest: Digest,
    pub content_digest: Digest,
    pub evidence_digest: Digest,
    pub decision: ConversationDecisionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    objective_digest: &'a Digest,
    mission: &'a MissionScopeBinding,
    workspace_id: &'a str,
    conversation_id: &'a str,
    conversation_revision: u64,
    state: IntercomConversationState,
    status: IntercomConversationState,
    priority: IntercomPriority,
    assignee_id: &'a Option<String>,
    team_id: &'a Option<String>,
    created_at_epoch_seconds: u64,
    updated_at_epoch_seconds: u64,
    first_response_at_epoch_seconds: Option<u64>,
    resolution_at_epoch_seconds: Option<u64>,
    conversation_digest: &'a Digest,
    parts_digest: &'a Digest,
    content_digest: &'a Digest,
    evidence_digest: &'a Digest,
    decision: ConversationDecisionDisposition,
    adopted: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl IntercomConversationResultProposal {
    fn from_evidence(
        evidence: &IntercomConversationEvidence,
        scope: &IntercomConversationScope,
    ) -> Self {
        let decision = if evidence.complete {
            ConversationDecisionDisposition::ReviewNextMissionDecision
        } else {
            ConversationDecisionDisposition::BlockedByProjection
        };
        let proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: evidence.registration_digest.clone(),
            objective_digest: scope.objective_digest(),
            mission: scope.mission.clone(),
            workspace_id: evidence.conversation.workspace.workspace_id.clone(),
            conversation_id: evidence.conversation.conversation.conversation_id.clone(),
            conversation_revision: evidence.conversation.conversation.revision,
            state: evidence.state,
            status: evidence.status,
            priority: evidence.priority,
            assignee_id: evidence.assignee_id.clone(),
            team_id: evidence.team_id.clone(),
            created_at_epoch_seconds: evidence.created_at_epoch_seconds,
            updated_at_epoch_seconds: evidence.updated_at_epoch_seconds,
            first_response_at_epoch_seconds: evidence.first_response_at_epoch_seconds,
            resolution_at_epoch_seconds: evidence.resolution_at_epoch_seconds,
            conversation_digest: evidence.conversation_digest.clone(),
            parts_digest: evidence.parts_digest.clone(),
            content_digest: evidence.content_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            decision,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: Digest::from_text("unsealed-proposal"),
        };
        let mut proposal = proposal;
        proposal.proposal_digest = proposal.expected_digest();
        proposal
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            objective_digest: &self.objective_digest,
            mission: &self.mission,
            workspace_id: &self.workspace_id,
            conversation_id: &self.conversation_id,
            conversation_revision: self.conversation_revision,
            state: self.state,
            status: self.status,
            priority: self.priority,
            assignee_id: &self.assignee_id,
            team_id: &self.team_id,
            created_at_epoch_seconds: self.created_at_epoch_seconds,
            updated_at_epoch_seconds: self.updated_at_epoch_seconds,
            first_response_at_epoch_seconds: self.first_response_at_epoch_seconds,
            resolution_at_epoch_seconds: self.resolution_at_epoch_seconds,
            conversation_digest: &self.conversation_digest,
            parts_digest: &self.parts_digest,
            content_digest: &self.content_digest,
            evidence_digest: &self.evidence_digest,
            decision: self.decision,
            adopted: self.adopted,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate_integrity(
        &self,
        scope: &IntercomConversationScope,
        registration: &IntercomRegistration,
    ) -> Result<(), IntercomError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.objective_digest != scope.objective_digest()
            || self.mission != scope.mission
            || self.workspace_id != scope.workspace.workspace_id
            || self.conversation_id != scope.conversation.conversation_id
            || self.conversation_revision != scope.conversation.revision
            || self.state != self.status
            || self.adopted
            || self.connected
            || self.native
            || self.first_party
            || !self.conversation_digest.is_valid()
            || !self.parts_digest.is_valid()
            || !self.content_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || self.proposal_digest != self.expected_digest()
        {
            return Err(IntercomError::ProposalTampered);
        }
        Ok(())
    }
}

pub type IntercomConversationOutcomeProposal = IntercomConversationResultProposal;
pub type ConversationResultProposal = IntercomConversationResultProposal;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntercomConversationRecording {
    pub schema_version: String,
    pub workspace_id: String,
    pub conversation_id: String,
    pub conversation_revision: u64,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub conversation_digest: Digest,
    pub parts_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub replayed: bool,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl IntercomConversationRecording {
    fn new(
        evidence: &IntercomConversationEvidence,
        registration: &IntercomRegistration,
        replayed: bool,
    ) -> Self {
        let mut recording = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            workspace_id: evidence.conversation.workspace.workspace_id.clone(),
            conversation_id: evidence.conversation.conversation.conversation_id.clone(),
            conversation_revision: evidence.conversation.conversation.revision,
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            conversation_digest: evidence.conversation_digest.clone(),
            parts_digest: evidence.parts_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: Digest::from_text("unsealed-recording"),
            replayed,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
        };
        recording.receipt_digest = recording.expected_digest();
        recording
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.schema_version,
            &self.workspace_id,
            &self.conversation_id,
            self.conversation_revision,
            &self.scope_digest,
            &self.registration_digest,
            &self.conversation_digest,
            &self.parts_digest,
            &self.evidence_digest,
            self.replayed,
            self.durable,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(
        &self,
        evidence: &IntercomConversationEvidence,
        registration: &IntercomRegistration,
    ) -> Result<(), IntercomError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.workspace_id != evidence.conversation.workspace.workspace_id
            || self.conversation_id != evidence.conversation.conversation.conversation_id
            || self.conversation_revision != evidence.conversation.conversation.revision
            || self.scope_digest != evidence.scope_digest
            || self.registration_digest != registration.registration_digest
            || self.conversation_digest != evidence.conversation_digest
            || self.parts_digest != evidence.parts_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.durable
            || self.connected
            || self.native
            || self.first_party
            || self.receipt_digest != self.expected_digest()
        {
            return Err(IntercomError::RecordingTampered);
        }
        Ok(())
    }
}

pub type IntercomConversationResultRecording = IntercomConversationRecording;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationProjection {
    pub schema_version: String,
    pub workspace_id: String,
    pub conversation_id: String,
    pub conversation_revision: u64,
    pub state: IntercomConversationState,
    pub conversation_digest: Digest,
    pub parts_digest: Digest,
    pub content_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub conversation_verified: bool,
    pub parts_verified: bool,
    pub redaction_verified: bool,
    pub registration_verified: bool,
    pub bounded_evidence_verified: bool,
    pub decision: ConversationDecisionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntercomServiceDefinition {
    pub schema_version: &'static str,
    pub contract_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub layer: u8,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub operations: Vec<IntercomOperation>,
    pub forbidden_effects: Vec<&'static str>,
    pub allowed_provenance: Vec<TransportProvenance>,
}

impl IntercomServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA,
            contract_version: CONTRACT_VERSION,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            layer: 1,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            operations: vec![
                IntercomOperation::DescribeWorkspace,
                IntercomOperation::ReadConversation,
                IntercomOperation::ReadConversationParts,
            ],
            forbidden_effects: vec![
                "send_reply",
                "close_conversation",
                "reopen_conversation",
                "assign_conversation",
                "tag_conversation",
                "create_webhook",
                "retain_raw_names",
                "retain_raw_emails",
                "retain_raw_phone_numbers",
                "retain_raw_message_bodies",
                "retain_raw_attachments",
                "own_inbox",
                "send_human_handoff",
                "adopt_kernel_outcome",
                "resolve_native_secret",
            ],
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
        }
    }
}

pub type IntercomConversationServiceDefinition = IntercomServiceDefinition;

#[derive(Clone, Debug)]
pub struct IntercomConversationResultService<T> {
    provider: IntercomProvider<T>,
    scope: IntercomConversationScope,
    secret_reference: SecretReference,
    registration: IntercomRegistration,
    recordings: BTreeMap<String, Digest>,
    observed_state: BTreeMap<String, IntercomConversationState>,
    observed_assignment: BTreeMap<String, Digest>,
}

impl<T: IntercomTransport> IntercomConversationResultService<T> {
    pub fn new(
        provider: IntercomProvider<T>,
        scope: IntercomConversationScope,
        secret_reference: SecretReference,
    ) -> Result<Self, IntercomError> {
        scope.validate()?;
        let registration = IntercomRegistration::new(&scope, &secret_reference)?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            registration,
            recordings: BTreeMap::new(),
            observed_state: BTreeMap::new(),
            observed_assignment: BTreeMap::new(),
        })
    }

    pub fn from_transport(
        scope: IntercomConversationScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, IntercomError> {
        Self::new(IntercomProvider::new(transport), scope, secret_reference)
    }

    pub fn definition() -> IntercomServiceDefinition {
        IntercomServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &IntercomConversationScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &IntercomRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &IntercomProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut IntercomProvider<T> {
        &mut self.provider
    }

    pub fn describe_workspace(&mut self) -> Result<IntercomWorkspaceIdentity, IntercomError> {
        self.ensure_active()?;
        let request = IntercomReadRequest::for_scope(&self.scope, 1_750_000_000);
        self.provider
            .describe_workspace(&self.scope, &request, &self.secret_reference)
    }

    pub fn read_conversation_evidence(
        &mut self,
        request: IntercomReadRequest,
    ) -> Result<IntercomConversationEvidence, IntercomError> {
        self.ensure_active()?;
        if request.workspace_id != self.scope.workspace.workspace_id {
            return Err(IntercomError::WorkspaceMismatch);
        }
        if request.conversation_id != self.scope.conversation.conversation_id {
            return Err(IntercomError::ConversationMismatch);
        }
        if request.conversation_revision != self.scope.conversation.revision {
            return Err(IntercomError::RevisionDrift);
        }
        let mut components = self.provider.read_conversation_components(
            &self.scope,
            &request,
            &self.secret_reference,
        )?;
        let conversation_id = components.conversation.conversation.conversation_id.clone();
        let assignment_digest = components.conversation.assignment()?.digest();
        if let Some(previous) = self.observed_assignment.get(&conversation_id)
            && previous != &assignment_digest
            && components.conversation.state != IntercomConversationState::AssignmentChanged
        {
            components.conversation.state = IntercomConversationState::AssignmentChanged;
            components.conversation.assignment_changed = true;
            components.conversation.reseal();
        }
        let evidence = IntercomConversationEvidence::new(
            &self.scope,
            &self.registration,
            components,
            request.observed_at_epoch_seconds,
            self.provider.provenance(),
        )?;
        if let Some(previous) = self.observed_state.get(&conversation_id)
            && !previous.can_follow(evidence.state)
        {
            return Err(IntercomError::InvalidStateTransition);
        }
        let assignment_digest = evidence.assignment()?.digest();
        if let Some(previous) = self.observed_assignment.get(&conversation_id)
            && previous != &assignment_digest
            && evidence.state != IntercomConversationState::AssignmentChanged
        {
            return Err(IntercomError::InvalidStateTransition);
        }
        self.observed_state
            .insert(conversation_id.clone(), evidence.state);
        self.observed_assignment
            .insert(conversation_id, assignment_digest);
        Ok(evidence)
    }

    pub fn read_conversation_result(
        &mut self,
        request: IntercomReadRequest,
    ) -> Result<IntercomConversationEvidence, IntercomError> {
        self.read_conversation_evidence(request)
    }

    pub fn read_conversation(
        &mut self,
        request: IntercomReadRequest,
    ) -> Result<IntercomConversationEvidence, IntercomError> {
        self.read_conversation_evidence(request)
    }

    pub fn read_result(
        &mut self,
        request: IntercomReadRequest,
    ) -> Result<IntercomConversationEvidence, IntercomError> {
        self.read_conversation_evidence(request)
    }

    pub fn compile_conversation_result_proposal(
        &self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<IntercomConversationResultProposal, IntercomError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        Ok(IntercomConversationResultProposal::from_evidence(
            evidence,
            &self.scope,
        ))
    }

    pub fn compile_conversation_outcome_proposal(
        &self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<IntercomConversationResultProposal, IntercomError> {
        self.compile_conversation_result_proposal(evidence)
    }

    pub fn compile_adoption_proposal(
        &self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<IntercomConversationResultProposal, IntercomError> {
        self.compile_conversation_result_proposal(evidence)
    }

    pub fn record_conversation_receipt(
        &mut self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<IntercomConversationRecording, IntercomError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        let conversation_id = evidence.conversation.conversation.conversation_id.clone();
        if let Some(existing) = self.recordings.get(&conversation_id) {
            if existing != &evidence.evidence_digest {
                return Err(IntercomError::DuplicateConversation);
            }
            return Ok(IntercomConversationRecording::new(
                evidence,
                &self.registration,
                true,
            ));
        }
        self.recordings
            .insert(conversation_id, evidence.evidence_digest.clone());
        Ok(IntercomConversationRecording::new(
            evidence,
            &self.registration,
            false,
        ))
    }

    pub fn record_conversation_result(
        &mut self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<IntercomConversationRecording, IntercomError> {
        self.record_conversation_receipt(evidence)
    }

    pub fn record_result(
        &mut self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<IntercomConversationRecording, IntercomError> {
        self.record_conversation_receipt(evidence)
    }

    pub fn verify_conversation_evidence(
        &self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<VerificationProjection, IntercomError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        let proposal = IntercomConversationResultProposal::from_evidence(evidence, &self.scope);
        proposal.validate_integrity(&self.scope, &self.registration)?;
        Ok(VerificationProjection {
            schema_version: CONTRACT_SCHEMA.into(),
            workspace_id: evidence.conversation.workspace.workspace_id.clone(),
            conversation_id: evidence.conversation.conversation.conversation_id.clone(),
            conversation_revision: evidence.conversation.conversation.revision,
            state: evidence.state,
            conversation_digest: evidence.conversation_digest.clone(),
            parts_digest: evidence.parts_digest.clone(),
            content_digest: evidence.content_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            conversation_verified: evidence.conversation_digest
                == evidence.conversation.conversation_digest,
            parts_verified: evidence.parts_digest
                == Digest::from_serializable(
                    &evidence
                        .parts
                        .iter()
                        .map(|part| &part.part_digest)
                        .collect::<Vec<_>>(),
                ),
            redaction_verified: !evidence.provenance.raw_names_retained
                && !evidence.provenance.raw_emails_retained
                && !evidence.provenance.raw_phone_numbers_retained
                && !evidence.provenance.raw_message_bodies_retained
                && !evidence.provenance.raw_attachments_retained,
            registration_verified: evidence.registration_digest
                == self.registration.registration_digest,
            bounded_evidence_verified: evidence.complete,
            decision: if evidence.complete {
                ConversationDecisionDisposition::Layer2AdoptionRequired
            } else {
                ConversationDecisionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn verify_conversation_result(
        &self,
        evidence: &IntercomConversationEvidence,
    ) -> Result<VerificationProjection, IntercomError> {
        self.verify_conversation_evidence(evidence)
    }

    pub fn projection_for_error(&self, error: &IntercomError) -> IntercomConversationState {
        error.projection()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence, IntercomError> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence, IntercomError> {
        if self.secret_reference.is_revoked() {
            return Err(IntercomError::SecretRevoked);
        }
        self.registration.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt, IntercomError> {
        self.registration.revoke(&mut self.secret_reference)
    }

    fn ensure_active(&self) -> Result<(), IntercomError> {
        if self.secret_reference.is_revoked() {
            return Err(IntercomError::SecretRevoked);
        }
        if !self.registration.is_active() {
            return Err(IntercomError::RegistrationInactive);
        }
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionIntercomConversation {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub objective_digest: Digest,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub workspace_id: String,
    pub conversation_id: String,
    pub conversation_revision: u64,
    pub state: IntercomConversationState,
    pub status: IntercomConversationState,
    pub priority: IntercomPriority,
    pub assignee_id: Option<String>,
    pub team_id: Option<String>,
    pub created_at_epoch_seconds: u64,
    pub updated_at_epoch_seconds: u64,
    pub first_response_at_epoch_seconds: Option<u64>,
    pub resolution_at_epoch_seconds: Option<u64>,
    pub proposal_digest: Digest,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct MissionIntercomConversationConsumer {
    binding: MissionScopeBinding,
    objective_digest: Digest,
    scope_digest: Digest,
    workspace_id: String,
    conversation_id: String,
    conversation_revision: u64,
    consumed: BTreeMap<String, Digest>,
    active: bool,
}

impl fmt::Debug for MissionIntercomConversationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIntercomConversationConsumer")
            .field("binding", &self.binding)
            .field("scope_digest", &self.scope_digest)
            .field("objective_digest", &self.objective_digest)
            .field("workspace_id", &self.workspace_id)
            .field("conversation_id", &self.conversation_id)
            .field("conversation_revision", &self.conversation_revision)
            .field("consumed_count", &self.consumed.len())
            .field("active", &self.active)
            .finish()
    }
}

impl MissionIntercomConversationConsumer {
    pub fn new(scope: &IntercomConversationScope) -> Result<Self, IntercomError> {
        scope.validate()?;
        Ok(Self {
            binding: scope.mission.clone(),
            objective_digest: scope.objective_digest(),
            scope_digest: scope.scope_digest(),
            workspace_id: scope.workspace.workspace_id.clone(),
            conversation_id: scope.conversation.conversation_id.clone(),
            conversation_revision: scope.conversation.revision,
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn binding(&self) -> &MissionScopeBinding {
        &self.binding
    }

    pub fn unmount(&mut self) {
        self.active = false;
    }

    pub fn remount(&mut self) {
        self.active = true;
    }

    pub fn revoke(&mut self) {
        self.active = false;
    }

    pub fn consume(
        &mut self,
        proposal: &IntercomConversationResultProposal,
    ) -> Result<MissionIntercomConversation, IntercomError> {
        if !self.active {
            return Err(IntercomError::ConsumerInactive);
        }
        if proposal.proposal_digest != proposal.expected_digest() {
            return Err(IntercomError::ProposalTampered);
        }
        if proposal.scope_digest != self.scope_digest
            || proposal.objective_digest != self.objective_digest
            || proposal.workspace_id != self.workspace_id
            || proposal.conversation_id != self.conversation_id
            || proposal.conversation_revision != self.conversation_revision
        {
            if proposal.mission.project_id == self.binding.project_id
                && proposal.mission.mission_id == self.binding.mission_id
                && proposal.mission.work_product_id == self.binding.work_product_id
            {
                return Err(IntercomError::StaleMissionRevision);
            }
            return Err(IntercomError::MissionScopeMismatch);
        }
        if proposal.mission != self.binding {
            if proposal.mission.project_id == self.binding.project_id
                && proposal.mission.mission_id == self.binding.mission_id
                && proposal.mission.work_product_id == self.binding.work_product_id
            {
                return Err(IntercomError::StaleMissionRevision);
            }
            return Err(IntercomError::MissionScopeMismatch);
        }
        let disposition = match self.consumed.get(&proposal.conversation_id) {
            None => {
                self.consumed.insert(
                    proposal.conversation_id.clone(),
                    proposal.proposal_digest.clone(),
                );
                MissionConsumptionDisposition::Fresh
            }
            Some(existing) if existing == &proposal.proposal_digest => {
                MissionConsumptionDisposition::Replay
            }
            Some(_) => return Err(IntercomError::DuplicateConversation),
        };
        Ok(MissionIntercomConversation {
            schema_version: CONTRACT_SCHEMA.into(),
            scope_digest: self.scope_digest.clone(),
            objective_digest: self.objective_digest.clone(),
            project_id: self.binding.project_id.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            project_revision: self.binding.project_revision,
            mission_revision: self.binding.mission_revision,
            work_product_revision: self.binding.work_product_revision,
            workspace_id: proposal.workspace_id.clone(),
            conversation_id: proposal.conversation_id.clone(),
            conversation_revision: proposal.conversation_revision,
            state: proposal.state,
            status: proposal.status,
            priority: proposal.priority,
            assignee_id: proposal.assignee_id.clone(),
            team_id: proposal.team_id.clone(),
            created_at_epoch_seconds: proposal.created_at_epoch_seconds,
            updated_at_epoch_seconds: proposal.updated_at_epoch_seconds,
            first_response_at_epoch_seconds: proposal.first_response_at_epoch_seconds,
            resolution_at_epoch_seconds: proposal.resolution_at_epoch_seconds,
            proposal_digest: proposal.proposal_digest.clone(),
            disposition,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

pub type MissionIntercomConversationResult = MissionIntercomConversation;

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn contract_constants_are_layer_one_and_non_native() {
        assert_eq!(CONTRACT_SCHEMA, "hartevo.intercom-conversation-result/v1");
        assert_eq!(CONTRACT_VERSION, "EXT-INTERCOM-01-L1/v1");
        assert!(!TransportProvenance::Recording.connected());
        assert!(!TransportProvenance::Loopback.native());
        assert!(!TransportProvenance::Fake.first_party());
        assert!(serde_json::from_str::<serde_json::Value>(CONTRACT_JSON).is_ok());
    }
}

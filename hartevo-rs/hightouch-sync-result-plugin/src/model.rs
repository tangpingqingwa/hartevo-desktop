use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RUNS_PER_PAGE: usize = 50;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_BACKOFF_SECONDS: u32 = 60;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("opaque SecretReference is empty, malformed, or too long")]
    InvalidSecretReference,
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("cursor is empty, too long, or not bound to the scope")]
    InvalidCursor,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("consent is invalid")]
    InvalidConsent,
    #[error("permission snapshot is invalid")]
    InvalidPermission,
    #[error("provider metadata response is malformed or outside the bound")]
    InvalidResponse,
    #[error("provider run metadata is invalid")]
    InvalidRun,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration or secret reference is revoked")]
    RegistrationRevoked,
    #[error("revision overflowed")]
    RevisionOverflow,
}

pub type Result<T> = std::result::Result<T, ModelError>;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_component(&mut bytes, domain);
        for (label, value) in fields {
            append_component(&mut bytes, label);
            append_component(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn pending() -> Self {
        Self::from_text("unsealed-hightouch-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
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

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("typed Hightouch value serializes"))
}

fn append_component(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'|');
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'$')
        })
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier {
                field: "identifier",
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts("hightouch-identifier/v1", &[("value", self.0.clone())])
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identifier")
            .field(&format!("id:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

macro_rules! identifier_aliases {
    ($($name:ident),+ $(,)?) => {
        $(pub type $name = Identifier;)+
    };
}

identifier_aliases!(
    HightouchWorkspaceId,
    HightouchSourceId,
    HightouchModelId,
    HightouchSyncId,
    HightouchDestinationId,
    HightouchRunId,
    ProjectId,
    MissionId,
    WorkProductId,
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(ModelError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn bump(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ModelError::RevisionOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: Identifier,
    revision: Revision,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &Identifier {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hightouch-identity-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;
pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl IdentityProjection {
    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        Revision::new(self.revision.get()).map(|_| ())
    }
}

impl From<&IdentityBinding> for IdentityProjection {
    fn from(value: &IdentityBinding) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}

pub type ProjectProjection = IdentityProjection;
pub type MissionProjection = IdentityProjection;
pub type WorkProductProjection = IdentityProjection;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    purpose_digest: Digest,
    revision: Revision,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(purpose: impl AsRef<str>, revision: u64) -> Result<Self> {
        let purpose = purpose.as_ref();
        if purpose.is_empty() || purpose.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::InvalidConsent);
        }
        let revision = Revision::new(revision).map_err(|_| ModelError::InvalidConsent)?;
        let purpose_digest = Digest::from_text(purpose);
        let digest = Digest::from_parts(
            "hightouch-consent/v1",
            &[
                ("purpose", purpose_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
            ],
        );
        Ok(Self {
            purpose_digest,
            revision,
            digest,
        })
    }

    #[must_use]
    pub fn purpose_digest(&self) -> &Digest {
        &self.purpose_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || self.digest
                != Digest::from_parts(
                    "hightouch-consent/v1",
                    &[
                        ("purpose", self.purpose_digest.as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
        {
            Err(ModelError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchPermission {
    WorkspaceMetadataRead,
    SourceMetadataRead,
    ModelMetadataRead,
    DestinationMetadataRead,
    SyncMetadataRead,
    RunMetadataRead,
    MissionScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchPermissionSnapshot {
    pub permissions: BTreeSet<HightouchPermission>,
    pub revision: Revision,
    pub digest: Digest,
}

impl HightouchPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = HightouchPermission>,
        revision: u64,
    ) -> Result<Self> {
        let permissions: BTreeSet<_> = permissions.into_iter().collect();
        let revision = Revision::new(revision).map_err(|_| ModelError::InvalidPermission)?;
        let required = Self::required_permissions();
        if !required
            .iter()
            .all(|permission| permissions.contains(permission))
        {
            return Err(ModelError::InvalidPermission);
        }
        let digest = canonical_digest(&(permissions.clone(), revision));
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    pub fn metadata_read(revision: u64) -> Result<Self> {
        Self::new(Self::required_permissions(), revision)
    }

    #[must_use]
    pub fn required_permissions() -> Vec<HightouchPermission> {
        vec![
            HightouchPermission::WorkspaceMetadataRead,
            HightouchPermission::SourceMetadataRead,
            HightouchPermission::ModelMetadataRead,
            HightouchPermission::DestinationMetadataRead,
            HightouchPermission::SyncMetadataRead,
            HightouchPermission::RunMetadataRead,
            HightouchPermission::MissionScope,
        ]
    }

    pub fn validate(&self) -> Result<()> {
        let expected = canonical_digest(&(self.permissions.clone(), self.revision));
        if self.revision.get() == 0
            || self.digest != expected
            || !Self::required_permissions()
                .iter()
                .all(|permission| self.permissions.contains(permission))
        {
            Err(ModelError::InvalidPermission)
        } else {
            Ok(())
        }
    }
}

/// The API key never survives construction. Only a scope-bound digest and
/// revocation state cross the provider boundary.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: HightouchSecretKind,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchSecretKind {
    ApiKey,
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

impl SecretReference {
    pub fn new(
        reference: impl Into<String>,
        scope: &HightouchSyncScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let mut reference = reference.into();
        if reference.is_empty()
            || reference.len() > MAX_SECRET_REFERENCE_BYTES
            || reference.chars().any(char::is_control)
        {
            reference.zeroize();
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = match Revision::new(credential_revision) {
            Ok(value) => value,
            Err(error) => {
                reference.zeroize();
                return Err(error);
            }
        };
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "hightouch-secret-reference/v1",
            &[
                ("reference", reference.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", credential_revision.get().to_string()),
                ("kind", "api_key".to_owned()),
            ],
        );
        reference.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind: HightouchSecretKind::ApiKey,
            revoked: false,
        })
    }

    pub fn api_key(
        reference: impl Into<String>,
        scope: &HightouchSyncScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, credential_revision)
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
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn kind(&self) -> HightouchSecretKind {
        self.kind
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionReceipt {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub previous_revision: Revision,
    pub registration_revision: Revision,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub transition_digest: Digest,
}

pub type RegistrationRevocationReceipt = RegistrationTransitionReceipt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchRegistration {
    pub registration_id_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl HightouchRegistration {
    pub fn new(
        registration_id: impl AsRef<str>,
        scope: &HightouchSyncScope,
        secret: &SecretReference,
        permissions: &HightouchPermissionSnapshot,
        consent: &ConsentScope,
        provider_digest: Digest,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration_id = Identifier::new(registration_id.as_ref())?;
        permissions.validate()?;
        consent.validate()?;
        if secret.is_revoked() || secret.scope_digest() != &scope.digest() {
            return Err(ModelError::RegistrationRevoked);
        }
        let registration_revision = Revision::new(registration_revision)?;
        let mut registration = Self {
            registration_id_digest: registration_id.digest(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest: permissions.digest.clone(),
            consent_digest: consent.digest().clone(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn validate(
        &self,
        scope: &HightouchSyncScope,
        secret: &SecretReference,
        permissions: &HightouchPermissionSnapshot,
        consent: &ConsentScope,
        provider_digest: &Digest,
    ) -> Result<()> {
        permissions.validate()?;
        consent.validate()?;
        if Revision::new(self.registration_revision.get()).is_err()
            || self.registration_id_digest.validate().is_err()
            || self.contract_digest.validate().is_err()
            || self.provider_digest.validate().is_err()
            || self.permission_digest.validate().is_err()
            || self.consent_digest.validate().is_err()
            || self.scope_digest.validate().is_err()
            || self.secret_reference_digest.validate().is_err()
            || self.registration_digest.validate().is_err()
            || !self.is_active()
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != *provider_digest
            || self.permission_digest != permissions.digest
            || self.consent_digest != *consent.digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || secret.is_revoked()
            || secret.scope_digest() != &scope.digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::RegistrationRevoked);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionReceipt> {
        if !self.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        self.transition(RegistrationState::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionReceipt> {
        if self.is_active() {
            return Err(ModelError::NotRevoked);
        }
        self.transition(RegistrationState::Active)
    }

    fn transition(
        &mut self,
        new_state: RegistrationState,
    ) -> Result<RegistrationTransitionReceipt> {
        let previous_state = self.state.clone();
        let previous_revision = self.registration_revision;
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self.registration_revision.bump()?;
        self.state = new_state.clone();
        self.registration_digest = self.compute_digest();
        let transition_digest = canonical_digest(&(
            &previous_state,
            &new_state,
            previous_revision,
            self.registration_revision,
            &previous_registration_digest,
            &self.registration_digest,
        ));
        Ok(RegistrationTransitionReceipt {
            previous_state,
            new_state,
            previous_revision,
            registration_revision: self.registration_revision,
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            reversible: true,
            transition_digest,
        })
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.registration_id_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            &self.state,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchOperation {
    GetWorkspace,
    GetSource,
    GetModel,
    GetDestination,
    GetSync,
    ListRuns,
}

impl HightouchOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetWorkspace => "get_workspace",
            Self::GetSource => "get_source",
            Self::GetModel => "get_model",
            Self::GetDestination => "get_destination",
            Self::GetSync => "get_sync",
            Self::ListRuns => "list_runs",
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::GetWorkspace => "/workspaces/{workspaceId}",
            Self::GetSource => "/sources/{sourceId}",
            Self::GetModel => "/models/{modelId}",
            Self::GetDestination => "/destinations/{destinationId}",
            Self::GetSync => "/syncs/{syncId}",
            Self::ListRuns => "/syncs/{syncId}/runs",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchCursor {
    pub cursor_digest: Digest,
    pub scope_digest: Option<Digest>,
    pub scope_revision: Option<Revision>,
}

impl HightouchCursor {
    pub fn from_token(token: impl AsRef<str>) -> Result<Self> {
        let token = token.as_ref();
        if token.is_empty() || token.len() > MAX_CURSOR_BYTES || token.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            cursor_digest: Digest::from_parts(
                "hightouch-pagination-cursor/v1",
                &[("token", token.to_owned())],
            ),
            scope_digest: None,
            scope_revision: None,
        })
    }

    pub fn for_scope(token: impl AsRef<str>, scope: &HightouchSyncScope) -> Result<Self> {
        let mut cursor = Self::from_token(token)?;
        cursor.scope_digest = Some(scope.digest());
        cursor.scope_revision = Some(scope.revision);
        Ok(cursor)
    }

    pub fn validate_for_scope(&self, scope: &HightouchSyncScope) -> Result<()> {
        self.cursor_digest.validate()?;
        let scope_digest = scope.digest();
        if self.scope_digest.as_ref() != Some(&scope_digest)
            || self.scope_revision != Some(scope.revision())
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdempotencyKey {
    pub digest: Digest,
}

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidIdentifier {
                field: "idempotency key",
            });
        }
        Ok(Self {
            digest: Digest::from_parts(
                "hightouch-idempotency-key/v1",
                &[("key", value.to_owned())],
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchResourceStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchRunStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchEvidenceState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchEvidenceClassification {
    Normalized,
    Partial,
    Denied,
    BlockedEnv,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchWorkspaceProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub status: HightouchResourceStatus,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchSourceProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub source_type_digest: Option<Digest>,
    pub status: HightouchResourceStatus,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchModelProjection {
    pub id_digest: Digest,
    pub source_id_digest: Digest,
    pub revision: Revision,
    pub model_type_digest: Option<Digest>,
    pub status: HightouchResourceStatus,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchDestinationProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub destination_type_digest: Option<Digest>,
    pub status: HightouchResourceStatus,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchSyncProjection {
    pub id_digest: Digest,
    pub model_id_digest: Digest,
    pub destination_id_digest: Digest,
    pub revision: Revision,
    pub status: HightouchResourceStatus,
    pub enabled: Option<bool>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchRunProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub status: HightouchRunStatus,
    pub started_at_digest: Option<Digest>,
    pub finished_at_digest: Option<Digest>,
    pub queried_rows: Option<u64>,
    pub added_rows: Option<u64>,
    pub changed_rows: Option<u64>,
    pub removed_rows: Option<u64>,
    pub rejected_rows: Option<u64>,
    pub metadata_digest: Digest,
}

impl HightouchWorkspaceProjection {
    pub(crate) fn new(
        id: &HightouchWorkspaceId,
        revision: Revision,
        status: HightouchResourceStatus,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            id_digest: id.digest(),
            revision,
            status,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.metadata_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl HightouchSourceProjection {
    pub(crate) fn new(
        id: &HightouchSourceId,
        revision: Revision,
        source_type_digest: Option<Digest>,
        status: HightouchResourceStatus,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            id_digest: id.digest(),
            revision,
            source_type_digest,
            status,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.metadata_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl HightouchModelProjection {
    pub(crate) fn new(
        id: &HightouchModelId,
        source_id: &HightouchSourceId,
        revision: Revision,
        model_type_digest: Option<Digest>,
        status: HightouchResourceStatus,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            id_digest: id.digest(),
            source_id_digest: source_id.digest(),
            revision,
            model_type_digest,
            status,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.source_id_digest.validate()?;
        self.metadata_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl HightouchDestinationProjection {
    pub(crate) fn new(
        id: &HightouchDestinationId,
        revision: Revision,
        destination_type_digest: Option<Digest>,
        status: HightouchResourceStatus,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            id_digest: id.digest(),
            revision,
            destination_type_digest,
            status,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.metadata_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl HightouchSyncProjection {
    pub(crate) fn new(
        id: &HightouchSyncId,
        model_id: &HightouchModelId,
        destination_id: &HightouchDestinationId,
        revision: Revision,
        status: HightouchResourceStatus,
        enabled: Option<bool>,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            id_digest: id.digest(),
            model_id_digest: model_id.digest(),
            destination_id_digest: destination_id.digest(),
            revision,
            status,
            enabled,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.model_id_digest.validate()?;
        self.destination_id_digest.validate()?;
        self.metadata_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl HightouchRunProjection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: &HightouchRunId,
        revision: Revision,
        status: HightouchRunStatus,
        started_at_digest: Option<Digest>,
        finished_at_digest: Option<Digest>,
        queried_rows: Option<u64>,
        added_rows: Option<u64>,
        changed_rows: Option<u64>,
        removed_rows: Option<u64>,
        rejected_rows: Option<u64>,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            id_digest: id.digest(),
            revision,
            status,
            started_at_digest,
            finished_at_digest,
            queried_rows,
            added_rows,
            changed_rows,
            removed_rows,
            rejected_rows,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        if let Some(digest) = &self.started_at_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.finished_at_digest {
            digest.validate()?;
        }
        self.metadata_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchRateLimitReceipt {
    pub limit_per_minute: Option<u32>,
    pub remaining: Option<u32>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
    pub digest: Digest,
}

impl Default for HightouchRateLimitReceipt {
    fn default() -> Self {
        Self::new(None, None, None, false).expect("default rate limit receipt")
    }
}

impl HightouchRateLimitReceipt {
    pub fn new(
        limit_per_minute: Option<u32>,
        remaining: Option<u32>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self> {
        if retry_after_seconds.is_some_and(|value| value > 3_600)
            || limit_per_minute.is_some_and(|value| value == 0)
        {
            return Err(ModelError::InvalidResponse);
        }
        let mut receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
            digest: Digest::pending(),
        };
        receipt.digest = canonical_digest(&(
            receipt.limit_per_minute,
            receipt.remaining,
            receipt.retry_after_seconds,
            receipt.throttled,
        ));
        Ok(receipt)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchBackoffReceipt {
    pub attempts: u8,
    pub retry_after_seconds: Option<u32>,
    pub backoff_seconds: u32,
    pub digest: Digest,
}

impl HightouchBackoffReceipt {
    pub(crate) fn new(
        attempts: u8,
        retry_after_seconds: Option<u32>,
        backoff_seconds: u32,
    ) -> Self {
        let digest = canonical_digest(&(attempts, retry_after_seconds, backoff_seconds));
        Self {
            attempts,
            retry_after_seconds,
            backoff_seconds,
            digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchReadReceipt {
    pub operation: HightouchOperation,
    pub method: HightouchHttpMethod,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub page: u16,
    pub cursor_digest: Option<Digest>,
    pub rate_limit_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
}

impl HightouchReadReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchFailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub diagnostic_digest: Digest,
    pub failure_digest: Digest,
}

impl HightouchFailureEvidence {
    pub(crate) fn new(
        category: impl Into<String>,
        status_code: Option<u16>,
        retry_after_seconds: Option<u32>,
        diagnostic: impl AsRef<str>,
    ) -> Self {
        let category = category.into();
        let diagnostic = diagnostic.as_ref();
        let diagnostic_digest =
            Digest::from_text(&diagnostic.as_bytes()[..diagnostic.len().min(MAX_DIAGNOSTIC_BYTES)]);
        let failure_digest = canonical_digest(&(
            &category,
            status_code,
            retry_after_seconds,
            &diagnostic_digest,
        ));
        Self {
            category,
            status_code,
            retry_after_seconds,
            diagnostic_digest,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub workspace_digest: Digest,
    pub source_digest: Digest,
    pub model_digest: Digest,
    pub sync_digest: Digest,
    pub destination_digest: Digest,
    pub run_digest: Digest,
    pub commit_digest: Digest,
    pub cursor_digests: Vec<Digest>,
    pub idempotency_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchSyncResultEvidence {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub workspace: Option<HightouchWorkspaceProjection>,
    pub source: Option<HightouchSourceProjection>,
    pub model: Option<HightouchModelProjection>,
    pub sync: Option<HightouchSyncProjection>,
    pub destination: Option<HightouchDestinationProjection>,
    pub run: Option<HightouchRunProjection>,
    pub runs: Vec<HightouchRunProjection>,
    pub commit_digest: Digest,
    pub state: HightouchEvidenceState,
    pub classification: HightouchEvidenceClassification,
    pub page_count: u16,
    pub listing_complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub read_receipts: Vec<HightouchReadReceipt>,
    pub rate_limit: HightouchRateLimitReceipt,
    pub backoff: Option<HightouchBackoffReceipt>,
    pub failure: Option<HightouchFailureEvidence>,
    pub provenance: TransportProvenance,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub work_product_adopted: bool,
    pub outcome_adopted: bool,
    pub digests: HightouchEvidenceDigests,
    pub evidence_digest: Digest,
}

impl HightouchSyncResultEvidence {
    pub(crate) fn seal(mut self) -> Self {
        self.evidence_digest = Digest::pending();
        self.digests.evidence_digest = Digest::pending();
        let evidence_digest = self.compute_digest();
        self.evidence_digest = evidence_digest.clone();
        self.digests.evidence_digest = evidence_digest;
        self
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.durable_provider_receipt
            || self.work_product_adopted
            || self.outcome_adopted
            || self.digests.evidence_digest != self.evidence_digest
            || self.evidence_digest != self.compute_digest()
            || self.commit_digest.validate().is_err()
        {
            return Err(ModelError::InvalidResponse);
        }
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Revision::new(self.registration_revision.get()).map_err(|_| ModelError::InvalidResponse)?;
        if let Some(value) = &self.workspace {
            value.validate()?;
        }
        if let Some(value) = &self.source {
            value.validate()?;
        }
        if let Some(value) = &self.model {
            value.validate()?;
        }
        if let Some(value) = &self.sync {
            value.validate()?;
        }
        if let Some(value) = &self.destination {
            value.validate()?;
        }
        if let Some(value) = &self.run {
            value.validate()?;
        }
        for value in &self.runs {
            value.validate()?;
        }
        for value in &self.cursor_digests {
            value.validate()?;
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        value.digests.evidence_digest = Digest::pending();
        canonical_digest(&value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HightouchRecommendationDisposition {
    ReviewSuccessfulDeliveryMetadata,
    ReviewQueuedRun,
    ReviewRunningRun,
    ReviewFailedRun,
    ReviewPartialRun,
    NoRecommendationDenied,
    NoRecommendationRateLimited,
    NoRecommendationProviderUnknown,
    NoRecommendationTampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchRecommendation {
    pub disposition: HightouchRecommendationDisposition,
    pub provider_reported_only: bool,
    pub non_mutating: bool,
    pub claims_delivery_truth: bool,
    pub claims_source_truth: bool,
    pub claims_business_success: bool,
    pub rationale_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchSyncResultProposal {
    pub evidence: HightouchSyncResultEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub contract_digest: Digest,
    pub idempotency_digest: Digest,
    pub recommendation: HightouchRecommendation,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub work_product_adopted: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl HightouchSyncResultProposal {
    pub(crate) fn seal(mut self) -> Self {
        self.proposal_digest = Digest::pending();
        self.proposal_digest = self.compute_digest();
        self
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.proposal_only
            || self.connected
            || self.native
            || self.work_product_adopted
            || self.outcome_adopted
            || self.source_evidence_digest != self.evidence.digest()
            || self.registration_digest != self.evidence.registration_digest
            || self.proposal_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidResponse);
        }
        self.evidence.validate_integrity()
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        canonical_digest(&value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub conflict: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

impl HightouchObservationReceipt {
    pub(crate) fn new(
        proposal: &HightouchSyncResultProposal,
        idempotency_digest: Digest,
        replayed: bool,
        conflict: bool,
    ) -> Self {
        let mut receipt = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            idempotency_digest,
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            provenance: proposal.evidence.provenance.clone(),
            replayed,
            conflict,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            receipt_digest: Digest::pending(),
        };
        receipt.receipt_digest = canonical_digest(&receipt_without_digest(&receipt));
        receipt
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.durable_provider_receipt
            || self.connected
            || self.native
            || self.receipt_digest != canonical_digest(&receipt_without_digest(self))
        {
            Err(ModelError::InvalidResponse)
        } else {
            Ok(())
        }
    }
}

fn receipt_without_digest(
    receipt: &HightouchObservationReceipt,
) -> (
    &Digest,
    &Digest,
    &Digest,
    &Digest,
    &Digest,
    &TransportProvenance,
    bool,
    bool,
    bool,
    bool,
    bool,
) {
    (
        &receipt.proposal_digest,
        &receipt.evidence_digest,
        &receipt.idempotency_digest,
        &receipt.registration_digest,
        &receipt.scope_digest,
        &receipt.provenance,
        receipt.replayed,
        receipt.conflict,
        receipt.durable_provider_receipt,
        receipt.connected,
        receipt.native,
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HightouchSyncScope {
    workspace_id: HightouchWorkspaceId,
    source_id: HightouchSourceId,
    model_id: HightouchModelId,
    sync_id: HightouchSyncId,
    destination_id: HightouchDestinationId,
    run_id: HightouchRunId,
    commit_digest: Digest,
    workspace_revision: Revision,
    source_revision: Revision,
    model_revision: Revision,
    sync_revision: Revision,
    destination_revision: Revision,
    run_revision: Revision,
    revision: Revision,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    workspace_allowlist: BTreeSet<HightouchWorkspaceId>,
    source_allowlist: BTreeSet<HightouchSourceId>,
    model_allowlist: BTreeSet<HightouchModelId>,
    sync_allowlist: BTreeSet<HightouchSyncId>,
    destination_allowlist: BTreeSet<HightouchDestinationId>,
    run_allowlist: BTreeSet<HightouchRunId>,
}

impl fmt::Debug for HightouchSyncScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HightouchSyncScope")
            .field("scope_digest", &self.digest())
            .field("workspace_digest", &self.workspace_id.digest())
            .field("source_digest", &self.source_id.digest())
            .field("model_digest", &self.model_id.digest())
            .field("sync_digest", &self.sync_id.digest())
            .field("destination_digest", &self.destination_id.digest())
            .field("run_digest", &self.run_id.digest())
            .field("project", &self.project.digest())
            .field("mission", &self.mission.digest())
            .field("work_product", &self.work_product.digest())
            .finish()
    }
}

impl HightouchSyncScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: impl Into<String>,
        source_id: impl Into<String>,
        model_id: impl Into<String>,
        sync_id: impl Into<String>,
        destination_id: impl Into<String>,
        run_id: impl Into<String>,
        commit: impl AsRef<str>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        let workspace_id = Identifier::new(workspace_id)?;
        let source_id = Identifier::new(source_id)?;
        let model_id = Identifier::new(model_id)?;
        let sync_id = Identifier::new(sync_id)?;
        let destination_id = Identifier::new(destination_id)?;
        let run_id = Identifier::new(run_id)?;
        let commit = commit.as_ref();
        if commit.is_empty()
            || commit.len() > MAX_IDENTIFIER_BYTES
            || commit.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidScope("commit"));
        }
        let scope = Self {
            workspace_allowlist: BTreeSet::from([workspace_id.clone()]),
            source_allowlist: BTreeSet::from([source_id.clone()]),
            model_allowlist: BTreeSet::from([model_id.clone()]),
            sync_allowlist: BTreeSet::from([sync_id.clone()]),
            destination_allowlist: BTreeSet::from([destination_id.clone()]),
            run_allowlist: BTreeSet::from([run_id.clone()]),
            workspace_id,
            source_id,
            model_id,
            sync_id,
            destination_id,
            run_id,
            commit_digest: Digest::from_text(commit),
            workspace_revision: Revision::new(1)?,
            source_revision: Revision::new(1)?,
            model_revision: Revision::new(1)?,
            sync_revision: Revision::new(1)?,
            destination_revision: Revision::new(1)?,
            run_revision: Revision::new(1)?,
            revision: Revision::new(1)?,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_revisions(
        mut self,
        workspace_revision: u64,
        source_revision: u64,
        model_revision: u64,
        sync_revision: u64,
        destination_revision: u64,
        run_revision: u64,
        scope_revision: u64,
    ) -> Result<Self> {
        self.workspace_revision = Revision::new(workspace_revision)?;
        self.source_revision = Revision::new(source_revision)?;
        self.model_revision = Revision::new(model_revision)?;
        self.sync_revision = Revision::new(sync_revision)?;
        self.destination_revision = Revision::new(destination_revision)?;
        self.run_revision = Revision::new(run_revision)?;
        self.revision = Revision::new(scope_revision)?;
        self.validate()?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_allowlists(
        mut self,
        workspaces: impl IntoIterator<Item = HightouchWorkspaceId>,
        sources: impl IntoIterator<Item = HightouchSourceId>,
        models: impl IntoIterator<Item = HightouchModelId>,
        syncs: impl IntoIterator<Item = HightouchSyncId>,
        destinations: impl IntoIterator<Item = HightouchDestinationId>,
        runs: impl IntoIterator<Item = HightouchRunId>,
    ) -> Result<Self> {
        self.workspace_allowlist = workspaces.into_iter().collect();
        self.source_allowlist = sources.into_iter().collect();
        self.model_allowlist = models.into_iter().collect();
        self.sync_allowlist = syncs.into_iter().collect();
        self.destination_allowlist = destinations.into_iter().collect();
        self.run_allowlist = runs.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn workspace_id(&self) -> &HightouchWorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub fn source_id(&self) -> &HightouchSourceId {
        &self.source_id
    }

    #[must_use]
    pub fn model_id(&self) -> &HightouchModelId {
        &self.model_id
    }

    #[must_use]
    pub fn sync_id(&self) -> &HightouchSyncId {
        &self.sync_id
    }

    #[must_use]
    pub fn destination_id(&self) -> &HightouchDestinationId {
        &self.destination_id
    }

    #[must_use]
    pub fn run_id(&self) -> &HightouchRunId {
        &self.run_id
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    #[must_use]
    pub const fn workspace_revision(&self) -> Revision {
        self.workspace_revision
    }

    #[must_use]
    pub const fn source_revision(&self) -> Revision {
        self.source_revision
    }

    #[must_use]
    pub const fn model_revision(&self) -> Revision {
        self.model_revision
    }

    #[must_use]
    pub const fn sync_revision(&self) -> Revision {
        self.sync_revision
    }

    #[must_use]
    pub const fn destination_revision(&self) -> Revision {
        self.destination_revision
    }

    #[must_use]
    pub const fn run_revision(&self) -> Revision {
        self.run_revision
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hightouch-sync-scope/v1",
            &[
                ("workspace", self.workspace_id.digest().as_str().to_owned()),
                ("source", self.source_id.digest().as_str().to_owned()),
                ("model", self.model_id.digest().as_str().to_owned()),
                ("sync", self.sync_id.digest().as_str().to_owned()),
                (
                    "destination",
                    self.destination_id.digest().as_str().to_owned(),
                ),
                ("run", self.run_id.digest().as_str().to_owned()),
                ("commit", self.commit_digest.as_str().to_owned()),
                (
                    "workspace_revision",
                    self.workspace_revision.get().to_string(),
                ),
                ("source_revision", self.source_revision.get().to_string()),
                ("model_revision", self.model_revision.get().to_string()),
                ("sync_revision", self.sync_revision.get().to_string()),
                (
                    "destination_revision",
                    self.destination_revision.get().to_string(),
                ),
                ("run_revision", self.run_revision.get().to_string()),
                ("revision", self.revision.get().to_string()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "workspace_allowlist",
                    digest_ids(&self.workspace_allowlist).as_str().to_owned(),
                ),
                (
                    "source_allowlist",
                    digest_ids(&self.source_allowlist).as_str().to_owned(),
                ),
                (
                    "model_allowlist",
                    digest_ids(&self.model_allowlist).as_str().to_owned(),
                ),
                (
                    "sync_allowlist",
                    digest_ids(&self.sync_allowlist).as_str().to_owned(),
                ),
                (
                    "destination_allowlist",
                    digest_ids(&self.destination_allowlist).as_str().to_owned(),
                ),
                (
                    "run_allowlist",
                    digest_ids(&self.run_allowlist).as_str().to_owned(),
                ),
            ],
        )
    }

    #[must_use]
    pub fn workspace_is_allowed(&self, value: &HightouchWorkspaceId) -> bool {
        self.workspace_allowlist.contains(value)
    }

    #[must_use]
    pub fn source_is_allowed(&self, value: &HightouchSourceId) -> bool {
        self.source_allowlist.contains(value)
    }

    #[must_use]
    pub fn model_is_allowed(&self, value: &HightouchModelId) -> bool {
        self.model_allowlist.contains(value)
    }

    #[must_use]
    pub fn sync_is_allowed(&self, value: &HightouchSyncId) -> bool {
        self.sync_allowlist.contains(value)
    }

    #[must_use]
    pub fn destination_is_allowed(&self, value: &HightouchDestinationId) -> bool {
        self.destination_allowlist.contains(value)
    }

    #[must_use]
    pub fn run_is_allowed(&self, value: &HightouchRunId) -> bool {
        self.run_allowlist.contains(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.workspace_allowlist.is_empty()
            || self.source_allowlist.is_empty()
            || self.model_allowlist.is_empty()
            || self.sync_allowlist.is_empty()
            || self.destination_allowlist.is_empty()
            || self.run_allowlist.is_empty()
        {
            return Err(ModelError::InvalidScope("empty resource allowlist"));
        }
        if !self.workspace_is_allowed(&self.workspace_id)
            || !self.source_is_allowed(&self.source_id)
            || !self.model_is_allowed(&self.model_id)
            || !self.sync_is_allowed(&self.sync_id)
            || !self.destination_is_allowed(&self.destination_id)
            || !self.run_is_allowed(&self.run_id)
        {
            return Err(ModelError::InvalidScope(
                "target is not explicitly allowlisted",
            ));
        }
        if Revision::new(self.workspace_revision.get()).is_err()
            || Revision::new(self.source_revision.get()).is_err()
            || Revision::new(self.model_revision.get()).is_err()
            || Revision::new(self.sync_revision.get()).is_err()
            || Revision::new(self.destination_revision.get()).is_err()
            || Revision::new(self.run_revision.get()).is_err()
            || Revision::new(self.revision.get()).is_err()
        {
            return Err(ModelError::InvalidScope("zero revision"));
        }
        self.project.id().digest().validate()?;
        self.mission.id().digest().validate()?;
        self.work_product.id().digest().validate()?;
        self.commit_digest.validate()
    }
}

fn digest_ids<T: AsRef<str> + Ord>(values: &BTreeSet<T>) -> Digest {
    let joined = values
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\u{1f}");
    Digest::from_parts("hightouch-resource-allowlist/v1", &[("values", joined)])
}

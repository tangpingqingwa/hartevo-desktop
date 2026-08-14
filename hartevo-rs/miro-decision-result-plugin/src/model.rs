use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MIRO_DECISION_RESULT_CONSUMER_ID, MIRO_DECISION_RESULT_CONTRACT_VERSION,
    MIRO_DECISION_RESULT_PROVIDER_ID, MIRO_DECISION_RESULT_SCHEMA_VERSION,
    MIRO_DECISION_RESULT_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_LABEL_BYTES: usize = 128;
pub(crate) const MAX_LABELS_PER_ITEM: usize = 32;
pub(crate) const MAX_EXTERNAL_LINK_BYTES: usize = 2_048;
pub(crate) const MAX_CURSOR_BYTES: usize = 4_096;
pub(crate) const MAX_ITEMS: usize = 256;
pub(crate) const MAX_PAGES: u8 = 8;
pub(crate) const MAX_PAGE_SIZE: u16 = 100;
pub(crate) const MAX_PROVIDER_PAGE_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp is empty, too long, or contains a control character")]
    InvalidTimestamp,
    #[error("scope is empty, duplicated, or otherwise invalid")]
    InvalidScope,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("label is empty, too long, or appears to contain personal data")]
    InvalidLabel,
    #[error("external URL is invalid or contains unsafe user information")]
    InvalidUrl,
    #[error("opaque cursor is empty, too large, or contains a control character")]
    InvalidCursor,
    #[error("board item is invalid")]
    InvalidItem,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("evidence digest does not match immutable fields")]
    DigestMismatch,
    #[error("duplicate board item")]
    DuplicateItem,
}

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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
    };
}

string_identifier!(TeamId);
string_identifier!(BoardId);
string_identifier!(ItemId);
string_identifier!(MissionId);
string_identifier!(ProjectId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UpdateTimestamp(String);

impl UpdateTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !value.is_empty()
            && value.len() <= 64
            && !value.chars().any(char::is_control)
            && !value.chars().any(char::is_whitespace)
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidTimestamp)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UpdateTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UpdateTimestamp")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiroAuthKind {
    OAuth,
}

/// Opaque reference into a host-managed keyring.  The original reference id
/// is intentionally not retained, serialized, or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: MiroAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &MiroDecisionScope,
        credential_revision: u64,
        auth_kind: MiroAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "miro-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &MiroDecisionScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            MiroAuthKind::OAuth,
        )
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> MiroAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiroDecisionScopeSpec {
    pub team_id: TeamId,
    pub board_id: BoardId,
    pub allowlisted_item_ids: BTreeSet<ItemId>,
    pub board_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiroDecisionScope {
    team_id: TeamId,
    board_id: BoardId,
    allowlisted_item_ids: BTreeSet<ItemId>,
    board_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    project_id: ProjectId,
    project_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl MiroDecisionScope {
    pub fn new(spec: MiroDecisionScopeSpec) -> Result<Self, ModelError> {
        if spec.allowlisted_item_ids.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "miro-decision-scope/v1",
            &[
                spec.team_id.as_str().to_owned(),
                spec.board_id.as_str().to_owned(),
                spec.allowlisted_item_ids
                    .iter()
                    .map(|item| item.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                spec.board_revision.get().to_string(),
                spec.mission_id.as_str().to_owned(),
                spec.mission_revision.get().to_string(),
                spec.project_id.as_str().to_owned(),
                spec.project_revision.get().to_string(),
                spec.work_product_id.as_str().to_owned(),
                spec.work_product_revision.get().to_string(),
                spec.permission_digest.as_str().to_owned(),
                spec.consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            team_id: spec.team_id,
            board_id: spec.board_id,
            allowlisted_item_ids: spec.allowlisted_item_ids,
            board_revision: spec.board_revision,
            mission_id: spec.mission_id,
            mission_revision: spec.mission_revision,
            project_id: spec.project_id,
            project_revision: spec.project_revision,
            work_product_id: spec.work_product_id,
            work_product_revision: spec.work_product_revision,
            permission_digest: spec.permission_digest,
            consent_digest: spec.consent_digest,
            scope_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        team_id: TeamId,
        board_id: BoardId,
        allowlisted_item_ids: impl IntoIterator<Item = ItemId>,
        board_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        project_id: ProjectId,
        project_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let allowlisted_item_ids = allowlisted_item_ids.into_iter().collect::<Vec<_>>();
        let unique_item_count = allowlisted_item_ids.iter().collect::<BTreeSet<_>>().len();
        if unique_item_count != allowlisted_item_ids.len() {
            return Err(ModelError::InvalidScope);
        }
        Self::new(MiroDecisionScopeSpec {
            team_id,
            board_id,
            allowlisted_item_ids: allowlisted_item_ids.into_iter().collect(),
            board_revision,
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            work_product_id,
            work_product_revision,
            permission_digest,
            consent_digest,
        })
    }

    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    pub fn board_id(&self) -> &BoardId {
        &self.board_id
    }

    pub fn allowlisted_item_ids(&self) -> &BTreeSet<ItemId> {
        &self.allowlisted_item_ids
    }

    pub const fn board_revision(&self) -> Revision {
        self.board_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn contains_item(&self, item_id: &ItemId) -> bool {
        self.allowlisted_item_ids.contains(item_id)
    }

    pub(crate) fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            mission_revision: self.mission_revision,
            project_revision: self.project_revision,
            work_product_revision: self.work_product_revision,
            board_revision: self.board_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub work_product_revision: Revision,
    pub board_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiroDecisionRegistration {
    schema_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: ProviderId,
    provider_version: String,
    provider_digest: Digest,
    implementation_digest: Digest,
    team_id: TeamId,
    board_id: BoardId,
    permission_digest: Digest,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    revision: Revision,
    registration_digest: Digest,
    state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub revocation_digest: Digest,
    pub state: RegistrationState,
}

impl MiroDecisionRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &MiroDecisionScope,
        secret_reference_digest: &Digest,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        provider_digest: Digest,
        contract_digest: Digest,
        implementation_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if !valid_version(&provider_version) {
            return Err(ModelError::InvalidRegistration);
        }
        let registration_digest = Digest::from_fields(
            "miro-decision-registration/v1",
            &[
                MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
                MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
                contract_digest.as_str().to_owned(),
                provider_id.as_str().to_owned(),
                provider_version.clone(),
                provider_digest.as_str().to_owned(),
                implementation_digest.as_str().to_owned(),
                scope.team_id.as_str().to_owned(),
                scope.board_id.as_str().to_owned(),
                scope.permission_digest.as_str().to_owned(),
                scope.scope_digest.as_str().to_owned(),
                secret_reference_digest.as_str().to_owned(),
                revision.get().to_string(),
            ],
        );
        Ok(Self {
            schema_version: MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id,
            provider_version,
            provider_digest,
            implementation_digest,
            team_id: scope.team_id.clone(),
            board_id: scope.board_id.clone(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.scope_digest(),
            secret_reference_digest: secret_reference_digest.clone(),
            revision,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    pub fn board_id(&self) -> &BoardId {
        &self.board_id
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if !self.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "miro-decision-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.revision,
            revocation_digest,
            state: self.state,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Label(String);

impl Label {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().trim().to_owned();
        if value.is_empty()
            || value.len() > MAX_LABEL_BYTES
            || value.chars().any(char::is_control)
            || looks_like_pii(&value)
        {
            Err(ModelError::InvalidLabel)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedExternalLink(String);

impl RedactedExternalLink {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Ok(Self(redact_url(value.as_ref())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn looks_like_pii(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    value.contains('@')
        || lowercase.contains("%40")
        || value.chars().filter(char::is_ascii_digit).count() >= 7
}

fn redact_url(value: &str) -> Result<String, ModelError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_EXTERNAL_LINK_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(ModelError::InvalidUrl);
    }
    let Some(separator) = value.find("://") else {
        return Err(ModelError::InvalidUrl);
    };
    let scheme = value[..separator].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ModelError::InvalidUrl);
    }
    let authority_start = separator + 3;
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |index| authority_start + index);
    let authority = &value[authority_start..authority_end];
    let authority = authority.rsplit('@').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('<') || authority.contains('>') {
        return Err(ModelError::InvalidUrl);
    }
    let authority = authority.to_ascii_lowercase();
    let path_and_suffix = &value[authority_end..];
    let path = path_and_suffix.split(['?', '#']).next().unwrap_or_default();
    let redacted_path = path
        .split('/')
        .map(|segment| {
            if looks_like_pii(segment) {
                "<redacted>".to_owned()
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    Ok(format!("{scheme}://{authority}{redacted_path}"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiroBoardItemKind {
    Card,
    Text,
    StickyNote,
    Link,
    Unsupported,
}

impl MiroBoardItemKind {
    pub fn from_api_type(value: &str) -> Self {
        match value {
            "card" => Self::Card,
            "text" => Self::Text,
            "sticky_note" => Self::StickyNote,
            "link" => Self::Link,
            _ => Self::Unsupported,
        }
    }

    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unsupported)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::Text => "text",
            Self::StickyNote => "sticky_note",
            Self::Link => "link",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroBoardItem {
    pub id: ItemId,
    pub kind: MiroBoardItemKind,
    pub revision: Revision,
    pub updated_at: UpdateTimestamp,
    pub labels: Vec<Label>,
    pub redacted_text_digest: Option<Digest>,
    pub redacted_external_link: Option<RedactedExternalLink>,
    pub item_digest: Digest,
}

impl MiroBoardItem {
    pub fn new(
        id: ItemId,
        kind: MiroBoardItemKind,
        revision: Revision,
        updated_at: UpdateTimestamp,
        labels: impl IntoIterator<Item = Label>,
        redacted_text_digest: Option<Digest>,
        redacted_external_link: Option<RedactedExternalLink>,
    ) -> Result<Self, ModelError> {
        let mut labels = labels.into_iter().collect::<Vec<_>>();
        if labels.len() > MAX_LABELS_PER_ITEM {
            return Err(ModelError::InvalidItem);
        }
        labels.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let item_digest = compute_item_digest(
            &id,
            kind,
            revision,
            &updated_at,
            &labels,
            redacted_text_digest.as_ref(),
            redacted_external_link.as_ref(),
        );
        Ok(Self {
            id,
            kind,
            revision,
            updated_at,
            labels,
            redacted_text_digest,
            redacted_external_link,
            item_digest,
        })
    }

    pub fn from_raw(
        id: ItemId,
        kind: MiroBoardItemKind,
        revision: Revision,
        updated_at: UpdateTimestamp,
        labels: impl IntoIterator<Item = Label>,
        raw_text: Option<&str>,
        external_link: Option<&str>,
    ) -> Result<Self, ModelError> {
        let redacted_text_digest = raw_text.map(Digest::from_text);
        let redacted_external_link = external_link.map(RedactedExternalLink::new).transpose()?;
        Self::new(
            id,
            kind,
            revision,
            updated_at,
            labels,
            redacted_text_digest,
            redacted_external_link,
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = compute_item_digest(
            &self.id,
            self.kind,
            self.revision,
            &self.updated_at,
            &self.labels,
            self.redacted_text_digest.as_ref(),
            self.redacted_external_link.as_ref(),
        );
        if expected == self.item_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn text_digest(&self) -> Option<&Digest> {
        self.redacted_text_digest.as_ref()
    }

    pub fn external_link(&self) -> Option<&RedactedExternalLink> {
        self.redacted_external_link.as_ref()
    }
}

fn compute_item_digest(
    id: &ItemId,
    kind: MiroBoardItemKind,
    revision: Revision,
    updated_at: &UpdateTimestamp,
    labels: &[Label],
    text_digest: Option<&Digest>,
    external_link: Option<&RedactedExternalLink>,
) -> Digest {
    Digest::from_fields(
        "miro-board-item/v1",
        &[
            id.as_str().to_owned(),
            kind.as_str().to_owned(),
            revision.get().to_string(),
            updated_at.as_str().to_owned(),
            labels
                .iter()
                .map(|label| label.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            text_digest.map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            external_link.map_or_else(|| "none".to_owned(), |link| link.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroBoardMetadata {
    pub team_id: TeamId,
    pub board_id: BoardId,
    pub revision: Revision,
    pub updated_at: UpdateTimestamp,
    pub board_digest: Digest,
}

impl MiroBoardMetadata {
    pub fn new(
        team_id: TeamId,
        board_id: BoardId,
        revision: Revision,
        updated_at: UpdateTimestamp,
    ) -> Self {
        let board_digest = Digest::from_fields(
            "miro-board-metadata/v1",
            &[
                team_id.as_str().to_owned(),
                board_id.as_str().to_owned(),
                revision.get().to_string(),
                updated_at.as_str().to_owned(),
            ],
        );
        Self {
            team_id,
            board_id,
            revision,
            updated_at,
            board_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.team_id.clone(),
            self.board_id.clone(),
            self.revision,
            self.updated_at.clone(),
        )
        .board_digest;
        if expected == self.board_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(Self(value))
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl Clone for OpaqueCursor {
    fn clone(&self) -> Self {
        Self(self.0.clone())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionBounds {
    max_pages: u8,
    max_items: u16,
    page_size: u16,
}

impl DecisionBounds {
    pub fn new(max_pages: u8, max_items: u16, page_size: u16) -> Result<Self, ModelError> {
        if !(1..=MAX_PAGES).contains(&max_pages)
            || !(1..=MAX_ITEMS as u16).contains(&max_items)
            || !(1..=MAX_PAGE_SIZE).contains(&page_size)
        {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(Self {
                max_pages,
                max_items,
                page_size,
            })
        }
    }

    pub const fn max_pages(self) -> u8 {
        self.max_pages
    }

    pub const fn max_items(self) -> u16 {
        self.max_items
    }

    pub const fn page_size(self) -> u16 {
        self.page_size
    }
}

impl Default for DecisionBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_items: MAX_ITEMS as u16,
            page_size: MAX_PAGE_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    UnsupportedItem,
    Deleted,
    AccessLost,
    Empty,
    Partial,
    RateLimited,
    ServerFailure,
    Timeout,
    ScopeDrift,
    InvalidResponse,
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        blocked_env: bool,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retryable,
            blocked_env,
            diagnostic_digest: Digest::from_bytes(diagnostic.as_ref()),
        }
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionResultAuthority;

impl DecisionResultAuthority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native_provider(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn durable_receipt(self) -> bool {
        false
    }

    pub const fn independent_read_back(self) -> bool {
        false
    }

    pub const fn verified_adoption(self) -> bool {
        false
    }

    pub const fn adopted_outcome(self) -> bool {
        false
    }

    pub const fn truth_authority(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAvailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceDigests {
    pub board_digest: Option<Digest>,
    pub item_set_digest: Digest,
    pub redaction_digest: Digest,
    pub result_digest: Digest,
}

impl EvidenceDigests {
    pub fn new(
        board_digest: Option<Digest>,
        item_set_digest: Digest,
        redaction_digest: Digest,
        result_digest: Digest,
    ) -> Self {
        Self {
            board_digest,
            item_set_digest,
            redaction_digest,
            result_digest,
        }
    }
}

pub(crate) fn canonical_item_set_digest(items: &[MiroBoardItem]) -> Digest {
    Digest::from_fields(
        "miro-board-item-set/v1",
        &items
            .iter()
            .map(|item| item.item_digest.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn canonical_redaction_digest(items: &[MiroBoardItem]) -> Digest {
    Digest::from_fields(
        "miro-redacted-decision-evidence/v1",
        &items
            .iter()
            .map(|item| {
                format!(
                    "{}:{}:{}",
                    item.id.as_str(),
                    item.redacted_text_digest
                        .as_ref()
                        .map_or("none", Digest::as_str),
                    item.redacted_external_link
                        .as_ref()
                        .map_or("none", RedactedExternalLink::as_str)
                )
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn canonical_result_digest(
    scope: &MiroDecisionScope,
    board: Option<&MiroBoardMetadata>,
    items: &[MiroBoardItem],
    projection: &str,
) -> Digest {
    Digest::from_fields(
        "miro-decision-result-evidence/v1",
        &[
            scope.scope_digest.as_str().to_owned(),
            board.map_or_else(
                || "none".to_owned(),
                |value| value.board_digest.as_str().to_owned(),
            ),
            canonical_item_set_digest(items).as_str().to_owned(),
            canonical_redaction_digest(items).as_str().to_owned(),
            projection.to_owned(),
        ],
    )
}

#[allow(dead_code)]
const _: (&str, &str, &str) = (
    MIRO_DECISION_RESULT_SERVICE_ID,
    MIRO_DECISION_RESULT_PROVIDER_ID,
    MIRO_DECISION_RESULT_CONSUMER_ID,
);

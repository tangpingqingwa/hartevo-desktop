use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_QUERY_BYTES: usize = 512;
pub const MAX_FILTER_BYTES: usize = 512;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_RESULTS: usize = 25;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 100;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_WORK_AUTHORS: usize = 1_000;
pub const MAX_WORK_INSTITUTIONS: usize = 1_000;
pub const MAX_WORK_CONCEPTS: usize = 1_000;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("OpenAlex typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is empty, malformed, or too long")]
    InvalidText { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("OpenAlex query is invalid")]
    InvalidQuery,
    #[error("OpenAlex filter is invalid")]
    InvalidFilter,
    #[error("OpenAlex cursor is invalid or exceeds the Layer-1 bound")]
    InvalidCursor,
    #[error("OpenAlex metadata permission is missing")]
    InvalidPermission,
    #[error("read consent is invalid")]
    InvalidConsent,
    #[error("OpenAlex scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("OpenAlex response is malformed or outside the bounded projection")]
    InvalidResponse,
    #[error("rate-limit receipt is outside the bounded range")]
    InvalidRateLimit,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/$".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidText { label });
    }
    Ok(())
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

fn validate_revision(value: u64, label: &'static str) -> Result<(), ModelError> {
    NonZeroU64::new(value)
        .map(|_| ())
        .ok_or(ModelError::InvalidRevision { label })
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "identifier")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: Identifier,
    revision: Revision,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAlexEntity {
    Work,
    Author,
    Institution,
    Concept,
}

impl OpenAlexEntity {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Work => "/works",
            Self::Author => "/authors",
            Self::Institution => "/institutions",
            Self::Concept => "/concepts",
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Author => "author",
            Self::Institution => "institution",
            Self::Concept => "concept",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAlexCitationDirection {
    Cites,
    CitedBy,
}

impl OpenAlexCitationDirection {
    #[must_use]
    pub const fn filter_name(self) -> &'static str {
        match self {
            Self::Cites => "cites",
            Self::CitedBy => "cited_by",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAlexOperation {
    List,
    Get,
    Cites,
    CitedBy,
}

impl OpenAlexOperation {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::List => "list_metadata",
            Self::Get => "get_metadata",
            Self::Cites => "citation_cites",
            Self::CitedBy => "citation_cited_by",
        }
    }

    #[must_use]
    pub const fn is_citation(self) -> bool {
        matches!(self, Self::Cites | Self::CitedBy)
    }
}

/// A query accepts raw selectors only long enough to hash them. Layer 1
/// retains the entity, operation, and digests, never the selector or filter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexQuery {
    entity: OpenAlexEntity,
    operation: OpenAlexOperation,
    selector_digest: Digest,
    filter_digest: Digest,
}

impl OpenAlexQuery {
    pub fn search(entity: OpenAlexEntity, selector: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::search_with_filter(entity, selector, "no-filter")
    }

    pub fn search_with_filter(
        entity: OpenAlexEntity,
        selector: impl AsRef<str>,
        filter: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let selector = selector.as_ref();
        let filter = filter.as_ref();
        validate_text(selector, MAX_QUERY_BYTES, "query")?;
        validate_text(filter, MAX_FILTER_BYTES, "filter")?;
        Ok(Self {
            entity,
            operation: OpenAlexOperation::List,
            selector_digest: sha256_digest(selector.as_bytes()),
            filter_digest: sha256_digest(filter.as_bytes()),
        })
    }

    pub fn get(entity: OpenAlexEntity, entity_id: impl AsRef<str>) -> Result<Self, ModelError> {
        let entity_id = entity_id.as_ref();
        validate_text(entity_id, MAX_IDENTIFIER_BYTES, "entity id")?;
        Ok(Self {
            entity,
            operation: OpenAlexOperation::Get,
            selector_digest: sha256_digest(entity_id.as_bytes()),
            filter_digest: sha256_digest(b"no-filter"),
        })
    }

    pub fn citations(
        direction: OpenAlexCitationDirection,
        work_id: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let work_id = work_id.as_ref();
        validate_text(work_id, MAX_IDENTIFIER_BYTES, "work id")?;
        Ok(Self {
            entity: OpenAlexEntity::Work,
            operation: match direction {
                OpenAlexCitationDirection::Cites => OpenAlexOperation::Cites,
                OpenAlexCitationDirection::CitedBy => OpenAlexOperation::CitedBy,
            },
            selector_digest: sha256_digest(work_id.as_bytes()),
            filter_digest: sha256_digest(direction.filter_name().as_bytes()),
        })
    }

    pub fn from_digests(
        entity: OpenAlexEntity,
        operation: OpenAlexOperation,
        selector_digest: impl Into<String>,
        filter_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let query = Self {
            entity,
            operation,
            selector_digest: selector_digest.into(),
            filter_digest: filter_digest.into(),
        };
        query.validate()?;
        Ok(query)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.selector_digest).map_err(|_| ModelError::InvalidQuery)?;
        validate_digest(&self.filter_digest).map_err(|_| ModelError::InvalidFilter)?;
        match self.operation {
            OpenAlexOperation::Get if self.filter_digest != sha256_digest(b"no-filter") => {
                return Err(ModelError::InvalidFilter);
            }
            OpenAlexOperation::Cites
                if self.entity != OpenAlexEntity::Work
                    || self.filter_digest != sha256_digest(b"cites") =>
            {
                return Err(ModelError::InvalidQuery);
            }
            OpenAlexOperation::CitedBy
                if self.entity != OpenAlexEntity::Work
                    || self.filter_digest != sha256_digest(b"cited_by") =>
            {
                return Err(ModelError::InvalidQuery);
            }
            _ => {}
        }
        Ok(())
    }

    #[must_use]
    pub const fn entity(&self) -> OpenAlexEntity {
        self.entity
    }

    #[must_use]
    pub const fn operation(&self) -> OpenAlexOperation {
        self.operation
    }

    #[must_use]
    pub fn selector_digest(&self) -> &str {
        &self.selector_digest
    }

    #[must_use]
    pub fn filter_digest(&self) -> &str {
        &self.filter_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    purpose_digest: Digest,
    revision: Revision,
}

impl ConsentScope {
    pub fn new(purpose: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        let purpose = purpose.as_ref();
        validate_text(purpose, MAX_QUERY_BYTES, "consent purpose")?;
        Ok(Self {
            purpose_digest: sha256_digest(purpose.as_bytes()),
            revision: Revision::new(revision)?,
        })
    }

    pub fn from_digest(
        purpose_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let consent = Self {
            purpose_digest: purpose_digest.into(),
            revision: Revision::new(revision)?,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.purpose_digest).map_err(|_| ModelError::InvalidConsent)
    }

    #[must_use]
    pub fn purpose_digest(&self) -> &str {
        &self.purpose_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexCursor {
    cursor_digest: Digest,
    query_digest: Digest,
    scope_revision: Revision,
}

impl OpenAlexCursor {
    pub fn new(
        cursor: impl AsRef<str>,
        query_digest: impl AsRef<str>,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let cursor = cursor.as_ref();
        validate_text(cursor, MAX_CURSOR_BYTES, "cursor")?;
        let query_digest = query_digest.as_ref();
        validate_digest(query_digest)?;
        Ok(Self {
            cursor_digest: sha256_digest(cursor.as_bytes()),
            query_digest: query_digest.to_owned(),
            scope_revision: Revision::new(scope_revision)?,
        })
    }

    pub fn for_scope(
        cursor: impl AsRef<str>,
        scope: &OpenAlexResearchScope,
    ) -> Result<Self, ModelError> {
        Self::new(cursor, scope.query().digest(), scope.revision().get())
    }

    pub fn for_query(
        cursor: impl AsRef<str>,
        query: &OpenAlexQuery,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(cursor, query.digest(), scope_revision)
    }

    pub fn from_digest(
        cursor_digest: impl Into<String>,
        query_digest: impl Into<String>,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let cursor = Self {
            cursor_digest: cursor_digest.into(),
            query_digest: query_digest.into(),
            scope_revision: Revision::new(scope_revision)?,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.cursor_digest)?;
        validate_digest(&self.query_digest)?;
        Ok(())
    }

    #[must_use]
    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    #[must_use]
    pub const fn scope_revision(&self) -> Revision {
        self.scope_revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexResearchScope {
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    query: OpenAlexQuery,
    page_size: u16,
    revision: Revision,
    cursor: Option<OpenAlexCursor>,
    consent: ConsentScope,
}

impl OpenAlexResearchScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        query: OpenAlexQuery,
        page_size: usize,
        revision: u64,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        Self::new_with_cursor(
            project,
            mission,
            work_product,
            query,
            page_size,
            revision,
            None,
            consent,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_cursor(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        query: OpenAlexQuery,
        page_size: usize,
        revision: u64,
        cursor: Option<OpenAlexCursor>,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        if !(1..=MAX_RESULTS).contains(&page_size) {
            return Err(ModelError::InvalidScope("page_size"));
        }
        query.validate()?;
        consent.validate()?;
        let scope_revision = Revision::new(revision)?;
        if let Some(cursor) = &cursor
            && (cursor.query_digest() != query.digest()
                || cursor.scope_revision() != scope_revision)
        {
            return Err(ModelError::InvalidScope("cursor binding"));
        }
        Ok(Self {
            project,
            mission,
            work_product,
            query,
            page_size: u16::try_from(page_size)
                .map_err(|_| ModelError::InvalidScope("page_size"))?,
            revision: scope_revision,
            cursor,
            consent,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        project: impl Into<String>,
        mission: impl Into<String>,
        work_product: impl Into<String>,
        query: OpenAlexQuery,
        page_size: usize,
        revision: u64,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            ProjectBinding::new(project, 1)?,
            MissionBinding::new(mission, 1)?,
            WorkProductBinding::new(work_product, 1)?,
            query,
            page_size,
            revision,
            consent,
        )
    }

    pub fn with_cursor(&self, cursor: OpenAlexCursor) -> Result<Self, ModelError> {
        Self::new_with_cursor(
            self.project.clone(),
            self.mission.clone(),
            self.work_product.clone(),
            self.query.clone(),
            self.page_size(),
            self.revision.get(),
            Some(cursor),
            self.consent.clone(),
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.query.validate()?;
        self.consent.validate()?;
        if !(1..=MAX_RESULTS).contains(&(self.page_size as usize)) {
            return Err(ModelError::InvalidScope("page_size"));
        }
        if let Some(cursor) = &self.cursor
            && (cursor.validate().is_err()
                || cursor.query_digest() != self.query.digest()
                || cursor.scope_revision() != self.revision)
        {
            return Err(ModelError::InvalidScope("cursor binding"));
        }
        Ok(())
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
    pub const fn query(&self) -> &OpenAlexQuery {
        &self.query
    }

    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size as usize
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<&OpenAlexCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub const fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexPermission {
    metadata_read: bool,
    permission_revision: Revision,
}

impl OpenAlexPermission {
    pub fn metadata_read(revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            metadata_read: true,
            permission_revision: Revision::new(revision)?,
        })
    }

    pub fn from_flags(metadata_read: bool, revision: u64) -> Result<Self, ModelError> {
        if !metadata_read {
            return Err(ModelError::InvalidPermission);
        }
        Self::metadata_read(revision)
    }

    #[must_use]
    pub const fn allows_metadata_read(&self) -> bool {
        self.metadata_read
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.permission_revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Opaque Layer-1 credential/configuration boundary. Only a digest, revision,
/// and revocation bit are retained; the supplied reference is never
/// serializable, formatted, or placed in a request or receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(reference: impl AsRef<str>) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        validate_text(reference, MAX_IDENTIFIER_BYTES, "secret reference")?;
        Ok(Self {
            reference_digest: sha256_digest(reference.as_bytes()),
            revision: Revision::new(1)?,
            revoked: false,
        })
    }

    pub fn from_digest(
        reference_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let secret = Self {
            reference_digest: reference_digest.into(),
            revision: Revision::new(revision)?,
            revoked: false,
        };
        validate_digest(&secret.reference_digest)?;
        Ok(secret)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &str {
        &self.reference_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(&self.reference_digest, self.revision))
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            return Err(ModelError::NotRevoked);
        }
        self.revoked = false;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

impl RegistrationState {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl OpenAlexRegistration {
    pub(crate) fn new(
        scope: &OpenAlexResearchScope,
        permission: &OpenAlexPermission,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::OPENALEX_RESEARCH_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent().digest(),
            secret_reference_digest: secret_reference.digest(),
            revision: 1,
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        registration.recompute_digest();
        registration
    }

    pub fn recompute_digest(&mut self) {
        self.registration_digest = canonical_digest(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.revision,
            self.state,
        ));
    }

    pub fn validate(
        &self,
        scope: &OpenAlexResearchScope,
        permission: &OpenAlexPermission,
        secret_reference: &SecretReference,
        provider_digest: &str,
    ) -> Result<(), ModelError> {
        if self.plugin_version != crate::OPENALEX_RESEARCH_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider_digest
            || self.permission_digest != permission.digest()
            || self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent().digest()
            || self.secret_reference_digest != secret_reference.digest()
            || self.registration_digest != {
                let mut expected = self.clone();
                expected.registration_digest.clear();
                expected.recompute_digest();
                expected.registration_digest
            }
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        if !self.state.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        if secret_reference.is_revoked() {
            return Err(ModelError::InvalidScope("secret reference revoked"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if !self.state.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ModelError::RevisionOverflow)?;
        self.recompute_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.state.is_active() {
            return Err(ModelError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ModelError::RevisionOverflow)?;
        self.recompute_digest();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitReceipt {
    pub limit_per_minute: Option<u16>,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl RateLimitReceipt {
    pub fn new(
        limit_per_minute: Option<u16>,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, ModelError> {
        if limit_per_minute.is_some_and(|value| value > MAX_REQUESTS_PER_MINUTE)
            || remaining.is_some_and(|value| value > MAX_REQUESTS_PER_MINUTE)
            || retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(ModelError::InvalidRateLimit);
        }
        Ok(Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
        })
    }

    #[must_use]
    pub fn throttled_for(retry_after_seconds: u32) -> Self {
        Self {
            limit_per_minute: Some(MAX_REQUESTS_PER_MINUTE),
            remaining: Some(0),
            retry_after_seconds: Some(retry_after_seconds.min(MAX_RETRY_AFTER_SECONDS)),
            throttled: true,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.limit_per_minute,
            self.remaining,
            self.retry_after_seconds,
            self.throttled,
        )
        .map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAlexEvidenceState {
    Complete,
    Partial,
    Empty,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    BlockedEnv,
    MalformedResponse,
    ResponseTooLarge,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexWorkProjection {
    pub id_digest: Digest,
    pub doi_digest: Option<Digest>,
    pub title_digest: Option<Digest>,
    pub work_type: Option<String>,
    pub publication_year: Option<u16>,
    pub cited_by_count: Option<u64>,
    pub reference_count: Option<u64>,
    pub author_count: u16,
    pub institution_count: u16,
    pub concept_count: u16,
    pub provider_reported_only: bool,
}

impl OpenAlexWorkProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn from_metadata(
        id: impl AsRef<str>,
        doi: Option<impl AsRef<str>>,
        title: Option<impl AsRef<str>>,
        work_type: Option<impl AsRef<str>>,
        publication_year: Option<u16>,
        cited_by_count: Option<u64>,
        reference_count: Option<u64>,
        author_count: usize,
        institution_count: usize,
        concept_count: usize,
    ) -> Result<Self, ModelError> {
        let id = id.as_ref();
        validate_text(id, MAX_IDENTIFIER_BYTES, "work id")?;
        if author_count > MAX_WORK_AUTHORS
            || institution_count > MAX_WORK_INSTITUTIONS
            || concept_count > MAX_WORK_CONCEPTS
        {
            return Err(ModelError::InvalidResponse);
        }
        let doi_digest = doi
            .map(|value| {
                let value = value.as_ref();
                validate_text(value, MAX_IDENTIFIER_BYTES, "doi")?;
                Ok(sha256_digest(value.to_ascii_lowercase().as_bytes()))
            })
            .transpose()?;
        let title_digest = title
            .map(|value| {
                let value = value.as_ref();
                validate_text(value, MAX_IDENTIFIER_BYTES * 2, "title")?;
                Ok(sha256_digest(value.as_bytes()))
            })
            .transpose()?;
        let work_type = work_type
            .map(|value| {
                let value = value.as_ref();
                validate_identifier(value, "work type")?;
                Ok(value.to_owned())
            })
            .transpose()?;
        Ok(Self {
            id_digest: sha256_digest(id.as_bytes()),
            doi_digest,
            title_digest,
            work_type,
            publication_year,
            cited_by_count,
            reference_count,
            author_count: u16::try_from(author_count).map_err(|_| ModelError::InvalidResponse)?,
            institution_count: u16::try_from(institution_count)
                .map_err(|_| ModelError::InvalidResponse)?,
            concept_count: u16::try_from(concept_count).map_err(|_| ModelError::InvalidResponse)?,
            provider_reported_only: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.id_digest)?;
        if let Some(value) = &self.doi_digest {
            validate_digest(value)?;
        }
        if let Some(value) = &self.title_digest {
            validate_digest(value)?;
        }
        if let Some(value) = &self.work_type {
            validate_identifier(value, "work type")?;
        }
        if self.author_count as usize > MAX_WORK_AUTHORS
            || self.institution_count as usize > MAX_WORK_INSTITUTIONS
            || self.concept_count as usize > MAX_WORK_CONCEPTS
            || !self.provider_reported_only
        {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexAuthorProjection {
    pub id_digest: Digest,
    pub display_name_digest: Option<Digest>,
    pub works_count: Option<u64>,
    pub cited_by_count: Option<u64>,
    pub affiliation_count: u16,
    pub provider_reported_only: bool,
}

impl OpenAlexAuthorProjection {
    pub fn from_metadata(
        id: impl AsRef<str>,
        display_name: Option<impl AsRef<str>>,
        works_count: Option<u64>,
        cited_by_count: Option<u64>,
        affiliation_count: usize,
    ) -> Result<Self, ModelError> {
        if affiliation_count > MAX_WORK_INSTITUTIONS {
            return Err(ModelError::InvalidResponse);
        }
        Ok(Self {
            id_digest: digest_text(id.as_ref(), MAX_IDENTIFIER_BYTES, "author id")?,
            display_name_digest: digest_optional_text(
                display_name,
                MAX_IDENTIFIER_BYTES * 2,
                "author display name",
            )?,
            works_count,
            cited_by_count,
            affiliation_count: u16::try_from(affiliation_count)
                .map_err(|_| ModelError::InvalidResponse)?,
            provider_reported_only: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.id_digest)?;
        if let Some(value) = &self.display_name_digest {
            validate_digest(value)?;
        }
        if self.affiliation_count as usize > MAX_WORK_INSTITUTIONS || !self.provider_reported_only {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexInstitutionProjection {
    pub id_digest: Digest,
    pub display_name_digest: Option<Digest>,
    pub ror_digest: Option<Digest>,
    pub country_code_digest: Option<Digest>,
    pub works_count: Option<u64>,
    pub cited_by_count: Option<u64>,
    pub provider_reported_only: bool,
}

impl OpenAlexInstitutionProjection {
    pub fn from_metadata(
        id: impl AsRef<str>,
        display_name: Option<impl AsRef<str>>,
        ror: Option<impl AsRef<str>>,
        country_code: Option<impl AsRef<str>>,
        works_count: Option<u64>,
        cited_by_count: Option<u64>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            id_digest: digest_text(id.as_ref(), MAX_IDENTIFIER_BYTES, "institution id")?,
            display_name_digest: digest_optional_text(
                display_name,
                MAX_IDENTIFIER_BYTES * 2,
                "institution display name",
            )?,
            ror_digest: digest_optional_text(ror, MAX_IDENTIFIER_BYTES, "ror")?,
            country_code_digest: digest_optional_text(
                country_code,
                MAX_IDENTIFIER_BYTES,
                "country code",
            )?,
            works_count,
            cited_by_count,
            provider_reported_only: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.id_digest)?;
        for value in [
            self.display_name_digest.as_ref(),
            self.ror_digest.as_ref(),
            self.country_code_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(value)?;
        }
        if !self.provider_reported_only {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexConceptProjection {
    pub id_digest: Digest,
    pub display_name_digest: Option<Digest>,
    pub works_count: Option<u64>,
    pub cited_by_count: Option<u64>,
    pub level: Option<u16>,
    pub provider_reported_only: bool,
}

impl OpenAlexConceptProjection {
    pub fn from_metadata(
        id: impl AsRef<str>,
        display_name: Option<impl AsRef<str>>,
        works_count: Option<u64>,
        cited_by_count: Option<u64>,
        level: Option<u16>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            id_digest: digest_text(id.as_ref(), MAX_IDENTIFIER_BYTES, "concept id")?,
            display_name_digest: digest_optional_text(
                display_name,
                MAX_IDENTIFIER_BYTES * 2,
                "concept display name",
            )?,
            works_count,
            cited_by_count,
            level,
            provider_reported_only: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.id_digest)?;
        if let Some(value) = &self.display_name_digest {
            validate_digest(value)?;
        }
        if !self.provider_reported_only {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexCitationProjection {
    pub citing_work_digest: Digest,
    pub cited_work_digest: Digest,
    pub provider_reported_only: bool,
}

impl OpenAlexCitationProjection {
    pub fn new(
        citing_work_id: impl AsRef<str>,
        cited_work_id: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            citing_work_digest: digest_text(
                citing_work_id.as_ref(),
                MAX_IDENTIFIER_BYTES,
                "citing work id",
            )?,
            cited_work_digest: digest_text(
                cited_work_id.as_ref(),
                MAX_IDENTIFIER_BYTES,
                "cited work id",
            )?,
            provider_reported_only: true,
        })
    }

    pub fn from_digests(
        citing_work_digest: impl Into<String>,
        cited_work_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let citation = Self {
            citing_work_digest: citing_work_digest.into(),
            cited_work_digest: cited_work_digest.into(),
            provider_reported_only: true,
        };
        citation.validate()?;
        Ok(citation)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.citing_work_digest)?;
        validate_digest(&self.cited_work_digest)?;
        if !self.provider_reported_only {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

fn digest_text(value: &str, max_bytes: usize, label: &'static str) -> Result<Digest, ModelError> {
    validate_text(value, max_bytes, label)?;
    Ok(sha256_digest(value.as_bytes()))
}

fn digest_optional_text<T: AsRef<str>>(
    value: Option<T>,
    max_bytes: usize,
    label: &'static str,
) -> Result<Option<Digest>, ModelError> {
    value
        .map(|value| digest_text(value.as_ref(), max_bytes, label))
        .transpose()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OpenAlexHttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexReadReceipt {
    pub status: u16,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub rate_limit_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
}

impl OpenAlexReadReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexResearchEvidence {
    pub entity: OpenAlexEntity,
    pub operation: OpenAlexOperation,
    pub query_digest: Digest,
    pub filter_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub response_digest: Digest,
    pub idempotency_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub next_cursor: Option<OpenAlexCursor>,
    pub state: OpenAlexEvidenceState,
    pub total_results: Option<u64>,
    pub returned_results: usize,
    pub works: Vec<OpenAlexWorkProjection>,
    pub authors: Vec<OpenAlexAuthorProjection>,
    pub institutions: Vec<OpenAlexInstitutionProjection>,
    pub concepts: Vec<OpenAlexConceptProjection>,
    pub citations: Vec<OpenAlexCitationProjection>,
    pub partial_reason: Option<String>,
    pub rate_limit: RateLimitReceipt,
    pub read_receipt: OpenAlexReadReceipt,
    pub evidence_digest: Digest,
}

impl OpenAlexResearchEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "entity": self.entity,
            "operation": self.operation,
            "queryDigest": self.query_digest,
            "filterDigest": self.filter_digest,
            "scopeDigest": self.scope_digest,
            "consentDigest": self.consent_digest,
            "providerDigest": self.provider_digest,
            "registrationDigest": self.registration_digest,
            "responseDigest": self.response_digest,
            "idempotencyDigest": self.idempotency_digest,
            "cursorDigest": self.cursor_digest,
            "nextCursor": self.next_cursor,
            "state": self.state,
            "totalResults": self.total_results,
            "returnedResults": self.returned_results,
            "works": self.works,
            "authors": self.authors,
            "institutions": self.institutions,
            "concepts": self.concepts,
            "citations": self.citations,
            "partialReason": self.partial_reason,
            "rateLimit": self.rate_limit,
            "readReceipt": self.read_receipt,
        }))
    }

    #[must_use]
    pub fn entity_digests(&self) -> Vec<Digest> {
        match self.entity {
            OpenAlexEntity::Work => self
                .works
                .iter()
                .map(OpenAlexWorkProjection::digest)
                .collect(),
            OpenAlexEntity::Author => self
                .authors
                .iter()
                .map(OpenAlexAuthorProjection::digest)
                .collect(),
            OpenAlexEntity::Institution => self
                .institutions
                .iter()
                .map(OpenAlexInstitutionProjection::digest)
                .collect(),
            OpenAlexEntity::Concept => self
                .concepts
                .iter()
                .map(OpenAlexConceptProjection::digest)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewProviderMetadata,
    ReviewPartialMetadata,
    NoMetadata,
    RetryAfterRateLimit,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexResearchProposal {
    pub scope: OpenAlexResearchScope,
    pub evidence: OpenAlexResearchEvidence,
    pub source_evidence_digest: Digest,
    pub idempotency_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub ranking_claim: bool,
    pub full_text: bool,
    pub author_identity_claim: bool,
    pub citation_truth_claim: bool,
    pub research_truth_claim: bool,
    pub recommendation: RecommendationDisposition,
    pub proposal_digest: Digest,
}

impl OpenAlexResearchProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "scope": self.scope,
            "evidence": self.evidence,
            "sourceEvidenceDigest": self.source_evidence_digest,
            "idempotencyDigest": self.idempotency_digest,
            "registrationDigest": self.registration_digest,
            "providerDigest": self.provider_digest,
            "permissionDigest": self.permission_digest,
            "contractDigest": self.contract_digest,
            "proposalOnly": self.proposal_only,
            "native": self.native,
            "connected": self.connected,
            "adoptsOutcome": self.adopts_outcome,
            "adoptsWorkProduct": self.adopts_work_product,
            "rankingClaim": self.ranking_claim,
            "fullText": self.full_text,
            "authorIdentityClaim": self.author_identity_claim,
            "citationTruthClaim": self.citation_truth_claim,
            "researchTruthClaim": self.research_truth_claim,
            "recommendation": self.recommendation,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub response_digest: Digest,
    pub state: OpenAlexEvidenceState,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub durable_native_receipt: bool,
    pub receipt_digest: Digest,
}

impl OpenAlexObservationReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.proposal_digest,
            &self.evidence_digest,
            &self.idempotency_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.response_digest,
            self.state,
            self.provenance,
            self.connected,
            self.native,
            self.durable_native_receipt,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionReceipt {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub registration_digest: Digest,
    pub revision: u64,
    pub reversible: bool,
    pub transition_digest: Digest,
}

impl RegistrationTransitionReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.from,
            self.to,
            &self.registration_digest,
            self.revision,
            self.reversible,
        ))
    }
}

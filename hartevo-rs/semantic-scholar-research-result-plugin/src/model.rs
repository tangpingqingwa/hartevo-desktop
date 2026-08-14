use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SEMANTIC_SCHOLAR_API_HOST, SEMANTIC_SCHOLAR_API_VERSION, SEMANTIC_SCHOLAR_CONTRACT_VERSION,
    SEMANTIC_SCHOLAR_PLUGIN_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_QUERY_BYTES: usize = 4 * 1024;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 16;
pub const MAX_RECORDS: usize = 1_000;
pub const MAX_CITATIONS_OR_REFERENCES: usize = 500;
pub const MAX_AUTHORS_PER_PAPER: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_CURSOR_BYTES: usize = 2 * 1024;
pub const MAX_TITLE_BYTES: usize = 1024;
pub const MAX_VENUE_BYTES: usize = 512;
pub const MAX_SCOPE_IDS: usize = 1_000;
pub const MAX_RETRIES: u8 = 3;
pub const MAX_BACKOFF_SECONDS: u32 = 60;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, contains unsafe control data, or is too long")]
    InvalidText { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("Semantic Scholar API host must be the HTTPS Academic Graph origin")]
    InvalidApiHost,
    #[error("Semantic Scholar API version is not supported")]
    InvalidApiVersion,
    #[error("the consent scope is empty or exceeds the Layer-1 bound")]
    InvalidConsentScope,
    #[error("the Semantic Scholar Project/Mission/Work Product scope is invalid")]
    InvalidScope,
    #[error("the opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("the query is invalid: {reason}")]
    InvalidQuery { reason: &'static str },
    #[error("the requested field set is empty, duplicated, or not allowlisted")]
    InvalidFieldSelection,
    #[error("the page or cursor is invalid")]
    InvalidPage,
    #[error("the bounded value {field} exceeded {maximum}")]
    BoundExceeded { field: &'static str, maximum: usize },
    #[error("the redacted Semantic Scholar metadata is invalid")]
    InvalidMetadata,
    #[error("a redacted metadata digest does not match its fields")]
    DigestMismatch,
    #[error("the registration is invalid")]
    InvalidRegistration,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
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

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Self, ModelError> {
        serde_json::to_vec(value)
            .map(|bytes| Self::from_bytes(&bytes))
            .map_err(|_| ModelError::DigestMismatch)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_sha256(self.as_str())
    }

    #[must_use]
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

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.starts_with('.')
        || value.ends_with('.')
        || value.chars().any(char::is_control)
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@' | b'%')
        })
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), ModelError> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
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
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identifier!(ProjectId, "project_id");
bounded_identifier!(MissionId, "mission_id");
bounded_identifier!(WorkProductId, "work_product_id");
bounded_identifier!(PaperId, "paper_id");
bounded_identifier!(AuthorId, "author_id");
bounded_identifier!(VenueId, "venue_id");

impl PaperId {
    pub fn from_api_identifier(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.starts_with("http://")
            || value.starts_with("https://")
            || value.starts_with("URL:")
        {
            return Err(ModelError::InvalidIdentifier { field: "paper_id" });
        }
        Self::new(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BoundedText(String);

impl BoundedText {
    pub fn new(value: impl Into<String>, maximum: usize) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "bounded_text", maximum)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct QueryText(String);

impl QueryText {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "query", MAX_QUERY_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let parts: Vec<_> = value.split('.').collect();
        let [major, minor, patch] = parts.as_slice() else {
            return Err(ModelError::InvalidRegistration);
        };
        Ok(Self {
            major: major.parse().map_err(|_| ModelError::InvalidRegistration)?,
            minor: minor.parse().map_err(|_| ModelError::InvalidRegistration)?,
            patch: patch.parse().map_err(|_| ModelError::InvalidRegistration)?,
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiHost {
    SemanticScholar,
}

impl ApiHost {
    pub fn new(value: &str) -> Result<Self, ModelError> {
        let host = value.strip_prefix("https://").unwrap_or(value);
        if host == SEMANTIC_SCHOLAR_API_HOST {
            Ok(Self::SemanticScholar)
        } else {
            Err(ModelError::InvalidApiHost)
        }
    }

    #[must_use]
    pub const fn origin(self) -> &'static str {
        match self {
            Self::SemanticScholar => "https://api.semanticscholar.org",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiVersion {
    V1,
}

impl ApiVersion {
    pub fn new(value: &str) -> Result<Self, ModelError> {
        if value == SEMANTIC_SCHOLAR_API_VERSION {
            Ok(Self::V1)
        } else {
            Err(ModelError::InvalidApiVersion)
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyPermission {
    AnonymousAcademicGraphRead,
    AcademicGraphReadKey,
    AcademicGraphAndRecommendationsReadKey,
}

impl ApiKeyPermission {
    #[must_use]
    pub const fn allows_recommendations(self) -> bool {
        matches!(self, Self::AcademicGraphAndRecommendationsReadKey)
    }

    #[must_use]
    pub const fn uses_api_key(self) -> bool {
        !matches!(self, Self::AnonymousAcademicGraphRead)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDataClass {
    PaperMetadata,
    AuthorMetadata,
    VenueMetadata,
    CitationMetadata,
    RecommendationMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
    data_classes: BTreeSet<ConsentDataClass>,
}

impl ConsentScope {
    pub fn new(
        consent_digest: Digest,
        revision: Revision,
        data_classes: impl IntoIterator<Item = ConsentDataClass>,
    ) -> Result<Self, ModelError> {
        if !consent_digest.is_valid() {
            return Err(ModelError::InvalidConsentScope);
        }
        let data_classes = data_classes.into_iter().collect::<BTreeSet<_>>();
        if data_classes.is_empty() || data_classes.len() > 8 {
            return Err(ModelError::InvalidConsentScope);
        }
        Ok(Self {
            consent_digest,
            revision,
            data_classes,
        })
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn data_classes(&self) -> &BTreeSet<ConsentDataClass> {
        &self.data_classes
    }

    #[must_use]
    pub fn allows(&self, class: ConsentDataClass) -> bool {
        self.data_classes.contains(&class)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarScopeInput {
    pub api_host: ApiHost,
    pub api_version: ApiVersion,
    pub api_key_permission: ApiKeyPermission,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub consent: ConsentScope,
    #[serde(default)]
    pub paper_ids: BTreeSet<PaperId>,
    #[serde(default)]
    pub author_ids: BTreeSet<AuthorId>,
    #[serde(default)]
    pub venue_ids: BTreeSet<VenueId>,
    pub permission_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarScope {
    api_host: ApiHost,
    api_version: ApiVersion,
    api_key_permission: ApiKeyPermission,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    consent: ConsentScope,
    paper_ids: BTreeSet<PaperId>,
    author_ids: BTreeSet<AuthorId>,
    venue_ids: BTreeSet<VenueId>,
    permission_digest: Digest,
    paper_scope_digest: Digest,
    author_scope_digest: Digest,
    venue_scope_digest: Digest,
    scope_digest: Digest,
}

impl SemanticScholarScope {
    pub fn new(input: SemanticScholarScopeInput) -> Result<Self, ModelError> {
        if input.api_host != ApiHost::SemanticScholar
            || input.api_version != ApiVersion::V1
            || !input.permission_digest.is_valid()
            || input.paper_ids.len() > MAX_SCOPE_IDS
            || input.author_ids.len() > MAX_SCOPE_IDS
            || input.venue_ids.len() > MAX_SCOPE_IDS
            || !input.consent.allows(ConsentDataClass::PaperMetadata)
        {
            return Err(ModelError::InvalidScope);
        }
        let paper_scope_digest = Digest::from_serializable(&input.paper_ids)?;
        let author_scope_digest = Digest::from_serializable(&input.author_ids)?;
        let venue_scope_digest = Digest::from_serializable(&input.venue_ids)?;
        let scope_identity = ScopeIdentity {
            api_host: input.api_host,
            api_version: input.api_version,
            api_key_permission: input.api_key_permission,
            project_id: input.project_id.clone(),
            project_revision: input.project_revision,
            mission_id: input.mission_id.clone(),
            mission_revision: input.mission_revision,
            work_product_id: input.work_product_id.clone(),
            work_product_revision: input.work_product_revision,
            consent: input.consent.clone(),
            paper_scope_digest: paper_scope_digest.clone(),
            author_scope_digest: author_scope_digest.clone(),
            venue_scope_digest: venue_scope_digest.clone(),
            permission_digest: input.permission_digest.clone(),
        };
        let scope_digest = Digest::from_serializable(&scope_identity)?;
        Ok(Self {
            api_host: input.api_host,
            api_version: input.api_version,
            api_key_permission: input.api_key_permission,
            project_id: input.project_id,
            project_revision: input.project_revision,
            mission_id: input.mission_id,
            mission_revision: input.mission_revision,
            work_product_id: input.work_product_id,
            work_product_revision: input.work_product_revision,
            consent: input.consent,
            paper_ids: input.paper_ids,
            author_ids: input.author_ids,
            venue_ids: input.venue_ids,
            permission_digest: input.permission_digest,
            paper_scope_digest,
            author_scope_digest,
            venue_scope_digest,
            scope_digest,
        })
    }

    #[must_use]
    pub const fn api_host(&self) -> ApiHost {
        self.api_host
    }

    #[must_use]
    pub const fn api_version(&self) -> ApiVersion {
        self.api_version
    }

    #[must_use]
    pub const fn api_key_permission(&self) -> ApiKeyPermission {
        self.api_key_permission
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    #[must_use]
    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    #[must_use]
    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    #[must_use]
    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn paper_ids(&self) -> &BTreeSet<PaperId> {
        &self.paper_ids
    }

    #[must_use]
    pub fn author_ids(&self) -> &BTreeSet<AuthorId> {
        &self.author_ids
    }

    #[must_use]
    pub fn venue_ids(&self) -> &BTreeSet<VenueId> {
        &self.venue_ids
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn paper_scope_digest(&self) -> &Digest {
        &self.paper_scope_digest
    }

    #[must_use]
    pub fn author_scope_digest(&self) -> &Digest {
        &self.author_scope_digest
    }

    #[must_use]
    pub fn venue_scope_digest(&self) -> &Digest {
        &self.venue_scope_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn allows_paper(&self, paper_id: &PaperId) -> bool {
        self.paper_ids.is_empty() || self.paper_ids.contains(paper_id)
    }

    #[must_use]
    pub fn allows_author(&self, author_id: &AuthorId) -> bool {
        self.author_ids.is_empty() || self.author_ids.contains(author_id)
    }

    #[must_use]
    pub fn allows_venue(&self, venue_id: Option<&VenueId>) -> bool {
        self.venue_ids.is_empty() || venue_id.is_some_and(|id| self.venue_ids.contains(id))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeIdentity {
    api_host: ApiHost,
    api_version: ApiVersion,
    api_key_permission: ApiKeyPermission,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    consent: ConsentScope,
    paper_scope_digest: Digest,
    author_scope_digest: Digest,
    venue_scope_digest: Digest,
    permission_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
    Anonymous,
}

/// Opaque host/keyring reference. The supplied identifier is only digested;
/// it is never serialised, displayed, or included in a request/result receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    permission: ApiKeyPermission,
    kind: SecretKind,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl Into<String>,
        scope: &SemanticScholarScope,
        credential_revision: u64,
        permission: ApiKeyPermission,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.into();
        if opaque_reference.trim().is_empty()
            || opaque_reference.trim() != opaque_reference
            || opaque_reference.len() > MAX_IDENTIFIER_BYTES
            || opaque_reference.chars().any(char::is_control)
            || permission != scope.api_key_permission()
        {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let kind = if permission.uses_api_key() {
            SecretKind::ApiKey
        } else {
            SecretKind::Anonymous
        };
        let reference_digest = Digest::from_fields(
            "semantic-scholar-secret-reference/v1",
            &[
                opaque_reference,
                scope.scope_digest().as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{permission:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            permission,
            kind,
            revoked: false,
        })
    }

    pub fn anonymous(scope: &SemanticScholarScope) -> Result<Self, ModelError> {
        Self::new(
            "anonymous",
            scope,
            1,
            ApiKeyPermission::AnonymousAcademicGraphRead,
        )
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
    pub const fn permission(&self) -> ApiKeyPermission {
        self.permission
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
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

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("permission", &self.permission)
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeField {
    PaperId,
    CorpusId,
    Title,
    Year,
    PublicationDate,
    Venue,
    PublicationVenue,
    Authors,
    CitationCount,
    ReferenceCount,
    InfluentialCitationCount,
    IsInfluential,
    AuthorId,
    Name,
    PaperCount,
    HIndex,
}

impl SafeField {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::PaperId => "paperId",
            Self::CorpusId => "corpusId",
            Self::Title => "title",
            Self::Year => "year",
            Self::PublicationDate => "publicationDate",
            Self::Venue => "venue",
            Self::PublicationVenue => "publicationVenue",
            Self::Authors => "authors",
            Self::CitationCount => "citationCount",
            Self::ReferenceCount => "referenceCount",
            Self::InfluentialCitationCount => "influentialCitationCount",
            Self::IsInfluential => "isInfluential",
            Self::AuthorId => "authorId",
            Self::Name => "name",
            Self::PaperCount => "paperCount",
            Self::HIndex => "hIndex",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldSelection {
    fields: BTreeSet<SafeField>,
}

impl FieldSelection {
    pub fn new(fields: impl IntoIterator<Item = SafeField>) -> Result<Self, ModelError> {
        let fields = fields.into_iter().collect::<BTreeSet<_>>();
        if fields.is_empty() || fields.len() > 32 {
            return Err(ModelError::InvalidFieldSelection);
        }
        Ok(Self { fields })
    }

    #[must_use]
    pub fn paper_metadata() -> Self {
        Self::new([
            SafeField::PaperId,
            SafeField::CorpusId,
            SafeField::Title,
            SafeField::Year,
            SafeField::PublicationDate,
            SafeField::Venue,
            SafeField::PublicationVenue,
            SafeField::Authors,
            SafeField::CitationCount,
            SafeField::ReferenceCount,
            SafeField::InfluentialCitationCount,
        ])
        .expect("static safe paper fields")
    }

    #[must_use]
    pub fn author_metadata() -> Self {
        Self::new([
            SafeField::AuthorId,
            SafeField::Name,
            SafeField::PaperCount,
            SafeField::CitationCount,
            SafeField::HIndex,
        ])
        .expect("static safe author fields")
    }

    #[must_use]
    pub fn citation_metadata() -> Self {
        Self::new([
            SafeField::PaperId,
            SafeField::CorpusId,
            SafeField::Title,
            SafeField::Year,
            SafeField::Venue,
            SafeField::Authors,
            SafeField::IsInfluential,
        ])
        .expect("static safe citation fields")
    }

    #[must_use]
    pub fn recommendation_metadata() -> Self {
        Self::new([
            SafeField::PaperId,
            SafeField::CorpusId,
            SafeField::Title,
            SafeField::Year,
            SafeField::Venue,
            SafeField::PublicationVenue,
            SafeField::Authors,
        ])
        .expect("static safe recommendation fields")
    }

    #[must_use]
    pub fn fields(&self) -> &BTreeSet<SafeField> {
        &self.fields
    }

    #[must_use]
    pub fn as_api_parameter(&self) -> String {
        self.fields
            .iter()
            .map(|field| field.clone().api_name())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidPage);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque-cursor>")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageRequest {
    limit: u16,
    offset: u32,
    cursor: Option<OpaqueCursor>,
}

impl PageRequest {
    pub fn new(limit: u16, offset: u32, cursor: Option<OpaqueCursor>) -> Result<Self, ModelError> {
        if limit == 0 || limit > MAX_PAGE_SIZE || (offset > 0 && cursor.is_some()) {
            return Err(ModelError::InvalidPage);
        }
        Ok(Self {
            limit,
            offset,
            cursor,
        })
    }

    pub fn first(limit: u16) -> Result<Self, ModelError> {
        Self::new(limit, 0, None)
    }

    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_seconds: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_RETRIES,
            max_backoff_seconds: MAX_BACKOFF_SECONDS,
        }
    }
}

impl RetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_seconds: u32) -> Result<Self, ModelError> {
        if max_attempts == 0
            || max_attempts > MAX_RETRIES
            || max_backoff_seconds > MAX_BACKOFF_SECONDS
        {
            return Err(ModelError::InvalidQuery {
                reason: "retry policy exceeds the Layer-1 bound",
            });
        }
        Ok(Self {
            max_attempts,
            max_backoff_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationPool {
    Recent,
    AllComputerScience,
}

impl RecommendationPool {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Recent => "recent",
            Self::AllComputerScience => "all-cs",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    PaperSearch,
    PaperBulkSearch,
    PaperDetails,
    PaperAuthors,
    PaperCitations,
    PaperReferences,
    AuthorSearch,
    AuthorDetails,
    AuthorPapers,
    VenueMetadata,
    Recommendations,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    PaperSearch,
    PaperBulkSearch,
    PaperDetails,
    PaperAuthors,
    PaperCitations,
    PaperReferences,
    AuthorSearch,
    AuthorDetails,
    AuthorPapers,
    Recommendations,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResearchQuery {
    PaperSearch {
        query: QueryText,
        page: PageRequest,
        fields: FieldSelection,
    },
    PaperBulkSearch {
        query: QueryText,
        page: PageRequest,
        fields: FieldSelection,
    },
    PaperDetails {
        paper_id: PaperId,
        fields: FieldSelection,
    },
    PaperAuthors {
        paper_id: PaperId,
        page: PageRequest,
        fields: FieldSelection,
    },
    PaperCitations {
        paper_id: PaperId,
        page: PageRequest,
        fields: FieldSelection,
    },
    PaperReferences {
        paper_id: PaperId,
        page: PageRequest,
        fields: FieldSelection,
    },
    AuthorSearch {
        query: QueryText,
        page: PageRequest,
        fields: FieldSelection,
    },
    AuthorDetails {
        author_id: AuthorId,
        fields: FieldSelection,
    },
    AuthorPapers {
        author_id: AuthorId,
        page: PageRequest,
        fields: FieldSelection,
    },
    VenueMetadata {
        paper_id: PaperId,
        fields: FieldSelection,
    },
    Recommendations {
        paper_id: PaperId,
        page: PageRequest,
        pool: RecommendationPool,
        fields: FieldSelection,
    },
}

impl ResearchQuery {
    pub fn validate(&self, scope: &SemanticScholarScope) -> Result<(), ModelError> {
        let (kind, fields) = match self {
            Self::PaperSearch { fields, .. } => (QueryKind::PaperSearch, fields),
            Self::PaperBulkSearch { fields, .. } => (QueryKind::PaperBulkSearch, fields),
            Self::PaperDetails { paper_id, fields } | Self::VenueMetadata { paper_id, fields } => {
                if !scope.allows_paper(paper_id) {
                    return Err(ModelError::InvalidQuery {
                        reason: "paper is outside the registered paper scope",
                    });
                }
                let kind = if matches!(self, Self::VenueMetadata { .. }) {
                    QueryKind::VenueMetadata
                } else {
                    QueryKind::PaperDetails
                };
                (kind, fields)
            }
            Self::PaperAuthors {
                paper_id, fields, ..
            }
            | Self::PaperCitations {
                paper_id, fields, ..
            }
            | Self::PaperReferences {
                paper_id, fields, ..
            } => {
                if !scope.allows_paper(paper_id) {
                    return Err(ModelError::InvalidQuery {
                        reason: "paper is outside the registered paper scope",
                    });
                }
                let kind = match self {
                    Self::PaperAuthors { .. } => QueryKind::PaperAuthors,
                    Self::PaperCitations { .. } => QueryKind::PaperCitations,
                    Self::PaperReferences { .. } => QueryKind::PaperReferences,
                    _ => unreachable!("matched paper graph query"),
                };
                (kind, fields)
            }
            Self::AuthorSearch { fields, .. } => (QueryKind::AuthorSearch, fields),
            Self::AuthorDetails { author_id, fields } => {
                if !scope.allows_author(author_id) {
                    return Err(ModelError::InvalidQuery {
                        reason: "author is outside the registered author scope",
                    });
                }
                (QueryKind::AuthorDetails, fields)
            }
            Self::AuthorPapers {
                author_id, fields, ..
            } => {
                if !scope.allows_author(author_id) {
                    return Err(ModelError::InvalidQuery {
                        reason: "author is outside the registered author scope",
                    });
                }
                (QueryKind::AuthorPapers, fields)
            }
            Self::Recommendations {
                paper_id, fields, ..
            } => {
                if !scope.allows_paper(paper_id) {
                    return Err(ModelError::InvalidQuery {
                        reason: "recommendation paper is outside the registered paper scope",
                    });
                }
                if !scope.api_key_permission().allows_recommendations() {
                    return Err(ModelError::InvalidQuery {
                        reason: "recommendations require the explicitly registered permission",
                    });
                }
                (QueryKind::Recommendations, fields)
            }
        };
        if fields.fields.is_empty() {
            return Err(ModelError::InvalidFieldSelection);
        }
        if matches!(kind, QueryKind::PaperCitations | QueryKind::PaperReferences)
            && fields.fields.contains(&SafeField::IsInfluential)
        {
            return Ok(());
        }
        Ok(())
    }

    #[must_use]
    pub const fn kind(&self) -> QueryKind {
        match self {
            Self::PaperSearch { .. } => QueryKind::PaperSearch,
            Self::PaperBulkSearch { .. } => QueryKind::PaperBulkSearch,
            Self::PaperDetails { .. } => QueryKind::PaperDetails,
            Self::PaperAuthors { .. } => QueryKind::PaperAuthors,
            Self::PaperCitations { .. } => QueryKind::PaperCitations,
            Self::PaperReferences { .. } => QueryKind::PaperReferences,
            Self::AuthorSearch { .. } => QueryKind::AuthorSearch,
            Self::AuthorDetails { .. } => QueryKind::AuthorDetails,
            Self::AuthorPapers { .. } => QueryKind::AuthorPapers,
            Self::VenueMetadata { .. } => QueryKind::VenueMetadata,
            Self::Recommendations { .. } => QueryKind::Recommendations,
        }
    }

    #[must_use]
    pub const fn endpoint_kind(&self) -> EndpointKind {
        match self {
            Self::PaperSearch { .. } => EndpointKind::PaperSearch,
            Self::PaperBulkSearch { .. } => EndpointKind::PaperBulkSearch,
            Self::PaperDetails { .. } | Self::VenueMetadata { .. } => EndpointKind::PaperDetails,
            Self::PaperAuthors { .. } => EndpointKind::PaperAuthors,
            Self::PaperCitations { .. } => EndpointKind::PaperCitations,
            Self::PaperReferences { .. } => EndpointKind::PaperReferences,
            Self::AuthorSearch { .. } => EndpointKind::AuthorSearch,
            Self::AuthorDetails { .. } => EndpointKind::AuthorDetails,
            Self::AuthorPapers { .. } => EndpointKind::AuthorPapers,
            Self::Recommendations { .. } => EndpointKind::Recommendations,
        }
    }

    pub fn digest(&self) -> Result<Digest, ModelError> {
        Digest::from_serializable(self)
    }

    pub fn logical_digest(&self) -> Result<Digest, ModelError> {
        let normalized_page =
            |page: &PageRequest| PageRequest::new(page.limit(), page.offset(), None);
        let normalized = match self {
            Self::PaperSearch {
                query,
                page,
                fields,
            } => Self::PaperSearch {
                query: query.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::PaperBulkSearch {
                query,
                page,
                fields,
            } => Self::PaperBulkSearch {
                query: query.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::PaperAuthors {
                paper_id,
                page,
                fields,
            } => Self::PaperAuthors {
                paper_id: paper_id.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::PaperCitations {
                paper_id,
                page,
                fields,
            } => Self::PaperCitations {
                paper_id: paper_id.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::PaperReferences {
                paper_id,
                page,
                fields,
            } => Self::PaperReferences {
                paper_id: paper_id.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::AuthorSearch {
                query,
                page,
                fields,
            } => Self::AuthorSearch {
                query: query.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::AuthorPapers {
                author_id,
                page,
                fields,
            } => Self::AuthorPapers {
                author_id: author_id.clone(),
                page: normalized_page(page)?,
                fields: fields.clone(),
            },
            Self::Recommendations {
                paper_id,
                page,
                pool,
                fields,
            } => Self::Recommendations {
                paper_id: paper_id.clone(),
                page: normalized_page(page)?,
                pool: *pool,
                fields: fields.clone(),
            },
            Self::PaperDetails { .. } | Self::AuthorDetails { .. } | Self::VenueMetadata { .. } => {
                self.clone()
            }
        };
        Digest::from_serializable(&normalized)
    }

    #[must_use]
    pub const fn page(&self) -> Option<&PageRequest> {
        match self {
            Self::PaperSearch { page, .. }
            | Self::PaperBulkSearch { page, .. }
            | Self::PaperAuthors { page, .. }
            | Self::PaperCitations { page, .. }
            | Self::PaperReferences { page, .. }
            | Self::AuthorSearch { page, .. }
            | Self::AuthorPapers { page, .. }
            | Self::Recommendations { page, .. } => Some(page),
            Self::PaperDetails { .. } | Self::AuthorDetails { .. } | Self::VenueMetadata { .. } => {
                None
            }
        }
    }

    #[must_use]
    pub fn query_revision(&self) -> Revision {
        let value = self.page().map_or(1, |page| u64::from(page.offset()) + 1);
        Revision::new(value).expect("query revision is positive")
    }

    #[must_use]
    pub fn paper_id(&self) -> Option<&PaperId> {
        match self {
            Self::PaperDetails { paper_id, .. }
            | Self::PaperAuthors { paper_id, .. }
            | Self::PaperCitations { paper_id, .. }
            | Self::PaperReferences { paper_id, .. }
            | Self::VenueMetadata { paper_id, .. }
            | Self::Recommendations { paper_id, .. } => Some(paper_id),
            _ => None,
        }
    }

    #[must_use]
    pub fn author_id(&self) -> Option<&AuthorId> {
        match self {
            Self::AuthorDetails { author_id, .. } | Self::AuthorPapers { author_id, .. } => {
                Some(author_id)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstractState {
    Present { digest: Digest },
    NoAbstract,
    Redacted { digest: Digest },
    Unknown,
}

impl AbstractState {
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    #[must_use]
    pub fn digest(&self) -> Option<&Digest> {
        match self {
            Self::Present { digest } | Self::Redacted { digest } => Some(digest),
            Self::NoAbstract | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetractionState {
    NotReported,
    Retracted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueKind {
    Journal,
    Conference,
    Repository,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VenueMetadataInput {
    pub venue_id: Option<VenueId>,
    pub name: Option<String>,
    pub kind: VenueKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VenueMetadata {
    pub venue_id: Option<VenueId>,
    pub name: Option<BoundedText>,
    pub kind: VenueKind,
    pub digest: Digest,
}

impl VenueMetadata {
    pub fn new(input: VenueMetadataInput) -> Result<Self, ModelError> {
        let name = input
            .name
            .map(|value| BoundedText::new(value, MAX_VENUE_BYTES))
            .transpose()?;
        if input.venue_id.is_none() && name.is_none() {
            return Err(ModelError::InvalidMetadata);
        }
        let digest = Digest::from_serializable(&(&input.venue_id, &name, input.kind))?;
        Ok(Self {
            venue_id: input.venue_id,
            name,
            kind: input.kind,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let digest = Digest::from_serializable(&(&self.venue_id, &self.name, self.kind))?;
        if digest != self.digest {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorMetadataInput {
    pub author_id: AuthorId,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorMetadata {
    pub author_id: AuthorId,
    pub name: Option<BoundedText>,
    pub identity: AuthorIdentityState,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorIdentityState {
    Indexed,
    Unknown,
}

impl AuthorMetadata {
    pub fn new(input: AuthorMetadataInput) -> Result<Self, ModelError> {
        let name = input
            .name
            .map(|value| BoundedText::new(value, MAX_TITLE_BYTES))
            .transpose()?;
        let identity = if name.is_some() {
            AuthorIdentityState::Indexed
        } else {
            AuthorIdentityState::Unknown
        };
        let digest = Digest::from_serializable(&(&input.author_id, &name, identity))?;
        Ok(Self {
            author_id: input.author_id,
            name,
            identity,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let digest = Digest::from_serializable(&(&self.author_id, &self.name, self.identity))?;
        if digest != self.digest {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaperMetadataInput {
    pub paper_id: PaperId,
    pub corpus_id: Option<u64>,
    pub title: Option<String>,
    pub year: Option<i32>,
    pub publication_date: Option<String>,
    pub venue: Option<VenueMetadataInput>,
    pub authors: Vec<AuthorMetadataInput>,
    pub citation_count: Option<u64>,
    pub reference_count: Option<u64>,
    pub influential_citation_count: Option<u64>,
    pub abstract_state: AbstractState,
    pub retraction_state: RetractionState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaperMetadata {
    pub paper_id: PaperId,
    pub corpus_id: Option<u64>,
    pub title: Option<BoundedText>,
    pub year: Option<i32>,
    pub publication_date: Option<BoundedText>,
    pub venue: Option<VenueMetadata>,
    pub authors: Vec<AuthorMetadata>,
    pub citation_count: Option<u64>,
    pub reference_count: Option<u64>,
    pub influential_citation_count: Option<u64>,
    pub abstract_state: AbstractState,
    pub retraction_state: RetractionState,
    pub digest: Digest,
}

impl PaperMetadata {
    pub fn new(input: PaperMetadataInput) -> Result<Self, ModelError> {
        if input.authors.len() > MAX_AUTHORS_PER_PAPER {
            return Err(ModelError::BoundExceeded {
                field: "authors",
                maximum: MAX_AUTHORS_PER_PAPER,
            });
        }
        let title = input
            .title
            .map(|value| BoundedText::new(value, MAX_TITLE_BYTES))
            .transpose()?;
        let publication_date = input
            .publication_date
            .map(|value| BoundedText::new(value, 32))
            .transpose()?;
        let venue = input.venue.map(VenueMetadata::new).transpose()?;
        let authors = input
            .authors
            .into_iter()
            .map(AuthorMetadata::new)
            .collect::<Result<Vec<_>, _>>()?;
        let digest = paper_digest(
            &input.paper_id,
            input.corpus_id,
            title.as_ref(),
            input.year,
            publication_date.as_ref(),
            venue.as_ref(),
            &authors,
            input.citation_count,
            input.reference_count,
            input.influential_citation_count,
            &input.abstract_state,
            input.retraction_state,
        )?;
        Ok(Self {
            paper_id: input.paper_id,
            corpus_id: input.corpus_id,
            title,
            year: input.year,
            publication_date,
            venue,
            authors,
            citation_count: input.citation_count,
            reference_count: input.reference_count,
            influential_citation_count: input.influential_citation_count,
            abstract_state: input.abstract_state,
            retraction_state: input.retraction_state,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.authors.len() > MAX_AUTHORS_PER_PAPER {
            return Err(ModelError::BoundExceeded {
                field: "authors",
                maximum: MAX_AUTHORS_PER_PAPER,
            });
        }
        if let Some(venue) = &self.venue {
            venue.validate()?;
        }
        for author in &self.authors {
            author.validate()?;
        }
        let digest = paper_digest(
            &self.paper_id,
            self.corpus_id,
            self.title.as_ref(),
            self.year,
            self.publication_date.as_ref(),
            self.venue.as_ref(),
            &self.authors,
            self.citation_count,
            self.reference_count,
            self.influential_citation_count,
            &self.abstract_state,
            self.retraction_state,
        )?;
        if digest != self.digest {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn venue_id(&self) -> Option<&VenueId> {
        self.venue
            .as_ref()
            .and_then(|venue| venue.venue_id.as_ref())
    }
}

fn paper_digest(
    paper_id: &PaperId,
    corpus_id: Option<u64>,
    title: Option<&BoundedText>,
    year: Option<i32>,
    publication_date: Option<&BoundedText>,
    venue: Option<&VenueMetadata>,
    authors: &[AuthorMetadata],
    citation_count: Option<u64>,
    reference_count: Option<u64>,
    influential_citation_count: Option<u64>,
    abstract_state: &AbstractState,
    retraction_state: RetractionState,
) -> Result<Digest, ModelError> {
    Digest::from_serializable(&(
        paper_id,
        corpus_id,
        title,
        year,
        publication_date,
        venue,
        authors,
        citation_count,
        reference_count,
        influential_citation_count,
        abstract_state,
        retraction_state,
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationDirection {
    Citing,
    CitedBy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitationRecord {
    pub direction: CitationDirection,
    pub paper: PaperMetadata,
    pub is_influential: Option<bool>,
    pub edge_digest: Digest,
}

impl CitationRecord {
    pub fn new(
        direction: CitationDirection,
        paper: PaperMetadata,
        is_influential: Option<bool>,
    ) -> Result<Self, ModelError> {
        paper.validate()?;
        let edge_digest = Digest::from_serializable(&(direction, &paper.digest, is_influential))?;
        Ok(Self {
            direction,
            paper,
            is_influential,
            edge_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.paper.validate()?;
        let digest =
            Digest::from_serializable(&(self.direction, &self.paper.digest, self.is_influential))?;
        if digest == self.edge_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecommendationRecord {
    pub paper: PaperMetadata,
    pub recommendation_digest: Digest,
}

impl RecommendationRecord {
    pub fn new(paper: PaperMetadata) -> Result<Self, ModelError> {
        paper.validate()?;
        let recommendation_digest =
            Digest::from_serializable(&(&paper.digest, "provider_order_not_quality"))?;
        Ok(Self {
            paper,
            recommendation_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.paper.validate()?;
        let digest =
            Digest::from_serializable(&(&self.paper.digest, "provider_order_not_quality"))?;
        if digest == self.recommendation_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchResultStatus {
    Indexed,
    Partial,
    NoAbstract,
    RetractedOrUnknown,
    AccessLost,
    RateLimited,
    ProviderUnknown,
    Empty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryEvidence {
    pub attempts: u8,
    pub retry_after_seconds: Option<u32>,
    pub bounded_backoff_seconds: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionNotice {
    AbstractText,
    FullText,
    PdfUrl,
    PaperUrl,
    AuthorContactData,
    AuthorAffiliation,
    AuthorHomepage,
    #[default]
    RawGraphBody,
    CitationContext,
    CitationIntent,
    RankingOrQualityClaim,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTransportProvenance {
    Fixture,
    Fake,
    Recording,
    Loopback,
    BlockedEnv,
}

impl NativeTransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorEvidence {
    pub code: String,
    pub retry_after_seconds: Option<u32>,
    pub provider_status_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        code: impl Into<String>,
        retry_after_seconds: Option<u32>,
    ) -> Result<Self, ModelError> {
        let code = code.into();
        validate_identifier(&code, "provider_error_code")?;
        let provider_status_digest = Digest::from_serializable(&(&code, retry_after_seconds))?;
        Ok(Self {
            code,
            retry_after_seconds,
            provider_status_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn truth() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted() -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractBinding {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
}

impl Default for ContractBinding {
    fn default() -> Self {
        Self {
            plugin_version: String::from(SEMANTIC_SCHOLAR_PLUGIN_VERSION),
            contract_version: String::from(SEMANTIC_SCHOLAR_CONTRACT_VERSION),
            contract_digest: Digest::from_text(crate::CONTRACT_DIGEST_INPUT),
        }
    }
}

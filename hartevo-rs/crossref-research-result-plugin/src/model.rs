use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_QUERY_BYTES: usize = 512;
pub const MAX_RESULTS: usize = 25;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 50;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_METADATA_AUTHORS: usize = 1_000;
pub const MAX_TITLE_BYTES: usize = 256;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Crossref typed value serializes");
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
    #[error("Crossref query is invalid")]
    InvalidQuery,
    #[error("Crossref scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Crossref metadata permission is missing")]
    InvalidPermission,
    #[error("read consent is invalid")]
    InvalidConsent,
    #[error("Crossref response is malformed or outside the bounded projection")]
    InvalidResponse,
    #[error("Crossref response is too large")]
    ResponseTooLarge,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossrefOperation {
    SearchWorks,
    RetrieveWork,
}

impl CrossrefOperation {
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::SearchWorks => "/works",
            Self::RetrieveWork => "/works/{doi}",
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SearchWorks => "search_works",
            Self::RetrieveWork => "retrieve_work",
        }
    }
}

/// A query contains only selector and filter digests. Raw terms and DOI
/// values are accepted at the construction boundary but are not retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefQuery {
    operation: CrossrefOperation,
    selector_digest: Digest,
    filter_digest: Digest,
}

impl CrossrefQuery {
    pub fn search(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::search_with_filter(value, "no-filter")
    }

    pub fn search_with_filter(
        value: impl AsRef<str>,
        filter: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let value = value.as_ref();
        let filter = filter.as_ref();
        validate_text(value, MAX_QUERY_BYTES, "query")?;
        validate_text(filter, MAX_QUERY_BYTES, "filter")?;
        Ok(Self {
            operation: CrossrefOperation::SearchWorks,
            selector_digest: sha256_digest(value.as_bytes()),
            filter_digest: sha256_digest(filter.as_bytes()),
        })
    }

    pub fn retrieve_doi(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, MAX_QUERY_BYTES, "doi")?;
        Ok(Self {
            operation: CrossrefOperation::RetrieveWork,
            selector_digest: sha256_digest(value.to_ascii_lowercase().as_bytes()),
            filter_digest: sha256_digest(b"no-filter"),
        })
    }

    pub fn from_digests(
        operation: CrossrefOperation,
        selector_digest: impl Into<String>,
        filter_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let query = Self {
            operation,
            selector_digest: selector_digest.into(),
            filter_digest: filter_digest.into(),
        };
        query.validate()?;
        Ok(query)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.selector_digest)?;
        validate_digest(&self.filter_digest)?;
        Ok(())
    }

    #[must_use]
    pub const fn operation(&self) -> CrossrefOperation {
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
        validate_digest(&self.purpose_digest).map_err(|_| ModelError::InvalidConsent)?;
        Ok(())
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
pub struct CrossrefResearchScope {
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    query: CrossrefQuery,
    max_results: u16,
    revision: Revision,
    consent: ConsentScope,
}

impl CrossrefResearchScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        query: CrossrefQuery,
        max_results: usize,
        revision: u64,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        if !(1..=MAX_RESULTS).contains(&max_results) {
            return Err(ModelError::InvalidScope("max_results"));
        }
        query.validate()?;
        consent.validate()?;
        Ok(Self {
            project,
            mission,
            work_product,
            query,
            max_results: u16::try_from(max_results)
                .map_err(|_| ModelError::InvalidScope("max_results"))?,
            revision: Revision::new(revision)?,
            consent,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        project: impl Into<String>,
        mission: impl Into<String>,
        work_product: impl Into<String>,
        query: CrossrefQuery,
        max_results: usize,
        revision: u64,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            ProjectBinding::new(project, 1)?,
            MissionBinding::new(mission, 1)?,
            WorkProductBinding::new(work_product, 1)?,
            query,
            max_results,
            revision,
            consent,
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.query.validate()?;
        self.consent.validate()?;
        if !(1..=MAX_RESULTS).contains(&(self.max_results as usize)) {
            return Err(ModelError::InvalidScope("max_results"));
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
    pub const fn query(&self) -> &CrossrefQuery {
        &self.query
    }

    #[must_use]
    pub const fn max_results(&self) -> usize {
        self.max_results as usize
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
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
pub struct CrossrefPermission {
    metadata_read: bool,
    permission_revision: Revision,
}

impl CrossrefPermission {
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

/// Opaque Layer-1 credential/configuration boundary. The supplied reference
/// is immediately reduced to a digest; the raw value is never stored,
/// serialized, formatted, or placed in a request/receipt.
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl CrossrefRegistration {
    pub(crate) fn new(
        scope: &CrossrefResearchScope,
        permission: &CrossrefPermission,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::CROSSREF_RESEARCH_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::CROSSREF_RESEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
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
            &self.secret_reference_digest,
            self.revision,
            self.state,
        ));
    }

    pub fn validate(
        &self,
        scope: &CrossrefResearchScope,
        permission: &CrossrefPermission,
        secret_reference: &SecretReference,
        provider_digest: &str,
    ) -> Result<(), ModelError> {
        if self.plugin_version != crate::CROSSREF_RESEARCH_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::CROSSREF_RESEARCH_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider_digest
            || self.permission_digest != permission.digest()
            || self.scope_digest != scope.digest()
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
    pub const fn first_party(self) -> bool {
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
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossrefEvidenceState {
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
pub struct CrossrefWorkProjection {
    pub doi_digest: Digest,
    pub title_digest: Option<Digest>,
    pub work_type: Option<String>,
    pub published_year: Option<u16>,
    pub author_count: u16,
    pub reference_count: Option<u64>,
    pub cited_by_count: Option<u64>,
    pub container_title_digest: Option<Digest>,
}

impl CrossrefWorkProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn from_metadata(
        doi: impl AsRef<str>,
        title: Option<impl AsRef<str>>,
        work_type: Option<impl AsRef<str>>,
        published_year: Option<u16>,
        author_count: usize,
        reference_count: Option<u64>,
        cited_by_count: Option<u64>,
        container_title: Option<impl AsRef<str>>,
    ) -> Result<Self, ModelError> {
        let doi = doi.as_ref();
        validate_text(doi, MAX_IDENTIFIER_BYTES, "doi")?;
        if author_count > MAX_METADATA_AUTHORS {
            return Err(ModelError::InvalidResponse);
        }
        let title_digest = title
            .map(|value| {
                let value = value.as_ref();
                validate_text(value, MAX_TITLE_BYTES, "title")?;
                Ok(sha256_digest(value.as_bytes()))
            })
            .transpose()?;
        let work_type = work_type
            .map(|value| {
                let value = value.as_ref();
                validate_text(value, MAX_IDENTIFIER_BYTES, "work type")?;
                Ok(value.to_owned())
            })
            .transpose()?;
        let container_title_digest = container_title
            .map(|value| {
                let value = value.as_ref();
                validate_text(value, MAX_TITLE_BYTES, "container title")?;
                Ok(sha256_digest(value.as_bytes()))
            })
            .transpose()?;
        Ok(Self {
            doi_digest: sha256_digest(doi.to_ascii_lowercase().as_bytes()),
            title_digest,
            work_type,
            published_year,
            author_count: u16::try_from(author_count).map_err(|_| ModelError::InvalidResponse)?,
            reference_count,
            cited_by_count,
            container_title_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.doi_digest)?;
        if let Some(digest) = &self.title_digest {
            validate_digest(digest)?;
        }
        if let Some(digest) = &self.container_title_digest {
            validate_digest(digest)?;
        }
        if self.author_count as usize > MAX_METADATA_AUTHORS {
            return Err(ModelError::InvalidResponse);
        }
        if let Some(work_type) = &self.work_type {
            validate_identifier(work_type, "work type")?;
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
pub struct CrossrefReadReceipt {
    pub status: u16,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl CrossrefReadReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefResearchEvidence {
    pub operation: CrossrefOperation,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub response_digest: Digest,
    pub state: CrossrefEvidenceState,
    pub total_results: Option<u64>,
    pub returned_results: usize,
    pub works: Vec<CrossrefWorkProjection>,
    pub partial_reason: Option<String>,
    pub rate_limit: RateLimitReceipt,
    pub read_receipt: CrossrefReadReceipt,
    pub evidence_digest: Digest,
}

impl CrossrefResearchEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.operation,
            &self.query_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.provider_digest,
            &self.registration_digest,
            &self.response_digest,
            &self.state,
            self.total_results,
            self.returned_results,
            &self.works,
            &self.partial_reason,
            &self.rate_limit,
            &self.read_receipt,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewMetadata,
    NoMetadata,
    RetryAfterRateLimit,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefResearchProposal {
    pub scope: CrossrefResearchScope,
    pub evidence: CrossrefResearchEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub recommendation: RecommendationDisposition,
    pub proposal_digest: Digest,
}

impl CrossrefResearchProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.evidence,
            &self.source_evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.contract_digest,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.adopts_outcome,
            self.adopts_work_product,
            self.recommendation,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub response_digest: Digest,
    pub state: CrossrefEvidenceState,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub receipt_digest: Digest,
}

impl CrossrefObservationReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.proposal_digest,
            &self.evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.response_digest,
            &self.state,
            self.provenance,
            self.connected,
            self.native,
            self.first_party,
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

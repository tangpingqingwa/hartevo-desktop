use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_QUERY_BYTES: usize = 512;
pub const MAX_MESH_TERM_BYTES: usize = 128;
pub const MAX_RESULTS: usize = 25;
pub const MAX_IDENTIFIER_LIST: usize = 25;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 50;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_JOURNAL_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_HISTORY_BYTES: usize = 512;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("PubMed typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is empty, malformed, or too long")]
    InvalidText { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("PubMed database is not allowlisted")]
    InvalidDatabase,
    #[error("PubMed query is invalid")]
    InvalidQuery,
    #[error("PubMed scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("PubMed metadata.read permission is missing")]
    InvalidPermission,
    #[error("read consent is invalid")]
    InvalidConsent,
    #[error("PubMed PMID is invalid")]
    InvalidPmid,
    #[error("PubMed PMCID is invalid")]
    InvalidPmcid,
    #[error("PubMed MeSH term is invalid")]
    InvalidMesh,
    #[error("PubMed response is malformed or outside the bounded projection")]
    InvalidResponse,
    #[error("PubMed response is too large")]
    ResponseTooLarge,
    #[error("rate-limit receipt is outside the bounded range")]
    InvalidRateLimit,
    #[error("opaque cursor is invalid")]
    InvalidCursor,
    #[error("opaque history binding is invalid")]
    InvalidHistory,
    #[error("scope binding does not match")]
    ScopeMismatch(&'static str),
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

fn normalize_pmid(value: &str) -> Result<String, ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<u64>().ok().is_none_or(|number| number == 0)
    {
        return Err(ModelError::InvalidPmid);
    }
    Ok(value.trim_start_matches('0').to_owned())
}

fn normalize_pmcid(value: &str) -> Result<String, ModelError> {
    let normalized = value.trim();
    let Some(prefix) = normalized.get(..3) else {
        return Err(ModelError::InvalidPmcid);
    };
    let Some(suffix) = normalized.get(3..) else {
        return Err(ModelError::InvalidPmcid);
    };
    if normalized.len() < 4
        || normalized.len() > MAX_IDENTIFIER_BYTES
        || !prefix.eq_ignore_ascii_case("pmc")
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        || suffix.parse::<u64>().ok().is_none_or(|number| number == 0)
    {
        return Err(ModelError::InvalidPmcid);
    }
    Ok(format!("PMC{suffix}"))
}

fn digest_identifier_list(values: &[String], label: &'static str) -> Result<Digest, ModelError> {
    if values.is_empty() || values.len() > MAX_IDENTIFIER_LIST {
        return Err(ModelError::InvalidScope(label));
    }
    let mut normalized = values.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.len() != values.len() {
        return Err(ModelError::InvalidScope(label));
    }
    Ok(canonical_digest(&normalized))
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PubMedDatabase {
    #[default]
    PubMed,
    Pmc,
}

impl PubMedDatabase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PubMed => "pubmed",
            Self::Pmc => "pmc",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value.to_ascii_lowercase().as_str() {
            "pubmed" => Ok(Self::PubMed),
            "pmc" => Ok(Self::Pmc),
            _ => Err(ModelError::InvalidDatabase),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PubMedOperation {
    Search,
    Summary,
    FetchMetadata,
    Link,
}

#[allow(non_upper_case_globals)]
impl PubMedOperation {
    pub const ESearch: Self = Self::Search;
    pub const ESummary: Self = Self::Summary;
    pub const EFetchMetadata: Self = Self::FetchMetadata;
    pub const EFetch: Self = Self::FetchMetadata;
    pub const ELink: Self = Self::Link;

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Search => "/esearch.fcgi",
            Self::Summary => "/esummary.fcgi",
            Self::FetchMetadata => "/efetch.fcgi",
            Self::Link => "/elink.fcgi",
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Search => "esearch",
            Self::Summary => "esummary",
            Self::FetchMetadata => "efetch_metadata",
            Self::Link => "elink",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedQuery {
    database: PubMedDatabase,
    operation: PubMedOperation,
    selector_digest: Digest,
    pmid_digest: Option<Digest>,
    pmcid_digest: Option<Digest>,
    mesh_digest: Option<Digest>,
    filter_digest: Digest,
}

impl PubMedQuery {
    pub fn esearch(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::search(value)
    }

    pub fn search(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::search_in(PubMedDatabase::PubMed, value)
    }

    pub fn search_mesh(
        value: impl AsRef<str>,
        mesh_term: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        Self::search_with_mesh(value, mesh_term)
    }

    pub fn search_in(database: PubMedDatabase, value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, MAX_QUERY_BYTES, "query")?;
        Ok(Self {
            database,
            operation: PubMedOperation::Search,
            selector_digest: sha256_digest(value.as_bytes()),
            pmid_digest: None,
            pmcid_digest: None,
            mesh_digest: None,
            filter_digest: sha256_digest(b"no-filter"),
        })
    }

    pub fn search_with_mesh(
        value: impl AsRef<str>,
        mesh_term: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let mut query = Self::search(value)?;
        let mesh_term = mesh_term.as_ref();
        validate_text(mesh_term, MAX_MESH_TERM_BYTES, "MeSH term")?;
        query.mesh_digest = Some(sha256_digest(mesh_term.to_ascii_lowercase().as_bytes()));
        Ok(query)
    }

    pub fn summary(ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::summary_in(PubMedDatabase::PubMed, ids)
    }

    pub fn esummary(ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::summary(ids)
    }

    pub fn by_pmid(pmid: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::summary(pmid)
    }

    pub fn by_pmcid(pmcid: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::summary(pmcid)
    }

    pub fn summary_in(database: PubMedDatabase, ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::id_operation(database, PubMedOperation::Summary, ids.as_ref())
    }

    pub fn summary_pmids(database: PubMedDatabase, pmids: &[u64]) -> Result<Self, ModelError> {
        let values = pmids.iter().map(u64::to_string).collect::<Vec<_>>();
        Self::id_operation(database, PubMedOperation::Summary, &values.join(","))
    }

    pub fn fetch_metadata(ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::fetch_metadata_in(PubMedDatabase::PubMed, ids)
    }

    pub fn efetch_metadata(ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::fetch_metadata(ids)
    }

    pub fn fetch_metadata_in(
        database: PubMedDatabase,
        ids: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        Self::id_operation(database, PubMedOperation::FetchMetadata, ids.as_ref())
    }

    pub fn fetch_metadata_pmids(
        database: PubMedDatabase,
        pmids: &[u64],
    ) -> Result<Self, ModelError> {
        let values = pmids.iter().map(u64::to_string).collect::<Vec<_>>();
        Self::id_operation(database, PubMedOperation::FetchMetadata, &values.join(","))
    }

    pub fn link(ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::link_in(PubMedDatabase::PubMed, ids)
    }

    pub fn elink(ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::link(ids)
    }

    pub fn link_in(database: PubMedDatabase, ids: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::id_operation(database, PubMedOperation::Link, ids.as_ref())
    }

    pub fn link_pmids(database: PubMedDatabase, pmids: &[u64]) -> Result<Self, ModelError> {
        let values = pmids.iter().map(u64::to_string).collect::<Vec<_>>();
        Self::id_operation(database, PubMedOperation::Link, &values.join(","))
    }

    pub fn from_digests(
        database: PubMedDatabase,
        operation: PubMedOperation,
        selector_digest: impl Into<String>,
        pmid_digest: Option<impl Into<String>>,
        pmcid_digest: Option<impl Into<String>>,
        mesh_digest: Option<impl Into<String>>,
    ) -> Result<Self, ModelError> {
        let query = Self {
            database,
            operation,
            selector_digest: selector_digest.into(),
            pmid_digest: pmid_digest.map(Into::into),
            pmcid_digest: pmcid_digest.map(Into::into),
            mesh_digest: mesh_digest.map(Into::into),
            filter_digest: sha256_digest(b"no-filter"),
        };
        query.validate()?;
        Ok(query)
    }

    fn id_operation(
        database: PubMedDatabase,
        operation: PubMedOperation,
        ids: &str,
    ) -> Result<Self, ModelError> {
        validate_text(ids, MAX_QUERY_BYTES, "identifier selector")?;
        let raw = ids.split(',').map(str::trim).collect::<Vec<_>>();
        if raw.is_empty() || raw.len() > MAX_IDENTIFIER_LIST || raw.iter().any(|id| id.is_empty()) {
            return Err(ModelError::InvalidQuery);
        }
        let mut pmids = Vec::new();
        let mut pmcids = Vec::new();
        for id in raw {
            if id.to_ascii_lowercase().starts_with("pmc") {
                pmcids.push(normalize_pmcid(id)?);
            } else {
                pmids.push(normalize_pmid(id)?);
            }
        }
        if pmids.is_empty() && pmcids.is_empty() {
            return Err(ModelError::InvalidQuery);
        }
        let pmid_digest = (!pmids.is_empty()).then(|| digest_identifier_list(&pmids, "PMIDs"));
        let pmcid_digest = (!pmcids.is_empty()).then(|| digest_identifier_list(&pmcids, "PMCIDs"));
        Ok(Self {
            database,
            operation,
            selector_digest: sha256_digest(ids.as_bytes()),
            pmid_digest: pmid_digest.transpose()?,
            pmcid_digest: pmcid_digest.transpose()?,
            mesh_digest: None,
            filter_digest: sha256_digest(b"no-filter"),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.selector_digest)?;
        validate_digest(&self.filter_digest)?;
        for digest in [&self.pmid_digest, &self.pmcid_digest, &self.mesh_digest]
            .into_iter()
            .flatten()
        {
            validate_digest(digest)?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn database(&self) -> PubMedDatabase {
        self.database
    }

    #[must_use]
    pub const fn operation(&self) -> PubMedOperation {
        self.operation
    }

    #[must_use]
    pub fn selector_digest(&self) -> &str {
        &self.selector_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> &str {
        &self.selector_digest
    }

    #[must_use]
    pub fn pmid_digest(&self) -> Option<&str> {
        self.pmid_digest.as_deref()
    }

    #[must_use]
    pub fn pmcid_digest(&self) -> Option<&str> {
        self.pmcid_digest.as_deref()
    }

    #[must_use]
    pub fn mesh_digest(&self) -> Option<&str> {
        self.mesh_digest.as_deref()
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
pub struct PubMedResearchScope {
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    database: PubMedDatabase,
    query: PubMedQuery,
    max_results: u16,
    revision: Revision,
    consent: ConsentScope,
}

impl PubMedResearchScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        query: PubMedQuery,
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
            database: query.database(),
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
        query: PubMedQuery,
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
        if self.database != self.query.database()
            || !(1..=MAX_RESULTS).contains(&(self.max_results as usize))
        {
            return Err(ModelError::InvalidScope("database or max_results"));
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
    pub const fn database(&self) -> PubMedDatabase {
        self.database
    }

    #[must_use]
    pub const fn query(&self) -> &PubMedQuery {
        &self.query
    }

    #[must_use]
    pub fn pmid_digest(&self) -> Option<&str> {
        self.query.pmid_digest()
    }

    #[must_use]
    pub fn pmcid_digest(&self) -> Option<&str> {
        self.query.pmcid_digest()
    }

    #[must_use]
    pub fn mesh_digest(&self) -> Option<&str> {
        self.query.mesh_digest()
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
pub struct PubMedPermission {
    metadata_read: bool,
    permission_revision: Revision,
}

impl PubMedPermission {
    pub fn research_metadata_read(revision: u64) -> Result<Self, ModelError> {
        Self::metadata_read(revision)
    }
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

/// An opaque Layer-1 credential/configuration boundary. The supplied
/// reference is immediately reduced to a digest and is never serializable.
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
    pub const fn is_opaque(&self) -> bool {
        true
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

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    history_digest: Option<Digest>,
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("history_digest", &self.history_digest)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token_digest: sha256_digest(value.as_bytes()),
            binding_digest: None,
            history_digest: None,
        })
    }

    pub fn from_digest(token_digest: impl Into<String>) -> Result<Self, ModelError> {
        let cursor = Self {
            token_digest: token_digest.into(),
            binding_digest: None,
            history_digest: None,
        };
        validate_digest(&cursor.token_digest)?;
        Ok(cursor)
    }

    #[must_use]
    pub fn bind(&self, binding_digest: &str) -> Self {
        let mut bound = self.clone();
        bound.binding_digest = Some(binding_digest.to_owned());
        bound
    }

    #[must_use]
    pub fn bind_to(&self, binding_digest: &str, history_digest: Option<&str>) -> Self {
        let mut bound = self.bind(binding_digest);
        bound.history_digest = history_digest.map(str::to_owned);
        bound
    }

    #[must_use]
    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    #[must_use]
    pub fn binding_digest(&self) -> Option<&str> {
        self.binding_digest.as_deref()
    }

    #[must_use]
    pub fn history_digest(&self) -> Option<&str> {
        self.history_digest.as_deref()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.token_digest,
            &self.binding_digest,
            &self.history_digest,
        ))
    }
}

/// WebEnv/query_key are reduced to digests immediately. A Layer-1 history
/// value can be bound to a query and scope without retaining NCBI state.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueHistory {
    web_env_digest: Digest,
    query_key_digest: Digest,
    binding_digest: Option<Digest>,
    revision: Revision,
}

pub type HistoryReference = OpaqueHistory;

impl fmt::Debug for OpaqueHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueHistory")
            .field("web_env_digest", &self.web_env_digest)
            .field("query_key_digest", &self.query_key_digest)
            .field("binding_digest", &self.binding_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for OpaqueHistory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueHistory", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

impl OpaqueHistory {
    pub fn new(web_env: impl AsRef<str>, query_key: impl AsRef<str>) -> Result<Self, ModelError> {
        let web_env = web_env.as_ref();
        let query_key = query_key.as_ref();
        if web_env.is_empty()
            || web_env.len() > MAX_HISTORY_BYTES
            || web_env.chars().any(char::is_control)
            || query_key.is_empty()
            || query_key.len() > MAX_IDENTIFIER_BYTES
            || !query_key.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ModelError::InvalidHistory);
        }
        Ok(Self {
            web_env_digest: sha256_digest(web_env.as_bytes()),
            query_key_digest: sha256_digest(query_key.as_bytes()),
            binding_digest: None,
            revision: Revision::new(1)?,
        })
    }

    pub fn from_digests(
        web_env_digest: impl Into<String>,
        query_key_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let history = Self {
            web_env_digest: web_env_digest.into(),
            query_key_digest: query_key_digest.into(),
            binding_digest: None,
            revision: Revision::new(revision)?,
        };
        validate_digest(&history.web_env_digest)?;
        validate_digest(&history.query_key_digest)?;
        Ok(history)
    }

    #[must_use]
    pub fn bind(&self, binding_digest: &str) -> Self {
        let mut bound = self.clone();
        bound.binding_digest = Some(binding_digest.to_owned());
        bound
    }

    #[must_use]
    pub fn web_env_digest(&self) -> &str {
        &self.web_env_digest
    }

    #[must_use]
    pub fn query_key_digest(&self) -> &str {
        &self.query_key_digest
    }

    #[must_use]
    pub fn binding_digest(&self) -> Option<&str> {
        self.binding_digest.as_deref()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.web_env_digest,
            &self.query_key_digest,
            &self.binding_digest,
            self.revision,
        ))
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
pub struct PubMedRegistration {
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

impl PubMedRegistration {
    pub(crate) fn new(
        scope: &PubMedResearchScope,
        permission: &PubMedPermission,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::PUBMED_RESEARCH_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::PUBMED_RESEARCH_RESULT_CONTRACT_VERSION.to_owned(),
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
        scope: &PubMedResearchScope,
        permission: &PubMedPermission,
        secret_reference: &SecretReference,
        provider_digest: &str,
    ) -> Result<(), ModelError> {
        let mut expected = self.clone();
        expected.registration_digest.clear();
        expected.recompute_digest();
        if self.plugin_version != crate::PUBMED_RESEARCH_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::PUBMED_RESEARCH_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider_digest
            || self.permission_digest != permission.digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != secret_reference.digest()
            || self.registration_digest != expected.registration_digest
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
    Fake,
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
            Self::Fake => "fake",
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
    pub fn throttled(retry_after_seconds: u32) -> Self {
        Self {
            limit_per_minute: Some(MAX_REQUESTS_PER_MINUTE),
            remaining: Some(0),
            retry_after_seconds: Some(retry_after_seconds.min(MAX_RETRY_AFTER_SECONDS)),
            throttled: true,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PubMedEvidenceState {
    Complete,
    Partial,
    Empty,
    Denied,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
    MalformedResponse,
    ResponseTooLarge,
    Tamper,
}

#[allow(non_upper_case_globals)]
impl PubMedEvidenceState {
    pub const AccessLost: Self = Self::Denied;

    #[must_use]
    pub const fn is_terminal_failure(self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::RateLimited
                | Self::ProviderUnknown
                | Self::BlockedEnv
                | Self::MalformedResponse
                | Self::ResponseTooLarge
                | Self::Tamper
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedArticleProjection {
    pub pmid_digest: Digest,
    pub pmcid_digest: Option<Digest>,
    pub title_digest: Option<Digest>,
    pub mesh_term_digests: Vec<Digest>,
    pub publication_year: Option<u16>,
    pub journal_digest: Option<Digest>,
    pub author_count: Option<u16>,
}

impl PubMedArticleProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn from_metadata(
        pmid: impl AsRef<str>,
        pmcid: Option<&str>,
        title: Option<&str>,
        mesh_terms: &[&str],
        publication_year: Option<u16>,
        journal: Option<&str>,
        author_count: Option<usize>,
    ) -> Result<Self, ModelError> {
        let pmid = normalize_pmid(pmid.as_ref())?;
        let pmcid_digest = pmcid
            .map(normalize_pmcid)
            .transpose()?
            .map(|value| sha256_digest(value.as_bytes()));
        let title_digest = title
            .map(|value| {
                validate_text(value, MAX_TITLE_BYTES, "title")?;
                Ok(sha256_digest(value.as_bytes()))
            })
            .transpose()?;
        let journal_digest = journal
            .map(|value| {
                validate_text(value, MAX_JOURNAL_BYTES, "journal")?;
                Ok(sha256_digest(value.as_bytes()))
            })
            .transpose()?;
        if mesh_terms.len() > MAX_IDENTIFIER_LIST {
            return Err(ModelError::InvalidResponse);
        }
        let mut mesh_term_digests = BTreeSet::new();
        for term in mesh_terms {
            validate_text(term, MAX_MESH_TERM_BYTES, "MeSH term")?;
            mesh_term_digests.insert(sha256_digest(term.to_ascii_lowercase().as_bytes()));
        }
        let author_count = author_count
            .map(|count| u16::try_from(count).map_err(|_| ModelError::InvalidResponse))
            .transpose()?;
        Ok(Self {
            pmid_digest: sha256_digest(pmid.as_bytes()),
            pmcid_digest,
            title_digest,
            mesh_term_digests: mesh_term_digests.into_iter().collect(),
            publication_year,
            journal_digest,
            author_count,
        })
    }

    pub fn minimal(pmid: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::from_metadata(pmid, None, None, &[], None, None, None)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.pmid_digest)?;
        for digest in [&self.pmcid_digest, &self.title_digest, &self.journal_digest]
            .into_iter()
            .flatten()
        {
            validate_digest(digest)?;
        }
        if self.mesh_term_digests.len() > MAX_IDENTIFIER_LIST
            || self
                .mesh_term_digests
                .iter()
                .any(|digest| validate_digest(digest).is_err())
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
pub struct PubMedLinkProjection {
    pub source_pmid_digest: Digest,
    pub target_database: PubMedDatabase,
    pub target_id_digest: Digest,
    pub link_type_digest: Digest,
}

impl PubMedLinkProjection {
    pub fn from_metadata(
        source_pmid: impl AsRef<str>,
        target_database: PubMedDatabase,
        target_id: impl AsRef<str>,
        link_type: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let source_pmid = normalize_pmid(source_pmid.as_ref())?;
        let target = target_id.as_ref();
        let target_id = if target.to_ascii_lowercase().starts_with("pmc") {
            normalize_pmcid(target)?
        } else {
            normalize_pmid(target)?
        };
        validate_text(link_type.as_ref(), MAX_IDENTIFIER_BYTES, "link type")?;
        Ok(Self {
            source_pmid_digest: sha256_digest(source_pmid.as_bytes()),
            target_database,
            target_id_digest: sha256_digest(target_id.as_bytes()),
            link_type_digest: sha256_digest(link_type.as_ref().as_bytes()),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.source_pmid_digest)?;
        validate_digest(&self.target_id_digest)?;
        validate_digest(&self.link_type_digest)?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedReadReceipt {
    pub status: u16,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit_digest: Digest,
    pub provenance: TransportProvenance,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub history_digest: Option<Digest>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl PubMedReadReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedResearchEvidence {
    pub operation: PubMedOperation,
    pub database: PubMedDatabase,
    pub query_digest: Digest,
    pub pmid_digest: Option<Digest>,
    pub pmcid_digest: Option<Digest>,
    pub mesh_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub response_digest: Digest,
    pub state: PubMedEvidenceState,
    pub total_results: Option<u64>,
    pub returned_results: usize,
    pub articles: Vec<PubMedArticleProjection>,
    pub links: Vec<PubMedLinkProjection>,
    pub partial_reason: Option<String>,
    pub rate_limit: RateLimitReceipt,
    pub read_receipt: PubMedReadReceipt,
    pub cursor_digest: Option<Digest>,
    pub history_digest: Option<Digest>,
    pub page_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    operation: PubMedOperation,
    database: PubMedDatabase,
    query_digest: &'a str,
    pmid_digest: &'a Option<Digest>,
    pmcid_digest: &'a Option<Digest>,
    mesh_digest: &'a Option<Digest>,
    scope_digest: &'a str,
    consent_digest: &'a str,
    provider_digest: &'a str,
    registration_digest: &'a str,
    response_digest: &'a str,
    state: &'a PubMedEvidenceState,
    total_results: Option<u64>,
    returned_results: usize,
    articles: &'a [PubMedArticleProjection],
    links: &'a [PubMedLinkProjection],
    partial_reason: &'a Option<String>,
    rate_limit: &'a RateLimitReceipt,
    read_receipt: &'a PubMedReadReceipt,
    cursor_digest: &'a Option<Digest>,
    history_digest: &'a Option<Digest>,
    page_digest: &'a str,
    request_digest: &'a str,
    idempotency_digest: &'a str,
}

impl PubMedResearchEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&EvidenceDigestMaterial {
            operation: self.operation,
            database: self.database,
            query_digest: &self.query_digest,
            pmid_digest: &self.pmid_digest,
            pmcid_digest: &self.pmcid_digest,
            mesh_digest: &self.mesh_digest,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            provider_digest: &self.provider_digest,
            registration_digest: &self.registration_digest,
            response_digest: &self.response_digest,
            state: &self.state,
            total_results: self.total_results,
            returned_results: self.returned_results,
            articles: &self.articles,
            links: &self.links,
            partial_reason: &self.partial_reason,
            rate_limit: &self.rate_limit,
            read_receipt: &self.read_receipt,
            cursor_digest: &self.cursor_digest,
            history_digest: &self.history_digest,
            page_digest: &self.page_digest,
            request_digest: &self.request_digest,
            idempotency_digest: &self.idempotency_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewMetadata,
    NoResults,
    RetryAfterRateLimit,
    AccessDenied,
    ProviderUnavailable,
    TamperRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedResearchProposal {
    pub scope: PubMedResearchScope,
    pub evidence: PubMedResearchEvidence,
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
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
}

impl PubMedResearchProposal {
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
            &self.idempotency_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub response_digest: Digest,
    pub state: PubMedEvidenceState,
    pub provenance: TransportProvenance,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub receipt_digest: Digest,
}

impl PubMedObservationReceipt {
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
            &self.request_digest,
            &self.idempotency_digest,
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

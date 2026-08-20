//! Layer 1 governed OpenSearch retrieval-evidence boundary.
//!
//! The crate is intentionally a standalone nested workspace. It owns typed
//! scope, mapping, query, PIT/search-after, provider projection, proposal,
//! receipt-candidate, and read-verification seams. It does not own live
//! HTTPS, SigV4 or secret resolution, writes, durable receipts, Truth,
//! Memory, Consent, Effect, Verification, Outcome, or Work Product adoption.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.opensearch-retrieval/v1";
pub const CONTRACT_VERSION: &str = "EXT-OPENSEARCH-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.opensearch-retrieval/v1|layer=1|service=search.opensearch.retrieval|provider=opensearch.search.recording|consumer=mission.retrieval-evidence.opensearch";
pub const CONTRACT_DIGEST: &str =
    "33c99028e167ef343c837504312dc28d7fcccc97bb621de0fb7f95771944cc79";
pub const PLUGIN_ID: &str = "opensearch.retrieval";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const SERVICE_ID: &str = "search.opensearch.retrieval";
pub const PROVIDER_ID: &str = "opensearch.search.recording";
pub const CONSUMER_ID: &str = "mission.retrieval-evidence.opensearch";
pub const MAX_PIT_KEEP_ALIVE_SECONDS: u32 = 3_600;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 32;
pub const MAX_HITS: usize = 1_000;
pub const MAX_CLAUSE_COUNT: u16 = 32;
pub const MAX_BOOL_DEPTH: u8 = 4;
pub const MAX_SOURCE_FIELD_BYTES: usize = 4_096;
pub const MAX_VALUE_BYTES: usize = 8 * 1024;

/// The checked-in Layer 1 contract. It is data, not a capability catalog.
pub const OPENSEARCH_RETRIEVAL_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/opensearch-retrieval/opensearch-retrieval.v1.json");

/// A lower-case SHA-256 digest used to fence every public proposal boundary.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_digest(bytes))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(
        value: &T,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let bytes = serde_json::to_vec(value).map_err(|_| OpenSearchEvidenceError::DigestInput)?;
        Ok(Self::from_bytes(&bytes))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(&self) -> bool {
        is_sha256(self.as_str())
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

/// Hash a serializable value using serde's deterministic struct ordering.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value).expect("contract values must serialize")
}

/// Hash bytes as lower-case hexadecimal SHA-256.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), OpenSearchEvidenceError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(OpenSearchEvidenceError::InvalidInput {
            field,
            reason: format!("must be non-empty, bounded to {max_bytes} bytes, and content-safe"),
        });
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), OpenSearchEvidenceError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'@')
        })
    {
        return Err(OpenSearchEvidenceError::InvalidInput {
            field,
            reason: String::from("must contain bounded identifier characters"),
        });
    }
    Ok(())
}

fn validate_field_name(value: &str, field: &'static str) -> Result<(), OpenSearchEvidenceError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('_') && value != "_id"
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(OpenSearchEvidenceError::InvalidInput {
            field,
            reason: String::from("must be an allowlist-safe field path"),
        });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, OpenSearchEvidenceError> {
                let value = value.into();
                validate_identifier(&value, $field, $max)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identifier!(ProjectId, "project_id", 128);
bounded_identifier!(MissionId, "mission_id", 128);
bounded_identifier!(ClaimId, "claim_id", 128);
bounded_identifier!(ResultId, "result_id", 128);

/// Semantic version bound into registration and proposals.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> Result<Self, OpenSearchEvidenceError> {
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() != 3 {
            return Err(OpenSearchEvidenceError::InvalidPluginVersion);
        }
        let [major, minor, patch] = parts.as_slice() else {
            return Err(OpenSearchEvidenceError::InvalidPluginVersion);
        };
        Ok(Self {
            major: major
                .parse()
                .map_err(|_| OpenSearchEvidenceError::InvalidPluginVersion)?,
            minor: minor
                .parse()
                .map_err(|_| OpenSearchEvidenceError::InvalidPluginVersion)?,
            patch: patch
                .parse()
                .map_err(|_| OpenSearchEvidenceError::InvalidPluginVersion)?,
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The only secret material boundary exposed by this crate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Bearer,
    Basic,
    ClientCertificate,
    SigV4,
}

/// Opaque host/keyring reference. It intentionally has no Serialize impl,
/// Display impl, or secret-bearing Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::with_kind(SecretKind::Bearer, opaque_id, scope_digest, revision)
    }

    pub fn with_kind(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let opaque_id = opaque_id.into();
        if opaque_id.trim().is_empty()
            || opaque_id.trim() != opaque_id
            || opaque_id.len() > 256
            || opaque_id.chars().any(char::is_control)
            || !scope_digest.is_valid()
            || revision == 0
        {
            return Err(OpenSearchEvidenceError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            opaque_id,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn bearer(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::with_kind(SecretKind::Bearer, opaque_id, scope_digest, revision)
    }

    pub fn basic(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::with_kind(SecretKind::Basic, opaque_id, scope_digest, revision)
    }

    pub fn sigv4(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::with_kind(SecretKind::SigV4, opaque_id, scope_digest, revision)
    }

    pub fn client_certificate(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::with_kind(
            SecretKind::ClientCertificate,
            opaque_id,
            scope_digest,
            revision,
        )
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("opaque_id", &"<redacted>")
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// Exact domain, cluster, index/alias, mapping, Project, and Mission fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchScope {
    domain: String,
    cluster: String,
    index: String,
    alias: Option<String>,
    mapping_digest: Digest,
    mapping_revision: String,
    project_id: ProjectId,
    mission_id: MissionId,
}

impl OpenSearchScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: impl Into<String>,
        cluster: impl Into<String>,
        index: impl Into<String>,
        alias: Option<String>,
        mapping_digest: Digest,
        mapping_revision: impl Into<String>,
        project_id: ProjectId,
        mission_id: MissionId,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let scope = Self {
            domain: domain.into(),
            cluster: cluster.into(),
            index: index.into(),
            alias,
            mapping_digest,
            mapping_revision: mapping_revision.into(),
            project_id,
            mission_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_mapping(
        domain: impl Into<String>,
        cluster: impl Into<String>,
        index: impl Into<String>,
        alias: Option<String>,
        mapping: &OpenSearchMapping,
        project_id: ProjectId,
        mission_id: MissionId,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            domain,
            cluster,
            index,
            alias,
            mapping.digest.clone(),
            mapping.revision.clone(),
            project_id,
            mission_id,
        )
    }

    pub fn fixture(mission_id: impl Into<String>) -> Result<Self, OpenSearchEvidenceError> {
        let mapping = OpenSearchMapping::fixture()?;
        Self::from_mapping(
            "https://search.example.test",
            "fixture-cluster",
            "missions",
            Some(String::from("missions-read")),
            &mapping,
            ProjectId::new("project.fixture")?,
            MissionId::new(mission_id)?,
        )
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        validate_https_domain(&self.domain)?;
        validate_identifier(&self.cluster, "cluster", 128)?;
        validate_identifier(&self.index, "index", 256)?;
        if let Some(alias) = &self.alias {
            validate_identifier(alias, "alias", 256)?;
        }
        if !self.mapping_digest.is_valid() {
            return Err(OpenSearchEvidenceError::InvalidDigest {
                field: "mapping_digest",
            });
        }
        validate_identifier(&self.mapping_revision, "mapping_revision", 128)?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    #[must_use]
    pub fn index(&self) -> &str {
        &self.index
    }

    #[must_use]
    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    #[must_use]
    pub fn mapping_digest(&self) -> &Digest {
        &self.mapping_digest
    }

    #[must_use]
    pub fn mapping_revision(&self) -> &str {
        &self.mapping_revision
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&ScopeDigestInput {
            domain: &self.domain,
            cluster: &self.cluster,
            index: &self.index,
            alias: self.alias.as_deref(),
            mapping_digest: &self.mapping_digest,
            mapping_revision: &self.mapping_revision,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
        })
    }
}

#[derive(Serialize)]
struct ScopeDigestInput<'a> {
    domain: &'a str,
    cluster: &'a str,
    index: &'a str,
    alias: Option<&'a str>,
    mapping_digest: &'a Digest,
    mapping_revision: &'a str,
    project_id: &'a ProjectId,
    mission_id: &'a MissionId,
}

fn validate_https_domain(value: &str) -> Result<(), OpenSearchEvidenceError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(OpenSearchEvidenceError::InvalidScope)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(OpenSearchEvidenceError::InvalidScope);
    }
    let host_without_port = remainder.split_once(':').map_or(remainder, |(host, port)| {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            ""
        } else {
            host
        }
    });
    if host_without_port.is_empty()
        || host_without_port.starts_with('.')
        || host_without_port.ends_with('.')
        || host_without_port.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(OpenSearchEvidenceError::InvalidScope);
    }
    Ok(())
}

/// Closed mapping type vocabulary. Arbitrary mapping JSON is never retained.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchFieldType {
    Keyword,
    Text,
    Integer,
    Long,
    Double,
    Boolean,
    Date,
    Json,
}

/// A digest-bound mapping snapshot used by scope and query validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchMapping {
    revision: String,
    fields: BTreeMap<String, OpenSearchFieldType>,
    digest: Digest,
}

impl OpenSearchMapping {
    pub fn new(
        revision: impl Into<String>,
        fields: BTreeMap<String, OpenSearchFieldType>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let revision = revision.into();
        validate_identifier(&revision, "mapping_revision", 128)?;
        if fields.is_empty() || fields.len() > 256 {
            return Err(OpenSearchEvidenceError::InvalidInput {
                field: "mapping_fields",
                reason: String::from("must contain between one and 256 fields"),
            });
        }
        for field in fields.keys() {
            validate_field_name(field, "mapping_field")?;
        }
        let digest = canonical_digest(&MappingDigestInput {
            revision: &revision,
            fields: &fields,
        });
        Ok(Self {
            revision,
            fields,
            digest,
        })
    }

    pub fn fixture() -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            "mapping-1",
            BTreeMap::from([
                (String::from("title"), OpenSearchFieldType::Text),
                (String::from("tenant"), OpenSearchFieldType::Keyword),
                (String::from("updated_at"), OpenSearchFieldType::Date),
                (String::from("priority"), OpenSearchFieldType::Integer),
                (String::from("_id"), OpenSearchFieldType::Keyword),
            ]),
        )
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        let expected = Self::new(self.revision.clone(), self.fields.clone())?;
        if expected.digest != self.digest {
            return Err(OpenSearchEvidenceError::MappingDrift {
                expected: expected.digest,
                actual: self.digest.clone(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn fields(&self) -> &BTreeMap<String, OpenSearchFieldType> {
        &self.fields
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn contains_field(&self, field: &str) -> bool {
        field == "_id" || self.fields.contains_key(field)
    }
}

#[derive(Serialize)]
struct MappingDigestInput<'a> {
    revision: &'a str,
    fields: &'a BTreeMap<String, OpenSearchFieldType>,
}

/// Query/sources/sort bounds that are part of registration, not UI metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchQueryPolicy {
    query_fields: BTreeSet<String>,
    source_fields: BTreeSet<String>,
    sort_fields: BTreeSet<String>,
    max_page_size: u16,
    max_pages: u16,
    max_hits: usize,
    max_clause_count: u16,
    max_bool_depth: u8,
    max_source_field_bytes: usize,
    digest: Digest,
}

impl OpenSearchQueryPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        query_fields: impl IntoIterator<Item = String>,
        source_fields: impl IntoIterator<Item = String>,
        sort_fields: impl IntoIterator<Item = String>,
        max_page_size: u16,
        max_pages: u16,
        max_hits: usize,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let query_fields: BTreeSet<String> = query_fields.into_iter().collect();
        let source_fields: BTreeSet<String> = source_fields.into_iter().collect();
        let sort_fields: BTreeSet<String> = sort_fields.into_iter().collect();
        if query_fields.is_empty()
            || source_fields.is_empty()
            || !sort_fields.contains("_id")
            || max_page_size == 0
            || max_page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_hits == 0
            || max_hits > MAX_HITS
        {
            return Err(OpenSearchEvidenceError::InvalidQueryPolicy);
        }
        for field in query_fields
            .iter()
            .chain(source_fields.iter())
            .chain(sort_fields.iter())
        {
            if field != "_id" {
                validate_field_name(field, "policy_field")?;
            }
        }
        let policy_without_digest = PolicyDigestInput {
            query_fields: &query_fields,
            source_fields: &source_fields,
            sort_fields: &sort_fields,
            max_page_size,
            max_pages,
            max_hits,
            max_clause_count: MAX_CLAUSE_COUNT,
            max_bool_depth: MAX_BOOL_DEPTH,
            max_source_field_bytes: MAX_SOURCE_FIELD_BYTES,
        };
        let digest = canonical_digest(&policy_without_digest);
        Ok(Self {
            query_fields,
            source_fields,
            sort_fields,
            max_page_size,
            max_pages,
            max_hits,
            max_clause_count: MAX_CLAUSE_COUNT,
            max_bool_depth: MAX_BOOL_DEPTH,
            max_source_field_bytes: MAX_SOURCE_FIELD_BYTES,
            digest,
        })
    }

    pub fn fixture() -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            [
                String::from("title"),
                String::from("tenant"),
                String::from("priority"),
            ],
            [
                String::from("title"),
                String::from("tenant"),
                String::from("priority"),
            ],
            [
                String::from("updated_at"),
                String::from("priority"),
                String::from("_id"),
            ],
            MAX_PAGE_SIZE,
            MAX_PAGES,
            MAX_HITS,
        )
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        let expected = Self::new(
            self.query_fields.clone(),
            self.source_fields.clone(),
            self.sort_fields.clone(),
            self.max_page_size,
            self.max_pages,
            self.max_hits,
        )?;
        if expected.digest != self.digest {
            return Err(OpenSearchEvidenceError::PolicyDrift {
                expected: expected.digest,
                actual: self.digest.clone(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn query_fields(&self) -> &BTreeSet<String> {
        &self.query_fields
    }

    #[must_use]
    pub fn source_fields(&self) -> &BTreeSet<String> {
        &self.source_fields
    }

    #[must_use]
    pub fn sort_fields(&self) -> &BTreeSet<String> {
        &self.sort_fields
    }

    #[must_use]
    pub const fn max_page_size(&self) -> u16 {
        self.max_page_size
    }

    #[must_use]
    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    #[must_use]
    pub const fn max_hits(&self) -> usize {
        self.max_hits
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn allows_query_field(&self, field: &str) -> bool {
        self.query_fields.contains(field)
    }

    fn allows_source_field(&self, field: &str) -> bool {
        self.source_fields.contains(field)
    }

    fn allows_sort_field(&self, field: &str) -> bool {
        self.sort_fields.contains(field)
    }
}

#[derive(Serialize)]
struct PolicyDigestInput<'a> {
    query_fields: &'a BTreeSet<String>,
    source_fields: &'a BTreeSet<String>,
    sort_fields: &'a BTreeSet<String>,
    max_page_size: u16,
    max_pages: u16,
    max_hits: usize,
    max_clause_count: u16,
    max_bool_depth: u8,
    max_source_field_bytes: usize,
}

/// Scalar values admitted to the bounded query DSL and sort cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum OpenSearchScalar {
    Text(String),
    Integer(i64),
    Float(String),
    Boolean(bool),
    Null,
}

impl OpenSearchScalar {
    fn validate(&self, field: &'static str) -> Result<(), OpenSearchEvidenceError> {
        match self {
            Self::Text(value) | Self::Float(value) => validate_text(value, field, MAX_VALUE_BYTES),
            Self::Integer(_) | Self::Boolean(_) | Self::Null => Ok(()),
        }
    }
}

/// The only query clauses accepted by this plugin. Raw JSON DSL is not an
/// input type and cannot bypass the policy or mapping allowlists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum OpenSearchQueryClause {
    Match {
        field: String,
        query: String,
    },
    Term {
        field: String,
        value: OpenSearchScalar,
    },
    Prefix {
        field: String,
        prefix: String,
    },
    Range {
        field: String,
        gte: Option<OpenSearchScalar>,
        lte: Option<OpenSearchScalar>,
    },
    Bool {
        must: Vec<Box<OpenSearchQueryClause>>,
        filter: Vec<Box<OpenSearchQueryClause>>,
    },
}

impl OpenSearchQueryClause {
    pub fn match_text(
        field: impl Into<String>,
        query: impl Into<String>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let field = field.into();
        let query = query.into();
        validate_field_name(&field, "query_field")?;
        validate_text(&query, "match_query", MAX_VALUE_BYTES)?;
        Ok(Self::Match { field, query })
    }

    pub fn term(
        field: impl Into<String>,
        value: OpenSearchScalar,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let field = field.into();
        validate_field_name(&field, "query_field")?;
        value.validate("term_value")?;
        Ok(Self::Term { field, value })
    }

    pub fn prefix(
        field: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let field = field.into();
        let prefix = prefix.into();
        validate_field_name(&field, "query_field")?;
        validate_text(&prefix, "prefix", MAX_VALUE_BYTES)?;
        Ok(Self::Prefix { field, prefix })
    }

    pub fn range(
        field: impl Into<String>,
        gte: Option<OpenSearchScalar>,
        lte: Option<OpenSearchScalar>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let field = field.into();
        validate_field_name(&field, "query_field")?;
        if gte.is_none() && lte.is_none() {
            return Err(OpenSearchEvidenceError::InvalidQuery {
                reason: String::from("range requires a lower or upper bound"),
            });
        }
        if let Some(value) = &gte {
            value.validate("range_gte")?;
        }
        if let Some(value) = &lte {
            value.validate("range_lte")?;
        }
        Ok(Self::Range { field, gte, lte })
    }

    pub fn bool(
        must: impl IntoIterator<Item = OpenSearchQueryClause>,
        filter: impl IntoIterator<Item = OpenSearchQueryClause>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let must: Vec<_> = must.into_iter().map(Box::new).collect();
        let filter: Vec<_> = filter.into_iter().map(Box::new).collect();
        if must.is_empty() && filter.is_empty() {
            return Err(OpenSearchEvidenceError::InvalidQuery {
                reason: String::from("bool requires at least one clause"),
            });
        }
        Ok(Self::Bool { must, filter })
    }

    fn validate_basic(&self, depth: u8, clauses: &mut u16) -> Result<(), OpenSearchEvidenceError> {
        *clauses = clauses.saturating_add(1);
        if *clauses > MAX_CLAUSE_COUNT {
            return Err(OpenSearchEvidenceError::QueryTooComplex);
        }
        if depth > MAX_BOOL_DEPTH {
            return Err(OpenSearchEvidenceError::QueryTooDeep);
        }
        match self {
            Self::Match { field, query } => {
                validate_field_name(field, "query_field")?;
                validate_text(query, "match_query", MAX_VALUE_BYTES)?;
            }
            Self::Term { field, value } => {
                validate_field_name(field, "query_field")?;
                value.validate("term_value")?;
            }
            Self::Prefix { field, prefix } => {
                validate_field_name(field, "query_field")?;
                validate_text(prefix, "prefix", MAX_VALUE_BYTES)?;
            }
            Self::Range { field, gte, lte } => {
                validate_field_name(field, "query_field")?;
                if gte.is_none() && lte.is_none() {
                    return Err(OpenSearchEvidenceError::InvalidQuery {
                        reason: String::from("range requires a bound"),
                    });
                }
                if let Some(value) = gte {
                    value.validate("range_gte")?;
                }
                if let Some(value) = lte {
                    value.validate("range_lte")?;
                }
            }
            Self::Bool { must, filter } => {
                for clause in must.iter().chain(filter.iter()) {
                    clause.validate_basic(depth.saturating_add(1), clauses)?;
                }
            }
        }
        Ok(())
    }

    fn validate_policy(
        &self,
        policy: &OpenSearchQueryPolicy,
        mapping: &OpenSearchMapping,
    ) -> Result<(), OpenSearchEvidenceError> {
        match self {
            Self::Match { field, .. }
            | Self::Term { field, .. }
            | Self::Prefix { field, .. }
            | Self::Range { field, .. } => {
                if !policy.allows_query_field(field) || !mapping.contains_field(field) {
                    return Err(OpenSearchEvidenceError::FieldNotAllowlisted {
                        field: field.clone(),
                    });
                }
            }
            Self::Bool { must, filter } => {
                for clause in must.iter().chain(filter.iter()) {
                    clause.validate_policy(policy, mapping)?;
                }
            }
        }
        Ok(())
    }
}

/// Sort order is explicit and must end with the unique `_id` tie-breaker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchSortOrder {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchSortField {
    field: String,
    order: OpenSearchSortOrder,
}

impl OpenSearchSortField {
    pub fn new(
        field: impl Into<String>,
        order: OpenSearchSortOrder,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let field = field.into();
        validate_field_name(&field, "sort_field")?;
        Ok(Self { field, order })
    }

    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    #[must_use]
    pub const fn order(&self) -> OpenSearchSortOrder {
        self.order
    }
}

/// A typed bounded search proposal. It contains no PIT token or credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchQuery {
    clause: OpenSearchQueryClause,
    source_fields: Vec<String>,
    sort: Vec<OpenSearchSortField>,
    page_size: u16,
    digest: Digest,
}

impl OpenSearchQuery {
    pub fn new(
        clause: OpenSearchQueryClause,
        source_fields: impl IntoIterator<Item = String>,
        sort: Vec<OpenSearchSortField>,
        page_size: u16,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let source_fields: Vec<String> = source_fields.into_iter().collect();
        if page_size == 0 || page_size > MAX_PAGE_SIZE || sort.is_empty() {
            return Err(OpenSearchEvidenceError::InvalidQuery {
                reason: String::from("page size and sort must be bounded and non-empty"),
            });
        }
        let mut clauses = 0;
        clause.validate_basic(1, &mut clauses)?;
        if source_fields.is_empty() || source_fields.len() > 64 {
            return Err(OpenSearchEvidenceError::InvalidQuery {
                reason: String::from("source fields must be bounded and non-empty"),
            });
        }
        let mut seen_sort_fields = BTreeSet::new();
        for field in &sort {
            if !seen_sort_fields.insert(field.field.clone()) {
                return Err(OpenSearchEvidenceError::SortInstability);
            }
        }
        if sort.last().map(|field| field.field.as_str()) != Some("_id") {
            return Err(OpenSearchEvidenceError::SortInstability);
        }
        for field in &source_fields {
            validate_field_name(field, "source_field")?;
        }
        let digest = canonical_digest(&QueryDigestInput {
            clause: &clause,
            source_fields: &source_fields,
            sort: &sort,
            page_size,
        });
        Ok(Self {
            clause,
            source_fields,
            sort,
            page_size,
            digest,
        })
    }

    #[must_use]
    pub fn clause(&self) -> &OpenSearchQueryClause {
        &self.clause
    }

    #[must_use]
    pub fn source_fields(&self) -> &[String] {
        &self.source_fields
    }

    #[must_use]
    pub fn sort(&self) -> &[OpenSearchSortField] {
        &self.sort
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate_for(
        &self,
        policy: &OpenSearchQueryPolicy,
        mapping: &OpenSearchMapping,
    ) -> Result<(), OpenSearchEvidenceError> {
        policy.validate()?;
        mapping.validate()?;
        let mut clauses = 0;
        self.clause.validate_basic(1, &mut clauses)?;
        self.clause.validate_policy(policy, mapping)?;
        if self.page_size > policy.max_page_size {
            return Err(OpenSearchEvidenceError::PageSizeExceeded);
        }
        for field in &self.source_fields {
            if !policy.allows_source_field(field) || !mapping.contains_field(field) {
                return Err(OpenSearchEvidenceError::FieldNotAllowlisted {
                    field: field.clone(),
                });
            }
        }
        for field in &self.sort {
            if !policy.allows_sort_field(&field.field) || !mapping.contains_field(&field.field) {
                return Err(OpenSearchEvidenceError::FieldNotAllowlisted {
                    field: field.field.clone(),
                });
            }
        }
        if self.sort.last().map(|field| field.field.as_str()) != Some("_id") {
            return Err(OpenSearchEvidenceError::SortInstability);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct QueryDigestInput<'a> {
    clause: &'a OpenSearchQueryClause,
    source_fields: &'a [String],
    sort: &'a [OpenSearchSortField],
    page_size: u16,
}

/// Query proposal bound to the exact provider scope, mapping, and policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchQueryProposal {
    scope_digest: Digest,
    mapping_digest: Digest,
    mapping_revision: String,
    policy_digest: Digest,
    query: OpenSearchQuery,
    query_digest: Digest,
    proposal_digest: Digest,
    non_mutating: bool,
    adopted: bool,
}

impl OpenSearchQueryProposal {
    fn new(
        scope: &OpenSearchScope,
        mapping: &OpenSearchMapping,
        policy: &OpenSearchQueryPolicy,
        query: OpenSearchQuery,
    ) -> Result<Self, OpenSearchEvidenceError> {
        query.validate_for(policy, mapping)?;
        if scope.mapping_digest != *mapping.digest() || scope.mapping_revision != mapping.revision {
            return Err(OpenSearchEvidenceError::MappingDrift {
                expected: scope.mapping_digest.clone(),
                actual: mapping.digest.clone(),
            });
        }
        let query_digest = query.digest.clone();
        let proposal_digest = canonical_digest(&QueryProposalDigestInput {
            scope_digest: &scope.digest(),
            mapping_digest: &mapping.digest,
            mapping_revision: &mapping.revision,
            policy_digest: &policy.digest,
            query_digest: &query_digest,
            non_mutating: true,
            adopted: false,
        });
        Ok(Self {
            scope_digest: scope.digest(),
            mapping_digest: mapping.digest.clone(),
            mapping_revision: mapping.revision.clone(),
            policy_digest: policy.digest.clone(),
            query,
            query_digest,
            proposal_digest,
            non_mutating: true,
            adopted: false,
        })
    }

    pub fn validate_for(
        &self,
        scope: &OpenSearchScope,
        mapping: &OpenSearchMapping,
        policy: &OpenSearchQueryPolicy,
    ) -> Result<(), OpenSearchEvidenceError> {
        if self.scope_digest != scope.digest()
            || self.mapping_digest != *mapping.digest()
            || self.mapping_revision != mapping.revision
            || self.policy_digest != *policy.digest()
        {
            return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
        }
        if self.query_digest != *self.query.digest() || !self.non_mutating || self.adopted {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        let expected = Self::new(scope, mapping, policy, self.query.clone())?;
        if expected.proposal_digest != self.proposal_digest {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn query(&self) -> &OpenSearchQuery {
        &self.query
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Serialize)]
struct QueryProposalDigestInput<'a> {
    scope_digest: &'a Digest,
    mapping_digest: &'a Digest,
    mapping_revision: &'a str,
    policy_digest: &'a Digest,
    query_digest: &'a Digest,
    non_mutating: bool,
    adopted: bool,
}

/// Provenance of a provider response. None of these values imply Connected or
/// native access; every Layer 1 value is explicitly BLOCKED_ENV.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

/// Auth is a transport seam. It never contains a credential or key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum OpenSearchAuthMode {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
    HttpsSecretReference {
        secret_kind: SecretKind,
    },
    HttpsSigV4 {
        region: String,
        service: String,
        secret_kind: SecretKind,
    },
}

impl OpenSearchAuthMode {
    fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        match self {
            Self::HttpsSecretReference { secret_kind } => {
                if !matches!(
                    secret_kind,
                    SecretKind::Bearer | SecretKind::Basic | SecretKind::ClientCertificate
                ) {
                    return Err(OpenSearchEvidenceError::InvalidAuthMode);
                }
            }
            Self::HttpsSigV4 {
                region,
                service,
                secret_kind,
            } => {
                validate_identifier(region, "sigv4_region", 64)?;
                validate_identifier(service, "sigv4_service", 64)?;
                if *secret_kind != SecretKind::SigV4 {
                    return Err(OpenSearchEvidenceError::InvalidAuthMode);
                }
            }
            Self::Fixture | Self::Recording | Self::Fake | Self::Loopback | Self::BlockedEnv => {}
        }
        Ok(())
    }

    #[must_use]
    pub const fn requires_secret_reference(&self) -> bool {
        matches!(
            self,
            Self::HttpsSecretReference { .. } | Self::HttpsSigV4 { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchProviderMode {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

/// Reversible, digest-bound registration. The field values are public for
/// audit tooling, while `validate` makes mutation fail closed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchRegistration {
    pub plugin_version: PluginVersion,
    pub contract_digest: Digest,
    pub provider_revision: u64,
    pub scope_digest: Digest,
    pub mapping_digest: Digest,
    pub policy_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
    pub enabled: bool,
    pub registration_digest: Digest,
}

impl OpenSearchRegistration {
    fn new(
        scope: &OpenSearchScope,
        mapping: &OpenSearchMapping,
        policy: &OpenSearchQueryPolicy,
        provider_revision: u64,
        registration_revision: u64,
    ) -> Self {
        let scope_digest = scope.digest();
        let mapping_digest = mapping.digest.clone();
        let policy_digest = policy.digest.clone();
        let registration_digest = canonical_digest(&RegistrationDigestInput {
            plugin_version: PLUGIN_VERSION,
            contract_digest: contract_digest(),
            provider_revision,
            scope_digest: scope_digest.clone(),
            mapping_digest: mapping_digest.clone(),
            policy_digest: policy_digest.clone(),
            registration_revision,
            reversible: true,
            enabled: true,
        });
        Self {
            plugin_version: PLUGIN_VERSION,
            contract_digest: contract_digest(),
            provider_revision,
            scope_digest,
            mapping_digest,
            policy_digest,
            registration_revision,
            reversible: true,
            enabled: true,
            registration_digest,
        }
    }

    pub fn validate(
        &self,
        scope: &OpenSearchScope,
        mapping: &OpenSearchMapping,
        policy: &OpenSearchQueryPolicy,
    ) -> Result<(), OpenSearchEvidenceError> {
        if self.plugin_version != PLUGIN_VERSION {
            return Err(OpenSearchEvidenceError::RegistrationVersionMismatch);
        }
        if self.contract_digest != contract_digest() {
            return Err(OpenSearchEvidenceError::RegistrationContractMismatch);
        }
        if self.provider_revision == 0 || self.registration_revision == 0 || !self.reversible {
            return Err(OpenSearchEvidenceError::InvalidRegistration);
        }
        if self.scope_digest != scope.digest()
            || self.mapping_digest != *mapping.digest()
            || self.policy_digest != *policy.digest()
        {
            return Err(OpenSearchEvidenceError::RegistrationScopeMismatch);
        }
        let expected = canonical_digest(&RegistrationDigestInput {
            plugin_version: self.plugin_version,
            contract_digest: self.contract_digest.clone(),
            provider_revision: self.provider_revision,
            scope_digest: self.scope_digest.clone(),
            mapping_digest: self.mapping_digest.clone(),
            policy_digest: self.policy_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            enabled: self.enabled,
        });
        if expected != self.registration_digest {
            return Err(OpenSearchEvidenceError::TamperedRegistration);
        }
        if !self.enabled {
            return Err(OpenSearchEvidenceError::RegistrationRevoked);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn is_reversible(&self) -> bool {
        self.reversible
    }

    fn rotated(&self, enabled: bool) -> Self {
        let registration_revision = self.registration_revision.saturating_add(1);
        let registration_digest = canonical_digest(&RegistrationDigestInput {
            plugin_version: self.plugin_version,
            contract_digest: self.contract_digest.clone(),
            provider_revision: self.provider_revision,
            scope_digest: self.scope_digest.clone(),
            mapping_digest: self.mapping_digest.clone(),
            policy_digest: self.policy_digest.clone(),
            registration_revision,
            reversible: self.reversible,
            enabled,
        });
        Self {
            registration_revision,
            enabled,
            registration_digest,
            ..self.clone()
        }
    }
}

#[derive(Serialize)]
struct RegistrationDigestInput {
    plugin_version: PluginVersion,
    contract_digest: Digest,
    provider_revision: u64,
    scope_digest: Digest,
    mapping_digest: Digest,
    policy_digest: Digest,
    registration_revision: u64,
    reversible: bool,
    enabled: bool,
}

/// Provider identity and all non-secret capabilities visible to the service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchProviderManifest {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub provider_id: String,
    pub provider_revision: u64,
    pub scope: OpenSearchScope,
    pub mapping: OpenSearchMapping,
    pub policy: OpenSearchQueryPolicy,
    pub mode: OpenSearchProviderMode,
    pub provenance: OpenSearchProvenance,
    pub auth_mode: OpenSearchAuthMode,
    pub native_status: NativeStatus,
    pub external_write_available: bool,
    pub connected: bool,
    pub native: bool,
    pub registration: OpenSearchRegistration,
    pub manifest_digest: Digest,
}

impl OpenSearchProviderManifest {
    pub fn new(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
        mode: OpenSearchProviderMode,
        provenance: OpenSearchProvenance,
        auth_mode: OpenSearchAuthMode,
        provider_revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        scope.validate()?;
        mapping.validate()?;
        policy.validate()?;
        auth_mode.validate()?;
        if provider_revision == 0 || scope.mapping_digest != *mapping.digest() {
            return Err(OpenSearchEvidenceError::MappingDrift {
                expected: scope.mapping_digest.clone(),
                actual: mapping.digest.clone(),
            });
        }
        let registration =
            OpenSearchRegistration::new(&scope, &mapping, &policy, provider_revision, 1);
        let mut manifest = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            scope,
            mapping,
            policy,
            mode,
            provenance,
            auth_mode,
            native_status: NativeStatus::BlockedEnv,
            external_write_available: false,
            connected: false,
            native: false,
            registration,
            manifest_digest: Digest::from_text("uninitialized"),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        Ok(manifest)
    }

    pub fn fixture(scope: OpenSearchScope) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            OpenSearchMapping::fixture()?,
            OpenSearchQueryPolicy::fixture()?,
            OpenSearchProviderMode::Fixture,
            OpenSearchProvenance::Fixture,
            OpenSearchAuthMode::Fixture,
            1,
        )
    }

    pub fn recording(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::Recording,
            OpenSearchProvenance::Recording,
            OpenSearchAuthMode::Recording,
            1,
        )
    }

    pub fn fake(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::Fake,
            OpenSearchProvenance::Fake,
            OpenSearchAuthMode::Fake,
            1,
        )
    }

    pub fn loopback(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::Loopback,
            OpenSearchProvenance::Loopback,
            OpenSearchAuthMode::Loopback,
            1,
        )
    }

    pub fn blocked_env(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::BlockedEnv,
            OpenSearchProvenance::BlockedEnv,
            OpenSearchAuthMode::BlockedEnv,
            1,
        )
    }

    pub fn https_secret_reference(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
        secret_kind: SecretKind,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::BlockedEnv,
            OpenSearchProvenance::BlockedEnv,
            OpenSearchAuthMode::HttpsSecretReference { secret_kind },
            1,
        )
    }

    pub fn https_sigv4(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::BlockedEnv,
            OpenSearchProvenance::BlockedEnv,
            OpenSearchAuthMode::HttpsSigV4 {
                region: region.into(),
                service: service.into(),
                secret_kind: SecretKind::SigV4,
            },
            1,
        )
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.provider_id != PROVIDER_ID
            || self.native_status != NativeStatus::BlockedEnv
            || self.external_write_available
            || self.connected
            || self.native
        {
            return Err(OpenSearchEvidenceError::ExternalWriteAuthority);
        }
        self.scope.validate()?;
        self.mapping.validate()?;
        self.policy.validate()?;
        if self.scope.mapping_digest != *self.mapping.digest() {
            return Err(OpenSearchEvidenceError::MappingDrift {
                expected: self.scope.mapping_digest.clone(),
                actual: self.mapping.digest.clone(),
            });
        }
        self.auth_mode.validate()?;
        self.registration
            .validate(&self.scope, &self.mapping, &self.policy)?;
        if self.calculate_digest() != self.manifest_digest {
            return Err(OpenSearchEvidenceError::ProviderManifestDrift {
                expected: self.calculate_digest(),
                actual: self.manifest_digest.clone(),
            });
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&ManifestDigestInput {
            plugin_id: &self.plugin_id,
            plugin_version: self.plugin_version,
            provider_id: &self.provider_id,
            provider_revision: self.provider_revision,
            scope: &self.scope,
            mapping: &self.mapping,
            policy: &self.policy,
            mode: self.mode,
            provenance: self.provenance,
            auth_mode: &self.auth_mode,
            native_status: self.native_status,
            external_write_available: self.external_write_available,
            connected: self.connected,
            native: self.native,
            registration: &self.registration,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn revoked(&self) -> Result<Self, OpenSearchEvidenceError> {
        let mut next = self.clone();
        next.registration = self.registration.rotated(false);
        next.manifest_digest = next.calculate_digest();
        Ok(next)
    }

    pub fn reactivated(&self) -> Result<Self, OpenSearchEvidenceError> {
        let mut next = self.clone();
        next.registration = self.registration.rotated(true);
        next.manifest_digest = next.calculate_digest();
        Ok(next)
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
struct ManifestDigestInput<'a> {
    plugin_id: &'a str,
    plugin_version: PluginVersion,
    provider_id: &'a str,
    provider_revision: u64,
    scope: &'a OpenSearchScope,
    mapping: &'a OpenSearchMapping,
    policy: &'a OpenSearchQueryPolicy,
    mode: OpenSearchProviderMode,
    provenance: OpenSearchProvenance,
    auth_mode: &'a OpenSearchAuthMode,
    native_status: NativeStatus,
    external_write_available: bool,
    connected: bool,
    native: bool,
    registration: &'a OpenSearchRegistration,
}

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Bounded request to create a point in time. The PIT is always scoped to one
/// exact index/alias and is never deleted by this Layer 1 crate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchPitRequest {
    pub scope: OpenSearchScope,
    pub keep_alive_seconds: u32,
    pub issued_at_epoch_seconds: u64,
}

impl OpenSearchPitRequest {
    pub fn new(
        scope: OpenSearchScope,
        keep_alive_seconds: u32,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::at(scope, keep_alive_seconds, 0)
    }

    pub fn at(
        scope: OpenSearchScope,
        keep_alive_seconds: u32,
        issued_at_epoch_seconds: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        scope.validate()?;
        if keep_alive_seconds == 0 || keep_alive_seconds > MAX_PIT_KEEP_ALIVE_SECONDS {
            return Err(OpenSearchEvidenceError::PitKeepAliveExceeded);
        }
        Ok(Self {
            scope,
            keep_alive_seconds,
            issued_at_epoch_seconds,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Opaque PIT identity. The raw provider token is retained only inside this
/// typed handle and is omitted from serialization and Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenSearchPitHandle {
    token: String,
    pit_digest: Digest,
    scope_digest: Digest,
    mapping_digest: Digest,
    expires_at_epoch_seconds: u64,
}

impl OpenSearchPitHandle {
    fn new(
        token: impl Into<String>,
        scope: &OpenSearchScope,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let token = token.into();
        validate_text(&token, "pit_token", 512)?;
        let pit_digest = Digest::from_text(&token);
        Ok(Self {
            token,
            pit_digest,
            scope_digest: scope.digest(),
            mapping_digest: scope.mapping_digest.clone(),
            expires_at_epoch_seconds,
        })
    }

    #[must_use]
    pub fn pit_digest(&self) -> &Digest {
        &self.pit_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn mapping_digest(&self) -> &Digest {
        &self.mapping_digest
    }

    #[must_use]
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    #[must_use]
    pub fn is_expired_at(&self, now_epoch_seconds: u64) -> bool {
        now_epoch_seconds >= self.expires_at_epoch_seconds
    }
}

impl fmt::Debug for OpenSearchPitHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenSearchPitHandle")
            .field("pit_digest", &self.pit_digest)
            .field("scope_digest", &self.scope_digest)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish_non_exhaustive()
    }
}

/// Provider PIT observation. Its opaque handle is intentionally not JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchPitResponse {
    pub scope: OpenSearchScope,
    pub pit_digest: Digest,
    pub mapping_digest: Digest,
    pub expires_at_epoch_seconds: u64,
    pub provider_manifest_digest: Digest,
    pub provenance: OpenSearchProvenance,
    pub native_status: NativeStatus,
    #[serde(skip)]
    handle: Option<OpenSearchPitHandle>,
}

impl OpenSearchPitResponse {
    pub fn recorded(
        request: &OpenSearchPitRequest,
        manifest: &OpenSearchProviderManifest,
        token: impl Into<String>,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let handle = OpenSearchPitHandle::new(token, &request.scope, expires_at_epoch_seconds)?;
        Ok(Self {
            scope: request.scope.clone(),
            pit_digest: handle.pit_digest.clone(),
            mapping_digest: request.scope.mapping_digest.clone(),
            expires_at_epoch_seconds,
            provider_manifest_digest: manifest.manifest_digest.clone(),
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            handle: Some(handle),
        })
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        if self.native_status != NativeStatus::BlockedEnv
            || self.scope.mapping_digest != self.mapping_digest
            || !self.pit_digest.is_valid()
            || !self.provider_manifest_digest.is_valid()
            || self.handle.is_none()
        {
            return Err(OpenSearchEvidenceError::InvalidProviderResponse);
        }
        if let Some(handle) = &self.handle
            && (handle.pit_digest != self.pit_digest
                || handle.scope_digest != self.scope.digest()
                || handle.expires_at_epoch_seconds != self.expires_at_epoch_seconds)
        {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn handle(&self) -> Option<&OpenSearchPitHandle> {
        self.handle.as_ref()
    }
}

/// Search-after values are closed typed scalars; arbitrary JSON cursor values
/// and unbounded scroll IDs are not admitted.
pub type OpenSearchSortValue = OpenSearchScalar;

#[derive(Clone, Eq, PartialEq)]
pub struct OpenSearchSearchAfterCursor {
    pit: OpenSearchPitHandle,
    query_digest: Digest,
    values: Vec<OpenSearchSortValue>,
    page_number: u16,
    cursor_digest: Digest,
}

impl OpenSearchSearchAfterCursor {
    pub fn new(
        pit: &OpenSearchPitHandle,
        query_digest: &Digest,
        values: Vec<OpenSearchSortValue>,
        page_number: u16,
    ) -> Result<Self, OpenSearchEvidenceError> {
        if values.is_empty() || values.len() > 32 || page_number == 0 || page_number > MAX_PAGES {
            return Err(OpenSearchEvidenceError::InvalidCursor);
        }
        for value in &values {
            value.validate("search_after")?;
        }
        let cursor_digest = canonical_digest(&CursorDigestInput {
            pit_digest: &pit.pit_digest,
            query_digest,
            values: &values,
            page_number,
        });
        Ok(Self {
            pit: pit.clone(),
            query_digest: query_digest.clone(),
            values,
            page_number,
            cursor_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }

    #[must_use]
    pub fn values(&self) -> &[OpenSearchSortValue] {
        &self.values
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    #[must_use]
    pub fn pit_digest(&self) -> &Digest {
        &self.pit.pit_digest
    }
}

impl fmt::Debug for OpenSearchSearchAfterCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenSearchSearchAfterCursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("pit_digest", &self.pit.pit_digest)
            .field("query_digest", &self.query_digest)
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct CursorDigestInput<'a> {
    pit_digest: &'a Digest,
    query_digest: &'a Digest,
    values: &'a [OpenSearchSortValue],
    page_number: u16,
}

/// Search request. The PIT and cursor token are not serializable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchSearchRequest {
    pub scope: OpenSearchScope,
    pub proposal: OpenSearchQueryProposal,
    pub now_epoch_seconds: u64,
    #[serde(skip)]
    pub pit: Option<OpenSearchPitHandle>,
    #[serde(skip)]
    pub cursor: Option<OpenSearchSearchAfterCursor>,
}

impl OpenSearchSearchRequest {
    pub fn new(
        scope: OpenSearchScope,
        proposal: OpenSearchQueryProposal,
        pit: OpenSearchPitHandle,
        cursor: Option<OpenSearchSearchAfterCursor>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::at(scope, proposal, pit, cursor, 0)
    }

    pub fn at(
        scope: OpenSearchScope,
        proposal: OpenSearchQueryProposal,
        pit: OpenSearchPitHandle,
        cursor: Option<OpenSearchSearchAfterCursor>,
        now_epoch_seconds: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        if pit.scope_digest != scope.digest() || pit.mapping_digest != *scope.mapping_digest() {
            return Err(OpenSearchEvidenceError::CursorIdentityMismatch);
        }
        if let Some(cursor) = &cursor
            && (cursor.pit_digest() != &pit.pit_digest
                || cursor.query_digest != *proposal.query_digest())
        {
            return Err(OpenSearchEvidenceError::CursorIdentityMismatch);
        }
        Ok(Self {
            scope,
            proposal,
            now_epoch_seconds,
            pit: Some(pit),
            cursor,
        })
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        self.proposal.query_digest()
    }
}

/// Values retained from an allowlisted `_source` projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum OpenSearchSourceValue {
    Text(String),
    Integer(i64),
    Float(String),
    Boolean(bool),
    Null,
    JsonDigest(Digest),
}

impl OpenSearchSourceValue {
    fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        match self {
            Self::Text(value) | Self::Float(value) => {
                validate_text(value, "source_value", MAX_SOURCE_FIELD_BYTES)
            }
            Self::JsonDigest(value) => {
                if value.is_valid() {
                    Ok(())
                } else {
                    Err(OpenSearchEvidenceError::InvalidDigest {
                        field: "source_json_digest",
                    })
                }
            }
            Self::Integer(_) | Self::Boolean(_) | Self::Null => Ok(()),
        }
    }
}

/// A deterministic bounded hit. Only source fields explicitly requested by
/// the typed query are retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchHit {
    pub id: String,
    pub sort_values: Vec<OpenSearchSortValue>,
    pub source: BTreeMap<String, OpenSearchSourceValue>,
    pub source_digest: Digest,
    pub hit_digest: Digest,
}

impl OpenSearchHit {
    pub fn new(
        id: impl Into<String>,
        sort_values: Vec<OpenSearchSortValue>,
        source: BTreeMap<String, OpenSearchSourceValue>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let id = id.into();
        validate_text(&id, "hit_id", 512)?;
        if sort_values.is_empty() || sort_values.len() > 32 || source.len() > 64 {
            return Err(OpenSearchEvidenceError::InvalidHit);
        }
        for value in &sort_values {
            value.validate("sort_value")?;
        }
        for (field, value) in &source {
            validate_field_name(field, "source_field")?;
            value.validate()?;
        }
        let source_digest = canonical_digest(&source);
        let hit_digest = canonical_digest(&HitDigestInput {
            id: &id,
            sort_values: &sort_values,
            source_digest: &source_digest,
        });
        Ok(Self {
            id,
            sort_values,
            source,
            source_digest,
            hit_digest,
        })
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        let expected = Self::new(
            self.id.clone(),
            self.sort_values.clone(),
            self.source.clone(),
        )?;
        if expected.source_digest != self.source_digest || expected.hit_digest != self.hit_digest {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct HitDigestInput<'a> {
    id: &'a str,
    sort_values: &'a [OpenSearchSortValue],
    source_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchShardFailure {
    pub shard: String,
    pub status: u16,
    pub reason_digest: Digest,
}

impl OpenSearchShardFailure {
    pub fn new(
        shard: impl Into<String>,
        status: u16,
        reason: impl AsRef<str>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let shard = shard.into();
        validate_identifier(&shard, "shard", 128)?;
        if status == 0 {
            return Err(OpenSearchEvidenceError::InvalidShardFailure);
        }
        Ok(Self {
            shard,
            status,
            reason_digest: Digest::from_text(reason.as_ref()),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchTotalRelation {
    Eq,
    Gte,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchResultStatus {
    Present,
    Empty,
    Partial,
    Timeout,
    ShardFailure,
    Deleted,
    AccessLoss,
    ProviderUnknown,
}

/// A bounded provider result projection. It never stores the raw OpenSearch
/// body, PIT token, or authorization material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchPage {
    pub scope: OpenSearchScope,
    pub query_digest: Digest,
    pub mapping_digest: Digest,
    pub pit_digest: Digest,
    pub hits: Vec<OpenSearchHit>,
    pub total: u64,
    pub total_relation: OpenSearchTotalRelation,
    pub timed_out: bool,
    pub shard_failures: Vec<OpenSearchShardFailure>,
    pub status: OpenSearchResultStatus,
    pub next_cursor_digest: Option<Digest>,
    pub provider_manifest_digest: Digest,
    pub provenance: OpenSearchProvenance,
    pub native_status: NativeStatus,
    pub took_millis: Option<u64>,
    pub result_digest: Digest,
    pub page_digest: Digest,
    #[serde(skip)]
    pub next_cursor: Option<OpenSearchSearchAfterCursor>,
}

impl OpenSearchPage {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &OpenSearchSearchRequest,
        manifest: &OpenSearchProviderManifest,
        hits: Vec<OpenSearchHit>,
        total: u64,
        total_relation: OpenSearchTotalRelation,
        timed_out: bool,
        shard_failures: Vec<OpenSearchShardFailure>,
        next_cursor: Option<OpenSearchSearchAfterCursor>,
        took_millis: Option<u64>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        if hits.len() > manifest.policy.max_page_size as usize
            || hits.len() > manifest.policy.max_hits
            || (total == 0 && !hits.is_empty())
        {
            return Err(OpenSearchEvidenceError::InvalidProviderResponse);
        }
        for hit in &hits {
            hit.validate()?;
        }
        let status = if !shard_failures.is_empty() {
            OpenSearchResultStatus::ShardFailure
        } else if timed_out {
            OpenSearchResultStatus::Timeout
        } else if total_relation == OpenSearchTotalRelation::Gte {
            OpenSearchResultStatus::Partial
        } else if hits.is_empty() {
            OpenSearchResultStatus::Empty
        } else {
            OpenSearchResultStatus::Present
        };
        let next_cursor_digest = next_cursor
            .as_ref()
            .map(|cursor| cursor.cursor_digest.clone());
        let result_digest = canonical_digest(&PageDigestInput {
            scope_digest: &request.scope.digest(),
            query_digest: request.query_digest(),
            mapping_digest: request.scope.mapping_digest(),
            pit_digest: &request
                .pit
                .as_ref()
                .ok_or(OpenSearchEvidenceError::InvalidCursor)?
                .pit_digest,
            hits: &hits,
            total,
            total_relation,
            timed_out,
            shard_failures: &shard_failures,
            status,
            next_cursor_digest: next_cursor_digest.as_ref(),
            provider_manifest_digest: &manifest.manifest_digest,
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            took_millis,
        });
        let page_digest = canonical_digest(&PageDigestWithResultInput {
            result_digest: &result_digest,
            query_digest: request.query_digest(),
            mapping_digest: request.scope.mapping_digest(),
            pit_digest: &request
                .pit
                .as_ref()
                .ok_or(OpenSearchEvidenceError::InvalidCursor)?
                .pit_digest,
            next_cursor_digest: next_cursor_digest.as_ref(),
        });
        Ok(Self {
            scope: request.scope.clone(),
            query_digest: request.query_digest().clone(),
            mapping_digest: request.scope.mapping_digest().clone(),
            pit_digest: request
                .pit
                .as_ref()
                .ok_or(OpenSearchEvidenceError::InvalidCursor)?
                .pit_digest
                .clone(),
            hits,
            total,
            total_relation,
            timed_out,
            shard_failures,
            status,
            next_cursor_digest,
            provider_manifest_digest: manifest.manifest_digest.clone(),
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            took_millis,
            result_digest,
            page_digest,
            next_cursor,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recorded(
        request: &OpenSearchSearchRequest,
        manifest: &OpenSearchProviderManifest,
        hits: Vec<OpenSearchHit>,
        total: u64,
        total_relation: OpenSearchTotalRelation,
        timed_out: bool,
        shard_failures: Vec<OpenSearchShardFailure>,
        next_cursor: Option<OpenSearchSearchAfterCursor>,
        took_millis: Option<u64>,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(
            request,
            manifest,
            hits,
            total,
            total_relation,
            timed_out,
            shard_failures,
            next_cursor,
            took_millis,
        )
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        if self.native_status != NativeStatus::BlockedEnv
            || !self.query_digest.is_valid()
            || !self.mapping_digest.is_valid()
            || !self.pit_digest.is_valid()
            || !self.provider_manifest_digest.is_valid()
            || self.hits.len() > MAX_HITS
        {
            return Err(OpenSearchEvidenceError::InvalidProviderResponse);
        }
        for hit in &self.hits {
            hit.validate()?;
        }
        if self.total == 0 && !self.hits.is_empty() {
            return Err(OpenSearchEvidenceError::InvalidProviderResponse);
        }
        let expected_status = if !self.shard_failures.is_empty() {
            OpenSearchResultStatus::ShardFailure
        } else if self.timed_out {
            OpenSearchResultStatus::Timeout
        } else if self.total_relation == OpenSearchTotalRelation::Gte {
            OpenSearchResultStatus::Partial
        } else if self.hits.is_empty() {
            OpenSearchResultStatus::Empty
        } else {
            OpenSearchResultStatus::Present
        };
        if self.status != expected_status {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        let expected_result = canonical_digest(&PageDigestInput {
            scope_digest: &self.scope.digest(),
            query_digest: &self.query_digest,
            mapping_digest: &self.mapping_digest,
            pit_digest: &self.pit_digest,
            hits: &self.hits,
            total: self.total,
            total_relation: self.total_relation,
            timed_out: self.timed_out,
            shard_failures: &self.shard_failures,
            status: self.status,
            next_cursor_digest: self.next_cursor_digest.as_ref(),
            provider_manifest_digest: &self.provider_manifest_digest,
            provenance: self.provenance,
            native_status: self.native_status,
            took_millis: self.took_millis,
        });
        if expected_result != self.result_digest {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        let expected_page = canonical_digest(&PageDigestWithResultInput {
            result_digest: &self.result_digest,
            query_digest: &self.query_digest,
            mapping_digest: &self.mapping_digest,
            pit_digest: &self.pit_digest,
            next_cursor_digest: self.next_cursor_digest.as_ref(),
        });
        if expected_page != self.page_digest {
            return Err(OpenSearchEvidenceError::TamperedResponse);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_source_evidence(&self) -> bool {
        matches!(
            self.status,
            OpenSearchResultStatus::Present | OpenSearchResultStatus::Empty
        )
    }

    #[must_use]
    pub const fn is_empty_success(&self) -> bool {
        matches!(self.status, OpenSearchResultStatus::Empty)
    }
}

#[derive(Serialize)]
struct PageDigestInput<'a> {
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    mapping_digest: &'a Digest,
    pit_digest: &'a Digest,
    hits: &'a [OpenSearchHit],
    total: u64,
    total_relation: OpenSearchTotalRelation,
    timed_out: bool,
    shard_failures: &'a [OpenSearchShardFailure],
    status: OpenSearchResultStatus,
    next_cursor_digest: Option<&'a Digest>,
    provider_manifest_digest: &'a Digest,
    provenance: OpenSearchProvenance,
    native_status: NativeStatus,
    took_millis: Option<u64>,
}

#[allow(clippy::struct_field_names)]
#[derive(Serialize)]
struct PageDigestWithResultInput<'a> {
    result_digest: &'a Digest,
    query_digest: &'a Digest,
    mapping_digest: &'a Digest,
    pit_digest: &'a Digest,
    next_cursor_digest: Option<&'a Digest>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenSearchOperation {
    Describe,
    CreatePit,
    Search,
    Paginate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchAccessLoss {
    Unauthorized,
    Forbidden,
    ScopeRevoked,
    CredentialRevoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchConflictReason {
    MappingDrift,
    PitConflict,
    ScopeConflict,
    AmbiguousProviderState,
}

/// Provider errors are content-free and preserve only typed status classes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpenSearchProviderError {
    #[error("OpenSearch live/native access is blocked in Layer 1")]
    BlockedEnv,
    #[error("an opaque SecretReference is required for this OpenSearch auth mode")]
    SecretReferenceRequired,
    #[error("the opaque SecretReference was revoked")]
    SecretRevoked,
    #[error("the SecretReference is bound to a different exact scope")]
    SecretScopeMismatch,
    #[error("provider manifest is invalid or has drifted")]
    ManifestMismatch,
    #[error("provider request scope does not match the registered scope")]
    ScopeMismatch,
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("no deterministic recording exists for {operation:?}")]
    NoRecordedResponse { operation: OpenSearchOperation },
    #[error("provider response was unknown for {operation:?}")]
    ProviderUnknown { operation: OpenSearchOperation },
    #[error("recorded provider response is invalid")]
    InvalidResponse,
    #[error("OpenSearch PIT expired")]
    PitExpired,
    #[error("OpenSearch cursor was repeated")]
    CursorLoop,
    #[error("OpenSearch mapping drifted")]
    MappingDrift,
    #[error("OpenSearch sort is unstable")]
    SortInstability,
    #[error("OpenSearch response was tampered with")]
    TamperedResponse,
    #[error("OpenSearch returned 401 Unauthorized ({access:?})")]
    Unauthorized401 { access: OpenSearchAccessLoss },
    #[error("OpenSearch returned 403 Forbidden ({access:?})")]
    Forbidden403 { access: OpenSearchAccessLoss },
    #[error("OpenSearch returned 404 Not Found (deleted={deleted})")]
    NotFound404 { deleted: bool },
    #[error("OpenSearch returned 409 Conflict ({reason:?})")]
    Conflict409 { reason: OpenSearchConflictReason },
    #[error("OpenSearch returned 429 Too Many Requests")]
    RateLimited429 { retry_after_seconds: Option<u64> },
    #[error("OpenSearch request timed out")]
    Timeout,
    #[error("OpenSearch returned shard failures")]
    ShardFailure { failures_digest: Digest },
    #[error("OpenSearch returned HTTP 5xx")]
    Server5xx { status: u16 },
    #[error("OpenSearch returned unsupported HTTP status")]
    Http { status: u16 },
}

impl OpenSearchProviderError {
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            401 => Self::Unauthorized401 {
                access: OpenSearchAccessLoss::Unauthorized,
            },
            403 => Self::Forbidden403 {
                access: OpenSearchAccessLoss::Forbidden,
            },
            404 => Self::NotFound404 { deleted: false },
            409 => Self::Conflict409 {
                reason: OpenSearchConflictReason::ScopeConflict,
            },
            429 => Self::RateLimited429 {
                retry_after_seconds: None,
            },
            500..=599 => Self::Server5xx { status },
            status => Self::Http { status },
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized401 { .. } => Some(401),
            Self::Forbidden403 { .. } => Some(403),
            Self::NotFound404 { .. } => Some(404),
            Self::Conflict409 { .. } => Some(409),
            Self::RateLimited429 { .. } => Some(429),
            Self::Server5xx { status } | Self::Http { status } => Some(*status),
            Self::BlockedEnv
            | Self::SecretReferenceRequired
            | Self::SecretRevoked
            | Self::SecretScopeMismatch
            | Self::ManifestMismatch
            | Self::ScopeMismatch
            | Self::RegistrationRevoked
            | Self::NoRecordedResponse { .. }
            | Self::ProviderUnknown { .. }
            | Self::InvalidResponse
            | Self::PitExpired
            | Self::CursorLoop
            | Self::MappingDrift
            | Self::SortInstability
            | Self::TamperedResponse
            | Self::Timeout
            | Self::ShardFailure { .. } => None,
        }
    }

    #[must_use]
    pub const fn projection_status(&self) -> OpenSearchResultStatus {
        match self {
            Self::Timeout => OpenSearchResultStatus::Timeout,
            Self::ShardFailure { .. } => OpenSearchResultStatus::ShardFailure,
            Self::NotFound404 { deleted: true } => OpenSearchResultStatus::Deleted,
            Self::Unauthorized401 { .. }
            | Self::Forbidden403 { .. }
            | Self::SecretRevoked
            | Self::SecretScopeMismatch
            | Self::SecretReferenceRequired => OpenSearchResultStatus::AccessLoss,
            Self::ProviderUnknown { .. }
            | Self::BlockedEnv
            | Self::ManifestMismatch
            | Self::ScopeMismatch
            | Self::RegistrationRevoked
            | Self::NoRecordedResponse { .. }
            | Self::InvalidResponse
            | Self::PitExpired
            | Self::CursorLoop
            | Self::MappingDrift
            | Self::SortInstability
            | Self::TamperedResponse
            | Self::NotFound404 { deleted: false }
            | Self::Conflict409 { .. }
            | Self::RateLimited429 { .. }
            | Self::Server5xx { .. }
            | Self::Http { .. } => OpenSearchResultStatus::ProviderUnknown,
        }
    }
}

/// Explicit projection for provider failures when a Page cannot be produced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchFailureProjection {
    pub status: OpenSearchResultStatus,
    pub status_code: Option<u16>,
    pub detail_digest: Digest,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub adopted: bool,
}

impl OpenSearchProviderError {
    #[must_use]
    pub fn projection(&self) -> OpenSearchFailureProjection {
        OpenSearchFailureProjection {
            status: self.projection_status(),
            status_code: self.status_code(),
            detail_digest: Digest::from_text(self.to_string().as_str()),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            adopted: false,
        }
    }
}

/// Service and Mission-consumer failures fail closed and retain no response
/// body, query token, or secret material.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpenSearchEvidenceError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("digest input could not be serialized")]
    DigestInput,
    #[error("{field} is not a lower-case SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("OpenSearch scope is invalid")]
    InvalidScope,
    #[error("SecretReference is invalid")]
    InvalidSecretReference,
    #[error("plugin version is invalid")]
    InvalidPluginVersion,
    #[error("OpenSearch query policy is invalid")]
    InvalidQueryPolicy,
    #[error("OpenSearch query policy drifted")]
    PolicyDrift { expected: Digest, actual: Digest },
    #[error("OpenSearch query is invalid: {reason}")]
    InvalidQuery { reason: String },
    #[error("OpenSearch query has too many clauses")]
    QueryTooComplex,
    #[error("OpenSearch query is too deeply nested")]
    QueryTooDeep,
    #[error("OpenSearch page size exceeds the registered bound")]
    PageSizeExceeded,
    #[error("OpenSearch field is not in the exact mapping/query/source allowlist: {field}")]
    FieldNotAllowlisted { field: String },
    #[error("OpenSearch sort is unstable; a unique _id tie-breaker is required")]
    SortInstability,
    #[error("OpenSearch auth mode is invalid")]
    InvalidAuthMode,
    #[error("OpenSearch registration is invalid")]
    InvalidRegistration,
    #[error("OpenSearch registration version drifted")]
    RegistrationVersionMismatch,
    #[error("OpenSearch registration contract digest drifted")]
    RegistrationContractMismatch,
    #[error("OpenSearch registration scope or policy binding drifted")]
    RegistrationScopeMismatch,
    #[error("OpenSearch registration is revoked")]
    RegistrationRevoked,
    #[error("OpenSearch registration digest was tampered with")]
    TamperedRegistration,
    #[error("Layer 1 provider exposes external write or native authority")]
    ExternalWriteAuthority,
    #[error("provider manifest drifted: expected {expected}, actual {actual}")]
    ProviderManifestDrift { expected: Digest, actual: Digest },
    #[error("OpenSearch mapping drifted: expected {expected}, actual {actual}")]
    MappingDrift { expected: Digest, actual: Digest },
    #[error("PIT keep-alive exceeds the Layer 1 bound")]
    PitKeepAliveExceeded,
    #[error("PIT expired")]
    PitExpired,
    #[error("cursor is invalid")]
    InvalidCursor,
    #[error("cursor identity does not match the exact PIT/query/scope")]
    CursorIdentityMismatch,
    #[error("cursor loop detected")]
    CursorLoop,
    #[error("pagination exceeded the bounded page budget")]
    PaginationBudgetExceeded,
    #[error("hit projection is invalid or unbounded")]
    InvalidHit,
    #[error("shard failure projection is invalid")]
    InvalidShardFailure,
    #[error("provider response is not a valid Layer 1 projection")]
    InvalidProviderResponse,
    #[error("provider response was tampered with")]
    TamperedResponse,
    #[error("query proposal is not bound to the exact Mission/provider scope")]
    ProposalBindingMismatch,
    #[error("Mission evidence binding is invalid")]
    InvalidEvidenceBinding,
    #[error("evidence proposal digest does not match its fields")]
    EvidenceDigestMismatch,
    #[error("provider error: {0}")]
    Provider(#[from] OpenSearchProviderError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OpenSearchHttpMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSearchTransportOperation {
    CreatePit,
    Search,
}

/// A redacted HTTPS/SigV4 request plan. Layer 1 plans; it does not execute.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchRequestPlan {
    pub operation: OpenSearchTransportOperation,
    pub method: OpenSearchHttpMethod,
    pub endpoint: String,
    pub headers: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub body_digest: Digest,
    pub auth_mode: OpenSearchAuthMode,
    pub secret_reference_required: bool,
    pub connected: bool,
    pub native: bool,
}

impl OpenSearchRequestPlan {
    pub fn for_pit(
        scope: &OpenSearchScope,
        keep_alive_seconds: u32,
        auth_mode: OpenSearchAuthMode,
    ) -> Result<Self, OpenSearchEvidenceError> {
        scope.validate()?;
        auth_mode.validate()?;
        if keep_alive_seconds == 0 || keep_alive_seconds > MAX_PIT_KEEP_ALIVE_SECONDS {
            return Err(OpenSearchEvidenceError::PitKeepAliveExceeded);
        }
        let endpoint = format!("{}/{}/_search/point_in_time", scope.domain, scope.index);
        let mut query = BTreeMap::new();
        query.insert(String::from("keep_alive"), format!("{keep_alive_seconds}s"));
        let headers = base_headers(scope, None, None);
        Ok(Self {
            operation: OpenSearchTransportOperation::CreatePit,
            method: OpenSearchHttpMethod::Post,
            endpoint,
            headers,
            query,
            body_digest: Digest::from_text("empty-body"),
            secret_reference_required: auth_mode.requires_secret_reference(),
            auth_mode,
            connected: false,
            native: false,
        })
    }

    pub fn for_search(
        scope: &OpenSearchScope,
        query_digest: &Digest,
        pit_digest: &Digest,
        cursor_digest: Option<&Digest>,
        auth_mode: OpenSearchAuthMode,
    ) -> Result<Self, OpenSearchEvidenceError> {
        scope.validate()?;
        auth_mode.validate()?;
        if !query_digest.is_valid() || !pit_digest.is_valid() {
            return Err(OpenSearchEvidenceError::InvalidDigest {
                field: "request_digest",
            });
        }
        let endpoint = format!("{}/_search", scope.domain);
        let mut query = BTreeMap::new();
        query.insert(String::from("pit_digest"), pit_digest.to_string());
        if let Some(cursor_digest) = cursor_digest {
            if !cursor_digest.is_valid() {
                return Err(OpenSearchEvidenceError::InvalidDigest {
                    field: "cursor_digest",
                });
            }
            query.insert(String::from("cursor_digest"), cursor_digest.to_string());
        }
        let headers = base_headers(scope, Some(query_digest), Some(pit_digest));
        Ok(Self {
            operation: OpenSearchTransportOperation::Search,
            method: OpenSearchHttpMethod::Post,
            endpoint,
            headers,
            query,
            body_digest: Digest::from_text(query_digest.as_str()),
            secret_reference_required: auth_mode.requires_secret_reference(),
            auth_mode,
            connected: false,
            native: false,
        })
    }
}

fn base_headers(
    scope: &OpenSearchScope,
    query_digest: Option<&Digest>,
    pit_digest: Option<&Digest>,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert(
        String::from("content-type"),
        String::from("application/json"),
    );
    headers.insert(
        String::from("x-hartevo-scope-digest"),
        scope.digest().to_string(),
    );
    if let Some(query_digest) = query_digest {
        headers.insert(
            String::from("x-hartevo-query-digest"),
            query_digest.to_string(),
        );
    }
    if let Some(pit_digest) = pit_digest {
        headers.insert(String::from("x-hartevo-pit-digest"), pit_digest.to_string());
    }
    headers
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum OpenSearchProviderCall {
    Describe {
        manifest_digest: Digest,
    },
    CreatePit {
        scope_digest: Digest,
        request_digest: Digest,
    },
    Search {
        scope_digest: Digest,
        query_digest: Digest,
        pit_digest: Digest,
        cursor_digest: Option<Digest>,
    },
}

/// Provider port used by the typed service. It has no write or delete method.
pub trait OpenSearchRetrievalProvider: fmt::Debug {
    fn manifest(&self) -> OpenSearchProviderManifest;

    fn create_pit(
        &self,
        request: &OpenSearchPitRequest,
    ) -> Result<OpenSearchPitResponse, OpenSearchProviderError>;

    fn search(
        &self,
        request: &OpenSearchSearchRequest,
    ) -> Result<OpenSearchPage, OpenSearchProviderError>;

    fn external_write_available(&self) -> bool {
        false
    }
}

#[derive(Default)]
struct RecordingState {
    calls: Vec<OpenSearchProviderCall>,
    pit_responses: VecDeque<Result<OpenSearchPitResponse, OpenSearchProviderError>>,
    search_responses: VecDeque<Result<OpenSearchPage, OpenSearchProviderError>>,
    fault: Option<OpenSearchProviderError>,
}

/// Deterministic fixture/recording/fake/loopback provider. It performs no
/// network I/O and always reports `BLOCKED_ENV`, `connected=false`.
#[derive(Clone)]
pub struct OpenSearchProvider {
    manifest: Arc<Mutex<OpenSearchProviderManifest>>,
    state: Arc<Mutex<RecordingState>>,
    secret_reference: Option<SecretReference>,
}

impl fmt::Debug for OpenSearchProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenSearchProvider")
            .field("manifest_digest", &self.manifest().manifest_digest)
            .field("secret_reference", &self.secret_reference)
            .finish_non_exhaustive()
    }
}

impl OpenSearchProvider {
    pub fn new(manifest: OpenSearchProviderManifest) -> Result<Self, OpenSearchEvidenceError> {
        if manifest.registration.enabled {
            manifest.validate()?;
        }
        Ok(Self {
            manifest: Arc::new(Mutex::new(manifest)),
            state: Arc::new(Mutex::new(RecordingState::default())),
            secret_reference: None,
        })
    }

    pub fn fixture(scope: OpenSearchScope) -> Result<Self, OpenSearchEvidenceError> {
        let mapping = OpenSearchMapping::fixture()?;
        let policy = OpenSearchQueryPolicy::fixture()?;
        Self::new(OpenSearchProviderManifest::new(
            scope,
            mapping,
            policy,
            OpenSearchProviderMode::Fixture,
            OpenSearchProvenance::Fixture,
            OpenSearchAuthMode::Fixture,
            1,
        )?)
    }

    pub fn recording(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(OpenSearchProviderManifest::recording(
            scope, mapping, policy,
        )?)
    }

    pub fn fake(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(OpenSearchProviderManifest::fake(scope, mapping, policy)?)
    }

    pub fn loopback(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(OpenSearchProviderManifest::loopback(
            scope, mapping, policy,
        )?)
    }

    pub fn blocked_env(
        scope: OpenSearchScope,
        mapping: OpenSearchMapping,
        policy: OpenSearchQueryPolicy,
    ) -> Result<Self, OpenSearchEvidenceError> {
        Self::new(OpenSearchProviderManifest::blocked_env(
            scope, mapping, policy,
        )?)
    }

    #[must_use]
    pub fn with_secret_reference(mut self, reference: SecretReference) -> Self {
        self.secret_reference = Some(reference);
        self
    }

    #[must_use]
    pub fn with_fault(self, fault: OpenSearchProviderError) -> Self {
        self.set_fault(fault);
        self
    }

    #[must_use]
    pub fn with_pit_response(
        self,
        response: Result<OpenSearchPitResponse, OpenSearchProviderError>,
    ) -> Self {
        self.set_pit_response(response);
        self
    }

    #[must_use]
    pub fn with_search_response(
        self,
        response: Result<OpenSearchPage, OpenSearchProviderError>,
    ) -> Self {
        self.set_search_response(response);
        self
    }

    pub fn set_fault(&self, fault: OpenSearchProviderError) {
        self.state.lock().expect("recording state lock").fault = Some(fault);
    }

    pub fn clear_fault(&self) {
        self.state.lock().expect("recording state lock").fault = None;
    }

    pub fn set_pit_response(
        &self,
        response: Result<OpenSearchPitResponse, OpenSearchProviderError>,
    ) {
        self.state
            .lock()
            .expect("recording state lock")
            .pit_responses
            .push_back(response);
    }

    pub fn set_search_response(&self, response: Result<OpenSearchPage, OpenSearchProviderError>) {
        self.state
            .lock()
            .expect("recording state lock")
            .search_responses
            .push_back(response);
    }

    pub fn set_search_responses(
        &self,
        responses: impl IntoIterator<Item = Result<OpenSearchPage, OpenSearchProviderError>>,
    ) {
        self.state
            .lock()
            .expect("recording state lock")
            .search_responses
            .extend(responses);
    }

    pub fn set_manifest(&self, manifest: OpenSearchProviderManifest) {
        *self.manifest.lock().expect("manifest lock") = manifest;
    }

    pub fn current_manifest(&self) -> OpenSearchProviderManifest {
        self.manifest.lock().expect("manifest lock").clone()
    }

    #[must_use]
    pub fn calls(&self) -> Vec<OpenSearchProviderCall> {
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .clone()
    }

    pub fn revoke_secret(&mut self) {
        if let Some(reference) = &mut self.secret_reference {
            reference.revoke();
        }
    }

    pub fn revoke(&self) -> Result<OpenSearchProviderManifest, OpenSearchEvidenceError> {
        let next = self.current_manifest().revoked()?;
        self.set_manifest(next.clone());
        Ok(next)
    }

    pub fn reactivate(&self) -> Result<OpenSearchProviderManifest, OpenSearchEvidenceError> {
        let next = self.current_manifest().reactivated()?;
        self.set_manifest(next.clone());
        Ok(next)
    }

    pub fn request_plan_for_pit(
        &self,
        request: &OpenSearchPitRequest,
    ) -> Result<OpenSearchRequestPlan, OpenSearchEvidenceError> {
        OpenSearchRequestPlan::for_pit(
            &request.scope,
            request.keep_alive_seconds,
            self.current_manifest().auth_mode,
        )
    }

    pub fn request_plan_for_search(
        &self,
        request: &OpenSearchSearchRequest,
    ) -> Result<OpenSearchRequestPlan, OpenSearchEvidenceError> {
        let pit = request
            .pit
            .as_ref()
            .ok_or(OpenSearchEvidenceError::InvalidCursor)?;
        OpenSearchRequestPlan::for_search(
            &request.scope,
            request.query_digest(),
            &pit.pit_digest,
            request
                .cursor
                .as_ref()
                .map(OpenSearchSearchAfterCursor::digest),
            self.current_manifest().auth_mode,
        )
    }

    pub fn create_pit(
        &self,
        request: &OpenSearchPitRequest,
    ) -> Result<OpenSearchPitResponse, OpenSearchProviderError> {
        <Self as OpenSearchRetrievalProvider>::create_pit(self, request)
    }

    pub fn search(
        &self,
        request: &OpenSearchSearchRequest,
    ) -> Result<OpenSearchPage, OpenSearchProviderError> {
        <Self as OpenSearchRetrievalProvider>::search(self, request)
    }

    #[must_use]
    pub const fn external_write_available(&self) -> bool {
        false
    }

    fn check_manifest_and_scope(
        &self,
        scope: &OpenSearchScope,
    ) -> Result<OpenSearchProviderManifest, OpenSearchProviderError> {
        let manifest = self.current_manifest();
        if !manifest.registration.enabled {
            return Err(OpenSearchProviderError::RegistrationRevoked);
        }
        manifest
            .validate()
            .map_err(|_| OpenSearchProviderError::ManifestMismatch)?;
        if manifest.scope != *scope {
            return Err(OpenSearchProviderError::ScopeMismatch);
        }
        if manifest.auth_mode.requires_secret_reference() {
            let Some(reference) = &self.secret_reference else {
                return Err(OpenSearchProviderError::SecretReferenceRequired);
            };
            if reference.scope_digest() != &scope.digest() {
                return Err(OpenSearchProviderError::SecretScopeMismatch);
            }
            if reference.is_revoked() {
                return Err(OpenSearchProviderError::SecretRevoked);
            }
        }
        if matches!(manifest.mode, OpenSearchProviderMode::BlockedEnv) {
            return Err(OpenSearchProviderError::BlockedEnv);
        }
        Ok(manifest)
    }

    fn default_pit(
        request: &OpenSearchPitRequest,
        manifest: &OpenSearchProviderManifest,
    ) -> Result<OpenSearchPitResponse, OpenSearchProviderError> {
        let token = format!(
            "fixture-pit-{}-{}",
            manifest.provider_revision,
            request.scope.digest().as_str().get(..12).unwrap_or("scope")
        );
        OpenSearchPitResponse::recorded(
            request,
            manifest,
            token,
            request
                .issued_at_epoch_seconds
                .saturating_add(u64::from(request.keep_alive_seconds)),
        )
        .map_err(|_| OpenSearchProviderError::InvalidResponse)
    }

    fn default_page(
        request: &OpenSearchSearchRequest,
        manifest: &OpenSearchProviderManifest,
    ) -> Result<OpenSearchPage, OpenSearchProviderError> {
        let mut source = BTreeMap::new();
        for field in request.proposal.query.source_fields() {
            source.insert(
                field.clone(),
                if field == "priority" {
                    OpenSearchSourceValue::Integer(1)
                } else {
                    OpenSearchSourceValue::Text(format!("fixture-{field}"))
                },
            );
        }
        let hit = OpenSearchHit::new(
            "fixture-hit-1",
            request
                .proposal
                .query
                .sort()
                .iter()
                .map(|field| {
                    if field.field == "_id" {
                        OpenSearchSortValue::Text(String::from("fixture-hit-1"))
                    } else {
                        OpenSearchSortValue::Integer(1)
                    }
                })
                .collect(),
            source,
        )
        .map_err(|_| OpenSearchProviderError::InvalidResponse)?;
        OpenSearchPage::new(
            request,
            manifest,
            vec![hit],
            1,
            OpenSearchTotalRelation::Eq,
            false,
            Vec::new(),
            None,
            Some(1),
        )
        .map_err(|_| OpenSearchProviderError::InvalidResponse)
    }
}

impl OpenSearchRetrievalProvider for OpenSearchProvider {
    fn manifest(&self) -> OpenSearchProviderManifest {
        self.current_manifest()
    }

    fn create_pit(
        &self,
        request: &OpenSearchPitRequest,
    ) -> Result<OpenSearchPitResponse, OpenSearchProviderError> {
        let manifest = self.check_manifest_and_scope(&request.scope)?;
        if let Some(fault) = self
            .state
            .lock()
            .expect("recording state lock")
            .fault
            .clone()
        {
            return Err(fault);
        }
        self.state.lock().expect("recording state lock").calls.push(
            OpenSearchProviderCall::CreatePit {
                scope_digest: request.scope.digest(),
                request_digest: request.digest(),
            },
        );
        if let Some(response) = self
            .state
            .lock()
            .expect("recording state lock")
            .pit_responses
            .pop_front()
        {
            return response;
        }
        Self::default_pit(request, &manifest)
    }

    fn search(
        &self,
        request: &OpenSearchSearchRequest,
    ) -> Result<OpenSearchPage, OpenSearchProviderError> {
        let manifest = self.check_manifest_and_scope(&request.scope)?;
        let pit = request
            .pit
            .as_ref()
            .ok_or(OpenSearchProviderError::InvalidResponse)?;
        if pit.is_expired_at(request.now_epoch_seconds) {
            return Err(OpenSearchProviderError::PitExpired);
        }
        if let Some(fault) = self
            .state
            .lock()
            .expect("recording state lock")
            .fault
            .clone()
        {
            return Err(fault);
        }
        self.state.lock().expect("recording state lock").calls.push(
            OpenSearchProviderCall::Search {
                scope_digest: request.scope.digest(),
                query_digest: request.query_digest().clone(),
                pit_digest: pit.pit_digest.clone(),
                cursor_digest: request
                    .cursor
                    .as_ref()
                    .map(|cursor| cursor.cursor_digest.clone()),
            },
        );
        if let Some(response) = self
            .state
            .lock()
            .expect("recording state lock")
            .search_responses
            .pop_front()
        {
            return response;
        }
        Self::default_page(request, &manifest)
    }

    fn external_write_available(&self) -> bool {
        false
    }
}

pub type RecordingOpenSearchProvider = OpenSearchProvider;
pub type FakeOpenSearchProvider = OpenSearchProvider;
pub type FixtureOpenSearchProvider = OpenSearchProvider;
pub type LoopbackOpenSearchProvider = OpenSearchProvider;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
}

impl OpenSearchServiceDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            id: SERVICE_ID.to_owned(),
            version: PLUGIN_VERSION,
            contract_digest: contract_digest(),
            operations: vec![
                String::from("describe_capabilities"),
                String::from("compile_bounded_query_proposal"),
                String::from("create_point_in_time_proposal"),
                String::from("search_with_pit_and_search_after"),
                String::from("paginate_bounded_evidence"),
                String::from("create_receipt_candidate"),
                String::from("verify_read_projection"),
                String::from("propose_retrieval_evidence"),
            ],
            read_only: true,
            proposal_only: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchProviderDefinition {
    pub id: String,
    pub provider_revision: u64,
    pub provenance: OpenSearchProvenance,
    pub auth_mode: OpenSearchAuthMode,
    pub native_status: NativeStatus,
    pub external_write: bool,
    pub connected: bool,
    pub native: bool,
}

impl OpenSearchProviderDefinition {
    fn from_manifest(manifest: &OpenSearchProviderManifest) -> Self {
        Self {
            id: manifest.provider_id.clone(),
            provider_revision: manifest.provider_revision,
            provenance: manifest.provenance,
            auth_mode: manifest.auth_mode.clone(),
            native_status: NativeStatus::BlockedEnv,
            external_write: false,
            connected: false,
            native: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRetrievalEvidenceConsumerDefinition {
    pub id: String,
    pub authority: String,
    pub can_adopt: bool,
    pub can_claim_verified_source: bool,
}

impl Default for MissionRetrievalEvidenceConsumerDefinition {
    fn default() -> Self {
        Self {
            id: CONSUMER_ID.to_owned(),
            authority: String::from("provider_evidence_below_kernel_authority"),
            can_adopt: false,
            can_claim_verified_source: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchCapabilityDescription {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub service: OpenSearchServiceDefinition,
    pub provider: OpenSearchProviderDefinition,
    pub consumer: MissionRetrievalEvidenceConsumerDefinition,
    pub scope_digest: Digest,
    pub mapping_digest: Digest,
    pub policy_digest: Digest,
    pub registration_digest: Digest,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRetrievalEvidenceRequest {
    pub scope: OpenSearchScope,
    pub claim_id: ClaimId,
    pub result_id: ResultId,
    pub result_revision: u64,
    pub consent_digest: Digest,
    pub policy_digest: Digest,
}

impl MissionRetrievalEvidenceRequest {
    pub fn new(
        scope: OpenSearchScope,
        claim_id: ClaimId,
        result_id: ResultId,
        result_revision: u64,
        consent_digest: Digest,
        policy_digest: Digest,
    ) -> Result<Self, OpenSearchEvidenceError> {
        scope.validate()?;
        claim_id.validate()?;
        result_id.validate()?;
        if result_revision == 0 || !consent_digest.is_valid() || !policy_digest.is_valid() {
            return Err(OpenSearchEvidenceError::InvalidEvidenceBinding);
        }
        Ok(Self {
            scope,
            claim_id,
            result_id,
            result_revision,
            consent_digest,
            policy_digest,
        })
    }

    pub fn for_scope(
        scope: OpenSearchScope,
        claim_id: ClaimId,
        result_id: ResultId,
        result_revision: u64,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let scope_digest = scope.digest();
        Self::new(
            scope,
            claim_id,
            result_id,
            result_revision,
            Digest::from_text(&format!("consent:{}", scope_digest.as_str())),
            Digest::from_text("policy:opensearch-layer1"),
        )
    }

    #[must_use]
    pub fn binding_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchReceiptCandidate {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub mapping_digest: Digest,
    pub pit_digest: Digest,
    pub result_digest: Digest,
    pub page_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub provider_provenance: OpenSearchProvenance,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub adopted: bool,
    pub receipt_digest: Digest,
}

impl OpenSearchReceiptCandidate {
    fn new(scope: &OpenSearchScope, page: &OpenSearchPage) -> Self {
        let candidate = Self {
            scope_digest: scope.digest(),
            query_digest: page.query_digest.clone(),
            mapping_digest: page.mapping_digest.clone(),
            pit_digest: page.pit_digest.clone(),
            result_digest: page.result_digest.clone(),
            page_digest: page.page_digest.clone(),
            provider_manifest_digest: page.provider_manifest_digest.clone(),
            provider_provenance: page.provenance,
            durable: false,
            native: false,
            connected: false,
            adopted: false,
            receipt_digest: Digest::from_text("uninitialized-receipt"),
        };
        let receipt_digest = canonical_digest(&ReceiptDigestInput {
            scope_digest: &candidate.scope_digest,
            query_digest: &candidate.query_digest,
            mapping_digest: &candidate.mapping_digest,
            pit_digest: &candidate.pit_digest,
            result_digest: &candidate.result_digest,
            page_digest: &candidate.page_digest,
            provider_manifest_digest: &candidate.provider_manifest_digest,
            provider_provenance: candidate.provider_provenance,
            durable: false,
            native: false,
            connected: false,
            adopted: false,
        });
        Self {
            receipt_digest,
            ..candidate
        }
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        if self.durable || self.native || self.connected || self.adopted {
            return Err(OpenSearchEvidenceError::ExternalWriteAuthority);
        }
        let expected = canonical_digest(&ReceiptDigestInput {
            scope_digest: &self.scope_digest,
            query_digest: &self.query_digest,
            mapping_digest: &self.mapping_digest,
            pit_digest: &self.pit_digest,
            result_digest: &self.result_digest,
            page_digest: &self.page_digest,
            provider_manifest_digest: &self.provider_manifest_digest,
            provider_provenance: self.provider_provenance,
            durable: self.durable,
            native: self.native,
            connected: self.connected,
            adopted: self.adopted,
        });
        if expected != self.receipt_digest {
            return Err(OpenSearchEvidenceError::EvidenceDigestMismatch);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct ReceiptDigestInput<'a> {
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    mapping_digest: &'a Digest,
    pit_digest: &'a Digest,
    result_digest: &'a Digest,
    page_digest: &'a Digest,
    provider_manifest_digest: &'a Digest,
    provider_provenance: OpenSearchProvenance,
    durable: bool,
    native: bool,
    connected: bool,
    adopted: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchReadVerification {
    pub status: OpenSearchResultStatus,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub mapping_digest: Digest,
    pub result_digest: Digest,
    pub page_digest: Digest,
    pub receipt_digest: Digest,
    pub complete: bool,
    pub metadata_only: bool,
    pub read_back: bool,
    pub kernel_verified: bool,
    pub verification_digest: Digest,
}

impl OpenSearchReadVerification {
    fn new(
        scope: &OpenSearchScope,
        page: &OpenSearchPage,
        receipt: &OpenSearchReceiptCandidate,
    ) -> Self {
        let verification = Self {
            status: page.status,
            scope_digest: scope.digest(),
            query_digest: page.query_digest.clone(),
            mapping_digest: page.mapping_digest.clone(),
            result_digest: page.result_digest.clone(),
            page_digest: page.page_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            complete: matches!(
                page.status,
                OpenSearchResultStatus::Present | OpenSearchResultStatus::Empty
            ),
            metadata_only: true,
            read_back: false,
            kernel_verified: false,
            verification_digest: Digest::from_text("uninitialized-verification"),
        };
        let verification_digest = canonical_digest(&VerificationDigestInput {
            status: verification.status,
            scope_digest: &verification.scope_digest,
            query_digest: &verification.query_digest,
            mapping_digest: &verification.mapping_digest,
            result_digest: &verification.result_digest,
            page_digest: &verification.page_digest,
            receipt_digest: &verification.receipt_digest,
            complete: verification.complete,
            metadata_only: true,
            read_back: false,
            kernel_verified: false,
        });
        Self {
            verification_digest,
            ..verification
        }
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        if !self.metadata_only || self.read_back || self.kernel_verified {
            return Err(OpenSearchEvidenceError::ExternalWriteAuthority);
        }
        let expected = canonical_digest(&VerificationDigestInput {
            status: self.status,
            scope_digest: &self.scope_digest,
            query_digest: &self.query_digest,
            mapping_digest: &self.mapping_digest,
            result_digest: &self.result_digest,
            page_digest: &self.page_digest,
            receipt_digest: &self.receipt_digest,
            complete: self.complete,
            metadata_only: self.metadata_only,
            read_back: self.read_back,
            kernel_verified: self.kernel_verified,
        });
        if expected != self.verification_digest {
            return Err(OpenSearchEvidenceError::EvidenceDigestMismatch);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct VerificationDigestInput<'a> {
    status: OpenSearchResultStatus,
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    mapping_digest: &'a Digest,
    result_digest: &'a Digest,
    page_digest: &'a Digest,
    receipt_digest: &'a Digest,
    complete: bool,
    metadata_only: bool,
    read_back: bool,
    kernel_verified: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchEvidenceProposal {
    pub mission_binding: MissionRetrievalEvidenceRequest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub mapping_digest: Digest,
    pub result_digest: Digest,
    pub page_digest: Digest,
    pub registration_digest: Digest,
    pub status: OpenSearchResultStatus,
    pub total: u64,
    pub hit_count: usize,
    pub complete: bool,
    pub receipt_candidate: OpenSearchReceiptCandidate,
    pub adopted: bool,
    pub kernel_verified: bool,
    pub can_claim_verified_source: bool,
    pub proposal_digest: Digest,
}

impl OpenSearchEvidenceProposal {
    fn new(
        request: &MissionRetrievalEvidenceRequest,
        page: &OpenSearchPage,
        registration: &OpenSearchRegistration,
        receipt_candidate: OpenSearchReceiptCandidate,
    ) -> Self {
        let proposal = Self {
            mission_binding: request.clone(),
            scope_digest: request.scope.digest(),
            query_digest: page.query_digest.clone(),
            mapping_digest: page.mapping_digest.clone(),
            result_digest: page.result_digest.clone(),
            page_digest: page.page_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            status: page.status,
            total: page.total,
            hit_count: page.hits.len(),
            complete: matches!(
                page.status,
                OpenSearchResultStatus::Present | OpenSearchResultStatus::Empty
            ),
            receipt_candidate,
            adopted: false,
            kernel_verified: false,
            can_claim_verified_source: false,
            proposal_digest: Digest::from_text("uninitialized-proposal"),
        };
        let proposal_digest = canonical_digest(&ProposalDigestInput {
            mission_binding: &proposal.mission_binding,
            scope_digest: &proposal.scope_digest,
            query_digest: &proposal.query_digest,
            mapping_digest: &proposal.mapping_digest,
            result_digest: &proposal.result_digest,
            page_digest: &proposal.page_digest,
            registration_digest: &proposal.registration_digest,
            status: proposal.status,
            total: proposal.total,
            hit_count: proposal.hit_count,
            complete: proposal.complete,
            receipt_digest: &proposal.receipt_candidate.receipt_digest,
            adopted: false,
            kernel_verified: false,
            can_claim_verified_source: false,
        });
        Self {
            proposal_digest,
            ..proposal
        }
    }

    pub fn validate(&self) -> Result<(), OpenSearchEvidenceError> {
        self.receipt_candidate.validate()?;
        self.mission_binding.scope.validate()?;
        if self.adopted || self.kernel_verified || self.can_claim_verified_source {
            return Err(OpenSearchEvidenceError::ExternalWriteAuthority);
        }
        let expected = canonical_digest(&ProposalDigestInput {
            mission_binding: &self.mission_binding,
            scope_digest: &self.scope_digest,
            query_digest: &self.query_digest,
            mapping_digest: &self.mapping_digest,
            result_digest: &self.result_digest,
            page_digest: &self.page_digest,
            registration_digest: &self.registration_digest,
            status: self.status,
            total: self.total,
            hit_count: self.hit_count,
            complete: self.complete,
            receipt_digest: &self.receipt_candidate.receipt_digest,
            adopted: self.adopted,
            kernel_verified: self.kernel_verified,
            can_claim_verified_source: self.can_claim_verified_source,
        });
        if expected != self.proposal_digest {
            return Err(OpenSearchEvidenceError::EvidenceDigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn requires_kernel_verification(&self) -> bool {
        true
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    mission_binding: &'a MissionRetrievalEvidenceRequest,
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    mapping_digest: &'a Digest,
    result_digest: &'a Digest,
    page_digest: &'a Digest,
    registration_digest: &'a Digest,
    status: OpenSearchResultStatus,
    total: u64,
    hit_count: usize,
    complete: bool,
    receipt_digest: &'a Digest,
    adopted: bool,
    kernel_verified: bool,
    can_claim_verified_source: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSearchPaginatedResult {
    pub pages: Vec<OpenSearchPage>,
    pub hits: Vec<OpenSearchHit>,
    pub total: u64,
    pub status: OpenSearchResultStatus,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub mapping_digest: Digest,
    pub pit_digest: Digest,
    pub result_digest: Digest,
    pub page_count: u16,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub adopted: bool,
    #[serde(skip)]
    pub next_cursor: Option<OpenSearchSearchAfterCursor>,
}

impl OpenSearchPaginatedResult {
    fn from_pages(
        pages: Vec<OpenSearchPage>,
        scope: &OpenSearchScope,
        query_digest: &Digest,
        mapping_digest: &Digest,
        pit_digest: &Digest,
    ) -> Result<Self, OpenSearchEvidenceError> {
        let first = pages
            .first()
            .ok_or(OpenSearchEvidenceError::PaginationBudgetExceeded)?;
        if pages.len() > MAX_PAGES as usize
            || first.scope.digest() != scope.digest()
            || first.query_digest != *query_digest
            || first.mapping_digest != *mapping_digest
            || first.pit_digest != *pit_digest
        {
            return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
        }
        let mut hits = Vec::new();
        let mut total = 0;
        let mut status = OpenSearchResultStatus::Empty;
        for page in &pages {
            page.validate()?;
            if page.scope.digest() != scope.digest()
                || page.query_digest != *query_digest
                || page.mapping_digest != *mapping_digest
                || page.pit_digest != *pit_digest
            {
                return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
            }
            hits.extend(page.hits.clone());
            total = page.total;
            status = page.status;
            if hits.len() > MAX_HITS {
                return Err(OpenSearchEvidenceError::PaginationBudgetExceeded);
            }
        }
        let page_digests: Vec<_> = pages.iter().map(|page| page.page_digest.clone()).collect();
        let result_digest = canonical_digest(&PaginatedDigestInput {
            scope_digest: &scope.digest(),
            query_digest,
            mapping_digest,
            pit_digest,
            page_digests: &page_digests,
            hit_count: hits.len(),
            total,
            status,
        });
        let next_cursor = pages.last().and_then(|page| page.next_cursor.clone());
        let page_count = u16::try_from(pages.len())
            .map_err(|_| OpenSearchEvidenceError::PaginationBudgetExceeded)?;
        Ok(Self {
            page_count,
            pages,
            hits,
            total,
            status,
            scope_digest: scope.digest(),
            query_digest: query_digest.clone(),
            mapping_digest: mapping_digest.clone(),
            pit_digest: pit_digest.clone(),
            result_digest,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            adopted: false,
            next_cursor,
        })
    }
}

#[derive(Serialize)]
struct PaginatedDigestInput<'a> {
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    mapping_digest: &'a Digest,
    pit_digest: &'a Digest,
    page_digests: &'a [Digest],
    hit_count: usize,
    total: u64,
    status: OpenSearchResultStatus,
}

/// Typed OpenSearch service. Every operation revalidates registration,
/// provider digest, exact scope, mapping, policy, and Layer 1 authority.
#[derive(Debug)]
pub struct OpenSearchRetrievalService<P> {
    provider: P,
    bound_manifest_digest: Digest,
}

impl<P> OpenSearchRetrievalService<P>
where
    P: OpenSearchRetrievalProvider,
{
    pub fn new(provider: P) -> Result<Self, OpenSearchEvidenceError> {
        let manifest = provider.manifest();
        if !manifest.registration.enabled {
            return Err(OpenSearchEvidenceError::RegistrationRevoked);
        }
        manifest.validate()?;
        if provider.external_write_available() {
            return Err(OpenSearchEvidenceError::ExternalWriteAuthority);
        }
        Ok(Self {
            bound_manifest_digest: manifest.manifest_digest.clone(),
            provider,
        })
    }

    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn provider_manifest(&self) -> Result<OpenSearchProviderManifest, OpenSearchEvidenceError> {
        self.ensure_provider()
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<OpenSearchCapabilityDescription, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        Ok(OpenSearchCapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            service: OpenSearchServiceDefinition::layer1(),
            provider: OpenSearchProviderDefinition::from_manifest(&manifest),
            consumer: MissionRetrievalEvidenceConsumerDefinition::default(),
            scope_digest: manifest.scope.digest(),
            mapping_digest: manifest.mapping.digest.clone(),
            policy_digest: manifest.policy.digest.clone(),
            registration_digest: manifest.registration.registration_digest.clone(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            external_write: false,
        })
    }

    pub fn compile_query_proposal(
        &self,
        query: OpenSearchQuery,
    ) -> Result<OpenSearchQueryProposal, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        OpenSearchQueryProposal::new(&manifest.scope, &manifest.mapping, &manifest.policy, query)
    }

    pub fn create_pit(
        &self,
        request: &OpenSearchPitRequest,
    ) -> Result<OpenSearchPitResponse, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        if request.scope != manifest.scope {
            return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
        }
        let response = self.provider.create_pit(request)?;
        response.validate()?;
        ensure_pit_binding(&response, request, &manifest)?;
        Ok(response)
    }

    pub fn search(
        &self,
        request: &OpenSearchSearchRequest,
    ) -> Result<OpenSearchPage, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        validate_search_request(request, &manifest)?;
        let page = self.provider.search(request)?;
        ensure_page_binding(&page, request, &manifest)?;
        page.validate()?;
        validate_page_hits(&page, &request.proposal.query, &manifest.policy)?;
        Ok(page)
    }

    pub fn paginate(
        &self,
        initial: OpenSearchSearchRequest,
        max_pages: u16,
    ) -> Result<OpenSearchPaginatedResult, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        if max_pages == 0 || max_pages > manifest.policy.max_pages || max_pages > MAX_PAGES {
            return Err(OpenSearchEvidenceError::PaginationBudgetExceeded);
        }
        let pit = initial
            .pit
            .clone()
            .ok_or(OpenSearchEvidenceError::InvalidCursor)?;
        let mut request = initial;
        let mut pages = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut seen_pages = BTreeSet::new();
        loop {
            if pages.len() >= max_pages as usize {
                return Err(OpenSearchEvidenceError::PaginationBudgetExceeded);
            }
            if let Some(cursor) = &request.cursor
                && !seen_cursors.insert(cursor.cursor_digest.clone())
            {
                return Err(OpenSearchEvidenceError::CursorLoop);
            }
            let page = self.search(&request)?;
            if !seen_pages.insert(page.page_digest.clone()) {
                return Err(OpenSearchEvidenceError::CursorLoop);
            }
            let next = page.next_cursor.clone();
            pages.push(page);
            let Some(next_cursor) = next else {
                break;
            };
            request = OpenSearchSearchRequest::at(
                request.scope.clone(),
                request.proposal.clone(),
                pit.clone(),
                Some(next_cursor),
                request.now_epoch_seconds,
            )?;
        }
        OpenSearchPaginatedResult::from_pages(
            pages,
            &manifest.scope,
            request.query_digest(),
            manifest.mapping.digest(),
            &pit.pit_digest,
        )
    }

    pub fn create_receipt_candidate(
        &self,
        page: &OpenSearchPage,
    ) -> Result<OpenSearchReceiptCandidate, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        if page.scope != manifest.scope {
            return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
        }
        page.validate()?;
        if page.provider_manifest_digest != manifest.manifest_digest {
            return Err(OpenSearchEvidenceError::ProviderManifestDrift {
                expected: manifest.manifest_digest,
                actual: page.provider_manifest_digest.clone(),
            });
        }
        Ok(OpenSearchReceiptCandidate::new(&manifest.scope, page))
    }

    pub fn verify_read_projection(
        &self,
        page: &OpenSearchPage,
    ) -> Result<OpenSearchReadVerification, OpenSearchEvidenceError> {
        let receipt = self.create_receipt_candidate(page)?;
        let verification = OpenSearchReadVerification::new(&page.scope, page, &receipt);
        verification.validate()?;
        Ok(verification)
    }

    pub fn propose_retrieval_evidence(
        &self,
        request: &MissionRetrievalEvidenceRequest,
        page: &OpenSearchPage,
    ) -> Result<OpenSearchEvidenceProposal, OpenSearchEvidenceError> {
        let manifest = self.ensure_provider()?;
        if request.scope != manifest.scope || page.scope != manifest.scope {
            return Err(OpenSearchEvidenceError::InvalidEvidenceBinding);
        }
        if request.policy_digest != *manifest.policy.digest() {
            return Err(OpenSearchEvidenceError::InvalidEvidenceBinding);
        }
        page.validate()?;
        let receipt = self.create_receipt_candidate(page)?;
        let proposal =
            OpenSearchEvidenceProposal::new(request, page, &manifest.registration, receipt);
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn consume_page(
        &self,
        request: &MissionRetrievalEvidenceRequest,
        page: &OpenSearchPage,
    ) -> Result<MissionRetrievalEvidence, OpenSearchEvidenceError> {
        let proposal = self.propose_retrieval_evidence(request, page)?;
        let verification = self.verify_read_projection(page)?;
        Ok(MissionRetrievalEvidence {
            proposal,
            receipt_candidate: self.create_receipt_candidate(page)?,
            verification,
        })
    }

    fn ensure_provider(&self) -> Result<OpenSearchProviderManifest, OpenSearchEvidenceError> {
        let manifest = self.provider.manifest();
        if !manifest.registration.enabled {
            return Err(OpenSearchEvidenceError::RegistrationRevoked);
        }
        manifest.validate()?;
        if self.provider.external_write_available() {
            return Err(OpenSearchEvidenceError::ExternalWriteAuthority);
        }
        if manifest.manifest_digest != self.bound_manifest_digest {
            return Err(OpenSearchEvidenceError::ProviderManifestDrift {
                expected: self.bound_manifest_digest.clone(),
                actual: manifest.manifest_digest,
            });
        }
        Ok(manifest)
    }
}

fn validate_search_request(
    request: &OpenSearchSearchRequest,
    manifest: &OpenSearchProviderManifest,
) -> Result<(), OpenSearchEvidenceError> {
    if request.scope != manifest.scope {
        return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
    }
    request
        .proposal
        .validate_for(&manifest.scope, &manifest.mapping, &manifest.policy)?;
    let pit = request
        .pit
        .as_ref()
        .ok_or(OpenSearchEvidenceError::InvalidCursor)?;
    if pit.scope_digest != request.scope.digest()
        || pit.mapping_digest != *request.scope.mapping_digest()
        || pit.is_expired_at(request.now_epoch_seconds)
    {
        return Err(OpenSearchEvidenceError::PitExpired);
    }
    if let Some(cursor) = &request.cursor {
        if cursor.pit_digest() != &pit.pit_digest || cursor.query_digest != *request.query_digest()
        {
            return Err(OpenSearchEvidenceError::CursorIdentityMismatch);
        }
        if cursor.values.len() != request.proposal.query.sort.len() {
            return Err(OpenSearchEvidenceError::SortInstability);
        }
    }
    Ok(())
}

fn ensure_pit_binding(
    response: &OpenSearchPitResponse,
    request: &OpenSearchPitRequest,
    manifest: &OpenSearchProviderManifest,
) -> Result<(), OpenSearchEvidenceError> {
    if response.scope != request.scope
        || response.scope != manifest.scope
        || response.mapping_digest != *manifest.mapping.digest()
        || response.provider_manifest_digest != manifest.manifest_digest
        || response.provenance != manifest.provenance
        || response.native_status != NativeStatus::BlockedEnv
    {
        return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
    }
    Ok(())
}

fn ensure_page_binding(
    page: &OpenSearchPage,
    request: &OpenSearchSearchRequest,
    manifest: &OpenSearchProviderManifest,
) -> Result<(), OpenSearchEvidenceError> {
    let pit = request
        .pit
        .as_ref()
        .ok_or(OpenSearchEvidenceError::InvalidCursor)?;
    if page.mapping_digest != *manifest.mapping.digest() {
        return Err(OpenSearchEvidenceError::MappingDrift {
            expected: manifest.mapping.digest.clone(),
            actual: page.mapping_digest.clone(),
        });
    }
    if page.scope != manifest.scope
        || page.scope != request.scope
        || page.query_digest != *request.query_digest()
        || page.pit_digest != pit.pit_digest
        || page.provider_manifest_digest != manifest.manifest_digest
        || page.provenance != manifest.provenance
        || page.native_status != NativeStatus::BlockedEnv
    {
        return Err(OpenSearchEvidenceError::ProposalBindingMismatch);
    }
    if let Some(cursor) = &page.next_cursor
        && (cursor.pit_digest() != &page.pit_digest || cursor.query_digest != page.query_digest)
    {
        return Err(OpenSearchEvidenceError::CursorIdentityMismatch);
    }
    Ok(())
}

fn validate_page_hits(
    page: &OpenSearchPage,
    query: &OpenSearchQuery,
    policy: &OpenSearchQueryPolicy,
) -> Result<(), OpenSearchEvidenceError> {
    if page.hits.len() > query.page_size as usize || page.hits.len() > policy.max_hits {
        return Err(OpenSearchEvidenceError::InvalidProviderResponse);
    }
    let expected_sort_len = query.sort.len();
    for hit in &page.hits {
        if hit.sort_values.len() != expected_sort_len {
            return Err(OpenSearchEvidenceError::SortInstability);
        }
        for field in hit.source.keys() {
            if !query.source_fields.contains(field) || !policy.allows_source_field(field) {
                return Err(OpenSearchEvidenceError::FieldNotAllowlisted {
                    field: field.clone(),
                });
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRetrievalEvidence {
    pub proposal: OpenSearchEvidenceProposal,
    pub receipt_candidate: OpenSearchReceiptCandidate,
    pub verification: OpenSearchReadVerification,
}

/// Mission-facing consumer. It composes provider evidence below kernel
/// authority and never adopts a Work Product or claims native connectivity.
#[derive(Debug)]
pub struct MissionRetrievalEvidenceConsumer<P>
where
    P: OpenSearchRetrievalProvider,
{
    service: OpenSearchRetrievalService<P>,
}

impl<P> MissionRetrievalEvidenceConsumer<P>
where
    P: OpenSearchRetrievalProvider,
{
    pub fn new(service: OpenSearchRetrievalService<P>) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn definition() -> MissionRetrievalEvidenceConsumerDefinition {
        MissionRetrievalEvidenceConsumerDefinition::default()
    }

    #[must_use]
    pub fn service(&self) -> &OpenSearchRetrievalService<P> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut OpenSearchRetrievalService<P> {
        &mut self.service
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<OpenSearchCapabilityDescription, OpenSearchEvidenceError> {
        self.service.describe_capabilities()
    }

    pub fn compile_query_proposal(
        &self,
        query: OpenSearchQuery,
    ) -> Result<OpenSearchQueryProposal, OpenSearchEvidenceError> {
        self.service.compile_query_proposal(query)
    }

    pub fn create_pit(
        &self,
        request: &OpenSearchPitRequest,
    ) -> Result<OpenSearchPitResponse, OpenSearchEvidenceError> {
        self.service.create_pit(request)
    }

    pub fn search(
        &self,
        request: &OpenSearchSearchRequest,
    ) -> Result<OpenSearchPage, OpenSearchEvidenceError> {
        self.service.search(request)
    }

    pub fn consume(
        &self,
        request: &MissionRetrievalEvidenceRequest,
        page: &OpenSearchPage,
    ) -> Result<MissionRetrievalEvidence, OpenSearchEvidenceError> {
        self.service.consume_page(request, page)
    }

    pub fn consume_paginated(
        &self,
        request: &MissionRetrievalEvidenceRequest,
        search_request: OpenSearchSearchRequest,
        max_pages: u16,
    ) -> Result<MissionRetrievalEvidence, OpenSearchEvidenceError> {
        let result = self.service.paginate(search_request, max_pages)?;
        let last = result
            .pages
            .last()
            .ok_or(OpenSearchEvidenceError::PaginationBudgetExceeded)?;
        self.service.consume_page(request, last)
    }

    #[must_use]
    pub fn into_service(self) -> OpenSearchRetrievalService<P> {
        self.service
    }
}

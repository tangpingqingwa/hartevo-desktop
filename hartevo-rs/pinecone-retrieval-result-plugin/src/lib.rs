//! Layer 1 governed Pinecone retrieval-result boundary.
//!
//! This nested workspace owns typed scope, bounded vector queries and filters,
//! query/fetch provider projections, read-unit/revision/tamper/replay fences,
//! and mission evidence proposals. It deliberately does not own live HTTPS,
//! API-key or service-account resolution, writes, namespace mutation, durable
//! receipts, Memory, Truth, Consent, Effect, Verification, Outcome, or
//! Work Product adoption.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.pinecone-retrieval-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-PINECONE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.pinecone-retrieval-result/v1|layer=1|service=search.pinecone.retrieval.result|provider=pinecone.retrieval.recording|consumer=mission.pinecone.retrieval";
pub const CONTRACT_DIGEST: &str =
    "5f5d9080db719267d7662e4669d394e645a6045863330349fb5f6e81b84042e8";
pub const PLUGIN_ID: &str = "pinecone.retrieval.result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const SERVICE_ID: &str = "search.pinecone.retrieval.result";
pub const PROVIDER_ID: &str = "pinecone.retrieval.recording";
pub const CONSUMER_ID: &str = "mission.pinecone.retrieval";
pub const MAX_VECTOR_DIMENSIONS: usize = 1_536;
pub const MAX_TOP_K: u16 = 100;
pub const MAX_FETCH_IDS: usize = 100;
pub const MAX_METADATA_FIELDS: usize = 64;
pub const MAX_METADATA_VALUE_BYTES: usize = 4_096;
pub const MAX_FILTER_CLAUSES: usize = 32;
pub const MAX_FILTER_DEPTH: u8 = 4;
pub const MAX_READ_UNITS: u32 = 10_000;
pub const MAX_ID_BYTES: usize = 256;
pub const MAX_RESULT_BYTES: usize = 16 * 1024;

/// The checked-in Layer 1 contract is data, not a generic capability catalog.
pub const PINECONE_RETRIEVAL_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/pinecone-retrieval-result/pinecone-retrieval-result.v1.json"
);

/// A lower-case SHA-256 digest used at every public proposal and response fence.
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
    ) -> Result<Self, PineconeEvidenceError> {
        let bytes = serde_json::to_vec(value).map_err(|_| PineconeEvidenceError::DigestInput)?;
        Ok(Self::from_bytes(&bytes))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(&self) -> bool {
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
///
/// # Panics
///
/// Panics only if a value that implements `Serialize` violates its own
/// serialization contract. All public contract values in this crate are
/// infallibly serializable.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value).expect("contract values must serialize")
}

#[must_use]
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

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), PineconeEvidenceError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(PineconeEvidenceError::InvalidInput {
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
) -> Result<(), PineconeEvidenceError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'@' | b':' | b'=')
        })
    {
        return Err(PineconeEvidenceError::InvalidInput {
            field,
            reason: String::from("must contain bounded identifier characters"),
        });
    }
    Ok(())
}

fn validate_field_name(value: &str, field: &'static str) -> Result<(), PineconeEvidenceError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(PineconeEvidenceError::InvalidInput {
            field,
            reason: String::from("must be a bounded metadata field name"),
        });
    }
    Ok(())
}

fn validate_serialized_size<T: Serialize>(value: &T) -> Result<(), PineconeEvidenceError> {
    let size = serde_json::to_vec(value)
        .map_err(|_| PineconeEvidenceError::InvalidProviderResponse)?
        .len();
    if size > MAX_RESULT_BYTES {
        return Err(PineconeEvidenceError::InvalidProviderResponse);
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $alias:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, PineconeEvidenceError> {
                let value = value.into();
                validate_identifier(&value, $field, $max)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        pub type $alias = $name;
    };
}

bounded_identifier!(ProjectId, PineconeProjectId, "project_id", 128);
bounded_identifier!(RegionId, PineconeRegionId, "region", 128);
bounded_identifier!(IndexId, PineconeIndexId, "index", 256);
bounded_identifier!(Namespace, PineconeNamespace, "namespace", 256);
bounded_identifier!(ModelId, PineconeModelId, "model", 128);
bounded_identifier!(VectorId, PineconeVectorId, "vector_id", MAX_ID_BYTES);
bounded_identifier!(MissionId, PineconeMissionId, "mission_id", 128);
bounded_identifier!(ConsentId, PineconeConsentId, "consent_id", 128);
bounded_identifier!(ResultId, PineconeResultId, "result_id", 128);
bounded_identifier!(WorkProductId, PineconeWorkProductId, "work_product_id", 128);

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

    pub fn parse(value: &str) -> Result<Self, PineconeEvidenceError> {
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() != 3 {
            return Err(PineconeEvidenceError::InvalidPluginVersion);
        }
        Ok(Self {
            major: parts[0]
                .parse()
                .map_err(|_| PineconeEvidenceError::InvalidPluginVersion)?,
            minor: parts[1]
                .parse()
                .map_err(|_| PineconeEvidenceError::InvalidPluginVersion)?,
            patch: parts[2]
                .parse()
                .map_err(|_| PineconeEvidenceError::InvalidPluginVersion)?,
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
    ApiKey,
    ServiceAccount,
}

/// Opaque host/keyring reference. It has no Serialize or Display impl and
/// never exposes the opaque identifier in Debug output.
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
    ) -> Result<Self, PineconeEvidenceError> {
        Self::with_kind(SecretKind::ApiKey, opaque_id, scope_digest, revision)
    }

    pub fn with_kind(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, PineconeEvidenceError> {
        let opaque_id = opaque_id.into();
        if opaque_id.trim().is_empty()
            || opaque_id.trim() != opaque_id
            || opaque_id.len() > 256
            || opaque_id.chars().any(char::is_control)
            || !scope_digest.is_valid()
            || revision == 0
        {
            return Err(PineconeEvidenceError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            opaque_id,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn api_key(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::with_kind(SecretKind::ApiKey, opaque_id, scope_digest, revision)
    }

    pub fn service_account(
        opaque_id: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::with_kind(
            SecretKind::ServiceAccount,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeCloud {
    Aws,
    Gcp,
    Azure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeMetric {
    Cosine,
    DotProduct,
    Euclidean,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeReadiness {
    Ready,
    NotReady,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeConsistency {
    Strong,
    Eventual,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconePaginationEvidence {
    pub page: u16,
    pub page_size: u16,
    pub has_more: bool,
    pub bounded: bool,
}

impl PineconePaginationEvidence {
    pub fn new(page: u16, page_size: u16, has_more: bool) -> Result<Self, PineconeEvidenceError> {
        let evidence = Self {
            page,
            page_size,
            has_more,
            bounded: true,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn single(page_size: u16) -> Self {
        Self {
            page: 1,
            page_size,
            has_more: false,
            bounded: true,
        }
    }

    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if self.page == 0 || self.page_size == 0 || self.page_size > MAX_TOP_K || !self.bounded {
            return Err(PineconeEvidenceError::InvalidProviderResponse);
        }
        Ok(())
    }
}

impl PineconeCloud {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
        }
    }
}

/// Exact mission identity carried by the Pinecone scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
}

pub type PineconeMissionScope = MissionScope;

impl MissionScope {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
    ) -> Result<Self, PineconeEvidenceError> {
        project_id.validate()?;
        mission_id.validate()?;
        Ok(Self {
            project_id,
            mission_id,
            mission_revision: 1,
        })
    }

    pub fn at_revision(
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
    ) -> Result<Self, PineconeEvidenceError> {
        let mut scope = Self::new(project_id, mission_id)?;
        if mission_revision == 0 {
            return Err(PineconeEvidenceError::InvalidInput {
                field: "mission_revision",
                reason: String::from("must be non-zero"),
            });
        }
        scope.mission_revision = mission_revision;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        self.project_id.validate()?;
        self.mission_id.validate()?;
        if self.mission_revision == 0 {
            return Err(PineconeEvidenceError::InvalidInput {
                field: "mission_revision",
                reason: String::from("must be non-zero"),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Consent is carried and bound, but its authority remains outside Layer 1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    pub consent_id: ConsentId,
    pub revision: u64,
    pub digest: Digest,
}

pub type PineconeConsentReference = ConsentReference;

impl ConsentReference {
    pub fn new(
        consent_id: ConsentId,
        revision: u64,
        digest: Digest,
    ) -> Result<Self, PineconeEvidenceError> {
        consent_id.validate()?;
        if revision == 0 || !digest.is_valid() {
            return Err(PineconeEvidenceError::InvalidConsent);
        }
        Ok(Self {
            consent_id,
            revision,
            digest,
        })
    }

    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        Self::new(self.consent_id.clone(), self.revision, self.digest.clone()).map(|_| ())
    }
}

/// Exact cloud, region, project, index, host, namespace, consent, and Mission
/// fence. Namespace is data scope only; it has no mutation operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeScope {
    pub cloud: PineconeCloud,
    pub region: RegionId,
    pub project: ProjectId,
    pub index: IndexId,
    pub host: String,
    pub namespace: Namespace,
    pub mission_scope: MissionScope,
    pub consent: ConsentReference,
    pub index_revision: u64,
}

impl PineconeScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cloud: PineconeCloud,
        region: RegionId,
        project: ProjectId,
        index: IndexId,
        host: impl Into<String>,
        namespace: Namespace,
        mission_scope: MissionScope,
        consent: ConsentReference,
        index_revision: u64,
    ) -> Result<Self, PineconeEvidenceError> {
        let scope = Self {
            cloud,
            region,
            project,
            index,
            host: host.into(),
            namespace,
            mission_scope,
            consent,
            index_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn fixture(mission_id: impl Into<String>) -> Result<Self, PineconeEvidenceError> {
        let project = ProjectId::new("project.fixture")?;
        let mission = MissionScope::new(project.clone(), MissionId::new(mission_id)?)?;
        let consent = ConsentReference::new(
            ConsentId::new("consent.fixture")?,
            1,
            Digest::from_text("fixture-consent"),
        )?;
        Self::new(
            PineconeCloud::Aws,
            RegionId::new("us-east-1")?,
            project,
            IndexId::new("fixture-index")?,
            "https://fixture-pinecone.example.test",
            Namespace::new("fixture")?,
            mission,
            consent,
            1,
        )
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        self.region.validate()?;
        self.project.validate()?;
        self.index.validate()?;
        validate_https_host(&self.host)?;
        self.namespace.validate()?;
        self.mission_scope.validate()?;
        self.consent.validate()?;
        if self.project != self.mission_scope.project_id || self.index_revision == 0 {
            return Err(PineconeEvidenceError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_scope.mission_id
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

fn validate_https_host(value: &str) -> Result<(), PineconeEvidenceError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(PineconeEvidenceError::InvalidScope)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(PineconeEvidenceError::InvalidScope);
    }
    let host = remainder.split_once(':').map_or(remainder, |(host, port)| {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            ""
        } else {
            host
        }
    });
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(PineconeEvidenceError::InvalidScope);
    }
    Ok(())
}

/// Closed metadata vocabulary. Raw JSON metadata is never retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum PineconeMetadataValue {
    Text(String),
    Integer(i64),
    Number(String),
    Boolean(bool),
    Null,
}

impl PineconeMetadataValue {
    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        match self {
            Self::Text(value) => validate_text(value, "metadata_value", MAX_METADATA_VALUE_BYTES),
            Self::Number(value) => {
                validate_text(value, "metadata_number", 64)?;
                if value
                    .parse::<f64>()
                    .map_or(true, |number| !number.is_finite())
                {
                    return Err(PineconeEvidenceError::InvalidInput {
                        field: "metadata_number",
                        reason: String::from("must be finite"),
                    });
                }
                Ok(())
            }
            Self::Integer(_) | Self::Boolean(_) | Self::Null => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PineconeMetadata(BTreeMap<String, PineconeMetadataValue>);

impl PineconeMetadata {
    pub fn new(
        values: BTreeMap<String, PineconeMetadataValue>,
    ) -> Result<Self, PineconeEvidenceError> {
        let metadata = Self(values);
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn fixture() -> Result<Self, PineconeEvidenceError> {
        Self::new(BTreeMap::from([
            (
                String::from("topic"),
                PineconeMetadataValue::Text(String::from("retrieval")),
            ),
            (
                String::from("tenant"),
                PineconeMetadataValue::Text(String::from("fixture")),
            ),
        ]))
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if self.0.len() > MAX_METADATA_FIELDS {
            return Err(PineconeEvidenceError::MetadataBudgetExceeded);
        }
        for (field, value) in &self.0 {
            validate_field_name(field, "metadata_field")?;
            value.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn values(&self) -> &BTreeMap<String, PineconeMetadataValue> {
        &self.0
    }

    #[must_use]
    pub fn get(&self, field: &str) -> Option<&PineconeMetadataValue> {
        self.0.get(field)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Vector values are finite and dimension-bounded at construction and again
/// at every provider response boundary.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PineconeVector(Vec<f32>);

impl PineconeVector {
    pub fn new(values: Vec<f32>) -> Result<Self, PineconeEvidenceError> {
        if values.is_empty() || values.len() > MAX_VECTOR_DIMENSIONS {
            return Err(PineconeEvidenceError::VectorBudgetExceeded);
        }
        if values
            .iter()
            .any(|value| !value.is_finite() || value.abs() > 1_000_000.0)
        {
            return Err(PineconeEvidenceError::InvalidVector);
        }
        Ok(Self(values))
    }

    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        Self::new(self.0.clone()).map(|_| ())
    }

    #[must_use]
    pub fn values(&self) -> &[f32] {
        &self.0
    }

    #[must_use]
    pub fn dimensions(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Closed typed filter AST; arbitrary provider filter JSON/DSL is not an API.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum PineconeFilter {
    Eq {
        field: String,
        value: PineconeMetadataValue,
    },
    In {
        field: String,
        values: Vec<PineconeMetadataValue>,
    },
    Gt {
        field: String,
        value: PineconeMetadataValue,
    },
    Gte {
        field: String,
        value: PineconeMetadataValue,
    },
    Lt {
        field: String,
        value: PineconeMetadataValue,
    },
    Lte {
        field: String,
        value: PineconeMetadataValue,
    },
    And(Vec<Box<PineconeFilter>>),
    Or(Vec<Box<PineconeFilter>>),
}

impl PineconeFilter {
    pub fn eq(
        field: impl Into<String>,
        value: PineconeMetadataValue,
    ) -> Result<Self, PineconeEvidenceError> {
        let field = field.into();
        validate_field_name(&field, "filter_field")?;
        value.validate()?;
        Ok(Self::Eq { field, value })
    }

    pub fn in_values(
        field: impl Into<String>,
        values: Vec<PineconeMetadataValue>,
    ) -> Result<Self, PineconeEvidenceError> {
        let field = field.into();
        validate_field_name(&field, "filter_field")?;
        if values.is_empty() || values.len() > MAX_FILTER_CLAUSES {
            return Err(PineconeEvidenceError::FilterBudgetExceeded);
        }
        for value in &values {
            value.validate()?;
        }
        Ok(Self::In { field, values })
    }

    pub fn and(filters: Vec<PineconeFilter>) -> Result<Self, PineconeEvidenceError> {
        Self::group(filters, true)
    }

    pub fn or(filters: Vec<PineconeFilter>) -> Result<Self, PineconeEvidenceError> {
        Self::group(filters, false)
    }

    fn group(
        filters: Vec<PineconeFilter>,
        conjunction: bool,
    ) -> Result<Self, PineconeEvidenceError> {
        if filters.is_empty() || filters.len() > MAX_FILTER_CLAUSES {
            return Err(PineconeEvidenceError::FilterBudgetExceeded);
        }
        let filters = filters.into_iter().map(Box::new).collect();
        Ok(if conjunction {
            Self::And(filters)
        } else {
            Self::Or(filters)
        })
    }

    fn validate_for(
        &self,
        allowed_fields: &BTreeSet<String>,
        depth: u8,
        clauses: &mut usize,
    ) -> Result<(), PineconeEvidenceError> {
        if depth > MAX_FILTER_DEPTH {
            return Err(PineconeEvidenceError::FilterBudgetExceeded);
        }
        *clauses = clauses.saturating_add(1);
        if *clauses > MAX_FILTER_CLAUSES {
            return Err(PineconeEvidenceError::FilterBudgetExceeded);
        }
        let check_value = |field: &str, value: &PineconeMetadataValue| {
            if !allowed_fields.contains(field) {
                return Err(PineconeEvidenceError::FilterFieldNotAllowlisted {
                    field: field.to_owned(),
                });
            }
            value.validate()
        };
        match self {
            Self::Eq { field, value }
            | Self::Gt { field, value }
            | Self::Gte { field, value }
            | Self::Lt { field, value }
            | Self::Lte { field, value } => check_value(field, value),
            Self::In { field, values } => {
                if !allowed_fields.contains(field)
                    || values.is_empty()
                    || values.len() > MAX_FILTER_CLAUSES
                {
                    return Err(PineconeEvidenceError::FilterFieldNotAllowlisted {
                        field: field.clone(),
                    });
                }
                for value in values {
                    value.validate()?;
                }
                Ok(())
            }
            Self::And(filters) | Self::Or(filters) => {
                if filters.is_empty() || filters.len() > MAX_FILTER_CLAUSES {
                    return Err(PineconeEvidenceError::FilterBudgetExceeded);
                }
                for filter in filters {
                    filter.validate_for(allowed_fields, depth.saturating_add(1), clauses)?;
                }
                Ok(())
            }
        }
    }
}

/// Query policy is versioned and digest-bound into the provider registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeQueryPolicy {
    pub model: ModelId,
    pub vector_dimensions: usize,
    pub metric: PineconeMetric,
    pub filter_fields: BTreeSet<String>,
    pub max_top_k: u16,
    pub max_fetch_ids: usize,
    pub max_metadata_fields: usize,
    pub max_metadata_value_bytes: usize,
    pub max_read_units: u32,
    pub digest: Digest,
}

impl PineconeQueryPolicy {
    pub fn new(
        model: ModelId,
        vector_dimensions: usize,
        filter_fields: impl IntoIterator<Item = String>,
        max_top_k: u16,
        max_fetch_ids: usize,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new_with_metric(
            model,
            vector_dimensions,
            PineconeMetric::Cosine,
            filter_fields,
            max_top_k,
            max_fetch_ids,
        )
    }

    pub fn new_with_metric(
        model: ModelId,
        vector_dimensions: usize,
        metric: PineconeMetric,
        filter_fields: impl IntoIterator<Item = String>,
        max_top_k: u16,
        max_fetch_ids: usize,
    ) -> Result<Self, PineconeEvidenceError> {
        let filter_fields: BTreeSet<String> = filter_fields.into_iter().collect();
        if vector_dimensions == 0
            || vector_dimensions > MAX_VECTOR_DIMENSIONS
            || filter_fields.is_empty()
            || max_top_k == 0
            || max_top_k > MAX_TOP_K
            || max_fetch_ids == 0
            || max_fetch_ids > MAX_FETCH_IDS
        {
            return Err(PineconeEvidenceError::InvalidQueryPolicy);
        }
        model.validate()?;
        for field in &filter_fields {
            validate_field_name(field, "filter_policy_field")?;
        }
        let policy = Self {
            model,
            vector_dimensions,
            metric,
            filter_fields,
            max_top_k,
            max_fetch_ids,
            max_metadata_fields: MAX_METADATA_FIELDS,
            max_metadata_value_bytes: MAX_METADATA_VALUE_BYTES,
            max_read_units: MAX_READ_UNITS,
            digest: Digest::from_text("placeholder"),
        };
        let digest = canonical_digest(&PolicyDigestInput {
            model: &policy.model,
            vector_dimensions: policy.vector_dimensions,
            metric: policy.metric,
            filter_fields: &policy.filter_fields,
            max_top_k: policy.max_top_k,
            max_fetch_ids: policy.max_fetch_ids,
            max_metadata_fields: policy.max_metadata_fields,
            max_metadata_value_bytes: policy.max_metadata_value_bytes,
            max_read_units: policy.max_read_units,
        });
        Ok(Self { digest, ..policy })
    }

    pub fn fixture() -> Result<Self, PineconeEvidenceError> {
        Self::new(
            ModelId::new("fixture-embedding-v1")?,
            3,
            [
                String::from("topic"),
                String::from("tenant"),
                String::from("rank"),
            ],
            10,
            10,
        )
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        let expected = Self::new_with_metric(
            self.model.clone(),
            self.vector_dimensions,
            self.metric,
            self.filter_fields.clone(),
            self.max_top_k,
            self.max_fetch_ids,
        )?;
        if expected.digest != self.digest {
            return Err(PineconeEvidenceError::PolicyDrift {
                expected: expected.digest,
                actual: self.digest.clone(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Serialize)]
struct PolicyDigestInput<'a> {
    model: &'a ModelId,
    vector_dimensions: usize,
    metric: PineconeMetric,
    filter_fields: &'a BTreeSet<String>,
    max_top_k: u16,
    max_fetch_ids: usize,
    max_metadata_fields: usize,
    max_metadata_value_bytes: usize,
    max_read_units: u32,
}

/// Redacted index readiness/shape projection. It is descriptive evidence, not
/// a control-plane or connectivity claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeIndexDescription {
    pub dimension: usize,
    pub metric: PineconeMetric,
    pub readiness: PineconeReadiness,
    pub revision: u64,
    pub digest: Digest,
}

impl PineconeIndexDescription {
    pub fn new(
        dimension: usize,
        metric: PineconeMetric,
        readiness: PineconeReadiness,
        revision: u64,
    ) -> Result<Self, PineconeEvidenceError> {
        if dimension == 0 || dimension > MAX_VECTOR_DIMENSIONS || revision == 0 {
            return Err(PineconeEvidenceError::InvalidIndexDescription);
        }
        let mut description = Self {
            dimension,
            metric,
            readiness,
            revision,
            digest: Digest::from_text("placeholder"),
        };
        description.digest = description.digest_input();
        Ok(description)
    }

    fn digest_input(&self) -> Digest {
        canonical_digest(&IndexDescriptionDigestInput {
            dimension: self.dimension,
            metric: self.metric,
            readiness: self.readiness,
            revision: self.revision,
        })
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if self.digest != self.digest_input() {
            return Err(PineconeEvidenceError::IndexDescriptionDrift);
        }
        if self.dimension == 0 || self.dimension > MAX_VECTOR_DIMENSIONS || self.revision == 0 {
            return Err(PineconeEvidenceError::InvalidIndexDescription);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct IndexDescriptionDigestInput {
    dimension: usize,
    metric: PineconeMetric,
    readiness: PineconeReadiness,
    revision: u64,
}

/// Typed Pinecone query. It has no raw filter string or arbitrary JSON field.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeQuery {
    pub model: ModelId,
    pub vector: PineconeVector,
    pub top_k: u16,
    pub filter: Option<PineconeFilter>,
    pub include_metadata: bool,
    pub include_values: bool,
}

impl PineconeQuery {
    pub fn new(
        model: ModelId,
        vector: PineconeVector,
        top_k: u16,
        filter: Option<PineconeFilter>,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::with_options(model, vector, top_k, filter, true, false)
    }

    pub fn with_options(
        model: ModelId,
        vector: PineconeVector,
        top_k: u16,
        filter: Option<PineconeFilter>,
        include_metadata: bool,
        include_values: bool,
    ) -> Result<Self, PineconeEvidenceError> {
        model.validate()?;
        if top_k == 0 || top_k > MAX_TOP_K {
            return Err(PineconeEvidenceError::TopKBudgetExceeded);
        }
        vector.validate()?;
        Ok(Self {
            model,
            vector,
            top_k,
            filter,
            include_metadata,
            include_values,
        })
    }

    pub fn validate_for(&self, policy: &PineconeQueryPolicy) -> Result<(), PineconeEvidenceError> {
        policy.validate()?;
        if self.model != policy.model {
            return Err(PineconeEvidenceError::ModelMismatch);
        }
        if self.vector.dimensions() != policy.vector_dimensions {
            return Err(PineconeEvidenceError::VectorDimensionMismatch {
                expected: policy.vector_dimensions,
                actual: self.vector.dimensions(),
            });
        }
        if self.top_k == 0 || self.top_k > policy.max_top_k {
            return Err(PineconeEvidenceError::TopKBudgetExceeded);
        }
        if let Some(filter) = &self.filter {
            let mut clauses = 0;
            filter.validate_for(&policy.filter_fields, 0, &mut clauses)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeQueryProposal {
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub query_digest: Digest,
    pub proposal_digest: Digest,
    pub query: PineconeQuery,
}

impl PineconeQueryProposal {
    pub fn new(
        scope: &PineconeScope,
        policy: &PineconeQueryPolicy,
        query: PineconeQuery,
    ) -> Result<Self, PineconeEvidenceError> {
        scope.validate()?;
        query.validate_for(policy)?;
        let scope_digest = scope.digest();
        let policy_digest = policy.digest.clone();
        let query_digest = query.digest();
        let proposal_digest = canonical_digest(&ProposalDigestInput {
            scope_digest: &scope_digest,
            policy_digest: &policy_digest,
            query_digest: &query_digest,
        });
        Ok(Self {
            scope_digest,
            policy_digest,
            query_digest,
            proposal_digest,
            query,
        })
    }

    pub fn validate_for(
        &self,
        scope: &PineconeScope,
        policy: &PineconeQueryPolicy,
    ) -> Result<(), PineconeEvidenceError> {
        if self.scope_digest != scope.digest() || self.policy_digest != *policy.digest() {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        self.query.validate_for(policy)?;
        if self.query_digest != self.query.digest() {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        let expected = canonical_digest(&ProposalDigestInput {
            scope_digest: &self.scope_digest,
            policy_digest: &self.policy_digest,
            query_digest: &self.query_digest,
        });
        if expected != self.proposal_digest {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct ProposalDigestInput<'a> {
    scope_digest: &'a Digest,
    policy_digest: &'a Digest,
    query_digest: &'a Digest,
}

/// A query request binds a proposal, exact index revision, and caller nonce.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeQueryRequest {
    pub scope: PineconeScope,
    pub proposal: PineconeQueryProposal,
    pub read_revision: u64,
    pub replay_nonce: String,
    pub request_digest: Digest,
    pub replay_fence: Digest,
}

impl PineconeQueryRequest {
    pub fn new(
        scope: PineconeScope,
        proposal: PineconeQueryProposal,
        read_revision: u64,
        replay_nonce: impl Into<String>,
    ) -> Result<Self, PineconeEvidenceError> {
        scope.validate()?;
        if proposal.scope_digest != scope.digest() {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        Self::new_unchecked_policy(scope, proposal, read_revision, replay_nonce)
    }

    pub fn for_policy(
        scope: PineconeScope,
        proposal: PineconeQueryProposal,
        policy: &PineconeQueryPolicy,
        read_revision: u64,
        replay_nonce: impl Into<String>,
    ) -> Result<Self, PineconeEvidenceError> {
        scope.validate()?;
        proposal.validate_for(&scope, policy)?;
        Self::new_unchecked_policy(scope, proposal, read_revision, replay_nonce)
    }

    fn new_unchecked_policy(
        scope: PineconeScope,
        proposal: PineconeQueryProposal,
        read_revision: u64,
        replay_nonce: impl Into<String>,
    ) -> Result<Self, PineconeEvidenceError> {
        let replay_nonce = replay_nonce.into();
        validate_identifier(&replay_nonce, "replay_nonce", 128)?;
        if read_revision == 0 || read_revision != scope.index_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: scope.index_revision,
                actual: read_revision,
            });
        }
        let request_digest = canonical_digest(&QueryRequestDigestInput {
            scope_digest: &scope.digest(),
            proposal_digest: &proposal.proposal_digest,
            read_revision,
            replay_nonce: &replay_nonce,
        });
        let replay_fence = canonical_digest(&ReplayFenceDigestInput {
            request_digest: &request_digest,
            replay_nonce: &replay_nonce,
        });
        Ok(Self {
            scope,
            proposal,
            read_revision,
            replay_nonce,
            request_digest,
            replay_fence,
        })
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        self.scope.validate()?;
        if self.proposal.scope_digest != self.scope.digest() {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        if self.read_revision == 0 || self.read_revision != self.scope.index_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: self.scope.index_revision,
                actual: self.read_revision,
            });
        }
        validate_identifier(&self.replay_nonce, "replay_nonce", 128)?;
        let expected_request = canonical_digest(&QueryRequestDigestInput {
            scope_digest: &self.scope.digest(),
            proposal_digest: &self.proposal.proposal_digest,
            read_revision: self.read_revision,
            replay_nonce: &self.replay_nonce,
        });
        let expected_replay = canonical_digest(&ReplayFenceDigestInput {
            request_digest: &expected_request,
            replay_nonce: &self.replay_nonce,
        });
        if self.request_digest != expected_request || self.replay_fence != expected_replay {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        Ok(())
    }

    pub fn validate_for(&self, policy: &PineconeQueryPolicy) -> Result<(), PineconeEvidenceError> {
        self.validate()?;
        self.proposal.validate_for(&self.scope, policy)
    }
}

#[derive(Serialize)]
struct QueryRequestDigestInput<'a> {
    scope_digest: &'a Digest,
    proposal_digest: &'a Digest,
    read_revision: u64,
    replay_nonce: &'a str,
}

#[derive(Serialize)]
struct ReplayFenceDigestInput<'a> {
    request_digest: &'a Digest,
    replay_nonce: &'a str,
}

/// Fetch is a bounded read of exact vector IDs in the already-bound namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeFetchRequest {
    pub scope: PineconeScope,
    pub ids: Vec<VectorId>,
    pub read_revision: u64,
    pub replay_nonce: String,
    pub request_digest: Digest,
    pub replay_fence: Digest,
}

impl PineconeFetchRequest {
    pub fn new(
        scope: PineconeScope,
        ids: Vec<VectorId>,
        read_revision: u64,
        replay_nonce: impl Into<String>,
    ) -> Result<Self, PineconeEvidenceError> {
        scope.validate()?;
        if ids.is_empty() || ids.len() > MAX_FETCH_IDS || read_revision == 0 {
            return Err(PineconeEvidenceError::FetchBudgetExceeded);
        }
        let mut seen = BTreeSet::new();
        for id in &ids {
            id.validate()?;
            if !seen.insert(id.clone()) {
                return Err(PineconeEvidenceError::DuplicateVectorId);
            }
        }
        if read_revision != scope.index_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: scope.index_revision,
                actual: read_revision,
            });
        }
        let replay_nonce = replay_nonce.into();
        validate_identifier(&replay_nonce, "replay_nonce", 128)?;
        let scope_digest = scope.digest();
        let request_digest = canonical_digest(&FetchRequestDigestInput {
            scope_digest: &scope_digest,
            ids: &ids,
            read_revision,
            replay_nonce: &replay_nonce,
        });
        let replay_fence = canonical_digest(&ReplayFenceDigestInput {
            request_digest: &request_digest,
            replay_nonce: &replay_nonce,
        });
        Ok(Self {
            scope,
            ids,
            read_revision,
            replay_nonce,
            request_digest,
            replay_fence,
        })
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        self.scope.validate()?;
        if self.ids.is_empty() || self.ids.len() > MAX_FETCH_IDS || self.read_revision == 0 {
            return Err(PineconeEvidenceError::FetchBudgetExceeded);
        }
        let mut seen = BTreeSet::new();
        for id in &self.ids {
            id.validate()?;
            if !seen.insert(id.clone()) {
                return Err(PineconeEvidenceError::DuplicateVectorId);
            }
        }
        if self.read_revision != self.scope.index_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: self.scope.index_revision,
                actual: self.read_revision,
            });
        }
        validate_identifier(&self.replay_nonce, "replay_nonce", 128)?;
        let expected_request = canonical_digest(&FetchRequestDigestInput {
            scope_digest: &self.scope.digest(),
            ids: &self.ids,
            read_revision: self.read_revision,
            replay_nonce: &self.replay_nonce,
        });
        let expected_replay = canonical_digest(&ReplayFenceDigestInput {
            request_digest: &expected_request,
            replay_nonce: &self.replay_nonce,
        });
        if self.request_digest != expected_request || self.replay_fence != expected_replay {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct FetchRequestDigestInput<'a> {
    scope_digest: &'a Digest,
    ids: &'a [VectorId],
    read_revision: u64,
    replay_nonce: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeOperation {
    Query,
    Fetch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeResultStatus {
    Present,
    Empty,
    Partial,
    AccessLoss,
    Deleted,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeMatch {
    pub id: VectorId,
    pub score: f64,
    pub metadata: PineconeMetadata,
    pub values: Option<PineconeVector>,
}

impl PineconeMatch {
    pub fn new(
        id: VectorId,
        score: f64,
        metadata: PineconeMetadata,
        values: Option<PineconeVector>,
    ) -> Result<Self, PineconeEvidenceError> {
        id.validate()?;
        if !score.is_finite() || score.abs() > 1_000_000.0 {
            return Err(PineconeEvidenceError::InvalidScore);
        }
        metadata.validate()?;
        if let Some(values) = &values {
            values.clone().validate()?;
        }
        Ok(Self {
            id,
            score,
            metadata,
            values,
        })
    }

    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        Self::new(
            self.id.clone(),
            self.score,
            self.metadata.clone(),
            self.values.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeFetchedVector {
    pub id: VectorId,
    pub metadata: PineconeMetadata,
    pub values: Option<PineconeVector>,
}

impl PineconeFetchedVector {
    pub fn new(
        id: VectorId,
        metadata: PineconeMetadata,
        values: Option<PineconeVector>,
    ) -> Result<Self, PineconeEvidenceError> {
        id.validate()?;
        metadata.validate()?;
        if let Some(values) = &values {
            values.clone().validate()?;
        }
        Ok(Self {
            id,
            metadata,
            values,
        })
    }

    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        Self::new(self.id.clone(), self.metadata.clone(), self.values.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeQueryResponse {
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub replay_fence: Digest,
    pub revision: u64,
    pub read_units: u32,
    pub consistency: PineconeConsistency,
    pub pagination: PineconePaginationEvidence,
    pub truncated: bool,
    pub matches: Vec<PineconeMatch>,
    pub status: PineconeResultStatus,
    pub response_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

impl PineconeQueryResponse {
    pub fn recorded(
        request: &PineconeQueryRequest,
        manifest: &PineconeProviderManifest,
        matches: Vec<PineconeMatch>,
        read_units: u32,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::recorded_with_evidence(
            request,
            manifest,
            matches,
            read_units,
            PineconeConsistency::Eventual,
            PineconePaginationEvidence::single(request.proposal.query.top_k),
            false,
        )
    }

    pub fn recorded_partial(
        request: &PineconeQueryRequest,
        manifest: &PineconeProviderManifest,
        matches: Vec<PineconeMatch>,
        read_units: u32,
        consistency: PineconeConsistency,
        pagination: PineconePaginationEvidence,
        truncated: bool,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::recorded_with_evidence(
            request,
            manifest,
            matches,
            read_units,
            consistency,
            pagination,
            truncated,
        )
    }

    fn recorded_with_evidence(
        request: &PineconeQueryRequest,
        manifest: &PineconeProviderManifest,
        matches: Vec<PineconeMatch>,
        read_units: u32,
        consistency: PineconeConsistency,
        pagination: PineconePaginationEvidence,
        truncated: bool,
    ) -> Result<Self, PineconeEvidenceError> {
        let status = if truncated || pagination.has_more {
            PineconeResultStatus::Partial
        } else if matches.is_empty() {
            PineconeResultStatus::Empty
        } else {
            PineconeResultStatus::Present
        };
        let mut response = Self {
            scope_digest: request.scope.digest(),
            proposal_digest: request.proposal.proposal_digest.clone(),
            request_digest: request.request_digest.clone(),
            replay_fence: request.replay_fence.clone(),
            revision: request.read_revision,
            read_units,
            consistency,
            pagination,
            truncated,
            matches,
            status,
            response_digest: Digest::from_text("placeholder"),
            provider_manifest_digest: manifest.manifest_digest.clone(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        };
        response.response_digest = response.digest_input();
        response.validate()?;
        Ok(response)
    }

    fn digest_input(&self) -> Digest {
        canonical_digest(&QueryResponseDigestInput {
            scope_digest: &self.scope_digest,
            proposal_digest: &self.proposal_digest,
            request_digest: &self.request_digest,
            replay_fence: &self.replay_fence,
            revision: self.revision,
            read_units: self.read_units,
            consistency: self.consistency,
            pagination: &self.pagination,
            truncated: self.truncated,
            matches: &self.matches,
            status: self.status,
            provider_manifest_digest: &self.provider_manifest_digest,
            native_status: self.native_status,
            connected: self.connected,
            native: self.native,
        })
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if !self.scope_digest.is_valid()
            || !self.proposal_digest.is_valid()
            || !self.request_digest.is_valid()
            || !self.replay_fence.is_valid()
            || !self.provider_manifest_digest.is_valid()
        {
            return Err(PineconeEvidenceError::InvalidDigest {
                field: "query_response",
            });
        }
        if self.revision == 0 || self.read_units == 0 || self.read_units > MAX_READ_UNITS {
            return Err(PineconeEvidenceError::ReadUnitBudgetExceeded);
        }
        if self.matches.len() > usize::from(MAX_TOP_K) {
            return Err(PineconeEvidenceError::InvalidProviderResponse);
        }
        self.pagination.validate()?;
        let mut ids = BTreeSet::new();
        let mut previous_score = None;
        for item in &self.matches {
            item.validate()?;
            if !ids.insert(item.id.clone()) {
                return Err(PineconeEvidenceError::DuplicateVectorId);
            }
            if previous_score.is_some_and(|score| item.score > score) {
                return Err(PineconeEvidenceError::InvalidProviderResponse);
            }
            previous_score = Some(item.score);
        }
        let expected_status = if self.truncated || self.pagination.has_more {
            PineconeResultStatus::Partial
        } else if self.matches.is_empty() {
            PineconeResultStatus::Empty
        } else {
            PineconeResultStatus::Present
        };
        if self.status != expected_status
            || self.native_status != NativeStatus::BlockedEnv
            || self.connected
            || self.native
            || self.response_digest != self.digest_input()
        {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        validate_serialized_size(self)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct QueryResponseDigestInput<'a> {
    scope_digest: &'a Digest,
    proposal_digest: &'a Digest,
    request_digest: &'a Digest,
    replay_fence: &'a Digest,
    revision: u64,
    read_units: u32,
    consistency: PineconeConsistency,
    pagination: &'a PineconePaginationEvidence,
    truncated: bool,
    matches: &'a [PineconeMatch],
    status: PineconeResultStatus,
    provider_manifest_digest: &'a Digest,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeFetchResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub replay_fence: Digest,
    pub revision: u64,
    pub read_units: u32,
    pub consistency: PineconeConsistency,
    pub pagination: PineconePaginationEvidence,
    pub truncated: bool,
    pub vectors: Vec<PineconeFetchedVector>,
    pub status: PineconeResultStatus,
    pub response_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

impl PineconeFetchResponse {
    pub fn recorded(
        request: &PineconeFetchRequest,
        manifest: &PineconeProviderManifest,
        vectors: Vec<PineconeFetchedVector>,
        read_units: u32,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::recorded_with_evidence(
            request,
            manifest,
            vectors,
            read_units,
            PineconeConsistency::Eventual,
            PineconePaginationEvidence::single(1),
            false,
        )
    }

    pub fn recorded_partial(
        request: &PineconeFetchRequest,
        manifest: &PineconeProviderManifest,
        vectors: Vec<PineconeFetchedVector>,
        read_units: u32,
        consistency: PineconeConsistency,
        pagination: PineconePaginationEvidence,
        truncated: bool,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::recorded_with_evidence(
            request,
            manifest,
            vectors,
            read_units,
            consistency,
            pagination,
            truncated,
        )
    }

    fn recorded_with_evidence(
        request: &PineconeFetchRequest,
        manifest: &PineconeProviderManifest,
        vectors: Vec<PineconeFetchedVector>,
        read_units: u32,
        consistency: PineconeConsistency,
        pagination: PineconePaginationEvidence,
        truncated: bool,
    ) -> Result<Self, PineconeEvidenceError> {
        let status = if truncated || pagination.has_more {
            PineconeResultStatus::Partial
        } else if vectors.is_empty() {
            PineconeResultStatus::Empty
        } else {
            PineconeResultStatus::Present
        };
        let mut response = Self {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
            replay_fence: request.replay_fence.clone(),
            revision: request.read_revision,
            read_units,
            consistency,
            pagination,
            truncated,
            vectors,
            status,
            response_digest: Digest::from_text("placeholder"),
            provider_manifest_digest: manifest.manifest_digest.clone(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        };
        response.response_digest = response.digest_input();
        response.validate()?;
        Ok(response)
    }

    fn digest_input(&self) -> Digest {
        canonical_digest(&FetchResponseDigestInput {
            scope_digest: &self.scope_digest,
            request_digest: &self.request_digest,
            replay_fence: &self.replay_fence,
            revision: self.revision,
            read_units: self.read_units,
            consistency: self.consistency,
            pagination: &self.pagination,
            truncated: self.truncated,
            vectors: &self.vectors,
            status: self.status,
            provider_manifest_digest: &self.provider_manifest_digest,
            native_status: self.native_status,
            connected: self.connected,
            native: self.native,
        })
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if !self.scope_digest.is_valid()
            || !self.request_digest.is_valid()
            || !self.replay_fence.is_valid()
            || !self.provider_manifest_digest.is_valid()
        {
            return Err(PineconeEvidenceError::InvalidDigest {
                field: "fetch_response",
            });
        }
        if self.revision == 0 || self.read_units == 0 || self.read_units > MAX_READ_UNITS {
            return Err(PineconeEvidenceError::ReadUnitBudgetExceeded);
        }
        if self.vectors.len() > MAX_FETCH_IDS {
            return Err(PineconeEvidenceError::InvalidProviderResponse);
        }
        self.pagination.validate()?;
        let mut ids = BTreeSet::new();
        for vector in &self.vectors {
            vector.validate()?;
            if !ids.insert(vector.id.clone()) {
                return Err(PineconeEvidenceError::DuplicateVectorId);
            }
        }
        let expected_status = if self.truncated || self.pagination.has_more {
            PineconeResultStatus::Partial
        } else if self.vectors.is_empty() {
            PineconeResultStatus::Empty
        } else {
            PineconeResultStatus::Present
        };
        if self.status != expected_status
            || self.native_status != NativeStatus::BlockedEnv
            || self.connected
            || self.native
            || self.response_digest != self.digest_input()
        {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        validate_serialized_size(self)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct FetchResponseDigestInput<'a> {
    scope_digest: &'a Digest,
    request_digest: &'a Digest,
    replay_fence: &'a Digest,
    revision: u64,
    read_units: u32,
    consistency: PineconeConsistency,
    pagination: &'a PineconePaginationEvidence,
    truncated: bool,
    vectors: &'a [PineconeFetchedVector],
    status: PineconeResultStatus,
    provider_manifest_digest: &'a Digest,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeProviderMode {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
    HttpsSecretReference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
    SecretReferencePlan,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeAuthMode {
    None,
    ApiKeySecretReference,
    ServiceAccountSecretReference,
}

impl PineconeAuthMode {
    #[must_use]
    pub const fn requires_secret_reference(self) -> bool {
        matches!(
            self,
            Self::ApiKeySecretReference | Self::ServiceAccountSecretReference
        )
    }

    #[must_use]
    pub const fn required_kind(self) -> Option<SecretKind> {
        match self {
            Self::ApiKeySecretReference => Some(SecretKind::ApiKey),
            Self::ServiceAccountSecretReference => Some(SecretKind::ServiceAccount),
            Self::None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconePermission {
    DescribeIndex,
    Query,
    Fetch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub permissions: BTreeSet<PineconePermission>,
    pub enabled: bool,
    pub reversible: bool,
    pub registration_digest: Digest,
}

impl PineconeRegistration {
    fn new(scope: &PineconeScope, enabled: bool) -> Self {
        let scope_digest = scope.digest();
        let permissions = BTreeSet::from([
            PineconePermission::DescribeIndex,
            PineconePermission::Fetch,
            PineconePermission::Query,
        ]);
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            contract_digest: contract_digest(),
            scope_digest,
            permissions,
            enabled,
            reversible: true,
            registration_digest: Digest::from_text("placeholder"),
        };
        registration.registration_digest = canonical_digest(&RegistrationDigestInput {
            plugin_id: &registration.plugin_id,
            plugin_version: registration.plugin_version,
            contract_digest: &registration.contract_digest,
            scope_digest: &registration.scope_digest,
            permissions: &registration.permissions,
            enabled: registration.enabled,
            reversible: registration.reversible,
        });
        registration
    }

    pub fn validate(&self, scope: &PineconeScope) -> Result<(), PineconeEvidenceError> {
        let expected = Self::new(scope, self.enabled);
        if self.plugin_id != expected.plugin_id
            || self.plugin_version != expected.plugin_version
            || self.contract_digest != expected.contract_digest
            || self.scope_digest != expected.scope_digest
            || self.permissions != expected.permissions
            || !self.reversible
            || self.registration_digest != expected.registration_digest
        {
            return Err(PineconeEvidenceError::RegistrationDrift);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct RegistrationDigestInput<'a> {
    plugin_id: &'a str,
    plugin_version: PluginVersion,
    contract_digest: &'a Digest,
    scope_digest: &'a Digest,
    permissions: &'a BTreeSet<PineconePermission>,
    enabled: bool,
    reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeProviderManifest {
    pub scope: PineconeScope,
    pub policy: PineconeQueryPolicy,
    pub index: PineconeIndexDescription,
    pub auth_mode: PineconeAuthMode,
    pub mode: PineconeProviderMode,
    pub provenance: PineconeProviderProvenance,
    pub registration: PineconeRegistration,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub manifest_digest: Digest,
}

impl PineconeProviderManifest {
    fn new(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
        auth_mode: PineconeAuthMode,
        mode: PineconeProviderMode,
        provenance: PineconeProviderProvenance,
    ) -> Result<Self, PineconeEvidenceError> {
        scope.validate()?;
        policy.validate()?;
        let index = PineconeIndexDescription::new(
            policy.vector_dimensions,
            policy.metric,
            PineconeReadiness::Ready,
            scope.index_revision,
        )?;
        let manifest = Self {
            registration: PineconeRegistration::new(&scope, true),
            scope,
            policy,
            index,
            auth_mode,
            mode,
            provenance,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            manifest_digest: Digest::from_text("placeholder"),
        };
        Ok(manifest.with_recomputed_digest())
    }

    pub fn fixture(scope: PineconeScope) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            PineconeQueryPolicy::fixture()?,
            PineconeAuthMode::None,
            PineconeProviderMode::Fixture,
            PineconeProviderProvenance::Fixture,
        )
    }

    pub fn recording(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            policy,
            PineconeAuthMode::None,
            PineconeProviderMode::Recording,
            PineconeProviderProvenance::Recording,
        )
    }

    pub fn fake(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            policy,
            PineconeAuthMode::None,
            PineconeProviderMode::Fake,
            PineconeProviderProvenance::Fake,
        )
    }

    pub fn loopback(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            policy,
            PineconeAuthMode::None,
            PineconeProviderMode::Loopback,
            PineconeProviderProvenance::Loopback,
        )
    }

    pub fn blocked_env(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            policy,
            PineconeAuthMode::None,
            PineconeProviderMode::BlockedEnv,
            PineconeProviderProvenance::BlockedEnv,
        )
    }

    pub fn with_index_description(
        mut self,
        index: PineconeIndexDescription,
    ) -> Result<Self, PineconeEvidenceError> {
        index.validate()?;
        self.index = index;
        Ok(self.with_recomputed_digest())
    }

    pub fn api_key_secret_reference(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            policy,
            PineconeAuthMode::ApiKeySecretReference,
            PineconeProviderMode::HttpsSecretReference,
            PineconeProviderProvenance::SecretReferencePlan,
        )
    }

    pub fn https_api_key(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::api_key_secret_reference(scope, policy)
    }

    pub fn service_account_secret_reference(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(
            scope,
            policy,
            PineconeAuthMode::ServiceAccountSecretReference,
            PineconeProviderMode::HttpsSecretReference,
            PineconeProviderProvenance::SecretReferencePlan,
        )
    }

    pub fn https_service_account(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::service_account_secret_reference(scope, policy)
    }

    pub fn validate(&self) -> Result<(), PineconeEvidenceError> {
        self.scope.validate()?;
        self.policy.validate()?;
        self.index.validate()?;
        if self.index.dimension != self.policy.vector_dimensions {
            return Err(PineconeEvidenceError::VectorDimensionMismatch {
                expected: self.policy.vector_dimensions,
                actual: self.index.dimension,
            });
        }
        if self.index.metric != self.policy.metric {
            return Err(PineconeEvidenceError::MetricMismatch);
        }
        if self.index.revision != self.scope.index_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: self.scope.index_revision,
                actual: self.index.revision,
            });
        }
        self.registration.validate(&self.scope)?;
        if self.native_status != NativeStatus::BlockedEnv || self.connected || self.native {
            return Err(PineconeEvidenceError::NativeClaim);
        }
        if self.manifest_digest != self.digest_input() {
            return Err(PineconeEvidenceError::ProviderManifestDrift {
                expected: self.digest_input(),
                actual: self.manifest_digest.clone(),
            });
        }
        Ok(())
    }

    fn digest_input(&self) -> Digest {
        canonical_digest(&ManifestDigestInput {
            scope: &self.scope,
            policy: &self.policy,
            index: &self.index,
            auth_mode: self.auth_mode,
            mode: self.mode,
            provenance: self.provenance,
            registration: &self.registration,
            native_status: self.native_status,
            connected: self.connected,
            native: self.native,
        })
    }

    fn with_recomputed_digest(mut self) -> Self {
        self.manifest_digest = self.digest_input();
        self
    }

    pub fn revoked(&self) -> Result<Self, PineconeEvidenceError> {
        let mut next = self.clone();
        next.registration = PineconeRegistration::new(&next.scope, false);
        Ok(next.with_recomputed_digest())
    }

    pub fn reactivated(&self) -> Result<Self, PineconeEvidenceError> {
        let mut next = self.clone();
        next.registration = PineconeRegistration::new(&next.scope, true);
        Ok(next.with_recomputed_digest())
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        self.native
    }
}

#[derive(Serialize)]
struct ManifestDigestInput<'a> {
    scope: &'a PineconeScope,
    policy: &'a PineconeQueryPolicy,
    index: &'a PineconeIndexDescription,
    auth_mode: PineconeAuthMode,
    mode: PineconeProviderMode,
    provenance: PineconeProviderProvenance,
    registration: &'a PineconeRegistration,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeRequestPlan {
    pub operation: PineconeOperation,
    pub method: String,
    pub path: String,
    pub namespace: Namespace,
    pub secret_reference_required: bool,
    pub auth_mode: PineconeAuthMode,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeAccessLoss {
    Unauthorized,
    Forbidden,
    CredentialRevoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PineconeConflictReason {
    RevisionMismatch,
    ScopeMismatch,
}

#[derive(Clone, Debug, Deserialize, Error, Eq, PartialEq, Serialize)]
pub enum PineconeProviderError {
    #[error("Pinecone access loss: {access:?}")]
    Unauthorized401 { access: PineconeAccessLoss },
    #[error("Pinecone forbidden")]
    Forbidden403,
    #[error("Pinecone index not found; deleted={index_deleted}")]
    NotFound404 { index_deleted: bool },
    #[error("Pinecone conflict: {reason:?}")]
    Conflict409 { reason: PineconeConflictReason },
    #[error("Pinecone rate limited")]
    RateLimited429 { retry_after_seconds: Option<u32> },
    #[error("Pinecone request timed out")]
    Timeout,
    #[error("Pinecone provider internal error")]
    Internal500,
    #[error("Pinecone provider unavailable")]
    ServiceUnavailable503,
    #[error("Pinecone index is not ready")]
    IndexNotReady,
    #[error("Pinecone live environment is blocked")]
    BlockedEnv,
    #[error("Pinecone provider returned an unknown result for {operation:?}")]
    ProviderUnknown { operation: PineconeOperation },
    #[error("Pinecone secret reference is required")]
    SecretReferenceRequired,
}

impl PineconeProviderError {
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            401 => Self::Unauthorized401 {
                access: PineconeAccessLoss::Unauthorized,
            },
            403 => Self::Forbidden403,
            404 => Self::NotFound404 {
                index_deleted: false,
            },
            409 => Self::Conflict409 {
                reason: PineconeConflictReason::ScopeMismatch,
            },
            429 => Self::RateLimited429 {
                retry_after_seconds: None,
            },
            408 | 504 => Self::Timeout,
            500 => Self::Internal500,
            502 | 503 => Self::ServiceUnavailable503,
            _ => Self::ProviderUnknown {
                operation: PineconeOperation::Query,
            },
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized401 { .. } => Some(401),
            Self::Forbidden403 => Some(403),
            Self::NotFound404 { .. } => Some(404),
            Self::Conflict409 { .. } => Some(409),
            Self::RateLimited429 { .. } => Some(429),
            Self::Internal500 => Some(500),
            Self::ServiceUnavailable503 => Some(503),
            Self::Timeout
            | Self::IndexNotReady
            | Self::BlockedEnv
            | Self::ProviderUnknown { .. }
            | Self::SecretReferenceRequired => None,
        }
    }

    #[must_use]
    pub const fn projection_status(&self) -> PineconeResultStatus {
        match self {
            Self::Unauthorized401 { .. } | Self::Forbidden403 => PineconeResultStatus::AccessLoss,
            Self::NotFound404 {
                index_deleted: true,
            } => PineconeResultStatus::Deleted,
            Self::NotFound404 {
                index_deleted: false,
            }
            | Self::Conflict409 { .. }
            | Self::RateLimited429 { .. }
            | Self::Timeout
            | Self::Internal500
            | Self::ServiceUnavailable503
            | Self::IndexNotReady
            | Self::BlockedEnv
            | Self::ProviderUnknown { .. }
            | Self::SecretReferenceRequired => PineconeResultStatus::ProviderUnknown,
        }
    }

    #[must_use]
    pub fn projection(&self) -> PineconeFailureProjection {
        PineconeFailureProjection {
            status: self.projection_status(),
            status_code: self.status_code(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PineconeFailureProjection {
    pub status: PineconeResultStatus,
    pub status_code: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PineconeProviderCall {
    Query {
        scope_digest: Digest,
        request_digest: Digest,
    },
    Fetch {
        scope_digest: Digest,
        request_digest: Digest,
    },
}

pub trait PineconeRetrievalProvider: fmt::Debug {
    fn manifest(&self) -> PineconeProviderManifest;
    fn query(
        &self,
        request: &PineconeQueryRequest,
    ) -> Result<PineconeQueryResponse, PineconeProviderError>;
    fn fetch(
        &self,
        request: &PineconeFetchRequest,
    ) -> Result<PineconeFetchResponse, PineconeProviderError>;
    fn external_write_available(&self) -> bool;
}

#[derive(Debug, Clone)]
struct ProviderState {
    manifest: PineconeProviderManifest,
    secret_reference: Option<SecretReference>,
    fault: Option<PineconeProviderError>,
    query_response: Option<PineconeQueryResponse>,
    fetch_response: Option<PineconeFetchResponse>,
    calls: Vec<PineconeProviderCall>,
}

/// Recording/fake/loopback provider. All live transport and secret resolution
/// remain BLOCKED_ENV; responses are typed fixtures or caller-supplied records.
#[derive(Clone, Debug)]
pub struct PineconeProvider {
    state: Arc<Mutex<ProviderState>>,
}

impl PineconeProvider {
    pub fn new(manifest: PineconeProviderManifest) -> Result<Self, PineconeEvidenceError> {
        if !manifest.registration.enabled {
            return Err(PineconeEvidenceError::RegistrationRevoked);
        }
        manifest.validate()?;
        Ok(Self {
            state: Arc::new(Mutex::new(ProviderState {
                manifest,
                secret_reference: None,
                fault: None,
                query_response: None,
                fetch_response: None,
                calls: Vec::new(),
            })),
        })
    }

    pub fn fixture(scope: PineconeScope) -> Result<Self, PineconeEvidenceError> {
        Self::new(PineconeProviderManifest::fixture(scope)?)
    }

    pub fn recording(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(PineconeProviderManifest::recording(scope, policy)?)
    }

    pub fn fake(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(PineconeProviderManifest::fake(scope, policy)?)
    }

    pub fn loopback(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(PineconeProviderManifest::loopback(scope, policy)?)
    }

    pub fn blocked_env(
        scope: PineconeScope,
        policy: PineconeQueryPolicy,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::new(PineconeProviderManifest::blocked_env(scope, policy)?)
    }

    #[must_use]
    pub fn with_secret_reference(self, reference: SecretReference) -> Self {
        self.state
            .lock()
            .expect("provider mutex is not poisoned")
            .secret_reference = Some(reference);
        self
    }

    #[must_use]
    pub fn with_fault(self, fault: PineconeProviderError) -> Self {
        self.state
            .lock()
            .expect("provider mutex is not poisoned")
            .fault = Some(fault);
        self
    }

    pub fn set_fault(&self, fault: PineconeProviderError) {
        self.state
            .lock()
            .expect("provider mutex is not poisoned")
            .fault = Some(fault);
    }

    pub fn clear_fault(&self) {
        self.state
            .lock()
            .expect("provider mutex is not poisoned")
            .fault = None;
    }

    pub fn set_query_response(
        &self,
        response: Result<PineconeQueryResponse, PineconeProviderError>,
    ) {
        let mut state = self.state.lock().expect("provider mutex is not poisoned");
        match response {
            Ok(response) => state.query_response = Some(response),
            Err(error) => state.fault = Some(error),
        }
    }

    pub fn set_fetch_response(
        &self,
        response: Result<PineconeFetchResponse, PineconeProviderError>,
    ) {
        let mut state = self.state.lock().expect("provider mutex is not poisoned");
        match response {
            Ok(response) => state.fetch_response = Some(response),
            Err(error) => state.fault = Some(error),
        }
    }

    pub fn current_manifest(&self) -> PineconeProviderManifest {
        self.state
            .lock()
            .expect("provider mutex is not poisoned")
            .manifest
            .clone()
    }

    pub fn calls(&self) -> Vec<PineconeProviderCall> {
        self.state
            .lock()
            .expect("provider mutex is not poisoned")
            .calls
            .clone()
    }

    pub fn revoke(&self) -> Result<PineconeProviderManifest, PineconeEvidenceError> {
        let mut state = self.state.lock().expect("provider mutex is not poisoned");
        state.manifest = state.manifest.revoked()?;
        Ok(state.manifest.clone())
    }

    pub fn reactivate(&self) -> Result<PineconeProviderManifest, PineconeEvidenceError> {
        let mut state = self.state.lock().expect("provider mutex is not poisoned");
        state.manifest = state.manifest.reactivated()?;
        Ok(state.manifest.clone())
    }

    pub fn request_plan_for_query(
        &self,
        request: &PineconeQueryRequest,
    ) -> Result<PineconeRequestPlan, PineconeEvidenceError> {
        let manifest = self.current_manifest();
        if request.scope != manifest.scope {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        Ok(PineconeRequestPlan {
            operation: PineconeOperation::Query,
            method: String::from("POST"),
            path: String::from("/query"),
            namespace: manifest.scope.namespace,
            secret_reference_required: manifest.auth_mode.requires_secret_reference(),
            auth_mode: manifest.auth_mode,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        })
    }

    pub fn request_plan_for_fetch(
        &self,
        request: &PineconeFetchRequest,
    ) -> Result<PineconeRequestPlan, PineconeEvidenceError> {
        let manifest = self.current_manifest();
        if request.scope != manifest.scope {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        Ok(PineconeRequestPlan {
            operation: PineconeOperation::Fetch,
            method: String::from("POST"),
            path: String::from("/vectors/fetch"),
            namespace: manifest.scope.namespace,
            secret_reference_required: manifest.auth_mode.requires_secret_reference(),
            auth_mode: manifest.auth_mode,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        })
    }

    fn validate_secret(
        &self,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        let state = self.state.lock().expect("provider mutex is not poisoned");
        if let Some(kind) = manifest.auth_mode.required_kind() {
            let Some(reference) = &state.secret_reference else {
                return Err(PineconeEvidenceError::SecretReferenceRequired);
            };
            if reference.kind() != kind
                || reference.scope_digest() != &manifest.scope.digest()
                || reference.revision() != manifest.scope.index_revision
            {
                return Err(PineconeEvidenceError::InvalidSecretReference);
            }
            if reference.is_revoked() {
                return Err(PineconeEvidenceError::SecretReferenceRevoked);
            }
        }
        Ok(())
    }

    fn default_query_response(
        &self,
        request: &PineconeQueryRequest,
    ) -> Result<PineconeQueryResponse, PineconeEvidenceError> {
        let manifest = self.current_manifest();
        let metadata = if request.proposal.query.include_metadata {
            PineconeMetadata::fixture()?
        } else {
            PineconeMetadata::default()
        };
        let values = request
            .proposal
            .query
            .include_values
            .then(|| PineconeVector::new(vec![0.1; manifest.policy.vector_dimensions]))
            .transpose()?;
        let item = PineconeMatch::new(VectorId::new("fixture-vector-1")?, 0.92, metadata, values)?;
        PineconeQueryResponse::recorded(request, &manifest, vec![item], 1)
    }

    fn default_fetch_response(
        &self,
        request: &PineconeFetchRequest,
    ) -> Result<PineconeFetchResponse, PineconeEvidenceError> {
        let manifest = self.current_manifest();
        let mut vectors = Vec::new();
        for id in &request.ids {
            vectors.push(PineconeFetchedVector::new(
                id.clone(),
                PineconeMetadata::fixture()?,
                Some(PineconeVector::new(vec![
                    0.1;
                    manifest.policy.vector_dimensions
                ])?),
            )?);
        }
        PineconeFetchResponse::recorded(request, &manifest, vectors, 1)
    }
}

impl PineconeRetrievalProvider for PineconeProvider {
    fn manifest(&self) -> PineconeProviderManifest {
        self.current_manifest()
    }

    fn query(
        &self,
        request: &PineconeQueryRequest,
    ) -> Result<PineconeQueryResponse, PineconeProviderError> {
        let mut state = self.state.lock().expect("provider mutex is not poisoned");
        state.calls.push(PineconeProviderCall::Query {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
        });
        let provider_mode = state.manifest.mode;
        if let Some(error) = &state.fault {
            return Err(error.clone());
        }
        if provider_mode == PineconeProviderMode::BlockedEnv {
            return Err(PineconeProviderError::BlockedEnv);
        }
        if state.manifest.index.readiness != PineconeReadiness::Ready {
            return Err(PineconeProviderError::IndexNotReady);
        }
        drop(state);
        self.validate_secret(&self.current_manifest())
            .map_err(|error| match error {
                PineconeEvidenceError::SecretReferenceRequired => {
                    PineconeProviderError::SecretReferenceRequired
                }
                PineconeEvidenceError::SecretReferenceRevoked => {
                    PineconeProviderError::Unauthorized401 {
                        access: PineconeAccessLoss::CredentialRevoked,
                    }
                }
                PineconeEvidenceError::InvalidSecretReference => {
                    PineconeProviderError::Unauthorized401 {
                        access: PineconeAccessLoss::Unauthorized,
                    }
                }
                _ => PineconeProviderError::ProviderUnknown {
                    operation: PineconeOperation::Query,
                },
            })?;
        if provider_mode == PineconeProviderMode::HttpsSecretReference {
            return Err(PineconeProviderError::BlockedEnv);
        }
        let state = self.state.lock().expect("provider mutex is not poisoned");
        if let Some(response) = &state.query_response {
            return Ok(response.clone());
        }
        drop(state);
        self.default_query_response(request)
            .map_err(|_| PineconeProviderError::ProviderUnknown {
                operation: PineconeOperation::Query,
            })
    }

    fn fetch(
        &self,
        request: &PineconeFetchRequest,
    ) -> Result<PineconeFetchResponse, PineconeProviderError> {
        let mut state = self.state.lock().expect("provider mutex is not poisoned");
        state.calls.push(PineconeProviderCall::Fetch {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
        });
        let provider_mode = state.manifest.mode;
        if let Some(error) = &state.fault {
            return Err(error.clone());
        }
        if provider_mode == PineconeProviderMode::BlockedEnv {
            return Err(PineconeProviderError::BlockedEnv);
        }
        if state.manifest.index.readiness != PineconeReadiness::Ready {
            return Err(PineconeProviderError::IndexNotReady);
        }
        drop(state);
        self.validate_secret(&self.current_manifest())
            .map_err(|error| match error {
                PineconeEvidenceError::SecretReferenceRequired => {
                    PineconeProviderError::SecretReferenceRequired
                }
                PineconeEvidenceError::SecretReferenceRevoked => {
                    PineconeProviderError::Unauthorized401 {
                        access: PineconeAccessLoss::CredentialRevoked,
                    }
                }
                PineconeEvidenceError::InvalidSecretReference => {
                    PineconeProviderError::Unauthorized401 {
                        access: PineconeAccessLoss::Unauthorized,
                    }
                }
                _ => PineconeProviderError::ProviderUnknown {
                    operation: PineconeOperation::Fetch,
                },
            })?;
        if provider_mode == PineconeProviderMode::HttpsSecretReference {
            return Err(PineconeProviderError::BlockedEnv);
        }
        let state = self.state.lock().expect("provider mutex is not poisoned");
        if let Some(response) = &state.fetch_response {
            return Ok(response.clone());
        }
        drop(state);
        self.default_fetch_response(request)
            .map_err(|_| PineconeProviderError::ProviderUnknown {
                operation: PineconeOperation::Fetch,
            })
    }

    fn external_write_available(&self) -> bool {
        false
    }
}

pub type RecordingPineconeProvider = PineconeProvider;
pub type FakePineconeProvider = PineconeProvider;
pub type FixturePineconeProvider = PineconeProvider;
pub type LoopbackPineconeProvider = PineconeProvider;

/// Typed Layer 1 errors. No raw provider body or secret is stored here.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PineconeEvidenceError {
    #[error("invalid input for {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("invalid digest for {field}")]
    InvalidDigest { field: &'static str },
    #[error("digest input could not be serialized")]
    DigestInput,
    #[error("invalid plugin version")]
    InvalidPluginVersion,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid consent reference")]
    InvalidConsent,
    #[error("invalid secret reference")]
    InvalidSecretReference,
    #[error("secret reference is revoked")]
    SecretReferenceRevoked,
    #[error("secret reference is required")]
    SecretReferenceRequired,
    #[error("invalid query policy")]
    InvalidQueryPolicy,
    #[error("query policy drift")]
    PolicyDrift { expected: Digest, actual: Digest },
    #[error("registration drift")]
    RegistrationDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("provider manifest drift")]
    ProviderManifestDrift { expected: Digest, actual: Digest },
    #[error("provider exposes external write authority")]
    ExternalWriteAuthority,
    #[error("provider attempted a native or connected claim")]
    NativeClaim,
    #[error("model is not the registered model")]
    ModelMismatch,
    #[error("vector dimension mismatch: expected {expected}, got {actual}")]
    VectorDimensionMismatch { expected: usize, actual: usize },
    #[error("vector dimension or value budget exceeded")]
    VectorBudgetExceeded,
    #[error("invalid vector value")]
    InvalidVector,
    #[error("invalid or unbounded similarity score")]
    InvalidScore,
    #[error("invalid index description")]
    InvalidIndexDescription,
    #[error("index description drift")]
    IndexDescriptionDrift,
    #[error("Pinecone index metric mismatch")]
    MetricMismatch,
    #[error("project scope mismatch")]
    ProjectScopeMismatch,
    #[error("Mission revision mismatch: expected {expected}, got {actual}")]
    MissionRevisionMismatch { expected: u64, actual: u64 },
    #[error("top-k budget exceeded")]
    TopKBudgetExceeded,
    #[error("fetch ID budget exceeded")]
    FetchBudgetExceeded,
    #[error("duplicate vector ID")]
    DuplicateVectorId,
    #[error("metadata budget exceeded")]
    MetadataBudgetExceeded,
    #[error("filter budget exceeded")]
    FilterBudgetExceeded,
    #[error("filter field is not allowlisted: {field}")]
    FilterFieldNotAllowlisted { field: String },
    #[error("proposal binding mismatch")]
    ProposalBindingMismatch,
    #[error("evidence binding mismatch")]
    InvalidEvidenceBinding,
    #[error("consent binding mismatch")]
    ConsentMismatch,
    #[error("Mission scope binding mismatch")]
    MissionScopeMismatch,
    #[error("read revision mismatch: expected {expected}, got {actual}")]
    RevisionMismatch { expected: u64, actual: u64 },
    #[error("read-unit budget exceeded")]
    ReadUnitBudgetExceeded,
    #[error("provider response was tampered or its digest did not verify")]
    TamperedResponse,
    #[error("replay fence was already consumed")]
    ReplayDetected,
    #[error("invalid provider response")]
    InvalidProviderResponse,
    #[error("native read-back or durable adoption is not a Layer 1 authority")]
    Layer1AuthorityUnavailable,
    #[error("provider error: {0}")]
    Provider(#[from] PineconeProviderError),
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeReadReceiptCandidate {
    pub operation: PineconeOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub replay_fence: Digest,
    pub revision: u64,
    pub read_units: u32,
    pub consistency: PineconeConsistency,
    pub pagination: PineconePaginationEvidence,
    pub truncated: bool,
    pub provider_manifest_digest: Digest,
    pub durable: bool,
    pub adopted: bool,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

impl PineconeReadReceiptCandidate {
    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if !self.scope_digest.is_valid()
            || !self.request_digest.is_valid()
            || !self.response_digest.is_valid()
            || !self.replay_fence.is_valid()
            || !self.provider_manifest_digest.is_valid()
            || self.revision == 0
            || self.read_units == 0
            || self.read_units > MAX_READ_UNITS
            || self.pagination.validate().is_err()
            || self.durable
            || self.adopted
            || self.native_status != NativeStatus::BlockedEnv
            || self.connected
            || self.native
        {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeReadVerification {
    pub operation: PineconeOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub replay_fence: Digest,
    pub revision: u64,
    pub read_units: u32,
    pub consistency: PineconeConsistency,
    pub pagination: PineconePaginationEvidence,
    pub truncated: bool,
    pub tamper_checked: bool,
    pub replay_checked: bool,
    pub revision_checked: bool,
    pub read_units_checked: bool,
    pub pagination_checked: bool,
    pub consistency_checked: bool,
    pub truncation_checked: bool,
    pub read_back: bool,
    pub kernel_verified: bool,
}

impl PineconeReadVerification {
    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if !self.tamper_checked
            || !self.replay_checked
            || !self.revision_checked
            || !self.read_units_checked
            || !self.pagination_checked
            || !self.consistency_checked
            || !self.truncation_checked
            || self.read_back
            || self.kernel_verified
            || self.revision == 0
            || self.read_units == 0
            || self.read_units > MAX_READ_UNITS
            || self.pagination.validate().is_err()
        {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionPineconeRetrievalRequest {
    pub scope: PineconeScope,
    pub mission_scope: MissionScope,
    pub consent: ConsentReference,
    pub result_id: ResultId,
    pub work_product_id: Option<WorkProductId>,
    pub binding_digest: Digest,
}

impl MissionPineconeRetrievalRequest {
    pub fn new(scope: PineconeScope, result_id: ResultId) -> Result<Self, PineconeEvidenceError> {
        Self::with_work_product(scope, result_id, None)
    }

    pub fn for_work_product(
        scope: PineconeScope,
        result_id: ResultId,
        work_product_id: WorkProductId,
    ) -> Result<Self, PineconeEvidenceError> {
        Self::with_work_product(scope, result_id, Some(work_product_id))
    }

    fn with_work_product(
        scope: PineconeScope,
        result_id: ResultId,
        work_product_id: Option<WorkProductId>,
    ) -> Result<Self, PineconeEvidenceError> {
        scope.validate()?;
        result_id.validate()?;
        if let Some(work_product_id) = &work_product_id {
            work_product_id.validate()?;
        }
        let mission_scope = scope.mission_scope.clone();
        let consent = scope.consent.clone();
        let binding_digest = canonical_digest(&MissionRequestDigestInput {
            scope_digest: &scope.digest(),
            mission_scope: &mission_scope,
            consent: &consent,
            result_id: &result_id,
            work_product_id: &work_product_id,
        });
        Ok(Self {
            scope,
            mission_scope,
            consent,
            result_id,
            work_product_id,
            binding_digest,
        })
    }

    pub fn validate(&self, scope: &PineconeScope) -> Result<(), PineconeEvidenceError> {
        if self.scope.project != scope.project {
            return Err(PineconeEvidenceError::ProjectScopeMismatch);
        }
        if self.mission_scope != scope.mission_scope {
            if self.mission_scope.mission_revision != scope.mission_scope.mission_revision {
                return Err(PineconeEvidenceError::MissionRevisionMismatch {
                    expected: scope.mission_scope.mission_revision,
                    actual: self.mission_scope.mission_revision,
                });
            }
            return Err(PineconeEvidenceError::MissionScopeMismatch);
        }
        if self.consent != scope.consent {
            return Err(PineconeEvidenceError::ConsentMismatch);
        }
        if self.scope != *scope
            || self.binding_digest
                != canonical_digest(&MissionRequestDigestInput {
                    scope_digest: &self.scope.digest(),
                    mission_scope: &self.mission_scope,
                    consent: &self.consent,
                    result_id: &self.result_id,
                    work_product_id: &self.work_product_id,
                })
        {
            return Err(PineconeEvidenceError::InvalidEvidenceBinding);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct MissionRequestDigestInput<'a> {
    scope_digest: &'a Digest,
    mission_scope: &'a MissionScope,
    consent: &'a ConsentReference,
    result_id: &'a ResultId,
    work_product_id: &'a Option<WorkProductId>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeRetrievalEvidenceProposal {
    pub operation: PineconeOperation,
    pub scope_digest: Digest,
    pub mission_scope_digest: Digest,
    pub consent_digest: Digest,
    pub result_id: ResultId,
    pub work_product_id: Option<WorkProductId>,
    pub work_product_digest: Option<Digest>,
    pub mission_revision: u64,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub replay_fence: Digest,
    pub revision: u64,
    pub read_units: u32,
    pub consistency: PineconeConsistency,
    pub pagination: PineconePaginationEvidence,
    pub truncated: bool,
    pub registration_digest: Digest,
    pub durable: bool,
    pub adopted: bool,
    pub kernel_verified: bool,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

impl PineconeRetrievalEvidenceProposal {
    fn validate(&self) -> Result<(), PineconeEvidenceError> {
        if !self.scope_digest.is_valid()
            || !self.mission_scope_digest.is_valid()
            || !self.consent_digest.is_valid()
            || !self.request_digest.is_valid()
            || !self.response_digest.is_valid()
            || !self.replay_fence.is_valid()
            || !self.registration_digest.is_valid()
            || self
                .work_product_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_valid())
            || self.revision == 0
            || self.mission_revision == 0
            || self.read_units == 0
            || self.read_units > MAX_READ_UNITS
            || self.pagination.validate().is_err()
            || self.durable
            || self.adopted
            || self.kernel_verified
            || self.native_status != NativeStatus::BlockedEnv
            || self.connected
            || self.native
        {
            return Err(PineconeEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PineconeQueryEvidence {
    pub proposal: PineconeRetrievalEvidenceProposal,
    pub receipt_candidate: PineconeReadReceiptCandidate,
    pub verification: PineconeReadVerification,
    pub response: PineconeQueryResponse,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PineconeFetchEvidence {
    pub proposal: PineconeRetrievalEvidenceProposal,
    pub receipt_candidate: PineconeReadReceiptCandidate,
    pub verification: PineconeReadVerification,
    pub response: PineconeFetchResponse,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PineconeRetrievalEvidence {
    Query(PineconeQueryEvidence),
    Fetch(PineconeFetchEvidence),
}

#[derive(Clone, Copy, Debug)]
pub enum PineconeRetrievalResponse<'a> {
    Query(&'a PineconeQueryResponse),
    Fetch(&'a PineconeFetchResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeServiceDefinition {
    pub id: String,
    pub type_name: String,
    pub layer: u8,
    pub reads_only: bool,
    pub live_external_io: bool,
}

impl PineconeServiceDefinition {
    fn layer1() -> Self {
        Self {
            id: SERVICE_ID.to_owned(),
            type_name: String::from("PineconeRetrievalResultService"),
            layer: 1,
            reads_only: true,
            live_external_io: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeProviderDefinition {
    pub id: String,
    pub type_name: String,
    pub provenance: PineconeProviderProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionPineconeRetrievalConsumerDefinition {
    pub id: String,
    pub type_name: String,
    pub layer: u8,
    pub adopts_memory: bool,
    pub claims_consent: bool,
}

impl Default for MissionPineconeRetrievalConsumerDefinition {
    fn default() -> Self {
        Self {
            id: CONSUMER_ID.to_owned(),
            type_name: String::from("MissionPineconeRetrievalConsumer"),
            layer: 1,
            adopts_memory: false,
            claims_consent: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PineconeCapabilityDescription {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub service: PineconeServiceDefinition,
    pub provider: PineconeProviderDefinition,
    pub consumer: MissionPineconeRetrievalConsumerDefinition,
    pub index: PineconeIndexDescription,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub registration_digest: Digest,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_write: bool,
}

/// Typed Layer 1 service. It revalidates registration and all evidence fences
/// on every query/fetch/proposal boundary.
#[derive(Debug)]
pub struct PineconeRetrievalResultService<P> {
    provider: P,
    bound_manifest_digest: Digest,
    replay_fences: Arc<Mutex<BTreeSet<Digest>>>,
}

impl<P> PineconeRetrievalResultService<P>
where
    P: PineconeRetrievalProvider,
{
    pub fn new(provider: P) -> Result<Self, PineconeEvidenceError> {
        let manifest = provider.manifest();
        if !manifest.registration.enabled {
            return Err(PineconeEvidenceError::RegistrationRevoked);
        }
        manifest.validate()?;
        if provider.external_write_available() {
            return Err(PineconeEvidenceError::ExternalWriteAuthority);
        }
        Ok(Self {
            bound_manifest_digest: manifest.manifest_digest,
            provider,
            replay_fences: Arc::new(Mutex::new(BTreeSet::new())),
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

    pub fn provider_manifest(&self) -> Result<PineconeProviderManifest, PineconeEvidenceError> {
        self.ensure_provider()
    }

    pub fn describe_index(&self) -> Result<PineconeIndexDescription, PineconeEvidenceError> {
        Ok(self.ensure_provider()?.index)
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<PineconeCapabilityDescription, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        Ok(PineconeCapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            service: PineconeServiceDefinition::layer1(),
            provider: PineconeProviderDefinition {
                id: PROVIDER_ID.to_owned(),
                type_name: String::from("PineconeProvider"),
                provenance: manifest.provenance,
                native_status: NativeStatus::BlockedEnv,
                connected: false,
                native: false,
                external_write: false,
            },
            consumer: MissionPineconeRetrievalConsumerDefinition::default(),
            index: manifest.index.clone(),
            scope_digest: manifest.scope.digest(),
            policy_digest: manifest.policy.digest.clone(),
            registration_digest: manifest.registration.registration_digest,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            external_write: false,
        })
    }

    pub fn compile_query_proposal(
        &self,
        query: PineconeQuery,
    ) -> Result<PineconeQueryProposal, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        PineconeQueryProposal::new(&manifest.scope, &manifest.policy, query)
    }

    pub fn query(
        &self,
        request: &PineconeQueryRequest,
    ) -> Result<PineconeQueryResponse, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        Self::validate_query_request(request, &manifest)?;
        let response = self.provider.query(request)?;
        Self::validate_query_response(request, &response, &manifest)?;
        self.mark_replay(&response.replay_fence)?;
        Ok(response)
    }

    pub fn fetch(
        &self,
        request: &PineconeFetchRequest,
    ) -> Result<PineconeFetchResponse, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        Self::validate_fetch_request(request, &manifest)?;
        let response = self.provider.fetch(request)?;
        Self::validate_fetch_response(request, &response, &manifest)?;
        self.mark_replay(&response.replay_fence)?;
        Ok(response)
    }

    pub fn create_receipt_candidate(
        &self,
        response: PineconeRetrievalResponse<'_>,
    ) -> Result<PineconeReadReceiptCandidate, PineconeEvidenceError> {
        match response {
            PineconeRetrievalResponse::Query(response) => {
                self.create_query_receipt_candidate(response)
            }
            PineconeRetrievalResponse::Fetch(response) => {
                self.create_fetch_receipt_candidate(response)
            }
        }
    }

    pub fn create_query_receipt_candidate(
        &self,
        response: &PineconeQueryResponse,
    ) -> Result<PineconeReadReceiptCandidate, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        response.validate()?;
        if response.provider_manifest_digest != manifest.manifest_digest {
            return Err(PineconeEvidenceError::ProviderManifestDrift {
                expected: manifest.manifest_digest,
                actual: response.provider_manifest_digest.clone(),
            });
        }
        let receipt = PineconeReadReceiptCandidate {
            operation: PineconeOperation::Query,
            scope_digest: response.scope_digest.clone(),
            request_digest: response.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            replay_fence: response.replay_fence.clone(),
            revision: response.revision,
            read_units: response.read_units,
            consistency: response.consistency,
            pagination: response.pagination.clone(),
            truncated: response.truncated,
            provider_manifest_digest: response.provider_manifest_digest.clone(),
            durable: false,
            adopted: false,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn create_fetch_receipt_candidate(
        &self,
        response: &PineconeFetchResponse,
    ) -> Result<PineconeReadReceiptCandidate, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        response.validate()?;
        if response.provider_manifest_digest != manifest.manifest_digest {
            return Err(PineconeEvidenceError::ProviderManifestDrift {
                expected: manifest.manifest_digest,
                actual: response.provider_manifest_digest.clone(),
            });
        }
        let receipt = PineconeReadReceiptCandidate {
            operation: PineconeOperation::Fetch,
            scope_digest: response.scope_digest.clone(),
            request_digest: response.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            replay_fence: response.replay_fence.clone(),
            revision: response.revision,
            read_units: response.read_units,
            consistency: response.consistency,
            pagination: response.pagination.clone(),
            truncated: response.truncated,
            provider_manifest_digest: response.provider_manifest_digest.clone(),
            durable: false,
            adopted: false,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn verify_read_projection(
        &self,
        response: PineconeRetrievalResponse<'_>,
    ) -> Result<PineconeReadVerification, PineconeEvidenceError> {
        match response {
            PineconeRetrievalResponse::Query(response) => self.verify_query_read(response),
            PineconeRetrievalResponse::Fetch(response) => self.verify_fetch_read(response),
        }
    }

    pub fn verify_query_read(
        &self,
        response: &PineconeQueryResponse,
    ) -> Result<PineconeReadVerification, PineconeEvidenceError> {
        let receipt = self.create_query_receipt_candidate(response)?;
        let verification = PineconeReadVerification {
            operation: PineconeOperation::Query,
            scope_digest: receipt.scope_digest.clone(),
            request_digest: receipt.request_digest.clone(),
            response_digest: receipt.response_digest.clone(),
            replay_fence: receipt.replay_fence.clone(),
            revision: receipt.revision,
            read_units: receipt.read_units,
            consistency: receipt.consistency,
            pagination: receipt.pagination.clone(),
            truncated: receipt.truncated,
            tamper_checked: true,
            replay_checked: true,
            revision_checked: true,
            read_units_checked: true,
            pagination_checked: true,
            consistency_checked: true,
            truncation_checked: true,
            read_back: false,
            kernel_verified: false,
        };
        verification.validate()?;
        Ok(verification)
    }

    pub fn verify_fetch_read(
        &self,
        response: &PineconeFetchResponse,
    ) -> Result<PineconeReadVerification, PineconeEvidenceError> {
        let receipt = self.create_fetch_receipt_candidate(response)?;
        let verification = PineconeReadVerification {
            operation: PineconeOperation::Fetch,
            scope_digest: receipt.scope_digest.clone(),
            request_digest: receipt.request_digest.clone(),
            response_digest: receipt.response_digest.clone(),
            replay_fence: receipt.replay_fence.clone(),
            revision: receipt.revision,
            read_units: receipt.read_units,
            consistency: receipt.consistency,
            pagination: receipt.pagination.clone(),
            truncated: receipt.truncated,
            tamper_checked: true,
            replay_checked: true,
            revision_checked: true,
            read_units_checked: true,
            pagination_checked: true,
            consistency_checked: true,
            truncation_checked: true,
            read_back: false,
            kernel_verified: false,
        };
        verification.validate()?;
        Ok(verification)
    }

    pub fn propose_retrieval_evidence(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: PineconeRetrievalResponse<'_>,
    ) -> Result<PineconeRetrievalEvidence, PineconeEvidenceError> {
        match response {
            PineconeRetrievalResponse::Query(response) => self
                .propose_query_evidence(request, response)
                .map(PineconeRetrievalEvidence::Query),
            PineconeRetrievalResponse::Fetch(response) => self
                .propose_fetch_evidence(request, response)
                .map(PineconeRetrievalEvidence::Fetch),
        }
    }

    pub fn propose_query_evidence(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: &PineconeQueryResponse,
    ) -> Result<PineconeQueryEvidence, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        request.validate(&manifest.scope)?;
        Self::validate_query_response_scope_only(response, &manifest)?;
        let receipt = self.create_query_receipt_candidate(response)?;
        let verification = self.verify_query_read(response)?;
        let proposal =
            Self::make_evidence_proposal(PineconeOperation::Query, request, &receipt, &manifest);
        proposal.validate()?;
        Ok(PineconeQueryEvidence {
            proposal,
            receipt_candidate: receipt,
            verification,
            response: response.clone(),
        })
    }

    pub fn propose_fetch_evidence(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: &PineconeFetchResponse,
    ) -> Result<PineconeFetchEvidence, PineconeEvidenceError> {
        let manifest = self.ensure_provider()?;
        request.validate(&manifest.scope)?;
        Self::validate_fetch_response_scope_only(response, &manifest)?;
        let receipt = self.create_fetch_receipt_candidate(response)?;
        let verification = self.verify_fetch_read(response)?;
        let proposal =
            Self::make_evidence_proposal(PineconeOperation::Fetch, request, &receipt, &manifest);
        proposal.validate()?;
        Ok(PineconeFetchEvidence {
            proposal,
            receipt_candidate: receipt,
            verification,
            response: response.clone(),
        })
    }

    pub fn consume_query(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: &PineconeQueryResponse,
    ) -> Result<PineconeQueryEvidence, PineconeEvidenceError> {
        self.propose_query_evidence(request, response)
    }

    pub fn consume_fetch(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: &PineconeFetchResponse,
    ) -> Result<PineconeFetchEvidence, PineconeEvidenceError> {
        self.propose_fetch_evidence(request, response)
    }

    fn make_evidence_proposal(
        operation: PineconeOperation,
        request: &MissionPineconeRetrievalRequest,
        receipt: &PineconeReadReceiptCandidate,
        manifest: &PineconeProviderManifest,
    ) -> PineconeRetrievalEvidenceProposal {
        PineconeRetrievalEvidenceProposal {
            operation,
            scope_digest: receipt.scope_digest.clone(),
            mission_scope_digest: request.mission_scope.digest(),
            consent_digest: request.consent.digest.clone(),
            result_id: request.result_id.clone(),
            work_product_id: request.work_product_id.clone(),
            work_product_digest: request.work_product_id.as_ref().map(canonical_digest),
            mission_revision: request.mission_scope.mission_revision,
            request_digest: receipt.request_digest.clone(),
            response_digest: receipt.response_digest.clone(),
            replay_fence: receipt.replay_fence.clone(),
            revision: receipt.revision,
            read_units: receipt.read_units,
            consistency: receipt.consistency,
            pagination: receipt.pagination.clone(),
            truncated: receipt.truncated,
            registration_digest: manifest.registration.registration_digest.clone(),
            durable: false,
            adopted: false,
            kernel_verified: false,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        }
    }

    fn ensure_provider(&self) -> Result<PineconeProviderManifest, PineconeEvidenceError> {
        let manifest = self.provider.manifest();
        if !manifest.registration.enabled {
            return Err(PineconeEvidenceError::RegistrationRevoked);
        }
        manifest.validate()?;
        if self.provider.external_write_available() {
            return Err(PineconeEvidenceError::ExternalWriteAuthority);
        }
        if manifest.manifest_digest != self.bound_manifest_digest {
            return Err(PineconeEvidenceError::ProviderManifestDrift {
                expected: self.bound_manifest_digest.clone(),
                actual: manifest.manifest_digest,
            });
        }
        Ok(manifest)
    }

    fn validate_query_request(
        request: &PineconeQueryRequest,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        if request.scope != manifest.scope {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        request.validate_for(&manifest.policy)
    }

    fn validate_fetch_request(
        request: &PineconeFetchRequest,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        if request.scope != manifest.scope || request.ids.len() > manifest.policy.max_fetch_ids {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        request.validate()
    }

    fn validate_query_response(
        request: &PineconeQueryRequest,
        response: &PineconeQueryResponse,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        Self::validate_query_response_scope_only(response, manifest)?;
        if response.proposal_digest != request.proposal.proposal_digest
            || response.request_digest != request.request_digest
            || response.replay_fence != request.replay_fence
        {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        if response.revision != request.read_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: request.read_revision,
                actual: response.revision,
            });
        }
        if response.read_units > manifest.policy.max_read_units {
            return Err(PineconeEvidenceError::ReadUnitBudgetExceeded);
        }
        if response.matches.len() > usize::from(request.proposal.query.top_k) {
            return Err(PineconeEvidenceError::InvalidProviderResponse);
        }
        for item in &response.matches {
            if let Some(values) = &item.values
                && values.dimensions() != manifest.policy.vector_dimensions
            {
                return Err(PineconeEvidenceError::VectorDimensionMismatch {
                    expected: manifest.policy.vector_dimensions,
                    actual: values.dimensions(),
                });
            }
            if (!request.proposal.query.include_metadata && !item.metadata.is_empty())
                || (!request.proposal.query.include_values && item.values.is_some())
            {
                return Err(PineconeEvidenceError::InvalidProviderResponse);
            }
        }
        Ok(())
    }

    fn validate_fetch_response(
        request: &PineconeFetchRequest,
        response: &PineconeFetchResponse,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        Self::validate_fetch_response_scope_only(response, manifest)?;
        if response.request_digest != request.request_digest
            || response.replay_fence != request.replay_fence
        {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        if response.revision != request.read_revision {
            return Err(PineconeEvidenceError::RevisionMismatch {
                expected: request.read_revision,
                actual: response.revision,
            });
        }
        if response.read_units > manifest.policy.max_read_units
            || response
                .vectors
                .iter()
                .any(|item| !request.ids.contains(&item.id))
        {
            return Err(PineconeEvidenceError::InvalidProviderResponse);
        }
        for item in &response.vectors {
            if let Some(values) = &item.values
                && values.dimensions() != manifest.policy.vector_dimensions
            {
                return Err(PineconeEvidenceError::VectorDimensionMismatch {
                    expected: manifest.policy.vector_dimensions,
                    actual: values.dimensions(),
                });
            }
        }
        Ok(())
    }

    fn validate_query_response_scope_only(
        response: &PineconeQueryResponse,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        response.validate()?;
        if response.scope_digest != manifest.scope.digest()
            || response.provider_manifest_digest != manifest.manifest_digest
        {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        Ok(())
    }

    fn validate_fetch_response_scope_only(
        response: &PineconeFetchResponse,
        manifest: &PineconeProviderManifest,
    ) -> Result<(), PineconeEvidenceError> {
        response.validate()?;
        if response.scope_digest != manifest.scope.digest()
            || response.provider_manifest_digest != manifest.manifest_digest
        {
            return Err(PineconeEvidenceError::ProposalBindingMismatch);
        }
        Ok(())
    }

    fn mark_replay(&self, fence: &Digest) -> Result<(), PineconeEvidenceError> {
        let mut fences = self
            .replay_fences
            .lock()
            .expect("replay mutex is not poisoned");
        if !fences.insert(fence.clone()) {
            return Err(PineconeEvidenceError::ReplayDetected);
        }
        Ok(())
    }
}

/// Mission-facing consumer. It proposes evidence below kernel authority and
/// never adopts Memory, Work Product, or Consent authority.
#[derive(Debug)]
pub struct MissionPineconeRetrievalConsumer<P>
where
    P: PineconeRetrievalProvider,
{
    service: PineconeRetrievalResultService<P>,
}

impl<P> MissionPineconeRetrievalConsumer<P>
where
    P: PineconeRetrievalProvider,
{
    pub fn new(service: PineconeRetrievalResultService<P>) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn definition() -> MissionPineconeRetrievalConsumerDefinition {
        MissionPineconeRetrievalConsumerDefinition::default()
    }

    #[must_use]
    pub fn service(&self) -> &PineconeRetrievalResultService<P> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut PineconeRetrievalResultService<P> {
        &mut self.service
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<PineconeCapabilityDescription, PineconeEvidenceError> {
        self.service.describe_capabilities()
    }

    pub fn query(
        &self,
        request: &PineconeQueryRequest,
    ) -> Result<PineconeQueryResponse, PineconeEvidenceError> {
        self.service.query(request)
    }

    pub fn fetch(
        &self,
        request: &PineconeFetchRequest,
    ) -> Result<PineconeFetchResponse, PineconeEvidenceError> {
        self.service.fetch(request)
    }

    pub fn consume_query(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: &PineconeQueryResponse,
    ) -> Result<PineconeQueryEvidence, PineconeEvidenceError> {
        self.service.consume_query(request, response)
    }

    pub fn consume_fetch(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: &PineconeFetchResponse,
    ) -> Result<PineconeFetchEvidence, PineconeEvidenceError> {
        self.service.consume_fetch(request, response)
    }

    pub fn consume(
        &self,
        request: &MissionPineconeRetrievalRequest,
        response: PineconeRetrievalResponse<'_>,
    ) -> Result<PineconeRetrievalEvidence, PineconeEvidenceError> {
        self.service.propose_retrieval_evidence(request, response)
    }

    #[must_use]
    pub fn into_service(self) -> PineconeRetrievalResultService<P> {
        self.service
    }
}

//! Standalone Layer-1 Contentful governed content-result plugin.
//!
//! The crate exposes a bounded, read-only evidence seam for one exact
//! organization/space/environment/content-type/entry/locale and one exact
//! Hartevo Project/Mission/Work Product generation.  It deliberately keeps
//! localized values out of every public evidence and receipt type: only
//! bounded field, locale, reference, request, and response digests survive
//! the provider boundary.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTENTFUL_ENTRY_RESULT_SCHEMA_VERSION: &str =
    "hartevo.contentful-entry-result-contract/v1";
pub const CONTENTFUL_ENTRY_RESULT_CONTRACT_VERSION: &str = "EXT-CONTENTFUL-01-L1/v1";
pub const CONTENTFUL_ENTRY_RESULT_PLUGIN_ID: &str = "contentful-entry-result";
pub const CONTENTFUL_ENTRY_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const CONTENTFUL_ENTRY_RESULT_SERVICE_ID: &str = "ContentfulEntryResultService";
pub const CONTENTFUL_PROVIDER_ID: &str = "ContentfulProvider";
pub const MISSION_CONTENTFUL_RESULT_CONSUMER_ID: &str = "MissionContentfulResultConsumer";
pub const CONTENTFUL_CMA_ORIGIN: &str = "https://api.contentful.com";
pub const CONTENTFUL_CDA_ORIGIN: &str = "https://cdn.contentful.com";
pub const CONTENTFUL_PROVIDER_REVISION: &str = "contentful-cma-cda-r1";
pub const CONTENTFUL_API_REVISION: &str = "contentful-cma-cda-v1";
pub const CONTENTFUL_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const CONTENTFUL_MAX_PAGE_SIZE: u16 = 50;
pub const CONTENTFUL_MAX_PAGES: u16 = 4;
pub const CONTENTFUL_MAX_REFERENCE_DEPTH: u8 = 10;
pub const CONTENTFUL_MAX_REFERENCES: usize = 1_000;
pub const CONTENTFUL_MAX_FIELDS: usize = 128;
pub const CONTENTFUL_MAX_LOCALES: usize = 64;
pub const CONTENTFUL_MAX_IDENTIFIER_LENGTH: usize = 128;
pub const CONTENTFUL_MAX_SECRET_REFERENCE_LENGTH: usize = 256;

/// The checked-in Layer-1 contract document.
pub const CONTENTFUL_ENTRY_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/contentful-entry-result/contentful-entry-result.v1.json"
);

/// A SHA-256 digest used wherever external identity or payload material must
/// be represented without retaining the original value.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(&Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ContentfulModelError> {
        let value = value.into();
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(ContentfulModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    let encoded = serde_json::to_vec(value).expect("contract values must serialize");
    Digest::from_bytes(&encoded)
}

/// Computes a deterministic digest for a caller-provided canonical value.
pub fn contentful_digest<T: Serialize>(value: &T) -> Digest {
    canonical_digest(value)
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_length: usize,
    allow_whitespace: bool,
) -> Result<(), ContentfulModelError> {
    if value.is_empty() {
        return Err(ContentfulModelError::Empty { field });
    }
    if value.len() > max_length {
        return Err(ContentfulModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ContentfulModelError::InvalidText { field });
    }
    if !allow_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ContentfulModelError::InvalidText { field });
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ContentfulModelError> {
                let value = value.into();
                validate_text(&value, $field, CONTENTFUL_MAX_IDENTIFIER_LENGTH, false)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&Digest::from_text(self.as_str()))
                    .finish()
            }
        }
    };
}

bounded_id!(OrganizationId, "organization");
bounded_id!(SpaceId, "space");
bounded_id!(EnvironmentId, "environment");
bounded_id!(ContentTypeId, "content_type");
bounded_id!(EntryId, "entry");
bounded_id!(LocaleCode, "locale");
bounded_id!(ProjectId, "project_id");
bounded_id!(MissionId, "mission_id");
bounded_id!(WorkProductId, "work_product_id");

/// Contentful's optimistic-locking version for an entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentfulVersion(u64);

impl ContentfulVersion {
    pub fn new(value: u64) -> Result<Self, ContentfulModelError> {
        if value == 0 {
            Err(ContentfulModelError::MustBePositive { field: "version" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The bounded publication counter associated with a Contentful entry.
/// Counter zero is valid for an entry that has never been published.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PublishedCounter(u64);

impl PublishedCounter {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// CMA or CDA read provenance.  A Layer-1 provider may describe both API
/// surfaces, but it never exposes a write operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentfulApi {
    Cma,
    Cda,
}

impl ContentfulApi {
    pub const fn origin(self) -> &'static str {
        match self {
            Self::Cma => CONTENTFUL_CMA_ORIGIN,
            Self::Cda => CONTENTFUL_CDA_ORIGIN,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cma => "cma",
            Self::Cda => "cda",
        }
    }
}

/// Evidence source labels are deliberately separate from native status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl EvidenceSource {
    pub const fn is_native(self) -> bool {
        false
    }
}

/// Every currently available source is non-native in Layer 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    pub const fn connected_claim(self) -> bool {
        false
    }
}

/// Projection of the externally observed Contentful entry lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentfulProjection {
    Draft,
    Published,
    Unpublished,
    Archived,
    Deleted,
    #[serde(rename = "provider-unknown")]
    ProviderUnknown,
}

impl ContentfulProjection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Unpublished => "unpublished",
            Self::Archived => "archived",
            Self::Deleted => "deleted",
            Self::ProviderUnknown => "provider-unknown",
        }
    }
}

/// Opaque pointer to a CMA/CDA credential.  The credential value itself is
/// never accepted by this crate, serialized, or placed in a debug string.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    locator: String,
    revision: u64,
}

impl SecretReference {
    pub fn new(locator: impl Into<String>, revision: u64) -> Result<Self, ContentfulModelError> {
        let locator = locator.into();
        validate_text(
            &locator,
            "secret_reference",
            CONTENTFUL_MAX_SECRET_REFERENCE_LENGTH,
            false,
        )?;
        if revision == 0 {
            return Err(ContentfulModelError::MustBePositive {
                field: "secret_reference_revision",
            });
        }
        Ok(Self { locator, revision })
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(&(self.locator.as_str(), self.revision))
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 2)?;
        state.serialize_field("digest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

/// Model validation failures.  These errors do not contain caller payloads.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContentfulModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains invalid text")]
    InvalidText { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("too many {kind}; maximum is {maximum}")]
    BoundExceeded { kind: &'static str, maximum: usize },
    #[error("invalid pagination request")]
    InvalidPagination,
    #[error("invalid reference depth")]
    InvalidReferenceDepth,
}

/// Exact external and Hartevo scope bound to one registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulScope {
    pub organization: OrganizationId,
    pub space: SpaceId,
    pub environment: EnvironmentId,
    pub content_type: ContentTypeId,
    pub entry: EntryId,
    pub locale: LocaleCode,
    pub version: ContentfulVersion,
    pub published_counter: PublishedCounter,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
}

/// String-shaped input for constructing an exact scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentfulScopeInput {
    pub organization: String,
    pub space: String,
    pub environment: String,
    pub content_type: String,
    pub entry: String,
    pub locale: String,
    pub version: u64,
    pub published_counter: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

impl ContentfulScope {
    pub fn new(input: ContentfulScopeInput) -> Result<Self, ContentfulModelError> {
        if input.project_revision == 0
            || input.mission_revision == 0
            || input.work_product_revision == 0
        {
            return Err(ContentfulModelError::MustBePositive {
                field: "scope_revision",
            });
        }
        Ok(Self {
            organization: OrganizationId::new(input.organization)?,
            space: SpaceId::new(input.space)?,
            environment: EnvironmentId::new(input.environment)?,
            content_type: ContentTypeId::new(input.content_type)?,
            entry: EntryId::new(input.entry)?,
            locale: LocaleCode::new(input.locale)?,
            version: ContentfulVersion::new(input.version)?,
            published_counter: PublishedCounter::new(input.published_counter),
            project_id: ProjectId::new(input.project_id)?,
            project_revision: input.project_revision,
            mission_id: MissionId::new(input.mission_id)?,
            mission_revision: input.mission_revision,
            work_product_id: WorkProductId::new(input.work_product_id)?,
            work_product_revision: input.work_product_revision,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Bounded page/cursor request.  Cursor values are never retained in
/// evidence; only a digest of the request is used in a receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentfulPagination {
    pub page: u16,
    pub limit: u16,
    pub cursor: Option<String>,
}

impl ContentfulPagination {
    pub fn new(
        page: u16,
        limit: u16,
        cursor: Option<String>,
    ) -> Result<Self, ContentfulModelError> {
        if page == 0
            || page > CONTENTFUL_MAX_PAGES
            || limit == 0
            || limit > CONTENTFUL_MAX_PAGE_SIZE
        {
            return Err(ContentfulModelError::InvalidPagination);
        }
        if cursor
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > CONTENTFUL_MAX_IDENTIFIER_LENGTH)
        {
            return Err(ContentfulModelError::InvalidPagination);
        }
        Ok(Self {
            page,
            limit,
            cursor,
        })
    }

    pub fn first_page() -> Self {
        Self {
            page: 1,
            limit: CONTENTFUL_MAX_PAGE_SIZE,
            cursor: None,
        }
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Request for a bounded CMA or CDA entry read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentfulReadRequest {
    pub scope: ContentfulScope,
    pub api: ContentfulApi,
    pub pagination: ContentfulPagination,
    pub expected_version: Option<ContentfulVersion>,
    pub expected_published_counter: Option<PublishedCounter>,
}

impl ContentfulReadRequest {
    pub fn new(scope: ContentfulScope, api: ContentfulApi) -> Self {
        Self {
            expected_version: Some(scope.version),
            expected_published_counter: Some(scope.published_counter),
            scope,
            api,
            pagination: ContentfulPagination::first_page(),
        }
    }

    #[must_use]
    pub fn with_pagination(mut self, pagination: ContentfulPagination) -> Self {
        self.pagination = pagination;
        self
    }

    #[must_use]
    pub fn with_expected_version(mut self, version: ContentfulVersion) -> Self {
        self.expected_version = Some(version);
        self
    }

    #[must_use]
    pub fn with_expected_published_counter(mut self, counter: PublishedCounter) -> Self {
        self.expected_published_counter = Some(counter);
        self
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Request for the Contentful recursive entry-reference endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentfulReferenceRequest {
    pub scope: ContentfulScope,
    pub api: ContentfulApi,
    pub pagination: ContentfulPagination,
    pub depth: u8,
}

impl ContentfulReferenceRequest {
    pub fn new(
        scope: ContentfulScope,
        api: ContentfulApi,
        depth: u8,
    ) -> Result<Self, ContentfulModelError> {
        if depth == 0 || depth > CONTENTFUL_MAX_REFERENCE_DEPTH {
            return Err(ContentfulModelError::InvalidReferenceDepth);
        }
        Ok(Self {
            scope,
            api,
            pagination: ContentfulPagination::first_page(),
            depth,
        })
    }

    #[must_use]
    pub fn with_pagination(mut self, pagination: ContentfulPagination) -> Self {
        self.pagination = pagination;
        self
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// A normalized entry projection.  It contains no localized field values,
/// URLs, links, or provider payload; each field is represented by a digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulEntrySnapshot {
    pub organization: OrganizationId,
    pub space: SpaceId,
    pub environment: EnvironmentId,
    pub content_type: ContentTypeId,
    pub entry: EntryId,
    pub projection: ContentfulProjection,
    pub version: ContentfulVersion,
    pub published_counter: PublishedCounter,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub version_observed_at: DateTime<Utc>,
    pub published_counter_observed_at: DateTime<Utc>,
    pub locale_coverage: BTreeSet<LocaleCode>,
    pub field_digests: BTreeMap<String, Digest>,
    pub reference_digest: Option<Digest>,
}

impl ContentfulEntrySnapshot {
    pub fn new(
        scope: &ContentfulScope,
        projection: ContentfulProjection,
        version: ContentfulVersion,
        published_counter: PublishedCounter,
        observed_at: DateTime<Utc>,
        locale_coverage: BTreeSet<LocaleCode>,
        field_digests: BTreeMap<String, Digest>,
        reference_digest: Option<Digest>,
    ) -> Result<Self, ContentfulModelError> {
        if locale_coverage.len() > CONTENTFUL_MAX_LOCALES {
            return Err(ContentfulModelError::BoundExceeded {
                kind: "locales",
                maximum: CONTENTFUL_MAX_LOCALES,
            });
        }
        if field_digests.len() > CONTENTFUL_MAX_FIELDS {
            return Err(ContentfulModelError::BoundExceeded {
                kind: "fields",
                maximum: CONTENTFUL_MAX_FIELDS,
            });
        }
        for field in field_digests.keys() {
            validate_text(field, "field", CONTENTFUL_MAX_IDENTIFIER_LENGTH, false)?;
        }
        Ok(Self {
            organization: scope.organization.clone(),
            space: scope.space.clone(),
            environment: scope.environment.clone(),
            content_type: scope.content_type.clone(),
            entry: scope.entry.clone(),
            projection,
            version,
            published_counter,
            created_at: observed_at,
            updated_at: observed_at,
            published_at: (projection == ContentfulProjection::Published).then_some(observed_at),
            version_observed_at: observed_at,
            published_counter_observed_at: observed_at,
            locale_coverage,
            field_digests,
            reference_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate_for_scope(&self, scope: &ContentfulScope) -> Result<(), ContentfulResultError> {
        if self.organization != scope.organization
            || self.space != scope.space
            || self.environment != scope.environment
            || self.content_type != scope.content_type
            || self.entry != scope.entry
        {
            return Err(ContentfulResultError::ScopeDrift {
                expected: scope.digest(),
                actual: self.digest(),
            });
        }
        if self.locale_coverage.len() > CONTENTFUL_MAX_LOCALES
            || self.field_digests.len() > CONTENTFUL_MAX_FIELDS
        {
            return Err(ContentfulResultError::BoundExceeded {
                kind: "entry projection",
                maximum: CONTENTFUL_MAX_FIELDS,
            });
        }
        if !self.locale_coverage.contains(&scope.locale) {
            return Err(ContentfulResultError::ScopeDrift {
                expected: scope.digest(),
                actual: self.digest(),
            });
        }
        Ok(())
    }
}

/// Metadata for one bounded descendant returned by the entry-references API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulReferenceMetadata {
    pub entry: EntryId,
    pub content_type: ContentTypeId,
    pub projection: ContentfulProjection,
    pub version: ContentfulVersion,
    pub published_counter: PublishedCounter,
    pub locale_coverage: BTreeSet<LocaleCode>,
    pub metadata_digest: Digest,
}

impl ContentfulReferenceMetadata {
    pub fn new(
        entry: EntryId,
        content_type: ContentTypeId,
        projection: ContentfulProjection,
        version: ContentfulVersion,
        published_counter: PublishedCounter,
        locale_coverage: BTreeSet<LocaleCode>,
    ) -> Result<Self, ContentfulModelError> {
        if locale_coverage.len() > CONTENTFUL_MAX_LOCALES {
            return Err(ContentfulModelError::BoundExceeded {
                kind: "reference locales",
                maximum: CONTENTFUL_MAX_LOCALES,
            });
        }
        let metadata_digest = canonical_digest(&(
            &entry,
            &content_type,
            projection,
            version,
            published_counter,
            &locale_coverage,
        ));
        Ok(Self {
            entry,
            content_type,
            projection,
            version,
            published_counter,
            locale_coverage,
            metadata_digest,
        })
    }
}

/// Redacted pagination evidence.  A provider cursor is represented only by a
/// digest, so replay receipts cannot become a cursor or content store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulPaginationEvidence {
    pub page: u16,
    pub limit: u16,
    pub total: usize,
    pub has_more: bool,
    pub next_cursor_digest: Option<Digest>,
}

impl ContentfulPaginationEvidence {
    fn from_request(request: &ContentfulPagination, total: usize) -> Self {
        Self {
            page: request.page,
            limit: request.limit,
            total,
            has_more: false,
            next_cursor_digest: None,
        }
    }
}

/// Bounded receipt for one read.  It records only hashes and non-sensitive
/// response metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulObservationReceipt {
    pub operation: String,
    pub api: ContentfulApi,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_status: u16,
    pub response_size: usize,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub native_connected_claim: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_localized_body_retained: bool,
    pub secret_material_retained: bool,
}

/// Evidence from an entry or published-entry read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulReadEvidence {
    pub entry: ContentfulEntrySnapshot,
    pub pagination: ContentfulPaginationEvidence,
    pub receipt: ContentfulObservationReceipt,
}

/// Evidence from the bounded entry-reference read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulReferenceEvidence {
    pub references: Vec<ContentfulReferenceMetadata>,
    pub depth: u8,
    pub pagination: ContentfulPaginationEvidence,
    pub receipt: ContentfulObservationReceipt,
}

/// Combined Mission-facing content result.  The optional published projection
/// is absent when Contentful reports that no published entry exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulResultEvidence {
    pub scope: ContentfulScope,
    pub draft: ContentfulReadEvidence,
    pub published: Option<ContentfulReadEvidence>,
    pub references: ContentfulReferenceEvidence,
    pub locale_coverage: BTreeSet<LocaleCode>,
    pub field_digests: BTreeMap<String, Digest>,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub result_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub native_connected_claim: bool,
    pub kernel_authority: bool,
}

impl ContentfulResultEvidence {
    pub fn validate(&self) -> Result<(), ContentfulResultError> {
        self.draft.entry.validate_for_scope(&self.scope)?;
        if let Some(published) = &self.published {
            published.entry.validate_for_scope(&self.scope)?;
        }
        if self.references.references.len() > CONTENTFUL_MAX_REFERENCES {
            return Err(ContentfulResultError::BoundExceeded {
                kind: "references",
                maximum: CONTENTFUL_MAX_REFERENCES,
            });
        }
        if self.native_connected_claim || self.kernel_authority {
            return Err(ContentfulResultError::NativeAuthority);
        }
        if self.scope_digest != self.scope.digest() {
            return Err(ContentfulResultError::ReplayOrTamper {
                kind: "scope_digest",
            });
        }
        if self.draft.receipt.scope_digest != self.scope_digest
            || self
                .published
                .as_ref()
                .is_some_and(|evidence| evidence.receipt.scope_digest != self.scope_digest)
            || self.references.receipt.scope_digest != self.scope_digest
            || self.draft.receipt.provider_digest != self.provider_digest
            || self.draft.receipt.api_digest != self.api_digest
            || self.draft.receipt.permission_digest != self.permission_digest
            || self.draft.receipt.revision_digest != self.revision_digest
            || self.published.as_ref().is_some_and(|evidence| {
                evidence.receipt.provider_digest != self.provider_digest
                    || evidence.receipt.api_digest != self.api_digest
                    || evidence.receipt.permission_digest != self.permission_digest
                    || evidence.receipt.revision_digest != self.revision_digest
            })
            || self.references.receipt.provider_digest != self.provider_digest
            || self.references.receipt.api_digest != self.api_digest
            || self.references.receipt.permission_digest != self.permission_digest
            || self.references.receipt.revision_digest != self.revision_digest
            || self.draft.receipt.raw_provider_payload_retained
            || self.draft.receipt.raw_localized_body_retained
            || self.draft.receipt.secret_material_retained
        {
            return Err(ContentfulResultError::ReplayOrTamper {
                kind: "receipt_redaction_or_scope",
            });
        }
        let mut expected_locales = self.draft.entry.locale_coverage.clone();
        if let Some(published) = &self.published {
            expected_locales.extend(published.entry.locale_coverage.iter().cloned());
        }
        if expected_locales != self.locale_coverage
            || self.field_digests != self.draft.entry.field_digests
        {
            return Err(ContentfulResultError::ReplayOrTamper {
                kind: "locale_or_field_digest",
            });
        }
        let expected_result_digest = canonical_digest(&(
            &self.scope,
            self.draft.entry.digest(),
            self.published.as_ref().map(|value| value.entry.digest()),
            &self.references.references,
            &self.draft.receipt.response_digest,
            &self.references.receipt.response_digest,
        ));
        if self.result_digest != expected_result_digest {
            return Err(ContentfulResultError::ReplayOrTamper {
                kind: "result_digest",
            });
        }
        Ok(())
    }
}

/// A proposal-shaped, non-adopting Work Product observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulWorkProductObservation {
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub evidence_digest: Digest,
    pub effect_authority: bool,
    pub outcome_authority: bool,
    pub adopted: bool,
}

/// Typed failures from the provider seam.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContentfulProviderError {
    #[error("Contentful returned 401 Unauthorized")]
    Unauthorized,
    #[error("Contentful returned 403 Forbidden")]
    Forbidden,
    #[error("Contentful returned 404 Not Found")]
    NotFound,
    #[error("Contentful returned 409 Conflict")]
    Conflict,
    #[error("Contentful returned 422 Unprocessable Entity")]
    UnprocessableEntity,
    #[error("Contentful request timed out")]
    Timeout,
    #[error("Contentful returned upstream status {status}")]
    ServerFailure { status: u16 },
    #[error("Contentful response was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Contentful response was malformed")]
    Malformed,
    #[error("Contentful response was partial")]
    Partial,
    #[error("Contentful response exceeded the byte bound: {bytes}")]
    ResponseTooLarge { bytes: usize },
    #[error("Contentful provider scope drifted")]
    ScopeDrift,
    #[error("Contentful provider revision drifted")]
    RevisionDrift,
    #[error("Contentful native environment is unavailable")]
    BlockedEnv,
    #[error("Contentful transport failed")]
    Network,
}

impl ContentfulProviderError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::UnprocessableEntity => Some(422),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status } => Some(*status),
            Self::Timeout
            | Self::Malformed
            | Self::Partial
            | Self::ResponseTooLarge { .. }
            | Self::ScopeDrift
            | Self::RevisionDrift
            | Self::BlockedEnv
            | Self::Network => None,
        }
    }
}

/// Service, model, registration, and replay failures.  Payloads are never
/// embedded in an error variant.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContentfulResultError {
    #[error("Contentful model error: {0}")]
    Model(#[from] ContentfulModelError),
    #[error("Contentful contract is invalid: {0}")]
    Contract(String),
    #[error("Contentful provider error: {0}")]
    Provider(#[from] ContentfulProviderError),
    #[error("Contentful registration is revoked")]
    RegistrationRevoked,
    #[error("Contentful registration is stale or drifted: {kind}")]
    RegistrationDrift { kind: &'static str },
    #[error("Contentful scope drifted")]
    ScopeDrift { expected: Digest, actual: Digest },
    #[error("Contentful Mission revision is stale")]
    StaleMission { expected: u64, actual: u64 },
    #[error("Contentful Project revision is stale")]
    StaleProject { expected: u64, actual: u64 },
    #[error("Contentful Work Product revision is stale")]
    StaleWorkProduct { expected: u64, actual: u64 },
    #[error("Contentful entry version regressed from {previous} to {observed}")]
    VersionRegression { previous: u64, observed: u64 },
    #[error("Contentful published counter regressed from {previous} to {observed}")]
    PublishedCounterRegression { previous: u64, observed: u64 },
    #[error("Contentful entry version drifted: expected {expected}, observed {observed}")]
    VersionDrift { expected: u64, observed: u64 },
    #[error("Contentful published counter drifted: expected {expected}, observed {observed}")]
    PublishedCounterDrift { expected: u64, observed: u64 },
    #[error("Contentful response exceeded the {kind} bound of {maximum}")]
    BoundExceeded { kind: &'static str, maximum: usize },
    #[error("Contentful response could not be replayed: {kind}")]
    ReplayOrTamper { kind: &'static str },
    #[error("Contentful native or kernel authority was requested")]
    NativeAuthority,
}

/// Provider capability and digest boundary.  The manifest is intentionally
/// immutable from the service's perspective and is rechecked before every
/// read to catch scope, permission, API, or revision drift.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulProviderManifest {
    pub provider_revision: String,
    pub api_revision: String,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub native_connected_claim: bool,
    pub entry_reads: bool,
    pub published_entry_reads: bool,
    pub reference_reads: bool,
    pub mutations: bool,
    pub arbitrary_graphql: bool,
}

impl ContentfulProviderManifest {
    pub fn layer1(scope: &ContentfulScope, source: EvidenceSource) -> Self {
        let permission_digest = canonical_digest(&[
            "entries:read",
            "published_entries:read",
            "entry_references:read",
        ]);
        let revision_digest = canonical_digest(&(
            CONTENTFUL_PROVIDER_REVISION,
            CONTENTFUL_API_REVISION,
            scope.version,
            scope.published_counter,
        ));
        Self {
            provider_revision: CONTENTFUL_PROVIDER_REVISION.to_owned(),
            api_revision: CONTENTFUL_API_REVISION.to_owned(),
            permission_digest,
            scope_digest: scope.digest(),
            revision_digest,
            evidence_source: source,
            native_status: NativeStatus::BlockedEnv,
            native_connected_claim: false,
            entry_reads: true,
            published_entry_reads: true,
            reference_reads: true,
            mutations: false,
            arbitrary_graphql: false,
        }
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn api_digest(&self) -> Digest {
        Digest::from_text(self.api_revision.as_bytes())
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_text(self.provider_revision.as_bytes())
    }

    pub fn validate(&self, scope: &ContentfulScope) -> Result<(), ContentfulResultError> {
        if self.provider_revision != CONTENTFUL_PROVIDER_REVISION
            || self.api_revision != CONTENTFUL_API_REVISION
            || self.scope_digest != scope.digest()
            || !self.entry_reads
            || !self.published_entry_reads
            || !self.reference_reads
            || self.mutations
            || self.arbitrary_graphql
            || self.native_connected_claim
            || self.native_status != NativeStatus::BlockedEnv
            || self.evidence_source.is_native()
        {
            return Err(ContentfulResultError::RegistrationDrift {
                kind: "provider_manifest",
            });
        }
        Ok(())
    }
}

/// A redacted request endpoint used by fixture, recording, and loopback
/// providers.  It models only bounded GET operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentfulEndpoint {
    Entry {
        api: ContentfulApi,
        space: SpaceId,
        environment: EnvironmentId,
        entry: EntryId,
        pagination: ContentfulPagination,
    },
    PublishedEntry {
        api: ContentfulApi,
        space: SpaceId,
        environment: EnvironmentId,
        entry: EntryId,
        pagination: ContentfulPagination,
    },
    References {
        api: ContentfulApi,
        space: SpaceId,
        environment: EnvironmentId,
        entry: EntryId,
        depth: u8,
        pagination: ContentfulPagination,
    },
}

impl ContentfulEndpoint {
    pub fn path_and_query(&self) -> String {
        match self {
            Self::Entry {
                space,
                environment,
                entry,
                pagination,
                ..
            }
            | Self::PublishedEntry {
                space,
                environment,
                entry,
                pagination,
                ..
            } => format!(
                "/spaces/{}/environments/{}/entries/{}?limit={}&page={}",
                space.as_str(),
                environment.as_str(),
                entry.as_str(),
                pagination.limit,
                pagination.page
            ),
            Self::References {
                space,
                environment,
                entry,
                depth,
                pagination,
                ..
            } => format!(
                "/spaces/{}/environments/{}/entries/{}/references?include={}&limit={}&page={}",
                space.as_str(),
                environment.as_str(),
                entry.as_str(),
                depth,
                pagination.limit,
                pagination.page
            ),
        }
    }

    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Entry { .. } => "read_entry",
            Self::PublishedEntry { .. } => "read_published_entry",
            Self::References { .. } => "read_entry_references",
        }
    }

    pub const fn api(&self) -> ContentfulApi {
        match self {
            Self::Entry { api, .. }
            | Self::PublishedEntry { api, .. }
            | Self::References { api, .. } => *api,
        }
    }
}

/// A bounded HTTP request descriptor.  No authorization header is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentfulHttpRequest {
    pub endpoint: ContentfulEndpoint,
    pub max_response_bytes: usize,
}

impl ContentfulHttpRequest {
    pub fn new(endpoint: ContentfulEndpoint) -> Result<Self, ContentfulModelError> {
        Ok(Self {
            endpoint,
            max_response_bytes: CONTENTFUL_MAX_RESPONSE_BYTES,
        })
    }

    pub fn path_and_query(&self) -> String {
        self.endpoint.path_and_query()
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(&(self.endpoint.path_and_query(), self.max_response_bytes))
    }
}

/// Redacted call record exposed by in-memory provider implementations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulProviderCall {
    pub operation: String,
    pub api: ContentfulApi,
    pub path_digest: Digest,
    pub request_digest: Digest,
    pub status: Option<u16>,
    pub response_digest: Option<Digest>,
    pub response_size: usize,
    pub source: EvidenceSource,
    pub native_connected_claim: bool,
}

/// Typed provider seam.  Implementations are read-only by construction: no
/// create, update, publish, unpublish, archive, or delete method exists.
pub trait ContentfulProvider: fmt::Debug {
    fn scope(&self) -> &ContentfulScope;
    fn manifest(&self) -> &ContentfulProviderManifest;
    fn secret_reference(&self) -> &SecretReference;
    fn read_entry(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulEntrySnapshot, ContentfulProviderError>;
    fn read_published_entry(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulEntrySnapshot, ContentfulProviderError>;
    fn read_entry_references(
        &mut self,
        request: &ContentfulReferenceRequest,
    ) -> Result<Vec<ContentfulReferenceMetadata>, ContentfulProviderError>;
}

#[derive(Clone, Debug)]
struct InMemoryContentfulData {
    scope: ContentfulScope,
    manifest: ContentfulProviderManifest,
    secret_reference: SecretReference,
    entry: Result<ContentfulEntrySnapshot, ContentfulProviderError>,
    published_entry: Result<ContentfulEntrySnapshot, ContentfulProviderError>,
    references: Result<Vec<ContentfulReferenceMetadata>, ContentfulProviderError>,
    calls: Vec<ContentfulProviderCall>,
}

impl InMemoryContentfulData {
    fn fixture(
        scope: ContentfulScope,
        source: EvidenceSource,
    ) -> Result<Self, ContentfulResultError> {
        let manifest = ContentfulProviderManifest::layer1(&scope, source);
        let secret_reference = SecretReference::new("contentful/cma-cda", 1)?;
        let observed_at = Utc
            .timestamp_opt(1_750_000_000, 0)
            .single()
            .expect("fixed fixture timestamp");
        let locales = BTreeSet::from([
            LocaleCode::new(scope.locale.as_str())?,
            LocaleCode::new("de-DE")?,
        ]);
        let fields = BTreeMap::from([
            (
                "title".to_owned(),
                Digest::from_text("fixture-title-en-and-de"),
            ),
            (
                "summary".to_owned(),
                Digest::from_text("fixture-summary-en-and-de"),
            ),
        ]);
        let reference = ContentfulReferenceMetadata::new(
            EntryId::new("referenced-entry")?,
            ContentTypeId::new("article")?,
            ContentfulProjection::Published,
            ContentfulVersion::new(2)?,
            PublishedCounter::new(1),
            BTreeSet::from([LocaleCode::new("en-US")?]),
        )?;
        let entry = ContentfulEntrySnapshot::new(
            &scope,
            ContentfulProjection::Draft,
            scope.version,
            scope.published_counter,
            observed_at,
            locales.clone(),
            fields.clone(),
            Some(Digest::from_text("fixture-reference-set")),
        )?;
        let published_entry = ContentfulEntrySnapshot::new(
            &scope,
            ContentfulProjection::Published,
            scope.version,
            scope.published_counter,
            observed_at,
            locales,
            fields,
            Some(Digest::from_text("fixture-reference-set")),
        )?;
        Ok(Self {
            scope,
            manifest,
            secret_reference,
            entry: Ok(entry),
            published_entry: Ok(published_entry),
            references: Ok(vec![reference]),
            calls: Vec::new(),
        })
    }

    fn validate_read_scope(
        &self,
        request_scope: &ContentfulScope,
    ) -> Result<(), ContentfulProviderError> {
        if request_scope != &self.scope || self.manifest.scope_digest != self.scope.digest() {
            Err(ContentfulProviderError::ScopeDrift)
        } else {
            Ok(())
        }
    }

    fn call_for(
        &mut self,
        endpoint: &ContentfulEndpoint,
        response: &Result<impl Serialize, ContentfulProviderError>,
    ) {
        let request = ContentfulHttpRequest::new(endpoint.clone())
            .expect("in-memory provider creates bounded requests");
        let (status, response_digest, response_size) = match &response {
            Ok(value) => {
                let digest = canonical_digest(value);
                (
                    Some(200),
                    Some(digest),
                    serde_json::to_vec(value).map_or(0, |v| v.len()),
                )
            }
            Err(error) => (error.status_code(), None, 0),
        };
        self.calls.push(ContentfulProviderCall {
            operation: endpoint.operation().to_owned(),
            api: endpoint.api(),
            path_digest: Digest::from_text(request.path_and_query()),
            request_digest: request.digest(),
            status,
            response_digest,
            response_size,
            source: self.manifest.evidence_source,
            native_connected_claim: self.manifest.native_connected_claim,
        });
    }

    fn calls(&self) -> &[ContentfulProviderCall] {
        &self.calls
    }
}

/// Deterministic fixture provider.  It never claims native Connected status.
#[derive(Clone, Debug)]
pub struct FixtureContentfulProvider {
    data: InMemoryContentfulData,
}

impl FixtureContentfulProvider {
    pub fn new(scope: ContentfulScope) -> Result<Self, ContentfulResultError> {
        Ok(Self {
            data: InMemoryContentfulData::fixture(scope, EvidenceSource::Fixture)?,
        })
    }

    pub fn from_responses(
        scope: ContentfulScope,
        secret_reference: SecretReference,
        entry: Result<ContentfulEntrySnapshot, ContentfulProviderError>,
        published_entry: Result<ContentfulEntrySnapshot, ContentfulProviderError>,
        references: Result<Vec<ContentfulReferenceMetadata>, ContentfulProviderError>,
    ) -> Self {
        Self {
            data: InMemoryContentfulData {
                manifest: ContentfulProviderManifest::layer1(&scope, EvidenceSource::Fixture),
                scope,
                secret_reference,
                entry,
                published_entry,
                references,
                calls: Vec::new(),
            },
        }
    }

    pub fn set_entry_response(
        &mut self,
        response: Result<ContentfulEntrySnapshot, ContentfulProviderError>,
    ) {
        self.data.entry = response;
    }

    pub fn set_published_entry_response(
        &mut self,
        response: Result<ContentfulEntrySnapshot, ContentfulProviderError>,
    ) {
        self.data.published_entry = response;
    }

    pub fn set_references_response(
        &mut self,
        response: Result<Vec<ContentfulReferenceMetadata>, ContentfulProviderError>,
    ) {
        self.data.references = response;
    }

    pub fn calls(&self) -> &[ContentfulProviderCall] {
        self.data.calls()
    }

    pub fn manifest(&self) -> &ContentfulProviderManifest {
        &self.data.manifest
    }
}

/// A compatibility name used by fixture-driven callers.
pub type FakeContentfulProvider = FixtureContentfulProvider;

/// Recording provider; it has the same deterministic payload shape as the
/// fixture provider but labels every receipt as recording evidence.
#[derive(Clone, Debug)]
pub struct RecordingContentfulProvider {
    data: InMemoryContentfulData,
}

impl RecordingContentfulProvider {
    pub fn new(scope: ContentfulScope) -> Result<Self, ContentfulResultError> {
        Ok(Self {
            data: InMemoryContentfulData::fixture(scope, EvidenceSource::Recording)?,
        })
    }

    pub fn from_fixture(fixture: FixtureContentfulProvider) -> Self {
        let mut data = fixture.data;
        data.manifest.evidence_source = EvidenceSource::Recording;
        Self { data }
    }

    pub fn calls(&self) -> &[ContentfulProviderCall] {
        self.data.calls()
    }
}

/// Loopback provider; loopback traffic is still non-native and non-Connected.
#[derive(Clone, Debug)]
pub struct LoopbackContentfulProvider {
    data: InMemoryContentfulData,
}

impl LoopbackContentfulProvider {
    pub fn new(scope: ContentfulScope) -> Result<Self, ContentfulResultError> {
        Ok(Self {
            data: InMemoryContentfulData::fixture(scope, EvidenceSource::Loopback)?,
        })
    }

    pub fn calls(&self) -> &[ContentfulProviderCall] {
        self.data.calls()
    }
}

/// Explicit native-environment gap provider.  It performs no request.
#[derive(Clone, Debug)]
pub struct BlockedEnvContentfulProvider {
    scope: ContentfulScope,
    manifest: ContentfulProviderManifest,
    secret_reference: SecretReference,
}

impl BlockedEnvContentfulProvider {
    pub fn new(scope: ContentfulScope) -> Result<Self, ContentfulResultError> {
        Ok(Self {
            manifest: ContentfulProviderManifest::layer1(&scope, EvidenceSource::BlockedEnv),
            scope,
            secret_reference: SecretReference::new("contentful/cma-cda", 1)?,
        })
    }
}

macro_rules! impl_memory_provider {
    ($provider:ty) => {
        impl ContentfulProvider for $provider {
            fn scope(&self) -> &ContentfulScope {
                &self.data.scope
            }

            fn manifest(&self) -> &ContentfulProviderManifest {
                &self.data.manifest
            }

            fn secret_reference(&self) -> &SecretReference {
                &self.data.secret_reference
            }

            fn read_entry(
                &mut self,
                request: &ContentfulReadRequest,
            ) -> Result<ContentfulEntrySnapshot, ContentfulProviderError> {
                self.data.validate_read_scope(&request.scope)?;
                let endpoint = ContentfulEndpoint::Entry {
                    api: request.api,
                    space: request.scope.space.clone(),
                    environment: request.scope.environment.clone(),
                    entry: request.scope.entry.clone(),
                    pagination: request.pagination.clone(),
                };
                let response = self.data.entry.clone();
                self.data.call_for(&endpoint, &response);
                response
            }

            fn read_published_entry(
                &mut self,
                request: &ContentfulReadRequest,
            ) -> Result<ContentfulEntrySnapshot, ContentfulProviderError> {
                self.data.validate_read_scope(&request.scope)?;
                let endpoint = ContentfulEndpoint::PublishedEntry {
                    api: request.api,
                    space: request.scope.space.clone(),
                    environment: request.scope.environment.clone(),
                    entry: request.scope.entry.clone(),
                    pagination: request.pagination.clone(),
                };
                let response = self.data.published_entry.clone();
                self.data.call_for(&endpoint, &response);
                response
            }

            fn read_entry_references(
                &mut self,
                request: &ContentfulReferenceRequest,
            ) -> Result<Vec<ContentfulReferenceMetadata>, ContentfulProviderError> {
                self.data.validate_read_scope(&request.scope)?;
                let endpoint = ContentfulEndpoint::References {
                    api: request.api,
                    space: request.scope.space.clone(),
                    environment: request.scope.environment.clone(),
                    entry: request.scope.entry.clone(),
                    depth: request.depth,
                    pagination: request.pagination.clone(),
                };
                let response = self.data.references.clone();
                self.data.call_for(&endpoint, &response);
                response
            }
        }
    };
}

impl_memory_provider!(FixtureContentfulProvider);
impl_memory_provider!(RecordingContentfulProvider);
impl_memory_provider!(LoopbackContentfulProvider);

impl ContentfulProvider for BlockedEnvContentfulProvider {
    fn scope(&self) -> &ContentfulScope {
        &self.scope
    }

    fn manifest(&self) -> &ContentfulProviderManifest {
        &self.manifest
    }

    fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    fn read_entry(
        &mut self,
        _request: &ContentfulReadRequest,
    ) -> Result<ContentfulEntrySnapshot, ContentfulProviderError> {
        Err(ContentfulProviderError::BlockedEnv)
    }

    fn read_published_entry(
        &mut self,
        _request: &ContentfulReadRequest,
    ) -> Result<ContentfulEntrySnapshot, ContentfulProviderError> {
        Err(ContentfulProviderError::BlockedEnv)
    }

    fn read_entry_references(
        &mut self,
        _request: &ContentfulReferenceRequest,
    ) -> Result<Vec<ContentfulReferenceMetadata>, ContentfulProviderError> {
        Err(ContentfulProviderError::BlockedEnv)
    }
}

/// Lifecycle state for the in-process registration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

/// Reversible registration proof.  It binds all provider/API/permission,
/// scope, revision, contract, and opaque-secret-reference digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulRegistration {
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registered_at: DateTime<Utc>,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl ContentfulRegistration {
    fn new<P: ContentfulProvider>(provider: &P, at: DateTime<Utc>) -> Self {
        let manifest = provider.manifest();
        let contract_digest = contract_digest();
        let registration_digest = canonical_digest(&(
            &contract_digest,
            manifest.provider_digest(),
            manifest.api_digest(),
            &manifest.permission_digest,
            &manifest.scope_digest,
            &manifest.revision_digest,
            provider.secret_reference().digest(),
            at,
        ));
        Self {
            contract_digest,
            provider_digest: manifest.provider_digest(),
            api_digest: manifest.api_digest(),
            permission_digest: manifest.permission_digest.clone(),
            scope_digest: manifest.scope_digest.clone(),
            revision_digest: manifest.revision_digest.clone(),
            secret_reference_digest: provider.secret_reference().digest(),
            registered_at: at,
            state: RegistrationState::Active,
            registration_digest,
        }
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn revoke(&mut self) -> Result<(), ContentfulResultError> {
        if !self.is_active() {
            return Err(ContentfulResultError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// A small typed view of the service's read-only capabilities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentfulCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub read_entry: bool,
    pub read_published_entry: bool,
    pub read_entry_references: bool,
    pub create: bool,
    pub update: bool,
    pub publish: bool,
    pub unpublish: bool,
    pub archive: bool,
    pub delete: bool,
    pub arbitrary_graphql: bool,
    pub native_connected_claim: bool,
}

impl Default for ContentfulCapabilities {
    fn default() -> Self {
        Self {
            service_id: CONTENTFUL_ENTRY_RESULT_SERVICE_ID,
            provider_id: CONTENTFUL_PROVIDER_ID,
            consumer_id: MISSION_CONTENTFUL_RESULT_CONSUMER_ID,
            read_entry: true,
            read_published_entry: true,
            read_entry_references: true,
            create: false,
            update: false,
            publish: false,
            unpublish: false,
            archive: false,
            delete: false,
            arbitrary_graphql: false,
            native_connected_claim: false,
        }
    }
}

/// Parsed contract document with fail-closed semantic validation.
#[derive(Clone, Debug)]
pub struct ContentfulEntryResultContract {
    document: serde_json::Value,
}

impl ContentfulEntryResultContract {
    pub fn baseline() -> Result<Self, ContentfulResultError> {
        let document = serde_json::from_str(CONTENTFUL_ENTRY_RESULT_CONTRACT_JSON)
            .map_err(|error| ContentfulResultError::Contract(error.to_string()))?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), ContentfulResultError> {
        let object = self.document.as_object().ok_or_else(|| {
            ContentfulResultError::Contract("contract is not an object".to_owned())
        })?;
        let expected_operations = serde_json::json!([
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_entry",
            "read_published_entry",
            "read_entry_references",
            "consume_observation"
        ]);
        let valid = object.get("schemaVersion")
            == Some(&serde_json::json!(CONTENTFUL_ENTRY_RESULT_SCHEMA_VERSION))
            && object.get("contractVersion")
                == Some(&serde_json::json!(CONTENTFUL_ENTRY_RESULT_CONTRACT_VERSION))
            && object.get("layer") == Some(&serde_json::json!(1))
            && object["service"]["id"] == CONTENTFUL_ENTRY_RESULT_SERVICE_ID
            && object["service"]["providerId"] == CONTENTFUL_PROVIDER_ID
            && object["service"]["consumerId"] == MISSION_CONTENTFUL_RESULT_CONSUMER_ID
            && object["service"]["operations"] == expected_operations
            && object["api"]["arbitraryGraphql"] == false
            && object["authority"]["entryCreate"] == false
            && object["authority"]["entryUpdate"] == false
            && object["authority"]["entryPublish"] == false
            && object["authority"]["entryUnpublish"] == false
            && object["authority"]["entryArchive"] == false
            && object["authority"]["entryDelete"] == false
            && object["authority"]["cmsRegistry"] == false
            && object["authority"]["kernelTruth"] == false
            && object["authority"]["kernelEffect"] == false
            && object["authority"]["kernelOutcome"] == false
            && object["authority"]["workProductAdoption"] == false
            && object["native"]["status"] == "BLOCKED_ENV"
            && object["native"]["fixtureConnected"] == false
            && object["native"]["recordingConnected"] == false
            && object["native"]["loopbackConnected"] == false
            && object["native"]["blockedEnvConnected"] == false
            && object["secretBoundary"]["opaqueCmaCdaSecretReferenceOnly"] == true
            && object["redaction"]["rawLocalizedBodyInEvidence"] == false
            && object["redaction"]["rawLocalizedBodyInReceipt"] == false
            && object["redaction"]["rawProviderPayload"] == false
            && object["readBoundaries"]["maxResponseBytes"] == CONTENTFUL_MAX_RESPONSE_BYTES
            && object["readBoundaries"]["maxPageSize"] == CONTENTFUL_MAX_PAGE_SIZE
            && object["readBoundaries"]["maxPages"] == CONTENTFUL_MAX_PAGES
            && object["readBoundaries"]["maxReferenceDepth"] == CONTENTFUL_MAX_REFERENCE_DEPTH
            && object["readBoundaries"]["maxReferences"] == CONTENTFUL_MAX_REFERENCES;
        if valid {
            Ok(())
        } else {
            Err(ContentfulResultError::Contract(
                "checked-in Contentful Layer-1 contract does not match the implementation baseline"
                    .to_owned(),
            ))
        }
    }
}

/// Returns the digest of the checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTENTFUL_ENTRY_RESULT_CONTRACT_JSON.as_bytes())
}

/// Reversible revocation evidence.  Revocation is local registration state;
/// it does not call a Contentful mutation endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentfulRevocationReceipt {
    pub registration_digest: Digest,
    pub revoked_at: DateTime<Utc>,
    pub evidence_source: EvidenceSource,
    pub native_connected_claim: bool,
}

/// The Layer-1 service that composes one provider into bounded read evidence.
#[derive(Clone, Debug)]
pub struct ContentfulEntryResultService<P: ContentfulProvider> {
    provider: P,
    scope: ContentfulScope,
    registration: ContentfulRegistration,
    last_version: Option<ContentfulVersion>,
    last_published_counter: Option<PublishedCounter>,
}

impl<P: ContentfulProvider> ContentfulEntryResultService<P> {
    pub fn new(provider: P) -> Result<Self, ContentfulResultError> {
        Self::new_at(provider, Utc::now())
    }

    pub fn new_at(
        provider: P,
        registered_at: DateTime<Utc>,
    ) -> Result<Self, ContentfulResultError> {
        let scope = provider.scope().clone();
        ContentfulEntryResultContract::baseline()?;
        provider.manifest().validate(&scope)?;
        let registration = ContentfulRegistration::new(&provider, registered_at);
        let service = Self {
            provider,
            scope,
            registration,
            last_version: None,
            last_published_counter: None,
        };
        service.ensure_registration()?;
        Ok(service)
    }

    pub fn scope(&self) -> &ContentfulScope {
        &self.scope
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn registration(&self) -> &ContentfulRegistration {
        &self.registration
    }

    pub fn describe_capabilities(&self) -> ContentfulCapabilities {
        ContentfulCapabilities::default()
    }

    /// Revalidates the provider and returns the active registration proof.
    pub fn register(&self) -> Result<ContentfulRegistration, ContentfulResultError> {
        self.ensure_registration()?;
        Ok(self.registration.clone())
    }

    pub fn revoke_registration(
        &mut self,
        revoked_at: DateTime<Utc>,
    ) -> Result<ContentfulRevocationReceipt, ContentfulResultError> {
        self.ensure_registration()?;
        self.registration.revoke()?;
        Ok(ContentfulRevocationReceipt {
            registration_digest: self.registration.digest(),
            revoked_at,
            evidence_source: self.provider.manifest().evidence_source,
            native_connected_claim: false,
        })
    }

    pub fn revoke(&mut self) -> Result<ContentfulRevocationReceipt, ContentfulResultError> {
        self.revoke_registration(Utc::now())
    }

    pub fn revoke_at(
        &mut self,
        revoked_at: DateTime<Utc>,
    ) -> Result<ContentfulRevocationReceipt, ContentfulResultError> {
        self.revoke_registration(revoked_at)
    }

    pub fn read_entry(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulReadEvidence, ContentfulResultError> {
        self.ensure_request(request)?;
        let snapshot = self.provider.read_entry(request)?;
        self.validate_snapshot(request, &snapshot)?;
        Ok(ContentfulReadEvidence {
            pagination: ContentfulPaginationEvidence::from_request(
                &request.pagination,
                snapshot.field_digests.len(),
            ),
            receipt: self.receipt(
                "read_entry",
                request.api,
                request.digest(),
                snapshot.digest(),
                200,
                snapshot_size(&snapshot),
            ),
            entry: snapshot,
        })
    }

    pub fn read_published_entry(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulReadEvidence, ContentfulResultError> {
        self.ensure_request(request)?;
        let snapshot = self.provider.read_published_entry(request)?;
        self.validate_snapshot(request, &snapshot)?;
        Ok(ContentfulReadEvidence {
            pagination: ContentfulPaginationEvidence::from_request(
                &request.pagination,
                snapshot.field_digests.len(),
            ),
            receipt: self.receipt(
                "read_published_entry",
                request.api,
                request.digest(),
                snapshot.digest(),
                200,
                snapshot_size(&snapshot),
            ),
            entry: snapshot,
        })
    }

    pub fn read_entry_references(
        &mut self,
        request: &ContentfulReferenceRequest,
    ) -> Result<ContentfulReferenceEvidence, ContentfulResultError> {
        self.ensure_reference_request(request)?;
        let references = self.provider.read_entry_references(request)?;
        if references.len() > CONTENTFUL_MAX_REFERENCES {
            return Err(ContentfulResultError::BoundExceeded {
                kind: "references",
                maximum: CONTENTFUL_MAX_REFERENCES,
            });
        }
        if references
            .iter()
            .any(|reference| reference.locale_coverage.len() > CONTENTFUL_MAX_LOCALES)
        {
            return Err(ContentfulResultError::BoundExceeded {
                kind: "reference locales",
                maximum: CONTENTFUL_MAX_LOCALES,
            });
        }
        let response_digest = canonical_digest(&references);
        Ok(ContentfulReferenceEvidence {
            pagination: ContentfulPaginationEvidence::from_request(
                &request.pagination,
                references.len(),
            ),
            receipt: self.receipt(
                "read_entry_references",
                request.api,
                request.digest(),
                response_digest,
                200,
                serde_json::to_vec(&references).map_or(0, |bytes| bytes.len()),
            ),
            depth: request.depth,
            references,
        })
    }

    /// Reads draft, published, and reference metadata in one bounded result.
    /// A 404 from the published-entry read is projected as an absent published
    /// entry, preserving the distinction between draft and unpublished state.
    pub fn read_result(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulResultEvidence, ContentfulResultError> {
        let draft = self.read_entry(request)?;
        let published = match self.read_published_entry(request) {
            Ok(evidence) => Some(evidence),
            Err(ContentfulResultError::Provider(ContentfulProviderError::NotFound)) => None,
            Err(error) => return Err(error),
        };
        let reference_request = ContentfulReferenceRequest::new(
            request.scope.clone(),
            request.api,
            CONTENTFUL_MAX_REFERENCE_DEPTH,
        )?;
        let references = self.read_entry_references(&reference_request)?;
        let field_digests = draft.entry.field_digests.clone();
        let mut locale_coverage = draft.entry.locale_coverage.clone();
        if let Some(published) = &published {
            locale_coverage.extend(published.entry.locale_coverage.iter().cloned());
        }
        let result_digest = canonical_digest(&(
            &self.scope,
            draft.entry.digest(),
            published.as_ref().map(|value| value.entry.digest()),
            &references.references,
            &draft.receipt.response_digest,
            &references.receipt.response_digest,
        ));
        let evidence = ContentfulResultEvidence {
            scope: self.scope.clone(),
            draft,
            published,
            references,
            locale_coverage,
            field_digests,
            provider_digest: self.provider.manifest().provider_digest(),
            api_digest: self.provider.manifest().api_digest(),
            permission_digest: self.provider.manifest().permission_digest.clone(),
            scope_digest: self.provider.manifest().scope_digest.clone(),
            revision_digest: self.provider.manifest().revision_digest.clone(),
            result_digest,
            evidence_source: self.provider.manifest().evidence_source,
            native_status: self.provider.manifest().native_status,
            native_connected_claim: false,
            kernel_authority: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn compile_work_product_observation(
        &self,
        evidence: &ContentfulResultEvidence,
    ) -> Result<ContentfulWorkProductObservation, ContentfulResultError> {
        self.ensure_registration()?;
        evidence.validate()?;
        if evidence.scope != self.scope {
            return Err(ContentfulResultError::ScopeDrift {
                expected: self.scope.digest(),
                actual: evidence.scope.digest(),
            });
        }
        Ok(ContentfulWorkProductObservation {
            project_id: self.scope.project_id.clone(),
            project_revision: self.scope.project_revision,
            mission_id: self.scope.mission_id.clone(),
            mission_revision: self.scope.mission_revision,
            work_product_id: self.scope.work_product_id.clone(),
            work_product_revision: self.scope.work_product_revision,
            evidence_digest: evidence.result_digest.clone(),
            effect_authority: false,
            outcome_authority: false,
            adopted: false,
        })
    }

    pub fn consume_observation(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulResultEvidence, ContentfulResultError> {
        self.read_result(request)
    }

    fn ensure_registration(&self) -> Result<(), ContentfulResultError> {
        if !self.registration.is_active() {
            return Err(ContentfulResultError::RegistrationRevoked);
        }
        self.provider.manifest().validate(&self.scope)?;
        if self.registration.contract_digest != contract_digest()
            || self.registration.provider_digest != self.provider.manifest().provider_digest()
            || self.registration.api_digest != self.provider.manifest().api_digest()
            || self.registration.permission_digest != self.provider.manifest().permission_digest
            || self.registration.scope_digest != self.scope.digest()
            || self.registration.revision_digest != self.provider.manifest().revision_digest
            || self.registration.secret_reference_digest
                != self.provider.secret_reference().digest()
        {
            return Err(ContentfulResultError::RegistrationDrift {
                kind: "registration_digest",
            });
        }
        Ok(())
    }

    fn ensure_request(&self, request: &ContentfulReadRequest) -> Result<(), ContentfulResultError> {
        self.ensure_registration()?;
        self.ensure_scope_revisions(&request.scope)?;
        if request.scope != self.scope {
            return Err(ContentfulResultError::ScopeDrift {
                expected: self.scope.digest(),
                actual: request.scope.digest(),
            });
        }
        Ok(())
    }

    fn ensure_reference_request(
        &self,
        request: &ContentfulReferenceRequest,
    ) -> Result<(), ContentfulResultError> {
        self.ensure_registration()?;
        self.ensure_scope_revisions(&request.scope)?;
        if request.scope != self.scope {
            return Err(ContentfulResultError::ScopeDrift {
                expected: self.scope.digest(),
                actual: request.scope.digest(),
            });
        }
        Ok(())
    }

    fn ensure_scope_revisions(&self, scope: &ContentfulScope) -> Result<(), ContentfulResultError> {
        if scope.mission_id != self.scope.mission_id {
            return Err(ContentfulResultError::ScopeDrift {
                expected: self.scope.digest(),
                actual: scope.digest(),
            });
        }
        if scope.mission_revision != self.scope.mission_revision {
            return Err(ContentfulResultError::StaleMission {
                expected: self.scope.mission_revision,
                actual: scope.mission_revision,
            });
        }
        if scope.project_revision != self.scope.project_revision {
            return Err(ContentfulResultError::StaleProject {
                expected: self.scope.project_revision,
                actual: scope.project_revision,
            });
        }
        if scope.work_product_revision != self.scope.work_product_revision {
            return Err(ContentfulResultError::StaleWorkProduct {
                expected: self.scope.work_product_revision,
                actual: scope.work_product_revision,
            });
        }
        Ok(())
    }

    fn validate_snapshot(
        &mut self,
        request: &ContentfulReadRequest,
        snapshot: &ContentfulEntrySnapshot,
    ) -> Result<(), ContentfulResultError> {
        snapshot.validate_for_scope(&self.scope)?;
        if let Some(expected) = request.expected_version
            && snapshot.version != expected
        {
            return Err(ContentfulResultError::VersionDrift {
                expected: expected.get(),
                observed: snapshot.version.get(),
            });
        }
        if let Some(expected) = request.expected_published_counter
            && snapshot.published_counter != expected
        {
            return Err(ContentfulResultError::PublishedCounterDrift {
                expected: expected.get(),
                observed: snapshot.published_counter.get(),
            });
        }
        if let Some(previous) = self.last_version
            && snapshot.version < previous
        {
            return Err(ContentfulResultError::VersionRegression {
                previous: previous.get(),
                observed: snapshot.version.get(),
            });
        }
        if let Some(previous) = self.last_published_counter
            && snapshot.published_counter < previous
        {
            return Err(ContentfulResultError::PublishedCounterRegression {
                previous: previous.get(),
                observed: snapshot.published_counter.get(),
            });
        }
        self.last_version = Some(snapshot.version);
        self.last_published_counter = Some(snapshot.published_counter);
        Ok(())
    }

    fn receipt(
        &self,
        operation: &str,
        api: ContentfulApi,
        request_digest: Digest,
        response_digest: Digest,
        response_status: u16,
        response_size: usize,
    ) -> ContentfulObservationReceipt {
        let manifest = self.provider.manifest();
        ContentfulObservationReceipt {
            operation: operation.to_owned(),
            api,
            request_digest,
            response_digest,
            response_status,
            response_size,
            provider_digest: manifest.provider_digest(),
            api_digest: manifest.api_digest(),
            permission_digest: manifest.permission_digest.clone(),
            scope_digest: manifest.scope_digest.clone(),
            revision_digest: manifest.revision_digest.clone(),
            evidence_source: manifest.evidence_source,
            native_status: NativeStatus::BlockedEnv,
            native_connected_claim: false,
            raw_provider_payload_retained: false,
            raw_localized_body_retained: false,
            secret_material_retained: false,
        }
    }
}

fn snapshot_size(snapshot: &ContentfulEntrySnapshot) -> usize {
    serde_json::to_vec(snapshot).map_or(0, |bytes| bytes.len())
}

/// Mission-facing typed consumer.  It can consume evidence and produce a
/// non-adopting Work Product observation, but owns no kernel authority.
#[derive(Clone, Debug)]
pub struct MissionContentfulResultConsumer<P: ContentfulProvider> {
    service: ContentfulEntryResultService<P>,
}

impl<P: ContentfulProvider> MissionContentfulResultConsumer<P> {
    pub fn new(service: ContentfulEntryResultService<P>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &ContentfulEntryResultService<P> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut ContentfulEntryResultService<P> {
        &mut self.service
    }

    pub fn read_result(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulResultEvidence, ContentfulResultError> {
        self.service.read_result(request)
    }

    pub fn consume_observation(
        &mut self,
        request: &ContentfulReadRequest,
    ) -> Result<ContentfulResultEvidence, ContentfulResultError> {
        self.service.consume_observation(request)
    }

    pub fn compile_work_product_observation(
        &self,
        evidence: &ContentfulResultEvidence,
    ) -> Result<ContentfulWorkProductObservation, ContentfulResultError> {
        self.service.compile_work_product_observation(evidence)
    }
}

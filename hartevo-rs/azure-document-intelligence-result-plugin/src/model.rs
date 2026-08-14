//! Bounded, provider-specific Azure Document Intelligence types.
//!
//! The model deliberately stores digests and summaries rather than Azure
//! payloads.  A host may hand a recorded JSON frame to the parser, but the
//! parser never puts raw bytes, source URLs, SAS material, or unbounded text
//! into a Layer-1 value.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION, AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION,
    AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID, AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID,
    MAX_DOCUMENT_INTELLIGENCE_OUTPUT_FIELDS, MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PAGES,
    MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PARAGRAPHS, MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLE_CELLS,
    MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLES, MAX_DOCUMENT_INTELLIGENCE_PAGE_NUMBER,
    MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES, MAX_DOCUMENT_INTELLIGENCE_TEXT_PREVIEW_BYTES,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 128;
pub const MAX_CONSENT_PURPOSE_LENGTH: usize = 128;
pub const MAX_OPERATION_LOCATION_LENGTH: usize = 2_048;

/// Model and projection validation failures.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains a URL or path-like value")]
    UrlOrPath { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is outside the permitted range")]
    OutOfRange { field: &'static str },
    #[error("{field} is not finite")]
    NotFinite { field: &'static str },
    #[error("{field} has an unsupported value")]
    Unsupported { field: &'static str },
    #[error("{field} has too many items")]
    BoundExceeded { field: &'static str },
    #[error("recorded provider JSON could not be decoded: {0}")]
    Decode(String),
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    if value.contains("://") || value.contains('/') || value.contains('\\') {
        return Err(ModelError::UrlOrPath { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_bounded_text(
                    &value,
                    $field,
                    MAX_IDENTIFIER_LENGTH,
                    $allow_internal_whitespace,
                )?;
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
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

bounded_identifier!(TenantId, "tenant id", false);
bounded_identifier!(ResourceName, "Azure resource name", false);
bounded_identifier!(AzureRegion, "Azure region", false);
bounded_identifier!(DocumentId, "document id", false);
bounded_identifier!(ConsentId, "consent id", false);
bounded_identifier!(ProjectId, "Project id", false);
bounded_identifier!(MissionId, "Mission id", false);
bounded_identifier!(WorkProductId, "Work Product id", false);
bounded_identifier!(ProviderRevision, "provider revision", false);

/// A canonical SHA-256 digest used for all Layer-1 bindings.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Digest {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Hash arbitrary bytes without retaining them.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .as_ref()
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}

/// Supported Azure Document Intelligence prebuilt models.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum DocumentModel {
    #[serde(rename = "prebuilt-read")]
    PrebuiltRead,
    #[serde(rename = "prebuilt-layout")]
    PrebuiltLayout,
}

impl DocumentModel {
    pub const ALLOWLIST: [Self; 2] = [Self::PrebuiltRead, Self::PrebuiltLayout];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrebuiltRead => "prebuilt-read",
            Self::PrebuiltLayout => "prebuilt-layout",
        }
    }

    pub const fn supports_tables(self) -> bool {
        matches!(self, Self::PrebuiltLayout)
    }
}

impl fmt::Display for DocumentModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

impl FromStr for DocumentModel {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prebuilt-read" => Ok(Self::PrebuiltRead),
            "prebuilt-layout" => Ok(Self::PrebuiltLayout),
            _ => Err(ModelError::Unsupported { field: "model" }),
        }
    }
}

/// The only permission this root can describe: a bounded read/analyze seam.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentIntelligencePermission {
    AnalyzeRead,
}

impl DocumentIntelligencePermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnalyzeRead => "document_intelligence_analyze_read",
        }
    }
}

/// Consent metadata is a local scope fence, not a kernel consent authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_id: ConsentId,
    revision: u64,
    purpose: String,
}

impl ConsentScope {
    pub fn new(consent_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::with_purpose(consent_id, revision, "document_processing")
    }

    pub fn with_purpose(
        consent_id: impl Into<String>,
        revision: u64,
        purpose: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let consent_id = ConsentId::parse(consent_id)?;
        validate_positive(revision, "consent revision")?;
        let purpose = purpose.into();
        validate_bounded_text(
            &purpose,
            "consent purpose",
            MAX_CONSENT_PURPOSE_LENGTH,
            false,
        )?;
        Ok(Self {
            consent_id,
            revision,
            purpose,
        })
    }

    pub fn consent_id(&self) -> &ConsentId {
        &self.consent_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

macro_rules! scoped_identity {
    ($name:ident, $id_type:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            id: $id_type,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
                validate_positive(revision, concat!($field, " revision"))?;
                Ok(Self {
                    id: $id_type::parse(id)?,
                    revision,
                })
            }

            pub fn id(&self) -> &$id_type {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }
        }
    };
}

scoped_identity!(ProjectScope, ProjectId, "Project");
scoped_identity!(MissionScope, MissionId, "Mission");
scoped_identity!(WorkProductScope, WorkProductId, "Work Product");

/// An inclusive page range pinned into the registration and every request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageRange {
    start_page: u16,
    end_page: u16,
}

impl PageRange {
    pub fn new(start_page: u16, end_page: u16) -> Result<Self, ModelError> {
        if start_page == 0 || end_page == 0 || start_page > end_page {
            return Err(ModelError::OutOfRange {
                field: "page range",
            });
        }
        if u32::from(end_page) > MAX_DOCUMENT_INTELLIGENCE_PAGE_NUMBER {
            return Err(ModelError::OutOfRange {
                field: "page range",
            });
        }
        Ok(Self {
            start_page,
            end_page,
        })
    }

    pub const fn single(page: u16) -> Result<Self, ModelError> {
        if page == 0 || page as u32 > MAX_DOCUMENT_INTELLIGENCE_PAGE_NUMBER {
            return Err(ModelError::OutOfRange { field: "page" });
        }
        Ok(Self {
            start_page: page,
            end_page: page,
        })
    }

    pub const fn start_page(self) -> u16 {
        self.start_page
    }

    pub const fn end_page(self) -> u16 {
        self.end_page
    }

    pub const fn count(self) -> u16 {
        self.end_page - self.start_page + 1
    }

    pub const fn contains(self, page: u16) -> bool {
        page >= self.start_page && page <= self.end_page
    }
}

/// Complete document, mission, and permission fence for one registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDocumentIntelligenceScope {
    tenant_id: TenantId,
    resource_name: ResourceName,
    region: AzureRegion,
    model: DocumentModel,
    document_id: DocumentId,
    source_digest: Digest,
    page_range: PageRange,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    consent: ConsentScope,
    permission: DocumentIntelligencePermission,
}

/// Convenient owned input for constructing an exact scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDocumentIntelligenceScopeInput {
    pub tenant_id: String,
    pub resource_name: String,
    pub region: String,
    pub model: DocumentModel,
    pub document_id: String,
    pub source_digest: Digest,
    pub page_range: PageRange,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub consent: ConsentScope,
    pub permission: DocumentIntelligencePermission,
}

impl AzureDocumentIntelligenceScope {
    pub fn new(input: AzureDocumentIntelligenceScopeInput) -> Result<Self, ModelError> {
        if !input.source_digest.is_sha256() {
            return Err(ModelError::InvalidDigest {
                field: "source digest",
            });
        }
        let scope = Self {
            tenant_id: TenantId::parse(input.tenant_id)?,
            resource_name: ResourceName::parse(input.resource_name)?,
            region: AzureRegion::parse(input.region)?,
            model: input.model,
            document_id: DocumentId::parse(input.document_id)?,
            source_digest: input.source_digest,
            page_range: input.page_range,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            consent: input.consent,
            permission: input.permission,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        tenant_id: impl Into<String>,
        resource_name: impl Into<String>,
        region: impl Into<String>,
        model: DocumentModel,
        document_id: impl Into<String>,
        source_digest: Digest,
        page_range: PageRange,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        consent: ConsentScope,
        permission: DocumentIntelligencePermission,
    ) -> Result<Self, ModelError> {
        Self::new(AzureDocumentIntelligenceScopeInput {
            tenant_id: tenant_id.into(),
            resource_name: resource_name.into(),
            region: region.into(),
            model,
            document_id: document_id.into(),
            source_digest,
            page_range,
            project,
            mission,
            work_product,
            consent,
            permission,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.source_digest.is_sha256() {
            return Err(ModelError::InvalidDigest {
                field: "source digest",
            });
        }
        if self.page_range.start_page == 0
            || self.page_range.end_page == 0
            || self.page_range.start_page > self.page_range.end_page
            || u32::from(self.page_range.end_page) > MAX_DOCUMENT_INTELLIGENCE_PAGE_NUMBER
        {
            return Err(ModelError::OutOfRange {
                field: "page range",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::digest_serializable(self)
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn tenant(&self) -> &TenantId {
        self.tenant_id()
    }

    pub fn resource_name(&self) -> &ResourceName {
        &self.resource_name
    }

    pub fn resource(&self) -> &ResourceName {
        self.resource_name()
    }

    pub fn region(&self) -> &AzureRegion {
        &self.region
    }

    pub const fn model(&self) -> DocumentModel {
        self.model
    }

    pub fn document_id(&self) -> &DocumentId {
        &self.document_id
    }

    pub fn document(&self) -> &DocumentId {
        self.document_id()
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub const fn page_range(&self) -> PageRange {
        self.page_range
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub const fn permission(&self) -> DocumentIntelligencePermission {
        self.permission
    }
}

/// An opaque host-owned credential handle. It intentionally implements no
/// serde traits and exposes no raw reference, tenant, or credential material.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    tenant_id: String,
    credential_revision: u64,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        tenant_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        let tenant_id = tenant_id.into();
        validate_opaque_reference(&reference_id, "secret reference id")?;
        validate_opaque_reference(&tenant_id, "secret tenant id")?;
        validate_positive(credential_revision, "credential revision")?;
        Ok(Self {
            reference_id,
            tenant_id,
            credential_revision,
        })
    }

    pub fn reference_digest(&self) -> Digest {
        crate::digest_serializable(&(
            "opaque-secret-reference",
            &self.reference_id,
            &self.tenant_id,
            self.credential_revision,
        ))
    }

    pub fn opaque_digest(&self) -> Digest {
        self.reference_digest()
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub(crate) fn matches_tenant(&self, tenant_id: &TenantId) -> bool {
        self.tenant_id == tenant_id.as_str()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &"<opaque>")
            .field("tenant_id", &"<opaque>")
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

fn validate_opaque_reference(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value.contains("://") {
        return Err(ModelError::UrlOrPath { field });
    }
    Ok(())
}

/// Redaction policy for text projections. Digest-only is the safe default.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPolicy {
    DigestOnly,
    BoundedPrefix { max_bytes: usize },
}

impl RedactionPolicy {
    pub const fn digest_only() -> Self {
        Self::DigestOnly
    }

    pub fn bounded_prefix(max_bytes: usize) -> Result<Self, ModelError> {
        if max_bytes == 0 || max_bytes > MAX_DOCUMENT_INTELLIGENCE_TEXT_PREVIEW_BYTES {
            return Err(ModelError::OutOfRange {
                field: "text preview bytes",
            });
        }
        Ok(Self::BoundedPrefix { max_bytes })
    }

    pub fn prefix(max_bytes: usize) -> Result<Self, ModelError> {
        Self::bounded_prefix(max_bytes)
    }

    pub const fn max_preview_bytes(self) -> Option<usize> {
        match self {
            Self::DigestOnly => None,
            Self::BoundedPrefix { max_bytes } => Some(max_bytes),
        }
    }
}

/// A bounded text projection containing a digest and optionally a short
/// explicitly authorized prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextProjection {
    content_digest: Digest,
    preview: Option<String>,
    preview_truncated: bool,
    character_count: usize,
}

impl TextProjection {
    pub fn from_text(value: &str, policy: RedactionPolicy) -> Self {
        let content_digest = sha256_digest(value.as_bytes());
        let character_count = value.chars().count();
        let (preview, preview_truncated) = match policy {
            RedactionPolicy::DigestOnly => (None, false),
            RedactionPolicy::BoundedPrefix { max_bytes } => {
                let mut end = value.len().min(max_bytes);
                while end > 0 && !value.is_char_boundary(end) {
                    end -= 1;
                }
                (Some(value[..end].to_owned()), end < value.len())
            }
        };
        Self {
            content_digest,
            preview,
            preview_truncated,
            character_count,
        }
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub fn preview(&self) -> Option<&str> {
        self.preview.as_deref()
    }

    pub const fn preview_truncated(&self) -> bool {
        self.preview_truncated
    }

    pub const fn character_count(&self) -> usize {
        self.character_count
    }
}

/// Fixed-point confidence summary avoids retaining provider floating-point
/// quirks while keeping a deterministic, bounded 0..=10000 basis-point value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ConfidenceSummary(u16);

impl ConfidenceSummary {
    pub fn new(value: f32) -> Result<Self, ModelError> {
        if !value.is_finite() {
            return Err(ModelError::NotFinite {
                field: "confidence",
            });
        }
        if !(0.0..=1.0).contains(&value) {
            return Err(ModelError::OutOfRange {
                field: "confidence",
            });
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let basis_points = (value * 10_000.0).round() as u16;
        Ok(Self(basis_points))
    }

    pub const fn from_basis_points(value: u16) -> Result<Self, ModelError> {
        if value > 10_000 {
            return Err(ModelError::OutOfRange {
                field: "confidence basis points",
            });
        }
        Ok(Self(value))
    }

    pub const fn basis_points(self) -> u16 {
        self.0
    }

    pub fn value(self) -> f32 {
        f32::from(self.0) / 10_000.0
    }
}

/// Geometry is reduced to a bounded count and fixed-point bounding box.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeometrySummary {
    point_count: u16,
    min_x_milli: u32,
    min_y_milli: u32,
    max_x_milli: u32,
    max_y_milli: u32,
}

impl GeometrySummary {
    pub const fn empty() -> Self {
        Self {
            point_count: 0,
            min_x_milli: 0,
            min_y_milli: 0,
            max_x_milli: 0,
            max_y_milli: 0,
        }
    }

    pub fn from_points(points: &[(f32, f32)]) -> Result<Self, ModelError> {
        if points.len() > usize::from(u16::MAX) {
            return Err(ModelError::BoundExceeded {
                field: "geometry points",
            });
        }
        let mut summary = Self::empty();
        for &(x, y) in points {
            summary.add_point(x, y)?;
        }
        Ok(summary)
    }

    pub const fn point_count(self) -> u16 {
        self.point_count
    }

    pub const fn min_x_milli(self) -> u32 {
        self.min_x_milli
    }

    pub const fn min_y_milli(self) -> u32 {
        self.min_y_milli
    }

    pub const fn max_x_milli(self) -> u32 {
        self.max_x_milli
    }

    pub const fn max_y_milli(self) -> u32 {
        self.max_y_milli
    }

    fn add_point(&mut self, x: f32, y: f32) -> Result<(), ModelError> {
        if !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0 {
            return Err(ModelError::NotFinite {
                field: "geometry coordinate",
            });
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let x_milli = (x * 1_000.0).round() as u32;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let y_milli = (y * 1_000.0).round() as u32;
        if self.point_count == 0 {
            self.min_x_milli = x_milli;
            self.min_y_milli = y_milli;
            self.max_x_milli = x_milli;
            self.max_y_milli = y_milli;
        } else {
            self.min_x_milli = self.min_x_milli.min(x_milli);
            self.min_y_milli = self.min_y_milli.min(y_milli);
            self.max_x_milli = self.max_x_milli.max(x_milli);
            self.max_y_milli = self.max_y_milli.max(y_milli);
        }
        self.point_count = self.point_count.saturating_add(1);
        Ok(())
    }

    fn merge(&mut self, other: Self) {
        if other.point_count == 0 {
            return;
        }
        if self.point_count == 0 {
            *self = other;
            return;
        }
        self.point_count = self.point_count.saturating_add(other.point_count);
        self.min_x_milli = self.min_x_milli.min(other.min_x_milli);
        self.min_y_milli = self.min_y_milli.min(other.min_y_milli);
        self.max_x_milli = self.max_x_milli.max(other.max_x_milli);
        self.max_y_milli = self.max_y_milli.max(other.max_y_milli);
    }
}

/// Bounded paragraph content and provider role metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParagraphProjection {
    text: TextProjection,
    role: Option<String>,
    geometry: GeometrySummary,
}

impl ParagraphProjection {
    pub fn text(&self) -> &TextProjection {
        &self.text
    }

    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    pub const fn geometry(&self) -> GeometrySummary {
        self.geometry
    }
}

/// A bounded table cell with redacted content and geometry/confidence summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableCellProjection {
    row_index: u16,
    column_index: u16,
    kind: Option<String>,
    text: TextProjection,
    confidence: Option<ConfidenceSummary>,
    geometry: GeometrySummary,
}

impl TableCellProjection {
    pub const fn row_index(&self) -> u16 {
        self.row_index
    }

    pub const fn column_index(&self) -> u16 {
        self.column_index
    }

    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    pub fn text(&self) -> &TextProjection {
        &self.text
    }

    pub const fn confidence(&self) -> Option<ConfidenceSummary> {
        self.confidence
    }

    pub const fn geometry(&self) -> GeometrySummary {
        self.geometry
    }
}

/// A bounded table projection; raw cell payloads are never retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableProjection {
    row_count: u16,
    column_count: u16,
    cells: Vec<TableCellProjection>,
}

impl TableProjection {
    pub const fn row_count(&self) -> u16 {
        self.row_count
    }

    pub const fn column_count(&self) -> u16 {
        self.column_count
    }

    pub fn cells(&self) -> &[TableCellProjection] {
        &self.cells
    }
}

/// Bounded field metadata from a prebuilt result. The field value is always a
/// redacted digest/prefix projection and never the provider value object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldProjection {
    name: String,
    value_type: Option<String>,
    value: TextProjection,
    confidence: Option<ConfidenceSummary>,
    geometry: GeometrySummary,
}

impl FieldProjection {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value_type(&self) -> Option<&str> {
        self.value_type.as_deref()
    }

    pub fn value(&self) -> &TextProjection {
        &self.value
    }

    pub const fn confidence(&self) -> Option<ConfidenceSummary> {
        self.confidence
    }

    pub const fn geometry(&self) -> GeometrySummary {
        self.geometry
    }
}

/// Page-level structural summary with no raw line/word geometry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageProjection {
    page_number: u16,
    line_count: u16,
    word_count: u16,
    selection_mark_count: u16,
    confidence: Option<ConfidenceSummary>,
    geometry: GeometrySummary,
}

impl PageProjection {
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn line_count(&self) -> u16 {
        self.line_count
    }

    pub const fn word_count(&self) -> u16 {
        self.word_count
    }

    pub const fn selection_mark_count(&self) -> u16 {
        self.selection_mark_count
    }

    pub const fn confidence(&self) -> Option<ConfidenceSummary> {
        self.confidence
    }

    pub const fn geometry(&self) -> GeometrySummary {
        self.geometry
    }
}

/// Redacted, bounded projection of an allowlisted Azure result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzeResultProjection {
    model: DocumentModel,
    source_digest: Digest,
    page_range: PageRange,
    content: Option<TextProjection>,
    pages: Vec<PageProjection>,
    paragraphs: Vec<ParagraphProjection>,
    tables: Vec<TableProjection>,
    fields: Vec<FieldProjection>,
    result_digest: Digest,
}

impl AnalyzeResultProjection {
    /// Build a projection from the provider's `analyzeResult` object.
    pub fn from_azure_json(
        model: DocumentModel,
        source_digest: &Digest,
        page_range: PageRange,
        value: &Value,
        redaction: RedactionPolicy,
    ) -> Result<Self, ModelError> {
        let object = value.as_object().ok_or(ModelError::Decode(
            "analyzeResult must be an object".to_owned(),
        ))?;
        if let Some(model_id) = object.get("modelId").and_then(Value::as_str)
            && model_id != model.as_str()
        {
            return Err(ModelError::Invalid {
                field: "result model id",
            });
        }
        let content = object
            .get("content")
            .and_then(Value::as_str)
            .map(|text| TextProjection::from_text(text, redaction));
        let pages = parse_pages(object.get("pages"), page_range)?;
        let paragraphs = parse_paragraphs(object.get("paragraphs"), redaction)?;
        let tables = parse_tables(object.get("tables"), redaction)?;
        let fields = parse_fields(object.get("documents"), redaction)?;
        if !model.supports_tables() && !tables.is_empty() {
            return Err(ModelError::Unsupported {
                field: "tables for prebuilt-read",
            });
        }
        let mut projection = Self {
            model,
            source_digest: source_digest.clone(),
            page_range,
            content,
            pages,
            paragraphs,
            tables,
            fields,
            result_digest: Digest::from_text("pending-result-digest"),
        };
        projection.result_digest = projection.compute_digest();
        Ok(projection)
    }

    /// A deterministic fixture projection for tests and local demos.
    pub fn fixture(
        model: DocumentModel,
        source_digest: &Digest,
        page_range: PageRange,
        redaction: RedactionPolicy,
    ) -> Result<Self, ModelError> {
        let body = serde_json::json!({
            "modelId": model.as_str(),
            "content": "fixture document text",
            "pages": [{
                "pageNumber": page_range.start_page(),
                "lines": [{"content": "fixture document text", "polygon": [0, 0, 1, 0, 1, 1, 0, 1]}],
                "words": [{"content": "fixture", "confidence": 0.99, "polygon": [0, 0, 1, 0, 1, 1, 0, 1]}]
            }],
            "paragraphs": [{"content": "fixture document text", "role": "body", "boundingRegions": [{"pageNumber": page_range.start_page(), "polygon": [0, 0, 1, 0, 1, 1, 0, 1]}]}],
            "tables": if model.supports_tables() { serde_json::json!([{"rowCount": 1, "columnCount": 1, "cells": [{"rowIndex": 0, "columnIndex": 0, "content": "fixture", "confidence": 0.98}]}]) } else { serde_json::json!([]) },
            "documents": []
        });
        Self::from_azure_json(model, source_digest, page_range, &body, redaction)
    }

    pub fn model(&self) -> DocumentModel {
        self.model
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub const fn page_range(&self) -> PageRange {
        self.page_range
    }

    pub fn content(&self) -> Option<&TextProjection> {
        self.content.as_ref()
    }

    pub fn pages(&self) -> &[PageProjection] {
        &self.pages
    }

    pub fn paragraphs(&self) -> &[ParagraphProjection] {
        &self.paragraphs
    }

    pub fn tables(&self) -> &[TableProjection] {
        &self.tables
    }

    pub fn fields(&self) -> &[FieldProjection] {
        &self.fields
    }

    pub fn result_digest(&self) -> &Digest {
        &self.result_digest
    }

    fn compute_digest(&self) -> Digest {
        crate::digest_serializable(&(
            self.model,
            &self.source_digest,
            self.page_range,
            &self.content,
            &self.pages,
            &self.paragraphs,
            &self.tables,
            &self.fields,
        ))
    }
}

fn parse_pages(
    value: Option<&Value>,
    page_range: PageRange,
) -> Result<Vec<PageProjection>, ModelError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if items.len() > MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PAGES {
        return Err(ModelError::BoundExceeded { field: "pages" });
    }
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or(ModelError::Decode("page must be an object".to_owned()))?;
        let page_number = required_u16(object, "pageNumber", "page number")?;
        if !page_range.contains(page_number) {
            return Err(ModelError::Invalid {
                field: "page outside registered range",
            });
        }
        let lines = bounded_array(object.get("lines"), "lines")?;
        let words = bounded_array(object.get("words"), "words")?;
        let selection_marks = bounded_array(object.get("selectionMarks"), "selection marks")?;
        let mut geometry = geometry_from_value(object.get("polygon"))?;
        geometry.merge(geometry_from_items(lines)?);
        geometry.merge(geometry_from_items(words)?);
        geometry.merge(geometry_from_items(selection_marks)?);
        let confidence = average_confidence(words)?;
        output.push(PageProjection {
            page_number,
            line_count: bounded_count(lines.len(), "lines")?,
            word_count: bounded_count(words.len(), "words")?,
            selection_mark_count: bounded_count(selection_marks.len(), "selection marks")?,
            confidence,
            geometry,
        });
    }
    Ok(output)
}

fn parse_paragraphs(
    value: Option<&Value>,
    redaction: RedactionPolicy,
) -> Result<Vec<ParagraphProjection>, ModelError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if items.len() > MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PARAGRAPHS {
        return Err(ModelError::BoundExceeded {
            field: "paragraphs",
        });
    }
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or(ModelError::Decode("paragraph must be an object".to_owned()))?;
        let content = object
            .get("content")
            .and_then(Value::as_str)
            .ok_or(ModelError::Decode(
                "paragraph content is missing".to_owned(),
            ))?;
        let role = bounded_optional_string(object.get("role"), "paragraph role")?;
        let geometry = geometry_from_value(object.get("boundingRegions"))?;
        output.push(ParagraphProjection {
            text: TextProjection::from_text(content, redaction),
            role,
            geometry,
        });
    }
    Ok(output)
}

fn parse_tables(
    value: Option<&Value>,
    redaction: RedactionPolicy,
) -> Result<Vec<TableProjection>, ModelError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if items.len() > MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLES {
        return Err(ModelError::BoundExceeded { field: "tables" });
    }
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or(ModelError::Decode("table must be an object".to_owned()))?;
        let row_count = required_u16(object, "rowCount", "table row count")?;
        let column_count = required_u16(object, "columnCount", "table column count")?;
        if row_count == 0 || column_count == 0 {
            return Err(ModelError::OutOfRange {
                field: "table dimensions",
            });
        }
        let cells = bounded_array(object.get("cells"), "table cells")?;
        if cells.len() > MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLE_CELLS {
            return Err(ModelError::BoundExceeded {
                field: "table cells",
            });
        }
        let mut projected_cells = Vec::with_capacity(cells.len());
        for cell in cells {
            let cell_object = cell.as_object().ok_or(ModelError::Decode(
                "table cell must be an object".to_owned(),
            ))?;
            let row_index = required_u16(cell_object, "rowIndex", "table row index")?;
            let column_index = required_u16(cell_object, "columnIndex", "table column index")?;
            if row_index >= row_count || column_index >= column_count {
                return Err(ModelError::OutOfRange {
                    field: "table cell index",
                });
            }
            let content = cell_object
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            projected_cells.push(TableCellProjection {
                row_index,
                column_index,
                kind: bounded_optional_string(cell_object.get("kind"), "table cell kind")?,
                text: TextProjection::from_text(content, redaction),
                confidence: optional_confidence(cell_object.get("confidence"))?,
                geometry: geometry_from_value(cell_object.get("boundingRegions"))?,
            });
        }
        output.push(TableProjection {
            row_count,
            column_count,
            cells: projected_cells,
        });
    }
    Ok(output)
}

fn parse_fields(
    value: Option<&Value>,
    redaction: RedactionPolicy,
) -> Result<Vec<FieldProjection>, ModelError> {
    let Some(documents) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut output = Vec::new();
    for document in documents {
        let Some(fields) = document.get("fields").and_then(Value::as_object) else {
            continue;
        };
        if fields.len() > MAX_DOCUMENT_INTELLIGENCE_OUTPUT_FIELDS {
            return Err(ModelError::BoundExceeded { field: "fields" });
        }
        for (name, value) in fields {
            if output.len() >= MAX_DOCUMENT_INTELLIGENCE_OUTPUT_FIELDS {
                return Err(ModelError::BoundExceeded { field: "fields" });
            }
            validate_bounded_text(name, "field name", MAX_IDENTIFIER_LENGTH, false)?;
            let object = value.as_object();
            let value_type = object
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let field_text = field_text(value);
            output.push(FieldProjection {
                name: name.clone(),
                value_type,
                value: TextProjection::from_text(&field_text, redaction),
                confidence: object
                    .and_then(|item| item.get("confidence"))
                    .map_or(Ok(None), |confidence| optional_confidence(Some(confidence)))?,
                geometry: object.map_or(Ok(GeometrySummary::empty()), |item| {
                    geometry_from_value(item.get("boundingRegions"))
                })?,
            });
        }
    }
    Ok(output)
}

fn field_text(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return String::new();
    };
    for key in [
        "content",
        "valueString",
        "valueDate",
        "valueTime",
        "valuePhoneNumber",
        "valueCountryRegion",
        "valueNumber",
        "valueInteger",
        "valueSelectionMark",
    ] {
        if let Some(value) = object.get(key) {
            if let Some(text) = value.as_str() {
                return text.to_owned();
            }
            if let Some(number) = value.as_f64() {
                return number.to_string();
            }
            if let Some(boolean) = value.as_bool() {
                return boolean.to_string();
            }
        }
    }
    String::new()
}

fn bounded_array<'a>(
    value: Option<&'a Value>,
    field: &'static str,
) -> Result<&'a [Value], ModelError> {
    match value {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or(ModelError::Decode(format!("{field} must be an array"))),
    }
}

fn bounded_count(value: usize, field: &'static str) -> Result<u16, ModelError> {
    u16::try_from(value).map_err(|_| ModelError::BoundExceeded { field })
}

fn required_u16(
    object: &Map<String, Value>,
    key: &'static str,
    field: &'static str,
) -> Result<u16, ModelError> {
    let value = object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(ModelError::Decode(format!("{field} is missing")))?;
    u16::try_from(value).map_err(|_| ModelError::OutOfRange { field })
}

fn bounded_optional_string(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Option<String>, ModelError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(ModelError::Decode(format!("{field} must be text")));
    };
    validate_bounded_text(value, field, MAX_IDENTIFIER_LENGTH, true)?;
    Ok(Some(value.to_owned()))
}

fn optional_confidence(value: Option<&Value>) -> Result<Option<ConfidenceSummary>, ModelError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .as_f64()
        .ok_or(ModelError::Decode("confidence must be numeric".to_owned()))?;
    #[allow(clippy::cast_possible_truncation)]
    ConfidenceSummary::new(value as f32).map(Some)
}

fn average_confidence(values: &[Value]) -> Result<Option<ConfidenceSummary>, ModelError> {
    let mut total = 0.0_f32;
    let mut count = 0_u16;
    for value in values {
        if let Some(confidence) = value.get("confidence") {
            let Some(confidence) = confidence.as_f64() else {
                return Err(ModelError::Decode("confidence must be numeric".to_owned()));
            };
            #[allow(clippy::cast_possible_truncation)]
            let confidence = confidence as f32;
            total += confidence;
            count = count.saturating_add(1);
        }
    }
    if count == 0 {
        Ok(None)
    } else {
        ConfidenceSummary::new(total / f32::from(count)).map(Some)
    }
}

fn geometry_from_items(items: &[Value]) -> Result<GeometrySummary, ModelError> {
    let mut summary = GeometrySummary::empty();
    for item in items {
        let Some(object) = item.as_object() else {
            return Err(ModelError::Decode(
                "geometry item must be an object".to_owned(),
            ));
        };
        summary.merge(geometry_from_value(object.get("polygon"))?);
        summary.merge(geometry_from_value(object.get("boundingRegions"))?);
    }
    Ok(summary)
}

fn geometry_from_value(value: Option<&Value>) -> Result<GeometrySummary, ModelError> {
    let Some(value) = value else {
        return Ok(GeometrySummary::empty());
    };
    if let Some(points) = value.as_array() {
        let mut parsed = Vec::new();
        if points.iter().all(Value::is_number) {
            if points.len() % 2 != 0 {
                return Err(ModelError::Decode(
                    "polygon has an odd coordinate count".to_owned(),
                ));
            }
            for pair in points.chunks_exact(2) {
                let x = pair[0]
                    .as_f64()
                    .ok_or(ModelError::Decode("polygon x is not numeric".to_owned()))?;
                let y = pair[1]
                    .as_f64()
                    .ok_or(ModelError::Decode("polygon y is not numeric".to_owned()))?;
                #[allow(clippy::cast_possible_truncation)]
                parsed.push((x as f32, y as f32));
            }
            return GeometrySummary::from_points(&parsed);
        }
        let mut summary = GeometrySummary::empty();
        for item in points {
            let Some(object) = item.as_object() else {
                return Err(ModelError::Decode(
                    "bounding region must be an object".to_owned(),
                ));
            };
            summary.merge(geometry_from_value(object.get("polygon"))?);
        }
        return Ok(summary);
    }
    Err(ModelError::Decode(
        "geometry value must be an array".to_owned(),
    ))
}

/// An Azure operation location represented only by its digest.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationLocation {
    location_digest: Digest,
}

impl OperationLocation {
    pub fn new(location: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::from_url(location)
    }

    pub fn from_url(location: impl AsRef<str>) -> Result<Self, ModelError> {
        let location = location.as_ref();
        if location.is_empty() {
            return Err(ModelError::Empty {
                field: "operation location",
            });
        }
        if location.len() > MAX_OPERATION_LOCATION_LENGTH {
            return Err(ModelError::TooLong {
                field: "operation location",
            });
        }
        if location.trim() != location || location.chars().any(char::is_control) {
            return Err(ModelError::ControlCharacter {
                field: "operation location",
            });
        }
        Ok(Self {
            location_digest: sha256_digest(location.as_bytes()),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.location_digest
    }
}

/// Typed status seam matching the asynchronous Azure operation lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    NotStarted,
    Running,
    Succeeded,
    Failed,
    Canceled,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl OperationStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::BlockedEnv
        )
    }

    pub const fn is_success(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// Evidence provenance. Every value in this root is explicitly non-native.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Recording,
    Fixture,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl ProviderMode {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

/// More descriptive alias for callers that model provenance separately.
pub type ProviderProvenance = ProviderMode;
/// Alias used by result-oriented callers.
pub type EvidenceProvenance = ProviderMode;
/// Short alias for callers that name the root by its capability.
pub type DocumentIntelligenceScope = AzureDocumentIntelligenceScope;
/// A source identity is a SHA-256 digest, never a source URL or byte buffer.
pub type SourceDigest = Digest;
/// Alias for the bounded request seam.
pub type AnalyzeRequest = DocumentAnalysisRequest;

/// Typed status/result frame returned by the provider seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationStatusFrame {
    operation_location: Option<OperationLocation>,
    status: OperationStatus,
    provider_revision: ProviderRevision,
    provenance: ProviderMode,
    response_digest: Digest,
    response_bytes: usize,
    failure_digest: Option<Digest>,
    result: Option<AnalyzeResultProjection>,
}

impl OperationStatusFrame {
    pub fn operation_location(&self) -> Option<&OperationLocation> {
        self.operation_location.as_ref()
    }

    pub const fn status(&self) -> OperationStatus {
        self.status
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub const fn provenance(&self) -> ProviderMode {
        self.provenance
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    pub fn failure_digest(&self) -> Option<&Digest> {
        self.failure_digest.as_ref()
    }

    pub fn result(&self) -> Option<&AnalyzeResultProjection> {
        self.result.as_ref()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        operation_location: Option<OperationLocation>,
        status: OperationStatus,
        provider_revision: ProviderRevision,
        provenance: ProviderMode,
        response_digest: Digest,
        response_bytes: usize,
        failure_digest: Option<Digest>,
        result: Option<AnalyzeResultProjection>,
    ) -> Self {
        Self {
            operation_location,
            status,
            provider_revision,
            provenance,
            response_digest,
            response_bytes,
            failure_digest,
            result,
        }
    }
}

/// A request contains only an immutable source digest, never document bytes
/// or a source URL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentAnalysisRequest {
    scope_digest: Digest,
    model: DocumentModel,
    document_id: DocumentId,
    source_digest: Digest,
    page_range: PageRange,
    redaction: RedactionPolicy,
    request_digest: Digest,
}

impl DocumentAnalysisRequest {
    pub(crate) fn for_scope(
        scope: &AzureDocumentIntelligenceScope,
        redaction: RedactionPolicy,
    ) -> Self {
        let mut request = Self {
            scope_digest: scope.digest(),
            model: scope.model,
            document_id: scope.document_id.clone(),
            source_digest: scope.source_digest.clone(),
            page_range: scope.page_range,
            redaction,
            request_digest: Digest::from_text("pending-request-digest"),
        };
        request.request_digest = request.compute_digest();
        request
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn model(&self) -> DocumentModel {
        self.model
    }

    pub fn document_id(&self) -> &DocumentId {
        &self.document_id
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub const fn page_range(&self) -> PageRange {
        self.page_range
    }

    pub const fn redaction(&self) -> RedactionPolicy {
        self.redaction
    }

    fn compute_digest(&self) -> Digest {
        crate::digest_serializable(&(
            &self.scope_digest,
            self.model,
            &self.document_id,
            &self.source_digest,
            self.page_range,
            self.redaction,
        ))
    }
}

/// Operation-level observation included in local evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationObservation {
    operation_location: Option<OperationLocation>,
    status: OperationStatus,
    response_digest: Digest,
    response_bytes: usize,
    failure_digest: Option<Digest>,
    result_digest: Option<Digest>,
}

impl OperationObservation {
    pub fn operation_location(&self) -> Option<&OperationLocation> {
        self.operation_location.as_ref()
    }

    pub const fn status(&self) -> OperationStatus {
        self.status
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    pub fn failure_digest(&self) -> Option<&Digest> {
        self.failure_digest.as_ref()
    }

    pub fn result_digest(&self) -> Option<&Digest> {
        self.result_digest.as_ref()
    }

    pub(crate) fn from_frame(frame: &OperationStatusFrame) -> Self {
        Self {
            operation_location: frame.operation_location.clone(),
            status: frame.status,
            response_digest: frame.response_digest.clone(),
            response_bytes: frame.response_bytes,
            failure_digest: frame.failure_digest.clone(),
            result_digest: frame
                .result
                .as_ref()
                .map(|result| result.result_digest.clone()),
        }
    }
}

/// Explicitly false Layer-1 authority flags. This is metadata, not a kernel
/// Truth/Receipt/Verification/Outcome implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct Layer1Authority {
    pub read_only: bool,
    pub external_writes: bool,
    pub uploads: bool,
    pub model_training: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub independent_read_back: bool,
    pub kernel_truth: bool,
    pub kernel_receipt: bool,
    pub kernel_verification: bool,
    pub kernel_outcome: bool,
    pub verified_work_product_adoption: bool,
}

impl Layer1Authority {
    pub const fn layer_one() -> Self {
        Self {
            read_only: true,
            external_writes: false,
            uploads: false,
            model_training: false,
            connected: false,
            native: false,
            durable_provider_receipt: false,
            independent_read_back: false,
            kernel_truth: false,
            kernel_receipt: false,
            kernel_verification: false,
            kernel_outcome: false,
            verified_work_product_adoption: false,
        }
    }
}

/// Redacted Layer-1 evidence consumed by a Mission/Work Product proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentIntelligenceEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: ProviderRevision,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub source_digest: Digest,
    pub model: DocumentModel,
    pub document_id: DocumentId,
    pub page_range: PageRange,
    pub provenance: ProviderMode,
    pub operation: OperationObservation,
    pub result: Option<AnalyzeResultProjection>,
    pub authority: Layer1Authority,
    pub evidence_digest: Digest,
}

impl DocumentIntelligenceEvidence {
    pub(crate) fn new(
        request: &DocumentAnalysisRequest,
        scope: &AzureDocumentIntelligenceScope,
        registration_digest: &Digest,
        provider_revision: ProviderRevision,
        frame: &OperationStatusFrame,
        contract_digest: Digest,
    ) -> Self {
        let operation = OperationObservation::from_frame(frame);
        let mut evidence = Self {
            contract_version: AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION.to_owned(),
            contract_digest,
            plugin_version: AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION.to_owned(),
            service_id: AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID.to_owned(),
            provider_id: AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID.to_owned(),
            provider_revision,
            registration_digest: registration_digest.clone(),
            scope_digest: scope.digest(),
            request_digest: request.digest().clone(),
            source_digest: scope.source_digest.clone(),
            model: scope.model,
            document_id: scope.document_id.clone(),
            page_range: scope.page_range,
            provenance: frame.provenance,
            operation,
            result: frame.result.clone(),
            authority: Layer1Authority::layer_one(),
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> Digest {
        crate::digest_serializable(&EvidenceMaterial {
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            plugin_version: &self.plugin_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            request_digest: &self.request_digest,
            source_digest: &self.source_digest,
            model: self.model,
            document_id: &self.document_id,
            page_range: self.page_range,
            provenance: self.provenance,
            operation: &self.operation,
            result: &self.result,
            authority: &self.authority,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.evidence_digest != self.compute_digest() {
            return Err(ModelError::Invalid {
                field: "evidence digest",
            });
        }
        if !self.authority.read_only
            || self.authority.external_writes
            || self.authority.uploads
            || self.authority.connected
            || self.authority.native
            || self.authority.durable_provider_receipt
            || self.authority.independent_read_back
            || self.authority.kernel_truth
            || self.authority.kernel_receipt
            || self.authority.kernel_verification
            || self.authority.kernel_outcome
            || self.authority.verified_work_product_adoption
        {
            return Err(ModelError::Invalid {
                field: "Layer-1 authority",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EvidenceMaterial<'a> {
    contract_version: &'a str,
    contract_digest: &'a Digest,
    plugin_version: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    provider_revision: &'a ProviderRevision,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    request_digest: &'a Digest,
    source_digest: &'a Digest,
    model: DocumentModel,
    document_id: &'a DocumentId,
    page_range: PageRange,
    provenance: ProviderMode,
    operation: &'a OperationObservation,
    result: &'a Option<AnalyzeResultProjection>,
    authority: &'a Layer1Authority,
}

/// Ensure constants referenced by the model remain intentionally bounded.
pub(crate) fn validate_model_constants() -> Result<(), ModelError> {
    if MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES == 0
        || MAX_DOCUMENT_INTELLIGENCE_TEXT_PREVIEW_BYTES == 0
        || MAX_DOCUMENT_INTELLIGENCE_OUTPUT_FIELDS == 0
        || MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PARAGRAPHS == 0
        || MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PAGES == 0
        || MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLE_CELLS == 0
        || MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLES == 0
    {
        return Err(ModelError::Invalid {
            field: "model bounds",
        });
    }
    Ok(())
}

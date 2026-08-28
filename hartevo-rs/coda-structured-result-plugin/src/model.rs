use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_METADATA_RECORDS: usize = 100;
pub const MAX_ALLOWLIST_ITEMS: usize = 16;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

pub type Digest = String;

/// Hash bytes with lowercase hexadecimal output.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

/// Hash the canonical JSON form of a typed contract value.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Coda contract value must serialize");
    sha256_digest(&bytes)
}

/// Hash a sequence with explicit separators so concatenation cannot create a
/// second interpretation of the same digest input.
#[must_use]
pub fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> Digest {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0);
    }
    sha256_digest(&bytes)
}

#[must_use]
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CodaModelError {
    #[error("{field} is empty, malformed, or exceeds its bound")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} contains unsupported content")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("Coda scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Coda page token is invalid")]
    InvalidPageToken,
    #[error("Coda page size must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidPageSize,
    #[error("Coda metadata record bound was exceeded")]
    TooManyMetadataRecords,
    #[error("Coda rate-limit receipt is outside its bound")]
    InvalidRateLimit,
    #[error("Coda registration is already revoked")]
    AlreadyRevoked,
    #[error("Coda registration is not revoked")]
    NotRevoked,
    #[error("Coda registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), CodaModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-~".contains(&byte))
    {
        return Err(CodaModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), CodaModelError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CodaModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), CodaModelError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(CodaModelError::InvalidDigest { field })
    }
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), CodaModelError> {
    if value == 0 {
        Err(CodaModelError::InvalidRevision { field })
    } else {
        Ok(())
    }
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CodaModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                sha256_digest(self.0.as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = CodaModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(CodaWorkspaceId, "workspace id");
identifier_type!(CodaDocId, "doc id");
identifier_type!(CodaPageId, "page id");
identifier_type!(CodaTableId, "table id");
identifier_type!(CodaViewId, "view id");
identifier_type!(CodaRowId, "row id");
identifier_type!(CodaColumnId, "column id");
identifier_type!(ProjectId, "Project id");
identifier_type!(MissionId, "Mission id");
identifier_type!(WorkProductId, "Work Product id");

pub type WorkspaceId = CodaWorkspaceId;
pub type DocId = CodaDocId;
pub type PageId = CodaPageId;
pub type TableId = CodaTableId;
pub type ViewId = CodaViewId;
pub type RowId = CodaRowId;
pub type ColumnId = CodaColumnId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, CodaModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        canonical_digest(&self)
    }
}

pub type CodaRevision = Revision;
pub type DocRevision = Revision;
pub type PageRevision = Revision;
pub type TableRevision = Revision;
pub type ViewRevision = Revision;
pub type RowRevision = Revision;
pub type ColumnRevision = Revision;

macro_rules! binding_type {
    ($name:ident, $id_type:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            id: $id_type,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, CodaModelError> {
                let value = Self {
                    id: $id_type::new(id)?,
                    revision: Revision::new(revision)?,
                };
                value.validate()?;
                Ok(value)
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

            pub fn validate(&self) -> Result<(), CodaModelError> {
                validate_identifier(self.id.as_str(), $field)?;
                validate_revision(self.revision.get(), $field)
            }
        }
    };
}

binding_type!(Project, ProjectId, "Project");
binding_type!(Mission, MissionId, "Mission");
binding_type!(WorkProduct, WorkProductId, "Work Product");

pub type ProjectBinding = Project;
pub type MissionBinding = Mission;
pub type WorkProductBinding = WorkProduct;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodaResourceKind {
    Doc,
    Page,
    Table,
    View,
    Column,
    Row,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodaReadOperation {
    DocMetadata,
    PageMetadata,
    TableMetadata,
    ViewMetadata,
    ColumnMetadata,
    RowMetadata,
}

impl CodaReadOperation {
    #[must_use]
    pub const fn resource_kind(self) -> CodaResourceKind {
        match self {
            Self::DocMetadata => CodaResourceKind::Doc,
            Self::PageMetadata => CodaResourceKind::Page,
            Self::TableMetadata => CodaResourceKind::Table,
            Self::ViewMetadata => CodaResourceKind::View,
            Self::ColumnMetadata => CodaResourceKind::Column,
            Self::RowMetadata => CodaResourceKind::Row,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DocMetadata => "doc_metadata",
            Self::PageMetadata => "page_metadata",
            Self::TableMetadata => "table_metadata",
            Self::ViewMetadata => "view_metadata",
            Self::ColumnMetadata => "column_metadata",
            Self::RowMetadata => "row_metadata",
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::DocMetadata => "/docs/{docId}",
            Self::PageMetadata => "/docs/{docId}/pages/{pageId}",
            Self::TableMetadata => "/docs/{docId}/tables/{tableId}",
            Self::ViewMetadata => "/docs/{docId}/tables/{viewId}?tableTypes=view",
            Self::ColumnMetadata => "/docs/{docId}/tables/{tableId}/columns/{columnId}",
            Self::RowMetadata => "/docs/{docId}/tables/{tableId}/rows/{rowId}",
        }
    }
}

/// Opaque host-owned API-token identity. The reference value is never
/// serialized or printed; only its digest participates in a registration.
#[derive(Clone, Deserialize, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, CodaModelError> {
        let value = Self {
            reference_id: reference_id.into(),
            credential_revision: Revision::new(credential_revision)?,
            revoked: false,
        };
        validate_text(&value.reference_id, "secret reference", 256)?;
        Ok(value)
    }

    pub fn api_token(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, CodaModelError> {
        Self::new(reference_id, credential_revision)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_parts([
            self.reference_id.as_str(),
            &self.credential_revision.get().to_string(),
            if self.revoked { "revoked" } else { "active" },
        ])
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), CodaModelError> {
        if self.revoked {
            return Err(CodaModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), CodaModelError> {
        if !self.revoked {
            return Err(CodaModelError::NotRevoked);
        }
        self.revoked = false;
        Ok(())
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 3)?;
        value.serialize_field("referenceDigest", &self.digest())?;
        value.serialize_field("credentialRevision", &self.credential_revision)?;
        value.serialize_field("revoked", &self.revoked)?;
        value.end()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.digest())
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

/// An opaque Coda `nextPageToken`. Raw token bytes remain private to the
/// transport seam and are never present in serialized requests or receipts.
#[derive(Clone, Eq, PartialEq)]
pub struct CodaPageToken {
    raw: String,
    token_digest: Digest,
    scope_digest: Digest,
    operation: CodaReadOperation,
    page_number: u16,
}

impl CodaPageToken {
    pub fn new(
        raw: impl Into<String>,
        scope_digest: impl Into<String>,
        operation: CodaReadOperation,
        page_number: u16,
    ) -> Result<Self, CodaModelError> {
        let raw = raw.into();
        let scope_digest = scope_digest.into();
        if raw.is_empty()
            || raw.len() > MAX_PAGE_TOKEN_BYTES
            || raw.chars().any(char::is_control)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(CodaModelError::InvalidPageToken);
        }
        validate_digest(&scope_digest, "page token scope digest")?;
        let token_digest = digest_parts([
            raw.as_str(),
            scope_digest.as_str(),
            operation.label(),
            &page_number.to_string(),
        ]);
        Ok(Self {
            raw,
            token_digest,
            scope_digest,
            operation,
            page_number,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn operation(&self) -> CodaReadOperation {
        self.operation
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn raw_digest(&self) -> Digest {
        sha256_digest(self.raw.as_bytes())
    }
}

impl Serialize for CodaPageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("CodaPageToken", 4)?;
        value.serialize_field("tokenDigest", &self.token_digest)?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.serialize_field("operation", &self.operation)?;
        value.serialize_field("pageNumber", &self.page_number)?;
        value.end()
    }
}

impl fmt::Debug for CodaPageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodaPageToken")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("operation", &self.operation)
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

pub type PageToken = CodaPageToken;
pub type OpaquePageToken = CodaPageToken;

/// A redacted, scope-bound read request. The actual resource ID is retained
/// only inside the crate so a transport can form its fixture lookup; public
/// serialization exposes its digest instead.
#[derive(Clone, Eq, PartialEq)]
pub struct CodaReadRequest {
    operation: CodaReadOperation,
    resource_id: String,
    scope_digest: Digest,
    resource_digest: Digest,
    revision: Revision,
    page_size: u32,
    page_number: u16,
    page_token: Option<CodaPageToken>,
    request_digest: Digest,
}

impl CodaReadRequest {
    pub fn new(
        scope: &CodaStructuredResultScope,
        operation: CodaReadOperation,
        resource_id: impl Into<String>,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<Self, CodaModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(CodaModelError::InvalidPageSize);
        }
        scope.validate()?;
        let resource_id = resource_id.into();
        if !scope.allows(operation.resource_kind(), &resource_id) {
            return Err(CodaModelError::InvalidScope(
                "resource is not in the allowlist",
            ));
        }
        let scope_digest = scope.digest();
        if let Some(token) = &page_token {
            if token.scope_digest() != &scope_digest || token.operation() != operation {
                return Err(CodaModelError::InvalidScope(
                    "page token is not scope-bound",
                ));
            }
            if token.page_number() >= MAX_PAGES {
                return Err(CodaModelError::InvalidPageToken);
            }
        }
        let page_number = page_token
            .as_ref()
            .map_or(1, |token| token.page_number() + 1);
        let resource_digest = scope.resource_digest(operation.resource_kind(), &resource_id);
        let request_digest = canonical_digest(&(
            operation,
            &scope_digest,
            &resource_digest,
            scope.revision,
            page_size,
            page_number,
            page_token.as_ref().map(CodaPageToken::digest),
        ));
        Ok(Self {
            operation,
            resource_id,
            scope_digest,
            resource_digest,
            revision: scope.revision,
            page_size,
            page_number,
            page_token,
            request_digest,
        })
    }

    pub fn doc(scope: &CodaStructuredResultScope, page_size: u32) -> Result<Self, CodaModelError> {
        Self::new(
            scope,
            CodaReadOperation::DocMetadata,
            scope.doc.as_str(),
            page_size,
            None,
        )
    }

    pub fn page(
        scope: &CodaStructuredResultScope,
        page: &CodaPageId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<Self, CodaModelError> {
        Self::new(
            scope,
            CodaReadOperation::PageMetadata,
            page.as_str(),
            page_size,
            page_token,
        )
    }

    pub fn table(
        scope: &CodaStructuredResultScope,
        table: &CodaTableId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<Self, CodaModelError> {
        Self::new(
            scope,
            CodaReadOperation::TableMetadata,
            table.as_str(),
            page_size,
            page_token,
        )
    }

    pub fn view(
        scope: &CodaStructuredResultScope,
        view: &CodaViewId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<Self, CodaModelError> {
        Self::new(
            scope,
            CodaReadOperation::ViewMetadata,
            view.as_str(),
            page_size,
            page_token,
        )
    }

    pub fn column(
        scope: &CodaStructuredResultScope,
        column: &CodaColumnId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<Self, CodaModelError> {
        Self::new(
            scope,
            CodaReadOperation::ColumnMetadata,
            column.as_str(),
            page_size,
            page_token,
        )
    }

    pub fn row(
        scope: &CodaStructuredResultScope,
        row: &CodaRowId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<Self, CodaModelError> {
        Self::new(
            scope,
            CodaReadOperation::RowMetadata,
            row.as_str(),
            page_size,
            page_token,
        )
    }

    #[must_use]
    pub const fn operation(&self) -> CodaReadOperation {
        self.operation
    }

    #[must_use]
    pub fn resource_digest(&self) -> &Digest {
        &self.resource_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&CodaPageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub(crate) fn resource_id(&self) -> &str {
        &self.resource_id
    }

    pub(crate) fn validate_for_scope(
        &self,
        scope: &CodaStructuredResultScope,
    ) -> Result<(), CodaModelError> {
        if self.scope_digest != scope.digest()
            || self.revision != scope.revision
            || !scope.allows(self.operation.resource_kind(), &self.resource_id)
        {
            return Err(CodaModelError::InvalidScope("request drifted from scope"));
        }
        Ok(())
    }
}

impl Serialize for CodaReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("CodaReadRequest", 8)?;
        value.serialize_field("operation", &self.operation)?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.serialize_field("resourceDigest", &self.resource_digest)?;
        value.serialize_field("revision", &self.revision)?;
        value.serialize_field("pageSize", &self.page_size)?;
        value.serialize_field("pageNumber", &self.page_number)?;
        value.serialize_field("pageToken", &self.page_token)?;
        value.serialize_field("requestDigest", &self.request_digest)?;
        value.end()
    }
}

impl fmt::Debug for CodaReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodaReadRequest")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("resource_digest", &self.resource_digest)
            .field("revision", &self.revision)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("page_token", &self.page_token)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

/// Exact workspace/doc/resource allowlists and the Mission bindings owned by
/// this one Layer-1 registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaStructuredResultScope {
    workspace: CodaWorkspaceId,
    doc: CodaDocId,
    page_allowlist: Vec<CodaPageId>,
    table_allowlist: Vec<CodaTableId>,
    view_allowlist: Vec<CodaViewId>,
    row_allowlist: Vec<CodaRowId>,
    column_allowlist: Vec<CodaColumnId>,
    revision: Revision,
    project: Project,
    mission: Mission,
    work_product: WorkProduct,
}

impl CodaStructuredResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: CodaWorkspaceId,
        doc: CodaDocId,
        mut page_allowlist: Vec<CodaPageId>,
        mut table_allowlist: Vec<CodaTableId>,
        mut view_allowlist: Vec<CodaViewId>,
        mut row_allowlist: Vec<CodaRowId>,
        mut column_allowlist: Vec<CodaColumnId>,
        revision: Revision,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
    ) -> Result<Self, CodaModelError> {
        page_allowlist.sort_unstable();
        table_allowlist.sort_unstable();
        view_allowlist.sort_unstable();
        row_allowlist.sort_unstable();
        column_allowlist.sort_unstable();
        let value = Self {
            workspace,
            doc,
            page_allowlist,
            table_allowlist,
            view_allowlist,
            row_allowlist,
            column_allowlist,
            revision,
            project,
            mission,
            work_product,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn workspace(&self) -> &CodaWorkspaceId {
        &self.workspace
    }

    #[must_use]
    pub fn doc(&self) -> &CodaDocId {
        &self.doc
    }

    #[must_use]
    pub fn pages(&self) -> &[CodaPageId] {
        &self.page_allowlist
    }

    #[must_use]
    pub fn tables(&self) -> &[CodaTableId] {
        &self.table_allowlist
    }

    #[must_use]
    pub fn views(&self) -> &[CodaViewId] {
        &self.view_allowlist
    }

    #[must_use]
    pub fn rows(&self) -> &[CodaRowId] {
        &self.row_allowlist
    }

    #[must_use]
    pub fn columns(&self) -> &[CodaColumnId] {
        &self.column_allowlist
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn project(&self) -> &Project {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &Mission {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProduct {
        &self.work_product
    }

    pub fn validate(&self) -> Result<(), CodaModelError> {
        validate_identifier(self.workspace.as_str(), "workspace id")?;
        validate_identifier(self.doc.as_str(), "doc id")?;
        validate_revision(self.revision.get(), "scope")?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        validate_allowlist(&self.page_allowlist, "page allowlist")?;
        validate_allowlist(&self.table_allowlist, "table allowlist")?;
        validate_allowlist(&self.view_allowlist, "view allowlist")?;
        validate_allowlist(&self.row_allowlist, "row allowlist")?;
        validate_allowlist(&self.column_allowlist, "column allowlist")?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    #[must_use]
    pub fn query_digest(&self) -> Digest {
        canonical_digest(&(
            &self.workspace,
            &self.doc,
            &self.page_allowlist,
            &self.table_allowlist,
            &self.view_allowlist,
            &self.row_allowlist,
            &self.column_allowlist,
            self.revision,
        ))
    }

    #[must_use]
    pub fn resource_digest(&self, kind: CodaResourceKind, id: &str) -> Digest {
        canonical_digest(&(&self.workspace, &self.doc, kind, id, self.revision))
    }

    #[must_use]
    pub fn allows(&self, kind: CodaResourceKind, id: &str) -> bool {
        match kind {
            CodaResourceKind::Doc => id == self.doc.as_str(),
            CodaResourceKind::Page => self.page_allowlist.iter().any(|value| value.as_str() == id),
            CodaResourceKind::Table => self
                .table_allowlist
                .iter()
                .any(|value| value.as_str() == id),
            CodaResourceKind::View => self.view_allowlist.iter().any(|value| value.as_str() == id),
            CodaResourceKind::Column => self
                .column_allowlist
                .iter()
                .any(|value| value.as_str() == id),
            CodaResourceKind::Row => self.row_allowlist.iter().any(|value| value.as_str() == id),
        }
    }
}

fn validate_allowlist<T>(values: &[T], field: &'static str) -> Result<(), CodaModelError>
where
    T: Serialize + Ord,
{
    if values.len() > MAX_ALLOWLIST_ITEMS {
        return Err(CodaModelError::InvalidScope(field));
    }
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(CodaModelError::InvalidScope(field));
    }
    for value in values {
        let serialized = serde_json::to_string(value).expect("identifier serializes");
        validate_identifier(serialized.trim_matches('"'), field)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodaTransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl CodaTransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodaEvidenceState {
    Present,
    Empty,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
    RegistrationRevoked,
    RevisionDrift,
}

impl CodaEvidenceState {
    #[must_use]
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Present)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodaEvidenceClassification {
    Present,
    Empty,
    Partial,
    Denied,
    RateLimit,
    ProviderUnknown,
    Tamper,
    RegistrationRevoked,
    RevisionDrift,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl Default for CodaRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: Some(MAX_REQUESTS_PER_MINUTE),
            retry_after_seconds: None,
            throttled: false,
        }
    }
}

impl CodaRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, CodaModelError> {
        if limit_per_minute == 0
            || limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || remaining.is_some_and(|value| value > limit_per_minute)
            || retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(CodaModelError::InvalidRateLimit);
        }
        Ok(Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
        })
    }

    pub fn validate(&self) -> Result<(), CodaModelError> {
        Self::new(
            self.limit_per_minute,
            self.remaining,
            self.retry_after_seconds,
            self.throttled,
        )
        .map(|_| ())
    }
}

/// Raw fixture/recording bytes are retained only behind this private response
/// boundary. Its public and Debug projections expose a digest and size.
#[derive(Clone, Eq, PartialEq)]
pub struct CodaResponse {
    status: u16,
    body: Vec<u8>,
    next_page_token: Option<String>,
    rate_limit: CodaRateLimitReceipt,
    reported_response_digest: Option<Digest>,
}

impl CodaResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec(value).expect("Coda fixture value serializes");
        Self {
            status,
            body,
            next_page_token: None,
            rate_limit: CodaRateLimitReceipt::default(),
            reported_response_digest: None,
        }
    }

    #[must_use]
    pub fn json_with_page_token<T: Serialize>(
        status: u16,
        value: &T,
        next_page_token: impl Into<String>,
    ) -> Self {
        let mut response = Self::json(status, value);
        response.next_page_token = Some(next_page_token.into());
        response
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: CodaRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            next_page_token: None,
            rate_limit,
            reported_response_digest: None,
        }
    }

    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: CodaRateLimitReceipt) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    pub fn with_reported_digest(mut self, digest: impl Into<String>) -> Self {
        self.reported_response_digest = Some(digest.into());
        self
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn rate_limit(&self) -> &CodaRateLimitReceipt {
        &self.rate_limit
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }

    pub(crate) fn reported_response_digest(&self) -> Option<&str> {
        self.reported_response_digest.as_deref()
    }
}

impl Serialize for CodaResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("CodaResponse", 6)?;
        value.serialize_field("status", &self.status)?;
        value.serialize_field("responseDigest", &self.response_digest())?;
        value.serialize_field("responseBytes", &self.response_bytes())?;
        value.serialize_field(
            "nextPageTokenDigest",
            &self
                .next_page_token
                .as_deref()
                .map(|token| sha256_digest(token.as_bytes())),
        )?;
        value.serialize_field("rateLimit", &self.rate_limit)?;
        value.serialize_field("reportedResponseDigest", &self.reported_response_digest)?;
        value.end()
    }
}

impl fmt::Debug for CodaResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodaResponse")
            .field("status", &self.status)
            .field("response_digest", &self.response_digest())
            .field("response_bytes", &self.response_bytes())
            .field(
                "next_page_token_digest",
                &self
                    .next_page_token
                    .as_deref()
                    .map(|token| sha256_digest(token.as_bytes())),
            )
            .field("rate_limit", &self.rate_limit)
            .finish_non_exhaustive()
    }
}

/// A bounded metadata projection. Names, timestamps, values, rich text, and
/// person-identifying fields are represented only by digests or counts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaMetadataRecord {
    pub kind: CodaResourceKind,
    pub identifier_digest: Digest,
    pub parent_digest: Option<Digest>,
    pub name_digest: Option<Digest>,
    pub type_digest: Option<Digest>,
    pub item_count: u32,
    pub row_count: Option<u64>,
    pub column_count: Option<u32>,
    pub value_count: Option<u32>,
    pub created_at_digest: Option<Digest>,
    pub updated_at_digest: Option<Digest>,
    pub revision: Revision,
    pub metadata_digest: Digest,
}

impl CodaMetadataRecord {
    pub(crate) fn from_safe_fields(
        kind: CodaResourceKind,
        identifier: &str,
        parent: Option<&str>,
        name: Option<&str>,
        type_name: Option<&str>,
        item_count: u32,
        row_count: Option<u64>,
        column_count: Option<u32>,
        value_count: Option<u32>,
        created_at: Option<&str>,
        updated_at: Option<&str>,
        revision: Revision,
    ) -> Self {
        let identifier_digest = sha256_digest(identifier.as_bytes());
        let parent_digest = parent.map(|value| sha256_digest(value.as_bytes()));
        let name_digest = name.map(|value| sha256_digest(value.as_bytes()));
        let type_digest = type_name.map(|value| sha256_digest(value.as_bytes()));
        let created_at_digest = created_at.map(|value| sha256_digest(value.as_bytes()));
        let updated_at_digest = updated_at.map(|value| sha256_digest(value.as_bytes()));
        let metadata_digest = canonical_digest(&(
            kind,
            &identifier_digest,
            &parent_digest,
            &name_digest,
            &type_digest,
            item_count,
            row_count,
            column_count,
            value_count,
            &created_at_digest,
            &updated_at_digest,
            revision,
        ));
        Self {
            kind,
            identifier_digest,
            parent_digest,
            name_digest,
            type_digest,
            item_count,
            row_count,
            column_count,
            value_count,
            created_at_digest,
            updated_at_digest,
            revision,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<(), CodaModelError> {
        validate_digest(&self.identifier_digest, "metadata identifier")?;
        for digest in [
            self.parent_digest.as_ref(),
            self.name_digest.as_ref(),
            self.type_digest.as_ref(),
            self.created_at_digest.as_ref(),
            self.updated_at_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest, "metadata field")?;
        }
        validate_revision(self.revision.get(), "metadata")?;
        validate_digest(&self.metadata_digest, "metadata")
    }
}

pub type CodaDocMetadata = CodaMetadataRecord;
pub type CodaPageMetadata = CodaMetadataRecord;
pub type CodaTableMetadata = CodaMetadataRecord;
pub type CodaViewMetadata = CodaMetadataRecord;
pub type CodaColumnMetadata = CodaMetadataRecord;
pub type CodaRowMetadata = CodaMetadataRecord;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaStructuredResultEvidence {
    pub operation: CodaReadOperation,
    pub state: CodaEvidenceState,
    pub classification: CodaEvidenceClassification,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub doc_digest: Digest,
    pub table_digest: Digest,
    pub row_digest: Digest,
    pub revision_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub metadata: Vec<CodaMetadataRecord>,
    #[serde(skip_deserializing)]
    pub next_page_token: Option<CodaPageToken>,
    pub rate_limit: CodaRateLimitReceipt,
    pub provenance: CodaTransportProvenance,
    pub partial: bool,
    pub redacted: bool,
    pub raw_rich_text_retained: bool,
    pub raw_pii_retained: bool,
    pub formula_executed: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub evidence_digest: Digest,
}

impl CodaStructuredResultEvidence {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    #[must_use]
    pub const fn state(&self) -> CodaEvidenceState {
        self.state
    }

    #[must_use]
    pub fn is_present(&self) -> bool {
        self.state == CodaEvidenceState::Present
    }

    #[must_use]
    pub fn metadata(&self) -> &[CodaMetadataRecord] {
        &self.metadata
    }

    pub fn validate(&self) -> Result<(), CodaModelError> {
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.query_digest, "query")?;
        validate_digest(&self.doc_digest, "doc")?;
        validate_digest(&self.table_digest, "table")?;
        validate_digest(&self.row_digest, "row")?;
        validate_digest(&self.revision_digest, "revision")?;
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.registration_digest, "registration")?;
        validate_digest(&self.response_digest, "response")?;
        validate_digest(&self.evidence_digest, "evidence")?;
        if self.metadata.len() > MAX_METADATA_RECORDS {
            return Err(CodaModelError::TooManyMetadataRecords);
        }
        for record in &self.metadata {
            record.validate()?;
        }
        self.rate_limit.validate()?;
        if !self.redacted
            || self.raw_rich_text_retained
            || self.raw_pii_retained
            || self.formula_executed
            || self.native
            || self.connected
            || self.first_party
            || self.durable_provider_receipt
        {
            return Err(CodaModelError::InvalidScope(
                "evidence authority/redaction flags",
            ));
        }
        if self.recompute_digest() != self.evidence_digest {
            return Err(CodaModelError::InvalidScope("evidence digest"));
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn recompute_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "operation": self.operation,
            "state": self.state,
            "classification": self.classification,
            "scopeDigest": self.scope_digest,
            "queryDigest": self.query_digest,
            "docDigest": self.doc_digest,
            "tableDigest": self.table_digest,
            "rowDigest": self.row_digest,
            "revisionDigest": self.revision_digest,
            "providerDigest": self.provider_digest,
            "registrationDigest": self.registration_digest,
            "responseDigest": self.response_digest,
            "responseBytes": self.response_bytes,
            "metadata": self.metadata,
            "pageTokenDigest": self.next_page_token.as_ref().map(CodaPageToken::digest),
            "rateLimit": self.rate_limit,
            "provenance": self.provenance,
            "partial": self.partial,
            "redacted": self.redacted,
        }))
    }

    pub(crate) fn build(
        operation: CodaReadOperation,
        state: CodaEvidenceState,
        classification: CodaEvidenceClassification,
        scope_digest: Digest,
        query_digest: Digest,
        doc_digest: Digest,
        table_digest: Digest,
        row_digest: Digest,
        revision_digest: Digest,
        provider_digest: Digest,
        registration_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
        metadata: Vec<CodaMetadataRecord>,
        next_page_token: Option<CodaPageToken>,
        rate_limit: CodaRateLimitReceipt,
        provenance: CodaTransportProvenance,
        partial: bool,
    ) -> Result<Self, CodaModelError> {
        let mut evidence = Self {
            operation,
            state,
            classification,
            scope_digest,
            query_digest,
            doc_digest,
            table_digest,
            row_digest,
            revision_digest,
            provider_digest,
            registration_digest,
            response_digest,
            response_bytes,
            metadata,
            next_page_token,
            rate_limit,
            provenance,
            partial,
            redacted: true,
            raw_rich_text_retained: false,
            raw_pii_retained: false,
            formula_executed: false,
            native: false,
            connected: false,
            first_party: false,
            durable_provider_receipt: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.recompute_digest();
        evidence.validate()?;
        Ok(evidence)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaStructuredResultProposal {
    pub operation: CodaReadOperation,
    pub state: CodaEvidenceState,
    pub evidence: CodaStructuredResultEvidence,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub revision_digest: Digest,
    pub query_digest: Digest,
    pub doc_digest: Digest,
    pub table_digest: Digest,
    pub row_digest: Digest,
    pub evidence_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_key: Digest,
    pub proposal_digest: Digest,
    pub provenance: CodaTransportProvenance,
    pub proposal_only: bool,
    pub read_only: bool,
    pub adoptable: bool,
    pub raw_rich_text_retained: bool,
    pub raw_pii_retained: bool,
    pub formula_executed: bool,
    pub external_write_performed: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl CodaStructuredResultProposal {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate(&self) -> Result<(), CodaModelError> {
        self.evidence.validate()?;
        if self.evidence.evidence_digest != self.evidence_digest {
            return Err(CodaModelError::InvalidScope("proposal evidence binding"));
        }
        for (field, value) in [
            ("scope", &self.scope_digest),
            ("project", &self.project_digest),
            ("mission", &self.mission_digest),
            ("work product", &self.work_product_digest),
            ("revision", &self.revision_digest),
            ("query", &self.query_digest),
            ("doc", &self.doc_digest),
            ("table", &self.table_digest),
            ("row", &self.row_digest),
            ("evidence", &self.evidence_digest),
            ("provider", &self.provider_digest),
            ("registration", &self.registration_digest),
            ("idempotency", &self.idempotency_key),
            ("proposal", &self.proposal_digest),
        ] {
            validate_digest(value, field)?;
        }
        if !self.proposal_only
            || !self.read_only
            || self.raw_rich_text_retained
            || self.raw_pii_retained
            || self.formula_executed
            || self.external_write_performed
            || self.native
            || self.connected
            || self.first_party
        {
            return Err(CodaModelError::InvalidScope(
                "proposal authority/redaction flags",
            ));
        }
        if self.adoptable != self.state.is_adoptable() {
            return Err(CodaModelError::InvalidScope("proposal adoptability"));
        }
        if self.recompute_digest() != self.proposal_digest {
            return Err(CodaModelError::InvalidScope("proposal digest"));
        }
        Ok(())
    }

    pub(crate) fn build(
        evidence: &CodaStructuredResultEvidence,
        scope: &CodaStructuredResultScope,
        provider_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, CodaModelError> {
        let scope_digest = scope.digest();
        let project_digest = scope.project.digest();
        let mission_digest = scope.mission.digest();
        let work_product_digest = scope.work_product.digest();
        let idempotency_key = canonical_digest(&(
            &scope_digest,
            &evidence.evidence_digest,
            &registration_digest,
            evidence.operation,
            &evidence.revision_digest,
        ));
        let mut proposal = Self {
            operation: evidence.operation,
            state: evidence.state,
            evidence: evidence.clone(),
            scope_digest,
            project_digest,
            mission_digest,
            work_product_digest,
            revision_digest: evidence.revision_digest.clone(),
            query_digest: evidence.query_digest.clone(),
            doc_digest: evidence.doc_digest.clone(),
            table_digest: evidence.table_digest.clone(),
            row_digest: evidence.row_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provider_digest,
            registration_digest,
            idempotency_key,
            proposal_digest: String::new(),
            provenance: evidence.provenance,
            proposal_only: true,
            read_only: true,
            adoptable: evidence.state.is_adoptable(),
            raw_rich_text_retained: false,
            raw_pii_retained: false,
            formula_executed: false,
            external_write_performed: false,
            native: false,
            connected: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.recompute_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    #[must_use]
    fn recompute_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "operation": self.operation,
            "state": self.state,
            "scopeDigest": self.scope_digest,
            "projectDigest": self.project_digest,
            "missionDigest": self.mission_digest,
            "workProductDigest": self.work_product_digest,
            "revisionDigest": self.revision_digest,
            "queryDigest": self.query_digest,
            "docDigest": self.doc_digest,
            "tableDigest": self.table_digest,
            "rowDigest": self.row_digest,
            "evidenceDigest": self.evidence_digest,
            "providerDigest": self.provider_digest,
            "registrationDigest": self.registration_digest,
            "idempotencyKey": self.idempotency_key,
            "provenance": self.provenance,
            "proposalOnly": self.proposal_only,
            "readOnly": self.read_only,
            "adoptable": self.adoptable,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaRecordingReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub idempotency_key: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: CodaTransportProvenance,
    pub durable_provider_receipt: bool,
    pub external_write_performed: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl CodaRecordingReceipt {
    pub fn validate(&self) -> Result<(), CodaModelError> {
        for (field, value) in [
            ("receipt", &self.receipt_digest),
            ("proposal", &self.proposal_digest),
            ("idempotency", &self.idempotency_key),
            ("scope", &self.scope_digest),
            ("provider", &self.provider_digest),
            ("registration", &self.registration_digest),
            ("evidence", &self.evidence_digest),
        ] {
            validate_digest(value, field)?;
        }
        if self.durable_provider_receipt
            || self.external_write_performed
            || self.native
            || self.connected
            || self.first_party
        {
            return Err(CodaModelError::InvalidScope("receipt authority flags"));
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn build(proposal: &CodaStructuredResultProposal) -> Self {
        let receipt_digest = canonical_digest(&(
            &proposal.proposal_digest,
            &proposal.idempotency_key,
            &proposal.scope_digest,
            &proposal.provider_digest,
            &proposal.registration_digest,
            &proposal.evidence_digest,
            CodaTransportProvenance::Recording,
        ));
        Self {
            receipt_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            scope_digest: proposal.scope_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            provenance: CodaTransportProvenance::Recording,
            durable_provider_receipt: false,
            external_write_performed: false,
            native: false,
            connected: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaRegistration {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub active: bool,
    pub registration_digest: Digest,
}

impl CodaRegistration {
    pub(crate) fn new(
        plugin_version_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        scope_digest: Digest,
        secret_reference_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version_digest,
            contract_digest,
            provider_digest,
            scope_digest,
            secret_reference_digest,
            registration_revision: Revision::new(1).expect("registration revision is non-zero"),
            active: true,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.recompute_digest();
        registration
    }

    #[must_use]
    fn recompute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            self.active,
        ))
    }

    pub fn validate(&self) -> Result<(), CodaModelError> {
        for (field, value) in [
            ("plugin version", &self.plugin_version_digest),
            ("contract", &self.contract_digest),
            ("provider", &self.provider_digest),
            ("scope", &self.scope_digest),
            ("secret reference", &self.secret_reference_digest),
            ("registration", &self.registration_digest),
        ] {
            validate_digest(value, field)?;
        }
        validate_revision(self.registration_revision.get(), "registration")?;
        if self.recompute_digest() != self.registration_digest {
            return Err(CodaModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<CodaRegistrationRevocation, CodaModelError> {
        if !self.active {
            return Err(CodaModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.active = false;
        self.rotate()?;
        Ok(CodaRegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            revoked: true,
        })
    }

    pub fn restore(&mut self) -> Result<CodaRegistrationRevocation, CodaModelError> {
        if self.active {
            return Err(CodaModelError::NotRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.active = true;
        self.rotate()?;
        Ok(CodaRegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            revoked: false,
        })
    }

    fn rotate(&mut self) -> Result<(), CodaModelError> {
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(CodaModelError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next)?;
        self.registration_digest = self.recompute_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaRegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub revoked: bool,
}

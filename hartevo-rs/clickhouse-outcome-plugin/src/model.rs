use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    CLICKHOUSE_OUTCOME_CONSUMER_ID, CLICKHOUSE_OUTCOME_CONTRACT_VERSION,
    CLICKHOUSE_OUTCOME_SCHEMA_VERSION, CLICKHOUSE_OUTCOME_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_QUERY_ID_BYTES: usize = 256;
pub(crate) const MAX_QUERY_BYTES: usize = 16 * 1024;
pub(crate) const MAX_RESULT_ROWS: u32 = 100_000;
pub(crate) const MAX_RESULT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_PROGRESS_EVENTS: u8 = 64;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("host must be an HTTPS origin without a path, query, or fragment")]
    InvalidHost,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("scope is incomplete or invalid")]
    InvalidScope,
    #[error("result bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("schema contains a duplicate or invalid column")]
    InvalidSchema,
    #[error("row contains an invalid cell")]
    InvalidRow,
    #[error("statistics are inconsistent or exceed the declared shape")]
    InvalidStatistics,
    #[error("query identifier is empty, malformed, or too long")]
    InvalidQueryId,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
}

/// A lower-case SHA-256 digest used to fence every proposal and evidence
/// object. Raw SQL, parameter values, credentials, and response bodies are
/// never placed in public evidence; only their digests may cross the seam.
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'$'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_column_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'$'))
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

string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(DatabaseId);
string_identifier!(TableId);
string_identifier!(SchemaId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

/// A normalized HTTPS origin. It may contain a port for self-hosted
/// ClickHouse, but never a path, query, fragment, userinfo, or HTTP scheme.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Host(String);

impl Host {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let remainder = value
            .strip_prefix("https://")
            .ok_or(ModelError::InvalidHost)?;
        if remainder.is_empty()
            || remainder.contains(['/', '?', '#', '@'])
            || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ModelError::InvalidHost);
        }
        let (host, port) = match remainder.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let number = port.parse::<u16>().map_err(|_| ModelError::InvalidHost)?;
                if number == 0 {
                    return Err(ModelError::InvalidHost);
                }
                (host, Some(number))
            }
            _ => (remainder, None),
        };
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
            return Err(ModelError::InvalidHost);
        }
        let normalized = match port {
            Some(port) => format!("https://{}:{port}", host.to_ascii_lowercase()),
            None => format!("https://{}", host.to_ascii_lowercase()),
        };
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Host {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Host").field(&self.0).finish()
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
pub enum ClickHouseAuthKind {
    HttpsBasic,
    ServiceToken,
}

/// An opaque host-owned secret reference. The reference handle is hashed at
/// construction time and then discarded; Layer 1 never accepts secret bytes,
/// serializes the handle, or resolves it.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: ClickHouseAuthKind,
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

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &ClickHouseScope,
        credential_revision: u64,
        auth_kind: ClickHouseAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if reference_id.is_empty()
            || reference_id.len() > 256
            || reference_id.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "clickhouse-secret-reference/v1",
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

    pub fn https_basic(
        reference_id: impl Into<String>,
        scope: &ClickHouseScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            ClickHouseAuthKind::HttpsBasic,
        )
    }

    pub fn basic(
        reference_id: impl Into<String>,
        scope: &ClickHouseScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::https_basic(reference_id, scope, credential_revision)
    }

    pub fn service_token(
        reference_id: impl Into<String>,
        scope: &ClickHouseScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            ClickHouseAuthKind::ServiceToken,
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

    pub const fn auth_kind(&self) -> ClickHouseAuthKind {
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

/// Exact endpoint/database/table/schema and Project/Mission/Work Product
/// binding for one analytical read proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClickHouseScope {
    https_host: Host,
    cluster: String,
    database: DatabaseId,
    table: TableId,
    schema: SchemaId,
    schema_revision: Revision,
    project_id: ProjectId,
    mission_id: MissionId,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl ClickHouseScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        https_host: impl Into<String>,
        cluster: impl Into<String>,
        database: impl Into<String>,
        table: impl Into<String>,
        schema: impl Into<String>,
        schema_revision: u64,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            https_host: Host::new(https_host)?,
            cluster: cluster.into(),
            database: DatabaseId::new(database)?,
            table: TableId::new(table)?,
            schema: SchemaId::new(schema)?,
            schema_revision: Revision::new(schema_revision)?,
            project_id: ProjectId::new(project_id)?,
            mission_id: MissionId::new(mission_id)?,
            work_product_id: WorkProductId::new(work_product_id)?,
            work_product_revision: Revision::new(work_product_revision)?,
            permission_digest,
            consent_digest,
            scope_digest: Digest::from_text("unsealed-clickhouse-scope"),
        };
        if !valid_identifier(&scope.cluster) {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "clickhouse-scope/v1",
            &[
                scope.https_host.as_str().to_owned(),
                scope.cluster.clone(),
                scope.database.as_str().to_owned(),
                scope.table.as_str().to_owned(),
                scope.schema.as_str().to_owned(),
                scope.schema_revision.get().to_string(),
                scope.project_id.as_str().to_owned(),
                scope.mission_id.as_str().to_owned(),
                scope.work_product_id.as_str().to_owned(),
                scope.work_product_revision.get().to_string(),
                scope.permission_digest.as_str().to_owned(),
                scope.consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    pub fn https_host(&self) -> &Host {
        &self.https_host
    }

    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    pub fn database(&self) -> &DatabaseId {
        &self.database
    }

    pub fn table(&self) -> &TableId {
        &self.table
    }

    pub fn schema(&self) -> &SchemaId {
        &self.schema
    }

    pub const fn schema_revision(&self) -> Revision {
        self.schema_revision
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
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

    pub(crate) fn contains_table(&self, database: &str, table: &str) -> bool {
        database == self.database.as_str() && table == self.table.as_str()
    }

    pub(crate) fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    DryRun,
    BoundedReadProposal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CellType {
    String,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Decimal,
    Boolean,
    Date,
    DateTime,
    Uuid,
    Json,
    Array,
    Tuple,
    Bytes,
    Null,
}

pub type ClickHouseType = CellType;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QueryId(String);

impl QueryId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_QUERY_ID_BYTES
            || value.chars().any(char::is_control)
            || value.chars().any(char::is_whitespace)
        {
            Err(ModelError::InvalidQueryId)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields("clickhouse-query-id/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for QueryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryId")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Pending,
    Running,
    Complete,
    Partial,
    Truncated,
    Timeout,
    Cancelled,
    Failed,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryProgress {
    pub read_rows: u64,
    pub read_bytes: u64,
    pub total_rows_to_read: Option<u64>,
    pub elapsed_ns: u64,
    pub progress_digest: Digest,
}

impl QueryProgress {
    pub fn new(
        read_rows: u64,
        read_bytes: u64,
        total_rows_to_read: Option<u64>,
        elapsed_ns: u64,
    ) -> Self {
        let progress_digest = Digest::from_fields(
            "clickhouse-progress/v1",
            &[
                read_rows.to_string(),
                read_bytes.to_string(),
                total_rows_to_read.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                elapsed_ns.to_string(),
            ],
        );
        Self {
            read_rows,
            read_bytes,
            total_rows_to_read,
            elapsed_ns,
            progress_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.read_rows,
            self.read_bytes,
            self.total_rows_to_read,
            self.elapsed_ns,
        )
        .progress_digest;
        (expected == self.progress_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryStatistics {
    pub read_rows: u64,
    pub read_bytes: u64,
    pub result_rows: u64,
    pub result_bytes: u64,
    pub elapsed_ns: u64,
    pub memory_usage: u64,
    pub statistics_digest: Digest,
}

impl QueryStatistics {
    pub fn new(
        read_rows: u64,
        read_bytes: u64,
        result_rows: u64,
        result_bytes: u64,
        elapsed_ns: u64,
        memory_usage: u64,
    ) -> Self {
        let statistics_digest = Digest::from_fields(
            "clickhouse-statistics/v1",
            &[
                read_rows.to_string(),
                read_bytes.to_string(),
                result_rows.to_string(),
                result_bytes.to_string(),
                elapsed_ns.to_string(),
                memory_usage.to_string(),
            ],
        );
        Self {
            read_rows,
            read_bytes,
            result_rows,
            result_bytes,
            elapsed_ns,
            memory_usage,
            statistics_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.result_rows > self.read_rows && self.read_rows != 0 {
            return Err(ModelError::InvalidStatistics);
        }
        let expected = Self::new(
            self.read_rows,
            self.read_bytes,
            self.result_rows,
            self.result_bytes,
            self.elapsed_ns,
            self.memory_usage,
        )
        .statistics_digest;
        (expected == self.statistics_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
}

/// Stable metadata derived from the ClickHouse HTTP summary headers/body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuerySummary {
    pub read_rows: u64,
    pub read_bytes: u64,
    pub result_rows: u64,
    pub result_bytes: u64,
    pub elapsed_ns: u64,
    pub memory_usage: u64,
    pub summary_digest: Digest,
}

impl QuerySummary {
    pub fn new(statistics: &QueryStatistics) -> Self {
        let summary_digest = Digest::from_fields(
            "clickhouse-summary/v1",
            &[
                statistics.read_rows.to_string(),
                statistics.read_bytes.to_string(),
                statistics.result_rows.to_string(),
                statistics.result_bytes.to_string(),
                statistics.elapsed_ns.to_string(),
                statistics.memory_usage.to_string(),
            ],
        );
        Self {
            read_rows: statistics.read_rows,
            read_bytes: statistics.read_bytes,
            result_rows: statistics.result_rows,
            result_bytes: statistics.result_bytes,
            elapsed_ns: statistics.elapsed_ns,
            memory_usage: statistics.memory_usage,
            summary_digest,
        }
    }

    pub fn validate_against(&self, statistics: &QueryStatistics) -> Result<(), ModelError> {
        let expected = Self::new(statistics);
        (expected == *self)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuerySchemaField {
    pub name: String,
    pub cell_type: CellType,
    pub nullable: bool,
}

pub type ColumnSchema = QuerySchemaField;

impl QuerySchemaField {
    pub fn new(
        name: impl Into<String>,
        cell_type: CellType,
        nullable: bool,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        if valid_column_name(&name) {
            Ok(Self {
                name,
                cell_type,
                nullable,
            })
        } else {
            Err(ModelError::InvalidSchema)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuerySchema {
    pub fields: Vec<QuerySchemaField>,
    pub schema_revision: Revision,
    pub schema_digest: Digest,
}

impl QuerySchema {
    pub fn new(fields: Vec<QuerySchemaField>) -> Result<Self, ModelError> {
        Self::with_revision(Revision::new(1)?, fields)
    }

    pub fn with_revision(
        schema_revision: Revision,
        fields: Vec<QuerySchemaField>,
    ) -> Result<Self, ModelError> {
        if fields.is_empty() {
            return Err(ModelError::InvalidSchema);
        }
        let mut names = BTreeSet::new();
        for field in &fields {
            if !names.insert(field.name.clone()) {
                return Err(ModelError::InvalidSchema);
            }
        }
        let schema_digest = Self::compute_digest(schema_revision, &fields);
        Ok(Self {
            fields,
            schema_revision,
            schema_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if Self::compute_digest(self.schema_revision, &self.fields) == self.schema_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(schema_revision: Revision, fields: &[QuerySchemaField]) -> Digest {
        let mut canonical = vec![schema_revision.get().to_string()];
        canonical.extend(
            fields
                .iter()
                .map(|field| format!("{}:{:?}:{}", field.name, field.cell_type, field.nullable)),
        );
        Digest::from_fields("clickhouse-schema/v1", &canonical)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedCell {
    pub cell_type: CellType,
    pub value_digest: Option<Digest>,
}

impl RedactedCell {
    pub fn from_digest(cell_type: CellType, value_digest: Digest) -> Result<Self, ModelError> {
        if cell_type == CellType::Null {
            return Err(ModelError::InvalidRow);
        }
        Ok(Self {
            cell_type,
            value_digest: Some(value_digest),
        })
    }

    pub fn from_public_value(
        cell_type: CellType,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        Self::from_digest(cell_type, Digest::from_text(value))
    }

    pub const fn null() -> Self {
        Self {
            cell_type: CellType::Null,
            value_digest: None,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match (self.cell_type, &self.value_digest) {
            (CellType::Null, None) => Ok(()),
            (CellType::Null, Some(_)) | (_, None) => Err(ModelError::InvalidRow),
            (_, Some(_)) => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedRow {
    pub cells: Vec<RedactedCell>,
    pub row_digest: Digest,
}

impl BoundedRow {
    pub fn new(cells: Vec<RedactedCell>) -> Result<Self, ModelError> {
        if cells.is_empty() {
            return Err(ModelError::InvalidRow);
        }
        for cell in &cells {
            cell.validate()?;
        }
        let row_digest = Self::compute_digest(&cells);
        Ok(Self { cells, row_digest })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.cells.is_empty() || self.cells.iter().any(|cell| cell.validate().is_err()) {
            return Err(ModelError::InvalidRow);
        }
        if Self::compute_digest(&self.cells) == self.row_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub(crate) fn encoded_bytes(&self) -> u64 {
        self.cells
            .iter()
            .map(|cell| {
                16_u64.saturating_add(
                    cell.value_digest
                        .as_ref()
                        .map_or(0, |digest| digest.as_str().len() as u64),
                )
            })
            .sum()
    }

    fn compute_digest(cells: &[RedactedCell]) -> Digest {
        let canonical = cells
            .iter()
            .map(|cell| {
                format!(
                    "{:?}:{}",
                    cell.cell_type,
                    cell.value_digest.as_ref().map_or("null", Digest::as_str)
                )
            })
            .collect::<Vec<_>>();
        Digest::from_fields("clickhouse-row/v1", &canonical)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    Cancelled,
    Duplicate,
    Replay,
    Malformed,
    Truncated,
    QueryDrift,
    SchemaDrift,
    Tampered,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    Warning,
    Final,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryErrorEvidence {
    pub kind: ProviderErrorKind,
    pub severity: ErrorSeverity,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl QueryErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        severity: ErrorSeverity,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            severity,
            status_code,
            error_digest: Digest::from_fields(
                "clickhouse-query-error/v1",
                &[
                    format!("{kind:?}"),
                    format!("{severity:?}"),
                    status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    Digest::from_text(diagnostic).as_str().to_owned(),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub attempt: u8,
    pub blocked_env: bool,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub(crate) fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        attempt: u8,
        blocked_env: bool,
        diagnostic_digest: &Digest,
    ) -> Self {
        let error_digest = Digest::from_fields(
            "clickhouse-provider-error/v1",
            &[
                format!("{kind:?}"),
                status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                retryable.to_string(),
                attempt.to_string(),
                blocked_env.to_string(),
                diagnostic_digest.as_str().to_owned(),
            ],
        );
        Self {
            kind,
            status_code,
            retryable,
            attempt,
            blocked_env,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceDigests {
    pub query_digest: Digest,
    pub schema_digest: Digest,
    pub row_set_digest: Digest,
    pub statistics_digest: Digest,
    pub registration_digest: Digest,
    pub result_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalyticalResultAuthority;

impl AnalyticalResultAuthority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn truth(self) -> bool {
        false
    }

    pub const fn adopted(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Complete,
    Partial,
    Truncated,
    Cancelled,
    AccessLost,
    ProviderUnknown,
    FinalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClickHouseRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub provider_version: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub capability_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

impl ClickHouseRegistration {
    pub fn new(
        scope_digest: Digest,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        capability_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new_with_permission(
            scope_digest.clone(),
            Digest::from_fields(
                "clickhouse-permission-placeholder/v1",
                &[scope_digest.as_str().to_owned()],
            ),
            provider_id,
            provider_version,
            capability_digest,
        )
    }

    pub fn new_with_permission(
        scope_digest: Digest,
        permission_digest: Digest,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        capability_digest: Digest,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty()
            || !is_digest(scope_digest.as_str())
            || !is_digest(permission_digest.as_str())
            || !is_digest(capability_digest.as_str())
        {
            return Err(ModelError::InvalidRegistration);
        }
        let service_id = ServiceId::new(CLICKHOUSE_OUTCOME_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(CLICKHOUSE_OUTCOME_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let revision = Revision::new(1)?;
        let registration_digest = Self::compute_digest(
            &scope_digest,
            &permission_digest,
            &provider_id,
            &provider_version,
            &capability_digest,
            revision,
        );
        Ok(Self {
            schema_version: CLICKHOUSE_OUTCOME_SCHEMA_VERSION.to_owned(),
            contract_version: CLICKHOUSE_OUTCOME_CONTRACT_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            provider_version,
            scope_digest,
            permission_digest,
            capability_digest,
            registration_digest,
            revision,
            state: RegistrationState::Active,
        })
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "clickhouse-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.schema_version != CLICKHOUSE_OUTCOME_SCHEMA_VERSION
            || self.contract_version != CLICKHOUSE_OUTCOME_CONTRACT_VERSION
            || self.service_id.as_str() != CLICKHOUSE_OUTCOME_SERVICE_ID
            || self.provider_id.as_str() != crate::CLICKHOUSE_OUTCOME_PROVIDER_ID
            || self.consumer_id.as_str() != CLICKHOUSE_OUTCOME_CONSUMER_ID
            || self.provider_version.is_empty()
            || !is_digest(self.scope_digest.as_str())
            || !is_digest(self.permission_digest.as_str())
            || !is_digest(self.capability_digest.as_str())
            || !is_digest(self.registration_digest.as_str())
        {
            return Err(ModelError::InvalidRegistration);
        }
        let expected = Self::compute_digest(
            &self.scope_digest,
            &self.permission_digest,
            &self.provider_id,
            &self.provider_version,
            &self.capability_digest,
            self.revision,
        );
        (expected == self.registration_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }

    fn compute_digest(
        scope_digest: &Digest,
        permission_digest: &Digest,
        provider_id: &ProviderId,
        provider_version: &str,
        capability_digest: &Digest,
        revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "clickhouse-registration/v1",
            &[
                CLICKHOUSE_OUTCOME_SCHEMA_VERSION.to_owned(),
                CLICKHOUSE_OUTCOME_CONTRACT_VERSION.to_owned(),
                CLICKHOUSE_OUTCOME_SERVICE_ID.to_owned(),
                provider_id.as_str().to_owned(),
                CLICKHOUSE_OUTCOME_CONSUMER_ID.to_owned(),
                provider_version.to_owned(),
                scope_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                capability_digest.as_str().to_owned(),
                revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResultBounds {
    max_rows: u32,
    max_bytes: u64,
}

impl ResultBounds {
    pub fn new(max_rows: u32, max_bytes: u64) -> Result<Self, ModelError> {
        if max_rows == 0
            || max_rows > MAX_RESULT_ROWS
            || max_bytes == 0
            || max_bytes > MAX_RESULT_BYTES
        {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(Self {
                max_rows,
                max_bytes,
            })
        }
    }

    pub const fn max_rows(self) -> u32 {
        self.max_rows
    }

    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }
}

impl Default for ResultBounds {
    fn default() -> Self {
        Self {
            max_rows: 1_000,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

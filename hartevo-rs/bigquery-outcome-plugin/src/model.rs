use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    BIGQUERY_OUTCOME_CONSUMER_ID, BIGQUERY_OUTCOME_CONTRACT_VERSION,
    BIGQUERY_OUTCOME_SCHEMA_VERSION, BIGQUERY_OUTCOME_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_QUERY_BYTES: usize = 16 * 1024;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub(crate) const MAX_RESULT_ROWS: u32 = 10_000;
pub(crate) const MAX_RESULT_BYTES: u64 = 100 * 1024 * 1024;
pub(crate) const MAX_RESULT_PAGES: u8 = 32;
pub(crate) const MAX_PAGE_SIZE: u32 = 1_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("scope must contain an allowlisted table")]
    InvalidScope,
    #[error("result bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("schema contains a duplicate or invalid field")]
    InvalidSchema,
    #[error("row contains an invalid cell")]
    InvalidRow,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("opaque page token is empty or too large")]
    InvalidPageToken,
}

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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_resource_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'$'))
}

macro_rules! string_identifier {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if $validator(&value) {
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

string_identifier!(ProjectId, valid_identifier);
string_identifier!(DatasetId, valid_identifier);
string_identifier!(TableId, valid_resource_name);
string_identifier!(MissionId, valid_identifier);
string_identifier!(WorkProductId, valid_identifier);
string_identifier!(JobId, valid_identifier);
string_identifier!(ServiceId, valid_identifier);
string_identifier!(ProviderId, valid_identifier);
string_identifier!(ConsumerId, valid_identifier);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Location(String);

impl Location {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
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

impl fmt::Debug for Location {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Location").field(&self.0).finish()
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
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

/// An opaque reference into the host keyring. It intentionally does not
/// implement Serialize and its Debug output never includes the reference id.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
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

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &BigQueryScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "bigquery-secret-reference/v1",
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

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GoogleAuthKind {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigQueryScope {
    project_id: ProjectId,
    location: Location,
    dataset_id: DatasetId,
    allowlisted_tables: BTreeSet<TableId>,
    mission_id: MissionId,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl BigQueryScope {
    pub fn new(
        project_id: ProjectId,
        location: Location,
        dataset_id: DatasetId,
        allowlisted_tables: impl IntoIterator<Item = TableId>,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let allowlisted_tables = allowlisted_tables.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_tables.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "bigquery-scope/v1",
            &[
                project_id.as_str().to_owned(),
                location.as_str().to_owned(),
                dataset_id.as_str().to_owned(),
                allowlisted_tables
                    .iter()
                    .map(TableId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                mission_id.as_str().to_owned(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            project_id,
            location,
            dataset_id,
            allowlisted_tables,
            mission_id,
            work_product_id,
            work_product_revision,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn dataset_id(&self) -> &DatasetId {
        &self.dataset_id
    }

    pub fn allowlisted_tables(&self) -> &BTreeSet<TableId> {
        &self.allowlisted_tables
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

    pub(crate) fn contains_table(&self, project: &str, dataset: &str, table: &str) -> bool {
        project == self.project_id.as_str()
            && dataset == self.dataset_id.as_str()
            && self
                .allowlisted_tables
                .iter()
                .any(|candidate| candidate.as_str() == table)
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
    Integer,
    Float,
    Boolean,
    Numeric,
    Date,
    Timestamp,
    Bytes,
    Json,
    Null,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Pending,
    Running,
    Done,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobReference {
    pub project_id: ProjectId,
    pub location: Location,
    pub job_id: JobId,
}

impl JobReference {
    pub fn new(project_id: ProjectId, location: Location, job_id: JobId) -> Self {
        Self {
            project_id,
            location,
            job_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobMetadata {
    pub reference: JobReference,
    pub state: JobState,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub credential_revision: Revision,
    pub expired: bool,
    pub job_digest: Digest,
}

impl JobMetadata {
    pub fn new(
        reference: JobReference,
        state: JobState,
        query_digest: Digest,
        config_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        credential_revision: Revision,
        expired: bool,
    ) -> Self {
        let job_digest = Self::compute_digest(
            &reference,
            state,
            &query_digest,
            &config_digest,
            &scope_digest,
            &permission_digest,
            credential_revision,
            expired,
        );
        Self {
            reference,
            state,
            query_digest,
            config_digest,
            scope_digest,
            permission_digest,
            credential_revision,
            expired,
            job_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            &self.reference,
            self.state,
            &self.query_digest,
            &self.config_digest,
            &self.scope_digest,
            &self.permission_digest,
            self.credential_revision,
            self.expired,
        );
        if expected == self.job_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        reference: &JobReference,
        state: JobState,
        query_digest: &Digest,
        config_digest: &Digest,
        scope_digest: &Digest,
        permission_digest: &Digest,
        credential_revision: Revision,
        expired: bool,
    ) -> Digest {
        Digest::from_fields(
            "bigquery-job/v1",
            &[
                reference.project_id.as_str().to_owned(),
                reference.location.as_str().to_owned(),
                reference.job_id.as_str().to_owned(),
                format!("{state:?}"),
                query_digest.as_str().to_owned(),
                config_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                expired.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuerySchemaField {
    pub name: String,
    pub cell_type: CellType,
    pub nullable: bool,
}

impl QuerySchemaField {
    pub fn new(
        name: impl Into<String>,
        cell_type: CellType,
        nullable: bool,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        if valid_resource_name(&name) {
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
    pub schema_digest: Digest,
}

impl QuerySchema {
    pub fn new(fields: Vec<QuerySchemaField>) -> Result<Self, ModelError> {
        if fields.is_empty() {
            return Err(ModelError::InvalidSchema);
        }
        let mut names = BTreeSet::new();
        for field in &fields {
            if !names.insert(field.name.clone()) {
                return Err(ModelError::InvalidSchema);
            }
        }
        let schema_digest = Self::compute_digest(&fields);
        Ok(Self {
            fields,
            schema_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if Self::compute_digest(&self.fields) == self.schema_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(fields: &[QuerySchemaField]) -> Digest {
        let canonical = fields
            .iter()
            .map(|field| format!("{}:{:?}:{}", field.name, field.cell_type, field.nullable))
            .collect::<Vec<_>>();
        Digest::from_fields("bigquery-schema/v1", &canonical)
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

    pub const fn null() -> Self {
        Self {
            cell_type: CellType::Null,
            value_digest: None,
        }
    }

    pub fn from_public_value(
        cell_type: CellType,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        Self::from_digest(cell_type, Digest::from_text(value))
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
        Digest::from_fields("bigquery-row/v1", &canonical)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Quota,
    RateLimited,
    ServerFailure,
    Timeout,
    LocationMismatch,
    QueryDrift,
    Tampered,
    Truncated,
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
        let error_digest = Digest::from_fields(
            "bigquery-query-error/v1",
            &[
                format!("{kind:?}"),
                format!("{severity:?}"),
                status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                hex::encode(Sha256::digest(diagnostic.as_ref())),
            ],
        );
        Self {
            kind,
            severity,
            status_code,
            error_digest,
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
            "bigquery-provider-error/v1",
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
    pub config_digest: Digest,
    pub schema_digest: Digest,
    pub row_set_digest: Digest,
    pub job_digest: Digest,
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
    Expired,
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
pub struct BigQueryRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub provider_version: String,
    pub scope_digest: Digest,
    pub capability_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

impl BigQueryRegistration {
    pub fn new(
        scope_digest: Digest,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        capability_digest: Digest,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() || !is_digest(scope_digest.as_str()) {
            return Err(ModelError::InvalidRegistration);
        }
        let service_id = ServiceId::new(BIGQUERY_OUTCOME_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(BIGQUERY_OUTCOME_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let revision = Revision::new(1)?;
        let registration_digest = Self::compute_digest(
            &scope_digest,
            &provider_id,
            &provider_version,
            &capability_digest,
            revision,
        );
        Ok(Self {
            schema_version: BIGQUERY_OUTCOME_SCHEMA_VERSION.to_owned(),
            contract_version: BIGQUERY_OUTCOME_CONTRACT_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            provider_version,
            scope_digest,
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
            "bigquery-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    fn compute_digest(
        scope_digest: &Digest,
        provider_id: &ProviderId,
        provider_version: &str,
        capability_digest: &Digest,
        revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "bigquery-registration/v1",
            &[
                BIGQUERY_OUTCOME_SCHEMA_VERSION.to_owned(),
                BIGQUERY_OUTCOME_CONTRACT_VERSION.to_owned(),
                BIGQUERY_OUTCOME_SERVICE_ID.to_owned(),
                provider_id.as_str().to_owned(),
                BIGQUERY_OUTCOME_CONSUMER_ID.to_owned(),
                provider_version.to_owned(),
                scope_digest.as_str().to_owned(),
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
    max_pages: u8,
    page_size: u32,
}

impl ResultBounds {
    pub fn new(
        max_rows: u32,
        max_bytes: u64,
        max_pages: u8,
        page_size: u32,
    ) -> Result<Self, ModelError> {
        if max_rows == 0
            || max_rows > MAX_RESULT_ROWS
            || max_bytes == 0
            || max_bytes > MAX_RESULT_BYTES
            || max_pages == 0
            || max_pages > MAX_RESULT_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_rows,
            max_bytes,
            max_pages,
            page_size,
        })
    }

    pub const fn max_rows(self) -> u32 {
        self.max_rows
    }

    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    pub const fn max_pages(self) -> u8 {
        self.max_pages
    }

    pub const fn page_size(self) -> u32 {
        self.page_size
    }
}

/// A page token can be forwarded to a provider but cannot be serialized or
/// printed. Evidence carries only its digest.
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_BYTES
            || value.chars().any(char::is_whitespace)
        {
            Err(ModelError::InvalidPageToken)
        } else {
            Ok(Self(value))
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields("bigquery-page-token/v1", std::slice::from_ref(&self.0))
    }
}

impl Clone for OpaquePageToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for OpaquePageToken {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for OpaquePageToken {}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

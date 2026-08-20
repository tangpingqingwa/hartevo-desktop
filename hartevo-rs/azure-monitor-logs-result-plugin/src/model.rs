use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AZURE_MONITOR_LOGS_CONTRACT_VERSION, AZURE_MONITOR_LOGS_PROVIDER_ID,
    AZURE_MONITOR_LOGS_SCHEMA_VERSION, AZURE_MONITOR_LOGS_SERVICE_ID,
    MISSION_AZURE_MONITOR_LOGS_CONSUMER_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_PARAMETERS: usize = 32;
pub const MAX_GROUP_BY_COLUMNS: usize = 8;
pub const MAX_AGGREGATES: usize = 8;
pub const MAX_RESPONSE_ROWS: usize = 256;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_DURATION_MS: u32 = 120_000;
pub const MAX_COST_MICROUNITS: u64 = 1_000_000;
pub const MAX_CELL_TEXT_BYTES: usize = 128;
pub const MAX_WINDOW_DAYS: i64 = 31;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("timestamp is not valid RFC3339")]
    InvalidTimestamp,
    #[error("time window is empty, reversed, or exceeds the 31-day ceiling")]
    InvalidTimeWindow,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("schema is empty, duplicated, unsafe, or exceeds the bounded shape")]
    InvalidSchema,
    #[error("projection contains a denied or unsupported column type")]
    ForbiddenProjection,
    #[error("row contains an invalid aggregate cell")]
    InvalidCell,
    #[error("row shape does not match the schema")]
    InvalidRow,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already reversed")]
    AlreadyReversed,
    #[error("registration cannot be restored")]
    CannotRestore,
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

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'\\')
        })
}

fn valid_table(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_column(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !forbidden_column_name(value)
}

fn forbidden_column_name(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "user",
        "email",
        "upn",
        "principal",
        "identity",
        "account",
        "userid",
        "ipaddress",
        "clientip",
        "raw",
        "body",
        "message",
        "payload",
        "properties",
        "dynamic",
    ]
    .iter()
    .any(|part| normalized.contains(part))
}

macro_rules! identifier_type {
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

identifier_type!(TenantId, valid_identifier);
identifier_type!(SubscriptionId, valid_identifier);
identifier_type!(WorkspaceId, valid_identifier);
identifier_type!(ProjectId, valid_identifier);
identifier_type!(MissionId, valid_identifier);
identifier_type!(WorkProductId, valid_identifier);
identifier_type!(QueryTemplateId, valid_identifier);
identifier_type!(TableName, valid_table);
identifier_type!(ColumnName, valid_column);
identifier_type!(ParameterName, valid_column);
identifier_type!(ServiceId, valid_identifier);
identifier_type!(ProviderId, valid_identifier);
identifier_type!(ConsumerId, valid_identifier);

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

/// An opaque pointer into host-managed Entra credentials.
///
/// The reference identifier is intentionally consumed into a digest and is
/// never stored, serialized, or printed. Layer 1 can bind a credential
/// revision without resolving or possessing credential material.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
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
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AzureMonitorLogsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "azure-monitor-logs-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsScope {
    pub tenant_id: TenantId,
    pub subscription_id: SubscriptionId,
    pub workspace_id: WorkspaceId,
    pub table: TableName,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
}

impl AzureMonitorLogsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        workspace_id: WorkspaceId,
        table: TableName,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope_digest = Digest::from_fields(
            "azure-monitor-logs-scope/v1",
            &[
                tenant_id.as_str().to_owned(),
                subscription_id.as_str().to_owned(),
                workspace_id.as_str().to_owned(),
                table.as_str().to_owned(),
                project_id.as_str().to_owned(),
                project_revision.get().to_string(),
                mission_id.as_str().to_owned(),
                mission_revision.get().to_string(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            tenant_id,
            subscription_id,
            workspace_id,
            table,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn mission_binding(&self) -> (MissionId, Revision) {
        (self.mission_id.clone(), self.mission_revision)
    }

    pub fn project_binding(&self) -> (ProjectId, Revision) {
        (self.project_id.clone(), self.project_revision)
    }

    pub fn work_product_binding(&self) -> (WorkProductId, Revision) {
        (self.work_product_id.clone(), self.work_product_revision)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(DateTime<Utc>);

impl fmt::Debug for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Timestamp")
            .field(&self.as_str())
            .finish()
    }
}

impl Timestamp {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        let parsed = DateTime::parse_from_rfc3339(value)
            .map_err(|_| ModelError::InvalidTimestamp)?
            .with_timezone(&Utc);
        Ok(Self(parsed))
    }

    pub fn as_str(&self) -> String {
        self.0.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    }

    pub fn millis(&self) -> i64 {
        self.0.timestamp_millis()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimeWindow {
    pub start: Timestamp,
    pub end: Timestamp,
    pub digest: Digest,
}

impl TimeWindow {
    pub fn new(start: impl AsRef<str>, end: impl AsRef<str>) -> Result<Self, ModelError> {
        let start = Timestamp::parse(start)?;
        let end = Timestamp::parse(end)?;
        Self::from_timestamps(start, end)
    }

    pub fn from_timestamps(start: Timestamp, end: Timestamp) -> Result<Self, ModelError> {
        let duration = end.millis().saturating_sub(start.millis());
        if duration <= 0 || duration > Duration::days(MAX_WINDOW_DAYS).num_milliseconds() {
            return Err(ModelError::InvalidTimeWindow);
        }
        let digest = Digest::from_fields(
            "azure-monitor-logs-time-window/v1",
            &[start.as_str(), end.as_str()],
        );
        Ok(Self { start, end, digest })
    }

    pub fn duration_ms(&self) -> u64 {
        self.end.millis().saturating_sub(self.start.millis()) as u64
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "azure-monitor-logs-time-window/v1",
            &[self.start.as_str(), self.end.as_str()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QueryBounds {
    pub max_rows: u32,
    pub max_response_bytes: u64,
    pub max_duration_ms: u32,
    pub max_cost_microunits: u64,
}

impl QueryBounds {
    pub fn new(
        max_rows: u32,
        max_response_bytes: u64,
        max_duration_ms: u32,
        max_cost_microunits: u64,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            max_rows,
            max_response_bytes,
            max_duration_ms,
            max_cost_microunits,
        };
        if max_rows == 0
            || max_rows as usize > MAX_RESPONSE_ROWS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_duration_ms == 0
            || max_duration_ms > MAX_DURATION_MS
            || max_cost_microunits == 0
            || max_cost_microunits > MAX_COST_MICROUNITS
        {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(bounds)
        }
    }
}

impl Default for QueryBounds {
    fn default() -> Self {
        Self {
            max_rows: MAX_RESPONSE_ROWS as u32,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_duration_ms: MAX_DURATION_MS,
            max_cost_microunits: MAX_COST_MICROUNITS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateColumnType {
    Category,
    Integer,
    Decimal,
    Boolean,
    Timestamp,
    Dynamic,
    Json,
    RawText,
    UserIdentifier,
}

impl AggregateColumnType {
    pub const fn is_denied(self) -> bool {
        matches!(
            self,
            Self::Dynamic | Self::Json | Self::RawText | Self::UserIdentifier
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateColumn {
    pub name: ColumnName,
    pub column_type: AggregateColumnType,
    pub nullable: bool,
}

impl AggregateColumn {
    pub fn new(
        name: ColumnName,
        column_type: AggregateColumnType,
        nullable: bool,
    ) -> Result<Self, ModelError> {
        if column_type.is_denied() {
            return Err(ModelError::ForbiddenProjection);
        }
        Ok(Self {
            name,
            column_type,
            nullable,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateSchema {
    pub columns: Vec<AggregateColumn>,
    pub schema_digest: Digest,
}

impl AggregateSchema {
    pub fn new(columns: Vec<AggregateColumn>) -> Result<Self, ModelError> {
        if columns.is_empty() || columns.len() > MAX_GROUP_BY_COLUMNS + MAX_AGGREGATES {
            return Err(ModelError::InvalidSchema);
        }
        let mut names = BTreeSet::new();
        for column in &columns {
            if column.column_type.is_denied() || !names.insert(column.name.as_str().to_owned()) {
                return Err(ModelError::InvalidSchema);
            }
        }
        let canonical = columns
            .iter()
            .map(|column| {
                format!(
                    "{}|{:?}|{}",
                    column.name.as_str(),
                    column.column_type,
                    column.nullable
                )
            })
            .collect::<Vec<_>>();
        let schema_digest = Digest::from_fields("azure-monitor-logs-schema/v1", &canonical);
        Ok(Self {
            columns,
            schema_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let canonical = self
            .columns
            .iter()
            .map(|column| {
                format!(
                    "{}|{:?}|{}",
                    column.name.as_str(),
                    column.column_type,
                    column.nullable
                )
            })
            .collect::<Vec<_>>();
        let expected = Digest::from_fields("azure-monitor-logs-schema/v1", &canonical);
        if expected == self.schema_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AggregateCell {
    Null,
    Integer(i64),
    Decimal(String),
    Boolean(bool),
    Text(String),
    Timestamp(Timestamp),
}

impl AggregateCell {
    pub fn validate_for(&self, column: &AggregateColumn) -> Result<(), ModelError> {
        let valid = match self {
            Self::Null => column.nullable,
            Self::Integer(_) => column.column_type == AggregateColumnType::Integer,
            Self::Decimal(value) => {
                column.column_type == AggregateColumnType::Decimal && valid_decimal(value)
            }
            Self::Boolean(_) => column.column_type == AggregateColumnType::Boolean,
            Self::Text(value) => {
                column.column_type == AggregateColumnType::Category
                    && value.len() <= MAX_CELL_TEXT_BYTES
                    && !value.chars().any(char::is_control)
                    && !looks_like_user_identifier(value)
            }
            Self::Timestamp(_) => column.column_type == AggregateColumnType::Timestamp,
        };
        if valid {
            Ok(())
        } else {
            Err(ModelError::InvalidCell)
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Integer(value) => format!("integer:{value}"),
            Self::Decimal(value) => format!("decimal:{value}"),
            Self::Boolean(value) => format!("boolean:{value}"),
            Self::Text(value) => format!("text:{value}"),
            Self::Timestamp(value) => format!("timestamp:{}", value.as_str()),
        }
    }

    pub fn estimated_size(&self) -> usize {
        self.canonical().len()
    }
}

fn valid_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || value.parse::<f64>().map_or(true, |v| !v.is_finite())
    {
        return false;
    }
    let mut digits = 0;
    let mut dots = 0;
    for (index, byte) in value.bytes().enumerate() {
        if byte.is_ascii_digit() {
            digits += 1;
        } else if byte == b'.' {
            dots += 1;
        } else if byte == b'-' && index == 0 {
            // A leading minus is the only non-digit character allowed here.
        } else {
            return false;
        }
    }
    digits > 0 && dots <= 1
}

fn looks_like_user_identifier(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains('@')
        || lower.contains("user_id")
        || lower.contains("userid")
        || lower.contains("upn")
        || lower.contains("principal")
        || lower.contains("email")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateRow {
    pub cells: Vec<AggregateCell>,
}

impl AggregateRow {
    pub fn new(cells: Vec<AggregateCell>) -> Self {
        Self { cells }
    }

    pub fn validate_against(&self, schema: &AggregateSchema) -> Result<(), ModelError> {
        if self.cells.len() != schema.columns.len() {
            return Err(ModelError::InvalidRow);
        }
        for (cell, column) in self.cells.iter().zip(&schema.columns) {
            cell.validate_for(column)?;
        }
        Ok(())
    }

    pub fn estimated_size(&self) -> usize {
        self.cells
            .iter()
            .map(AggregateCell::estimated_size)
            .sum::<usize>()
            .saturating_add(self.cells.len() * 2)
    }

    pub fn canonical(&self) -> String {
        self.cells
            .iter()
            .map(AggregateCell::canonical)
            .collect::<Vec<_>>()
            .join("|")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ResultStatus {
    #[serde(rename = "COMPLETE")]
    Complete,
    #[serde(rename = "EMPTY")]
    Empty,
    #[serde(rename = "PARTIAL")]
    Partial,
    #[serde(rename = "TRUNCATED")]
    Truncated,
    #[serde(rename = "TIMEOUT")]
    Timeout,
    #[serde(rename = "ACCESS_LOST")]
    AccessLost,
    #[serde(rename = "PROVIDER_UNKNOWN")]
    ProviderUnknown,
    #[serde(rename = "TAMPERED")]
    Tampered,
    #[serde(rename = "REVOKED")]
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Layer1Authority {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth: bool,
    pub consent: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

impl Layer1Authority {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            truth: false,
            consent: false,
            effect: false,
            receipt: false,
            verification: false,
            outcome: false,
            work_product_adoption: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationTransition {
    pub previous: RegistrationState,
    pub current: RegistrationState,
    pub revision: Revision,
    pub registration_digest: Digest,
}

pub(crate) fn contract_identity_fields() -> [String; 5] {
    [
        AZURE_MONITOR_LOGS_SCHEMA_VERSION.to_owned(),
        AZURE_MONITOR_LOGS_CONTRACT_VERSION.to_owned(),
        AZURE_MONITOR_LOGS_SERVICE_ID.to_owned(),
        AZURE_MONITOR_LOGS_PROVIDER_ID.to_owned(),
        MISSION_AZURE_MONITOR_LOGS_CONSUMER_ID.to_owned(),
    ]
}

//! Layer-1 Snowflake outcome-evidence plugin.
//!
//! This crate is intentionally a standalone nested workspace. It describes a
//! typed Snowflake capability, compiles bounded read-only proposals, and
//! models the SQL API state machine behind recording/fake/loopback transports.
//! It has no live HTTPS client, credential resolver, cancellation authority, or
//! Hartevo kernel authority.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.snowflake-outcome-plugin/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.snowflake-outcome-plugin/v1|layer=1|service=warehouse.snowflake.outcome.read|provider=snowflake.sql-api.recording|consumer=mission.outcome-evidence.snowflake";
// The contract file is patched with the SHA-256 of CONTRACT_DIGEST_INPUT after
// the source is created. Keeping the digest as a public constant makes every
// registration explicitly bind to one contract revision.
pub const CONTRACT_DIGEST: &str =
    "3c3326864b3bfe297f83ad15f00346abb73db6a2eaeeca0d4c59c9497a15647f";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "warehouse.snowflake.outcome.read";
pub const PROVIDER_ID: &str = "snowflake.sql-api.recording";
pub const CONSUMER_ID: &str = "mission.outcome-evidence.snowflake";
pub const MAX_RESULT_ROWS: u64 = 100_000;
pub const MAX_RESULT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RESULT_PARTITIONS: u32 = 128;
pub const MAX_CHUNK_ROWS: u64 = 10_000;
pub const MAX_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
const FORBIDDEN_SQL_WORDS: &[&str] = &[
    "ALTER", "BEGIN", "CALL", "COMMIT", "COPY", "CREATE", "DELETE", "DESCRIBE", "DROP", "EXECUTE",
    "FETCH", "GET", "GRANT", "INSERT", "MERGE", "PUT", "REVOKE", "ROLLBACK", "SET", "SHOW",
    "TRUNCATE", "UNSET", "USE", "UPDATE",
];

/// A SHA-256 digest used to fence all public proposal and evidence bindings.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    fn from_parts(label: &str, fields: &[(&str, String)]) -> Self {
        let mut canonical = String::new();
        canonical.push_str(label);
        canonical.push('\n');
        for (name, value) in fields {
            let _ = write!(canonical, "{name}={}:{};", value.len(), value);
        }
        Self::from_bytes(canonical.as_bytes())
    }

    /// Returns the lower-case hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

/// The only credential kinds recognized by the Layer-1 seam.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    PrivateKey,
}

/// An opaque host-owned credential reference.
///
/// The reference handle is intentionally private and has no `Serialize`,
/// `Display`, or secret-bearing `Debug` implementation. Layer 1 can bind the
/// existence and revision of this boundary without resolving credential bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    revision: u64,
}

impl SecretReference {
    /// Creates an opaque OAuth reference. `opaque_id` is a host handle, never
    /// an OAuth token or private key.
    pub fn oauth(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, SnowflakeOutcomeError> {
        Self::new(SecretKind::OAuth, opaque_id, revision)
    }

    /// Creates an opaque private-key reference. Key material is never accepted
    /// by this constructor; the string is only a host-side handle.
    pub fn private_key(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, SnowflakeOutcomeError> {
        Self::new(SecretKind::PrivateKey, opaque_id, revision)
    }

    fn new(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let opaque_id = opaque_id.into();
        if revision == 0
            || opaque_id.is_empty()
            || opaque_id.trim() != opaque_id
            || opaque_id.len() > 256
            || opaque_id.chars().any(char::is_control)
        {
            return Err(SnowflakeOutcomeError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            opaque_id,
            revision,
        })
    }

    /// Returns the credential kind without revealing the handle.
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    /// Returns the host-managed rotation revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("opaque_id", &"<redacted>")
            .finish()
    }
}

fn validate_component(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn validate_host(value: &str) -> Option<String> {
    let remainder = value.strip_prefix("https://")?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains(':')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    let host = remainder.to_ascii_lowercase();
    if !host.contains('.')
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
        return None;
    }
    Some(format!("https://{host}"))
}

/// Exact Project/Mission and Snowflake account scope.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowflakeScope {
    organization: String,
    account: String,
    https_host: String,
    database: String,
    schema: String,
    warehouse: String,
    role: String,
    project_id: String,
    mission_id: String,
}

impl SnowflakeScope {
    /// Creates a scope whose host is normalized to an HTTPS origin host.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: impl Into<String>,
        account: impl Into<String>,
        https_host: impl Into<String>,
        database: impl Into<String>,
        schema: impl Into<String>,
        warehouse: impl Into<String>,
        role: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let organization = organization.into();
        let account = account.into();
        let https_host = https_host.into();
        let database = database.into();
        let schema = schema.into();
        let warehouse = warehouse.into();
        let role = role.into();
        let project_id = project_id.into();
        let mission_id = mission_id.into();
        let Some(https_host) = validate_host(&https_host) else {
            return Err(SnowflakeOutcomeError::InvalidScope);
        };
        if !validate_component(&organization)
            || !validate_component(&account)
            || !validate_component(&database)
            || !validate_component(&schema)
            || !validate_component(&warehouse)
            || !validate_component(&role)
            || !validate_component(&project_id)
            || !validate_component(&mission_id)
        {
            return Err(SnowflakeOutcomeError::InvalidScope);
        }
        Ok(Self {
            organization,
            account,
            https_host,
            database,
            schema,
            warehouse,
            role,
            project_id,
            mission_id,
        })
    }

    #[must_use]
    pub fn organization(&self) -> &str {
        &self.organization
    }

    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    #[must_use]
    pub fn https_host(&self) -> &str {
        &self.https_host
    }

    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn warehouse(&self) -> &str {
        &self.warehouse
    }

    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    #[must_use]
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    /// Returns the scope fence used by registration, requests, and results.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "snowflake-scope/v1",
            &[
                ("organization", self.organization.clone()),
                ("account", self.account.clone()),
                ("https_host", self.https_host.clone()),
                ("database", self.database.clone()),
                ("schema", self.schema.clone()),
                ("warehouse", self.warehouse.clone()),
                ("role", self.role.clone()),
                ("project_id", self.project_id.clone()),
                ("mission_id", self.mission_id.clone()),
            ],
        )
    }
}

impl fmt::Debug for SnowflakeScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowflakeScope")
            .field("scope_digest", &self.digest())
            .finish()
    }
}

/// Semantic plugin version bound into a registration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub fn parse(value: &str) -> Result<Self, SnowflakeOutcomeError> {
        let mut parts = value.split('.');
        let parsed = [parts.next(), parts.next(), parts.next()];
        if parts.next().is_some() || parsed.iter().any(Option::is_none) {
            return Err(SnowflakeOutcomeError::InvalidPluginVersion);
        }
        let [Some(major), Some(minor), Some(patch)] = parsed else {
            return Err(SnowflakeOutcomeError::InvalidPluginVersion);
        };
        let Ok(major) = major.parse() else {
            return Err(SnowflakeOutcomeError::InvalidPluginVersion);
        };
        let Ok(minor) = minor.parse() else {
            return Err(SnowflakeOutcomeError::InvalidPluginVersion);
        };
        let Ok(patch) = patch.parse() else {
            return Err(SnowflakeOutcomeError::InvalidPluginVersion);
        };
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Snowflake scalar types permitted in query bindings and result schemas.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowflakeType {
    Text,
    Integer,
    Decimal,
    Boolean,
    Date,
    Timestamp,
    Json,
    Binary,
}

/// Compatibility names used by provider-facing callers.
pub type ParameterType = SnowflakeType;

/// Typed value used for query parameters and bounded result rows.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum SnowflakeValue {
    Null,
    Text(String),
    Integer(i64),
    Decimal(String),
    Boolean(bool),
    Date(String),
    Timestamp(String),
    Json(String),
    Binary(String),
}

impl SnowflakeValue {
    fn snowflake_type(&self) -> Option<SnowflakeType> {
        match self {
            Self::Null => None,
            Self::Text(_) => Some(SnowflakeType::Text),
            Self::Integer(_) => Some(SnowflakeType::Integer),
            Self::Decimal(_) => Some(SnowflakeType::Decimal),
            Self::Boolean(_) => Some(SnowflakeType::Boolean),
            Self::Date(_) => Some(SnowflakeType::Date),
            Self::Timestamp(_) => Some(SnowflakeType::Timestamp),
            Self::Json(_) => Some(SnowflakeType::Json),
            Self::Binary(_) => Some(SnowflakeType::Binary),
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Text(value) => format!("text:{}:{value}", value.len()),
            Self::Integer(value) => format!("integer:{value}"),
            Self::Decimal(value) => format!("decimal:{}:{value}", value.len()),
            Self::Boolean(value) => format!("boolean:{value}"),
            Self::Date(value) => format!("date:{}:{value}", value.len()),
            Self::Timestamp(value) => format!("timestamp:{}:{value}", value.len()),
            Self::Json(value) => format!("json:{}:{value}", value.len()),
            Self::Binary(value) => format!("binary:{}:{value}", value.len()),
        }
    }

    fn digest(&self) -> Digest {
        Digest::from_parts("snowflake-value/v1", &[("value", self.canonical())])
    }
}

/// Compatibility name for typed query bindings.
pub type ParameterValue = SnowflakeValue;
/// Result cells use the same closed type vocabulary as query parameters.
pub type CellValue = SnowflakeValue;

impl fmt::Debug for SnowflakeValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowflakeValue")
            .field("type", &self.snowflake_type())
            .field("value_digest", &self.digest())
            .finish()
    }
}

/// A parameter declaration in an allowlisted template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParameterSpec {
    name: String,
    data_type: SnowflakeType,
}

impl ParameterSpec {
    pub fn new(
        name: impl Into<String>,
        data_type: SnowflakeType,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let name = name.into();
        if !valid_parameter_name(&name) {
            return Err(SnowflakeOutcomeError::InvalidParameterName);
        }
        Ok(Self { name, data_type })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn data_type(&self) -> SnowflakeType {
        self.data_type
    }
}

/// A typed binding supplied to a compiled proposal.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundParameter {
    name: String,
    value: SnowflakeValue,
}

impl BoundParameter {
    pub fn new(
        name: impl Into<String>,
        value: SnowflakeValue,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let name = name.into();
        if !valid_parameter_name(&name) {
            return Err(SnowflakeOutcomeError::InvalidParameterName);
        }
        Ok(Self { name, value })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &SnowflakeValue {
        &self.value
    }
}

impl fmt::Debug for BoundParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundParameter")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

fn valid_parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphabetic() || byte == b'_'
            } else {
                byte.is_ascii_alphanumeric() || byte == b'_'
            }
        })
}

/// Bounded row, byte, partition, and chunk policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultBounds {
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_partitions: u32,
    pub max_chunk_rows: u64,
    pub max_chunk_bytes: u64,
}

impl ResultBounds {
    pub fn new(
        max_rows: u64,
        max_bytes: u64,
        max_partitions: u32,
        max_chunk_rows: u64,
        max_chunk_bytes: u64,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let bounds = Self {
            max_rows,
            max_bytes,
            max_partitions,
            max_chunk_rows,
            max_chunk_bytes,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    fn validate(&self) -> Result<(), SnowflakeOutcomeError> {
        if self.max_rows == 0
            || self.max_rows > MAX_RESULT_ROWS
            || self.max_bytes == 0
            || self.max_bytes > MAX_RESULT_BYTES
            || self.max_partitions == 0
            || self.max_partitions > MAX_RESULT_PARTITIONS
            || self.max_chunk_rows == 0
            || self.max_chunk_rows > MAX_CHUNK_ROWS
            || self.max_chunk_bytes == 0
            || self.max_chunk_bytes > MAX_CHUNK_BYTES
        {
            return Err(SnowflakeOutcomeError::InvalidBounds);
        }
        Ok(())
    }
}

impl Default for ResultBounds {
    fn default() -> Self {
        Self {
            max_rows: 1_000,
            max_bytes: 4 * 1024 * 1024,
            max_partitions: 16,
            max_chunk_rows: 1_000,
            max_chunk_bytes: 1024 * 1024,
        }
    }
}

/// An allowlisted SQL template. SQL is validated when a proposal is compiled.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryTemplate {
    name: String,
    sql: String,
    parameters: Vec<ParameterSpec>,
    bounds: ResultBounds,
}

impl QueryTemplate {
    pub fn new(
        name: impl Into<String>,
        sql: impl Into<String>,
        parameters: Vec<ParameterSpec>,
        bounds: ResultBounds,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let name = name.into();
        let sql = sql.into();
        if !valid_component(&name)
            || parameters
                .iter()
                .map(ParameterSpec::name)
                .collect::<BTreeSet<_>>()
                .len()
                != parameters.len()
        {
            return Err(SnowflakeOutcomeError::InvalidTemplate);
        }
        bounds.validate()?;
        Ok(Self {
            name,
            sql,
            parameters,
            bounds,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
    }

    #[must_use]
    pub fn parameters(&self) -> &[ParameterSpec] {
        &self.parameters
    }

    #[must_use]
    pub const fn bounds(&self) -> ResultBounds {
        self.bounds
    }

    /// Returns a digest that is stable across harmless SQL whitespace changes.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let canonical_sql = canonicalize_sql(&self.sql).unwrap_or_else(|_| self.sql.clone());
        template_digest(&self.name, &canonical_sql, &self.parameters, self.bounds)
    }
}

impl fmt::Debug for QueryTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryTemplate")
            .field("name", &self.name)
            .field("sql_digest", &Digest::from_bytes(self.sql.as_bytes()))
            .field("parameter_count", &self.parameters.len())
            .field("bounds", &self.bounds)
            .finish()
    }
}

fn valid_component(value: &str) -> bool {
    validate_component(value)
}

fn template_digest(
    name: &str,
    canonical_sql: &str,
    parameters: &[ParameterSpec],
    bounds: ResultBounds,
) -> Digest {
    let parameter_shape = parameters
        .iter()
        .map(|parameter| format!("{}:{:?}", parameter.name(), parameter.data_type()))
        .collect::<Vec<_>>()
        .join(",");
    Digest::from_parts(
        "snowflake-query-template/v1",
        &[
            ("name", name.to_owned()),
            ("sql", canonical_sql.to_owned()),
            ("parameters", parameter_shape),
            ("max_rows", bounds.max_rows.to_string()),
            ("max_bytes", bounds.max_bytes.to_string()),
            ("max_partitions", bounds.max_partitions.to_string()),
            ("max_chunk_rows", bounds.max_chunk_rows.to_string()),
            ("max_chunk_bytes", bounds.max_chunk_bytes.to_string()),
        ],
    )
}

/// A reversible, scope-bound registration.
#[derive(Clone, Eq, PartialEq)]
pub struct SnowflakeOutcomeRegistration {
    plugin_version: PluginVersion,
    contract_digest: Digest,
    provider_revision: u64,
    scope: SnowflakeScope,
    secret_reference: SecretReference,
    registration_revision: u64,
    revoked: bool,
    allowed_templates: BTreeMap<Digest, QueryTemplate>,
    registration_digest: Digest,
}

impl SnowflakeOutcomeRegistration {
    pub fn new(
        scope: SnowflakeScope,
        secret_reference: SecretReference,
        provider_revision: u64,
        allowed_templates: Vec<QueryTemplate>,
    ) -> Result<Self, SnowflakeOutcomeError> {
        Self::with_binding(
            PluginVersion::V1,
            Digest(CONTRACT_DIGEST.to_owned()),
            provider_revision,
            scope,
            secret_reference,
            1,
            allowed_templates,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_binding(
        plugin_version: PluginVersion,
        contract_digest: Digest,
        provider_revision: u64,
        scope: SnowflakeScope,
        secret_reference: SecretReference,
        registration_revision: u64,
        allowed_templates: Vec<QueryTemplate>,
    ) -> Result<Self, SnowflakeOutcomeError> {
        if provider_revision == 0
            || registration_revision == 0
            || contract_digest.as_str().len() != 64
        {
            return Err(SnowflakeOutcomeError::InvalidRegistration);
        }
        let mut template_map = BTreeMap::new();
        for template in allowed_templates {
            template_map.insert(template.digest(), template);
        }
        let mut registration = Self {
            plugin_version,
            contract_digest,
            provider_revision,
            scope,
            secret_reference,
            registration_revision,
            revoked: false,
            allowed_templates: template_map,
            registration_digest: Digest::from_bytes(b"unsealed-snowflake-registration"),
        };
        registration.registration_digest = registration.computed_digest();
        Ok(registration)
    }

    #[must_use]
    pub const fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    #[must_use]
    pub fn scope(&self) -> &SnowflakeScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_kind(&self) -> SecretKind {
        self.secret_reference.kind()
    }

    #[must_use]
    pub const fn secret_revision(&self) -> u64 {
        self.secret_reference.revision()
    }

    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn allowed_templates(&self) -> impl Iterator<Item = &QueryTemplate> {
        self.allowed_templates.values()
    }

    /// Creates a lifecycle copy with a new reversible registration revision.
    pub fn with_registration_revision(self, revision: u64) -> Result<Self, SnowflakeOutcomeError> {
        Self::with_binding(
            self.plugin_version,
            self.contract_digest,
            self.provider_revision,
            self.scope,
            self.secret_reference,
            revision,
            self.allowed_templates.into_values().collect(),
        )
    }

    /// Marks this binding revoked. Revocation is fail-closed for providers.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Reverses a local revocation without changing the immutable binding
    /// digest. A host registry may choose to require a fresh receipt.
    pub fn restore(&mut self) {
        self.revoked = false;
    }

    fn computed_digest(&self) -> Digest {
        let template_digests = self
            .allowed_templates
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts(
            "snowflake-registration/v1",
            &[
                ("plugin_version", self.plugin_version.to_string()),
                ("contract_digest", self.contract_digest.to_string()),
                ("provider_revision", self.provider_revision.to_string()),
                ("scope_digest", self.scope.digest().to_string()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("allowed_template_digests", template_digests),
            ],
        )
    }

    fn accepts_template(&self, template: &QueryTemplate) -> bool {
        self.allowed_templates.is_empty() || self.allowed_templates.contains_key(&template.digest())
    }
}

impl fmt::Debug for SnowflakeOutcomeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowflakeOutcomeRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("scope_digest", &self.scope.digest())
            .field("secret_kind", &self.secret_reference.kind())
            .field("secret_revision", &self.secret_reference.revision())
            .field("registration_revision", &self.registration_revision)
            .field("revoked", &self.revoked)
            .field("allowed_template_count", &self.allowed_templates.len())
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

/// Short name for callers that treat the registration as the plugin binding.
pub type Registration = SnowflakeOutcomeRegistration;

impl Serialize for SnowflakeOutcomeRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SnowflakeOutcomeRegistration", 9)?;
        state.serialize_field("schema", "hartevo.snowflake-registration/v1")?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.serialize_field(
            "allowedTemplateDigests",
            &self.allowed_templates.keys().collect::<Vec<_>>(),
        )?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

/// A host registry receipt that contains no credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub plugin_version: PluginVersion,
    pub contract_digest: Digest,
    pub provider_revision: u64,
    pub registration_revision: u64,
    pub registry_revision: u64,
    pub revoked: bool,
}

/// In-memory model of reversible registration lifecycle.
#[derive(Debug, Default)]
pub struct RegistrationAuthority {
    registrations: BTreeMap<Digest, SnowflakeOutcomeRegistration>,
    registry_revision: u64,
}

impl RegistrationAuthority {
    pub fn register(
        &mut self,
        registration: SnowflakeOutcomeRegistration,
    ) -> Result<RegistrationReceipt, SnowflakeOutcomeError> {
        if registration.is_revoked() || self.registrations.contains_key(registration.digest()) {
            return Err(SnowflakeOutcomeError::RegistrationAlreadyExists);
        }
        self.registry_revision = self
            .registry_revision
            .checked_add(1)
            .ok_or(SnowflakeOutcomeError::RegistryRevisionOverflow)?;
        let digest = registration.digest().clone();
        self.registrations.insert(digest.clone(), registration);
        Ok(self.receipt(&digest))
    }

    pub fn revoke(&mut self, registration_digest: &Digest) -> Result<(), SnowflakeOutcomeError> {
        let registration = self
            .registrations
            .get_mut(registration_digest)
            .ok_or(SnowflakeOutcomeError::RegistrationUnknown)?;
        registration.revoke();
        self.registry_revision = self
            .registry_revision
            .checked_add(1)
            .ok_or(SnowflakeOutcomeError::RegistryRevisionOverflow)?;
        Ok(())
    }

    pub fn restore(&mut self, registration_digest: &Digest) -> Result<(), SnowflakeOutcomeError> {
        let registration = self
            .registrations
            .get_mut(registration_digest)
            .ok_or(SnowflakeOutcomeError::RegistrationUnknown)?;
        registration.restore();
        self.registry_revision = self
            .registry_revision
            .checked_add(1)
            .ok_or(SnowflakeOutcomeError::RegistryRevisionOverflow)?;
        Ok(())
    }

    pub fn unregister(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<(), SnowflakeOutcomeError> {
        if self.registrations.remove(registration_digest).is_none() {
            return Err(SnowflakeOutcomeError::RegistrationUnknown);
        }
        self.registry_revision = self
            .registry_revision
            .checked_add(1)
            .ok_or(SnowflakeOutcomeError::RegistryRevisionOverflow)?;
        Ok(())
    }

    #[must_use]
    pub fn get(&self, registration_digest: &Digest) -> Option<&SnowflakeOutcomeRegistration> {
        self.registrations.get(registration_digest)
    }

    #[must_use]
    pub fn is_active(&self, registration_digest: &Digest) -> bool {
        self.get(registration_digest)
            .is_some_and(|item| !item.is_revoked())
    }

    fn receipt(&self, digest: &Digest) -> RegistrationReceipt {
        let registration = &self.registrations[digest];
        RegistrationReceipt {
            registration_digest: digest.clone(),
            scope_digest: registration.scope.digest(),
            plugin_version: registration.plugin_version,
            contract_digest: registration.contract_digest.clone(),
            provider_revision: registration.provider_revision,
            registration_revision: registration.registration_revision,
            registry_revision: self.registry_revision,
            revoked: registration.revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccess {
    ReadOnly,
}

/// The typed service definition contributed by this plugin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowflakeServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub access: ServiceAccess,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub consumer_id: String,
}

/// Service-side compiler for bounded Snowflake query proposals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnowflakeOutcomeService;

impl SnowflakeOutcomeService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn definition(&self) -> SnowflakeServiceDefinition {
        SnowflakeServiceDefinition {
            id: SERVICE_ID.to_owned(),
            version: PluginVersion::V1,
            access: ServiceAccess::ReadOnly,
            contract_digest: Digest(CONTRACT_DIGEST.to_owned()),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
        }
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> SnowflakeServiceDefinition {
        self.definition()
    }

    /// Compiles one canonical, typed, scope-bound query proposal.
    pub fn compile_query_proposal(
        &self,
        registration: &SnowflakeOutcomeRegistration,
        mission_revision: u64,
        template: &QueryTemplate,
        parameters: &[BoundParameter],
    ) -> Result<QueryProposal, SnowflakeOutcomeError> {
        if registration.revoked {
            return Err(SnowflakeOutcomeError::RegistrationRevoked);
        }
        if template.parameters().is_empty() {
            return Err(SnowflakeOutcomeError::QueryRejected(
                QueryRejection::RequiresTypedParameter,
            ));
        }
        if mission_revision == 0 || !registration.accepts_template(template) {
            return Err(SnowflakeOutcomeError::RegistrationMismatch);
        }
        let canonical_sql = validate_and_canonicalize_sql(template, parameters)?;
        let parameters_digest = parameters_digest(parameters)?;
        let template_digest = template_digest(
            template.name(),
            &canonical_sql,
            template.parameters(),
            template.bounds(),
        );
        let scope_digest = registration.scope.digest();
        let request_id = RequestId(Digest::from_parts(
            "snowflake-request/v1",
            &[
                ("mission_revision", mission_revision.to_string()),
                ("scope_digest", scope_digest.to_string()),
                ("registration_digest", registration.digest().to_string()),
                ("template_digest", template_digest.to_string()),
                ("parameters_digest", parameters_digest.to_string()),
            ],
        ));
        let proposal_digest = Digest::from_parts(
            "snowflake-query-proposal/v1",
            &[
                ("request_id", request_id.to_string()),
                ("canonical_sql", canonical_sql.clone()),
                ("template_digest", template_digest.to_string()),
                ("parameters_digest", parameters_digest.to_string()),
                ("scope_digest", scope_digest.to_string()),
                ("registration_digest", registration.digest().to_string()),
            ],
        );
        Ok(QueryProposal {
            schema: "hartevo.snowflake-query-proposal/v1".to_owned(),
            mission_revision,
            scope: registration.scope.clone(),
            scope_digest,
            registration_digest: registration.digest().clone(),
            plugin_version: registration.plugin_version,
            contract_digest: registration.contract_digest.clone(),
            provider_revision: registration.provider_revision,
            template_name: template.name.clone(),
            template_digest,
            canonical_sql,
            parameters: parameters.to_vec(),
            parameters_digest,
            bounds: template.bounds,
            request_id,
            proposal_digest,
        })
    }
}

/// A deterministic request identifier bound to Mission revision and query data.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RequestId(Digest);

impl RequestId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Opaque SQL API statement handle.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StatementHandle(String);

impl StatementHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, SnowflakeOutcomeError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(SnowflakeOutcomeError::InvalidStatementHandle);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The fully-bound, secret-free proposal passed to the provider seam.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryProposal {
    pub schema: String,
    pub mission_revision: u64,
    pub scope: SnowflakeScope,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub plugin_version: PluginVersion,
    pub contract_digest: Digest,
    pub provider_revision: u64,
    pub template_name: String,
    pub template_digest: Digest,
    pub canonical_sql: String,
    pub parameters: Vec<BoundParameter>,
    pub parameters_digest: Digest,
    pub bounds: ResultBounds,
    pub request_id: RequestId,
    pub proposal_digest: Digest,
}

impl QueryProposal {
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

impl fmt::Debug for QueryProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryProposal")
            .field("schema", &self.schema)
            .field("mission_revision", &self.mission_revision)
            .field("scope_digest", &self.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .field("plugin_version", &self.plugin_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("template_name", &self.template_name)
            .field("template_digest", &self.template_digest)
            .field("parameters_digest", &self.parameters_digest)
            .field("bounds", &self.bounds)
            .field("request_id", &self.request_id)
            .field("proposal_digest", &self.proposal_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SqlToken {
    Word(String),
    Number(String),
    Literal(String),
    QuotedIdentifier(String),
    Placeholder(String),
    Symbol(String),
}

#[allow(clippy::too_many_lines)]
fn lex_sql(sql: &str) -> Result<Vec<SqlToken>, SnowflakeOutcomeError> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if (byte == b'-' && bytes.get(index + 1) == Some(&b'-'))
            || (byte == b'/' && bytes.get(index + 1) == Some(&b'*'))
            || byte == b'#'
        {
            return Err(SnowflakeOutcomeError::QueryRejected(
                QueryRejection::Comment,
            ));
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            let quote = byte;
            let start = index;
            index += 1;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == quote {
                    if bytes.get(index + 1) == Some(&quote) {
                        index += 2;
                    } else {
                        index += 1;
                        closed = true;
                        break;
                    }
                } else {
                    index += 1;
                }
            }
            if !closed {
                return Err(SnowflakeOutcomeError::QueryRejected(
                    QueryRejection::UnterminatedLiteral,
                ));
            }
            let token = sql[start..index].to_owned();
            if quote == b'\'' {
                tokens.push(SqlToken::Literal(token));
            } else {
                tokens.push(SqlToken::QuotedIdentifier(token));
            }
            continue;
        }
        if byte == b':' {
            if bytes.get(index + 1) == Some(&b':') {
                tokens.push(SqlToken::Symbol("::".to_owned()));
                index += 2;
                continue;
            }
            let start = index + 1;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if start == index {
                return Err(SnowflakeOutcomeError::QueryRejected(
                    QueryRejection::UnsupportedParameterSyntax,
                ));
            }
            let name = &sql[start..index];
            if !valid_parameter_name(name) {
                return Err(SnowflakeOutcomeError::InvalidParameterName);
            }
            tokens.push(SqlToken::Placeholder(name.to_owned()));
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'$')
            {
                index += 1;
            }
            tokens.push(SqlToken::Word(sql[start..index].to_owned()));
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                index += 1;
            }
            tokens.push(SqlToken::Number(sql[start..index].to_owned()));
            continue;
        }
        if byte == b'?' {
            return Err(SnowflakeOutcomeError::QueryRejected(
                QueryRejection::UnsupportedParameterSyntax,
            ));
        }
        let mut symbol = String::from(char::from(byte));
        if let Some(next) = bytes.get(index + 1).copied()
            && matches!(
                (byte, next),
                (b'<' | b'>' | b'!', b'=') | (b'<', b'>') | (b'|', b'|')
            )
        {
            symbol.push(char::from(next));
            index += 1;
        }
        index += 1;
        tokens.push(SqlToken::Symbol(symbol));
    }
    Ok(tokens)
}

fn keyword(value: &str) -> String {
    value.to_ascii_uppercase()
}

fn canonicalize_sql(sql: &str) -> Result<String, SnowflakeOutcomeError> {
    let tokens = lex_sql(sql)?;
    if tokens.is_empty() {
        return Err(SnowflakeOutcomeError::QueryRejected(QueryRejection::Empty));
    }
    Ok(tokens
        .iter()
        .map(|token| match token {
            SqlToken::Word(value) => keyword(value),
            SqlToken::Number(value)
            | SqlToken::Literal(value)
            | SqlToken::QuotedIdentifier(value)
            | SqlToken::Symbol(value) => value.clone(),
            SqlToken::Placeholder(value) => format!(":{value}"),
        })
        .collect::<Vec<_>>()
        .join(" "))
}

#[allow(clippy::too_many_lines)]
fn validate_and_canonicalize_sql(
    template: &QueryTemplate,
    parameters: &[BoundParameter],
) -> Result<String, SnowflakeOutcomeError> {
    let tokens = lex_sql(template.sql())?;
    if tokens.is_empty() {
        return Err(SnowflakeOutcomeError::QueryRejected(QueryRejection::Empty));
    }
    if tokens
        .iter()
        .any(|token| matches!(token, SqlToken::Symbol(value) if value == ";"))
    {
        return Err(SnowflakeOutcomeError::QueryRejected(
            QueryRejection::MultipleStatements,
        ));
    }
    let words = tokens
        .iter()
        .filter_map(|token| match token {
            SqlToken::Word(value) => Some(keyword(value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let first_word = words.first().ok_or(SnowflakeOutcomeError::QueryRejected(
        QueryRejection::OnlySelectOrExplain,
    ))?;
    if first_word != "SELECT" && first_word != "EXPLAIN" && first_word != "WITH" {
        return Err(SnowflakeOutcomeError::QueryRejected(
            QueryRejection::OnlySelectOrExplain,
        ));
    }
    if first_word == "EXPLAIN" && !words.iter().skip(1).any(|word| word == "SELECT") {
        return Err(SnowflakeOutcomeError::QueryRejected(
            QueryRejection::OnlySelectOrExplain,
        ));
    }
    if first_word == "WITH" && !words.iter().any(|word| word == "SELECT") {
        return Err(SnowflakeOutcomeError::QueryRejected(
            QueryRejection::OnlySelectOrExplain,
        ));
    }
    if words
        .iter()
        .any(|word| FORBIDDEN_SQL_WORDS.contains(&word.as_str()))
    {
        return Err(SnowflakeOutcomeError::QueryRejected(
            QueryRejection::MutationOrSession,
        ));
    }

    let mut limit_count = 0;
    let mut seen_parameters = BTreeSet::new();
    let parameter_specs = template
        .parameters()
        .iter()
        .map(|spec| (spec.name().to_owned(), spec.data_type()))
        .collect::<BTreeMap<_, _>>();
    let supplied = parameters
        .iter()
        .map(|parameter| parameter.name().to_owned())
        .collect::<BTreeSet<_>>();
    if supplied.len() != parameters.len() {
        return Err(SnowflakeOutcomeError::DuplicateParameter);
    }
    for (index, token) in tokens.iter().enumerate() {
        if let SqlToken::Word(value) = token {
            let upper = keyword(value);
            if upper == "LIMIT" {
                limit_count += 1;
                let Some(next) = tokens.get(index + 1) else {
                    return Err(SnowflakeOutcomeError::QueryRejected(
                        QueryRejection::UnboundedLimit,
                    ));
                };
                let SqlToken::Number(limit) = next else {
                    return Err(SnowflakeOutcomeError::QueryRejected(
                        QueryRejection::UnboundedLimit,
                    ));
                };
                let Ok(limit) = limit.parse::<u64>() else {
                    return Err(SnowflakeOutcomeError::QueryRejected(
                        QueryRejection::UnboundedLimit,
                    ));
                };
                if limit == 0 || limit > template.bounds().max_rows {
                    return Err(SnowflakeOutcomeError::QueryRejected(
                        QueryRejection::UnboundedLimit,
                    ));
                }
            }
        }
        let SqlToken::Placeholder(name) = token else {
            continue;
        };
        let Some(expected_type) = parameter_specs.get(name) else {
            return Err(SnowflakeOutcomeError::UnknownParameter);
        };
        let previous_word = (0..index).rev().find_map(|cursor| match &tokens[cursor] {
            SqlToken::Word(value) => Some(keyword(value)),
            _ => None,
        });
        let preceding_words = (0..index)
            .rev()
            .filter_map(|cursor| match &tokens[cursor] {
                SqlToken::Word(value) => Some(keyword(value)),
                _ => None,
            })
            .take(2)
            .collect::<Vec<_>>();
        let previous_symbol = tokens.get(index.wrapping_sub(1));
        let next_symbol = tokens.get(index + 1);
        let identifier_position = matches!(
            previous_word.as_deref(),
            Some("FROM" | "JOIN" | "INTO" | "TABLE" | "UPDATE" | "USING" | "AS")
        ) || preceding_words.as_slice() == ["BY", "ORDER"]
            || preceding_words.as_slice() == ["BY", "GROUP"]
            || preceding_words.as_slice() == ["BY", "PARTITION"]
            || matches!(previous_symbol, Some(SqlToken::Symbol(value)) if value == ".")
            || matches!(next_symbol, Some(SqlToken::Symbol(value)) if value == ".")
            || preceding_words.iter().any(|word| word == "IDENTIFIER")
            || (previous_word.as_deref() == Some("LIMIT"));
        if identifier_position {
            return Err(SnowflakeOutcomeError::QueryRejected(
                QueryRejection::UnboundIdentifier,
            ));
        }
        if seen_parameters.contains(name) {
            // Repeated value bindings are deterministic and safe; the digest
            // still contains one typed value for the named parameter.
        }
        seen_parameters.insert(name.clone());
        let bound = parameters
            .iter()
            .find(|parameter| parameter.name() == name)
            .ok_or(SnowflakeOutcomeError::UnknownParameter)?;
        if let Some(actual_type) = bound.value().snowflake_type()
            && actual_type != *expected_type
        {
            return Err(SnowflakeOutcomeError::ParameterTypeMismatch);
        }
    }
    if limit_count == 0 {
        return Err(SnowflakeOutcomeError::QueryRejected(
            QueryRejection::UnboundedLimit,
        ));
    }
    if supplied != parameter_specs.keys().cloned().collect::<BTreeSet<_>>() {
        return Err(SnowflakeOutcomeError::MissingOrUnexpectedParameter);
    }
    Ok(tokens
        .iter()
        .map(|token| match token {
            SqlToken::Word(value) => keyword(value),
            SqlToken::Number(value)
            | SqlToken::Literal(value)
            | SqlToken::QuotedIdentifier(value)
            | SqlToken::Symbol(value) => value.clone(),
            SqlToken::Placeholder(value) => format!(":{value}"),
        })
        .collect::<Vec<_>>()
        .join(" "))
}

fn parameters_digest(parameters: &[BoundParameter]) -> Result<Digest, SnowflakeOutcomeError> {
    let mut sorted = parameters.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    if sorted.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(SnowflakeOutcomeError::DuplicateParameter);
    }
    let fields = sorted
        .iter()
        .map(|parameter| {
            (
                "parameter",
                format!("{}={}", parameter.name, parameter.value.canonical()),
            )
        })
        .collect::<Vec<_>>();
    Ok(Digest::from_parts("snowflake-parameters/v1", &fields))
}

/// Reasons a query proposal is rejected before it reaches a transport.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryRejection {
    Empty,
    Comment,
    UnterminatedLiteral,
    MultipleStatements,
    UnsupportedParameterSyntax,
    OnlySelectOrExplain,
    MutationOrSession,
    UnboundIdentifier,
    UnboundedLimit,
    RequiresTypedParameter,
}

/// Errors raised while constructing or validating the Layer-1 contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SnowflakeOutcomeError {
    #[error("scope is invalid")]
    InvalidScope,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("plugin version is invalid")]
    InvalidPluginVersion,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration registry revision overflowed")]
    RegistryRevisionOverflow,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration does not allow this query template")]
    RegistrationMismatch,
    #[error("query template is invalid")]
    InvalidTemplate,
    #[error("parameter name is invalid")]
    InvalidParameterName,
    #[error("result bounds are invalid")]
    InvalidBounds,
    #[error("duplicate parameter")]
    DuplicateParameter,
    #[error("unknown parameter")]
    UnknownParameter,
    #[error("missing or unexpected parameter")]
    MissingOrUnexpectedParameter,
    #[error("parameter type does not match its declaration")]
    ParameterTypeMismatch,
    #[error("statement handle is invalid")]
    InvalidStatementHandle,
    #[error("query rejected: {0:?}")]
    QueryRejected(QueryRejection),
}

/// Result schema metadata returned by the provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ColumnSchema {
    pub name: String,
    pub data_type: SnowflakeType,
    pub nullable: bool,
    pub ordinal: u32,
}

impl ColumnSchema {
    pub fn new(
        name: impl Into<String>,
        data_type: SnowflakeType,
        nullable: bool,
        ordinal: u32,
    ) -> Result<Self, SnowflakeOutcomeError> {
        let name = name.into();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(SnowflakeOutcomeError::InvalidTemplate);
        }
        Ok(Self {
            name,
            data_type,
            nullable,
            ordinal,
        })
    }
}

/// Ordered result schema with a deterministic schema digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultSchema {
    pub columns: Vec<ColumnSchema>,
    pub schema_digest: Digest,
}

impl ResultSchema {
    pub fn new(mut columns: Vec<ColumnSchema>) -> Result<Self, SnowflakeOutcomeError> {
        columns.sort_by_key(|column| column.ordinal);
        if columns
            .iter()
            .enumerate()
            .any(|(index, column)| column.ordinal != u32::try_from(index).unwrap_or(u32::MAX))
            || columns
                .iter()
                .map(|column| column.name.to_ascii_uppercase())
                .collect::<BTreeSet<_>>()
                .len()
                != columns.len()
        {
            return Err(SnowflakeOutcomeError::InvalidTemplate);
        }
        let schema_digest = Digest::from_parts(
            "snowflake-result-schema/v1",
            &columns
                .iter()
                .map(|column| {
                    (
                        "column",
                        format!(
                            "{}:{:?}:{}:{}",
                            column.name, column.data_type, column.nullable, column.ordinal
                        ),
                    )
                })
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            columns,
            schema_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.schema_digest
    }

    fn validate_row(&self, row: &[SnowflakeValue]) -> Result<(), ProjectionError> {
        if row.len() != self.columns.len() {
            return Err(ProjectionError::SchemaDrift);
        }
        for (value, column) in row.iter().zip(&self.columns) {
            let Some(value_type) = value.snowflake_type() else {
                if column.nullable {
                    continue;
                }
                return Err(ProjectionError::SchemaDrift);
            };
            if value_type != column.data_type {
                return Err(ProjectionError::SchemaDrift);
            }
        }
        Ok(())
    }
}

/// One partition's provider metadata and bounded row payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionMetadata {
    pub index: u32,
    pub row_count: u64,
    pub byte_count: u64,
    pub content_digest: Digest,
    pub chunk_digests: Vec<Digest>,
}

/// Recording/fake input payload. It is never retained wholesale by the final
/// projection; only rows within the declared bounds are copied.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct PartitionData {
    metadata: PartitionMetadata,
    rows: Vec<Vec<SnowflakeValue>>,
}

impl PartitionData {
    pub fn new(index: u32, rows: Vec<Vec<SnowflakeValue>>) -> Self {
        let metadata = partition_metadata(index, &rows);
        Self { metadata, rows }
    }

    /// Creates intentionally declared metadata for adversarial drift tests.
    pub fn with_metadata(metadata: PartitionMetadata, rows: Vec<Vec<SnowflakeValue>>) -> Self {
        Self { metadata, rows }
    }

    #[must_use]
    pub fn metadata(&self) -> &PartitionMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn rows(&self) -> &[Vec<SnowflakeValue>] {
        &self.rows
    }
}

impl fmt::Debug for PartitionData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartitionData")
            .field("metadata", &self.metadata)
            .field("row_count_in_memory", &self.rows.len())
            .finish()
    }
}

fn row_canonical(row: &[SnowflakeValue]) -> String {
    row.iter()
        .map(SnowflakeValue::canonical)
        .collect::<Vec<_>>()
        .join("|")
}

fn row_digest(row: &[SnowflakeValue]) -> Digest {
    Digest::from_parts("snowflake-row/v1", &[("row", row_canonical(row))])
}

fn partition_metadata(index: u32, rows: &[Vec<SnowflakeValue>]) -> PartitionMetadata {
    let row_bytes = rows
        .iter()
        .map(|row| row_canonical(row).len() as u64)
        .sum::<u64>();
    let row_digests = rows.iter().map(|row| row_digest(row)).collect::<Vec<_>>();
    let content_digest = Digest::from_parts(
        "snowflake-partition/v1",
        &[
            ("index", index.to_string()),
            ("row_count", rows.len().to_string()),
            (
                "row_digests",
                row_digests
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    );
    let chunk_digests = row_digests
        .chunks(1_000)
        .map(|chunk| {
            Digest::from_parts(
                "snowflake-chunk/v1",
                &[(
                    "rows",
                    chunk
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )],
            )
        })
        .collect();
    PartitionMetadata {
        index,
        row_count: rows.len() as u64,
        byte_count: row_bytes,
        content_digest,
        chunk_digests,
    }
}

/// A statement's bounded completion metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatementCompletion {
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
    pub schema: ResultSchema,
    pub expected_partition_count: u32,
    pub truncated: bool,
    pub provider_request_id: Option<String>,
}

/// Stable public name for the provider statement receipt suggested by the
/// contract. It remains provider evidence and carries no kernel authority.
pub type StatementReceipt = StatementCompletion;

/// Ordered, complete partition receipts retained in a projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionReceipt {
    pub index: u32,
    pub row_count: u64,
    pub byte_count: u64,
    pub content_digest: Digest,
    pub chunk_digests: Vec<Digest>,
}

/// Evidence completeness after partition and bound verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    BoundedTruncated,
}

/// A bounded result projection. This is provider evidence only, not a Hartevo
/// Receipt, Verification, Outcome, or adopted Work Product.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WarehouseResultProjection {
    pub schema: ResultSchema,
    pub schema_digest: Digest,
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
    pub provider_request_id: Option<String>,
    pub partitions: Vec<PartitionReceipt>,
    pub rows: Vec<Vec<SnowflakeValue>>,
    pub row_count: u64,
    pub byte_count: u64,
    pub result_digest: Digest,
    pub completeness: ProjectionCompleteness,
    pub bounds: ResultBounds,
    pub provenance: TransportProvenance,
    pub native: bool,
    pub first_party: bool,
}

/// Short provider-facing name for the bounded result projection.
pub type ResultProjection = WarehouseResultProjection;

impl fmt::Debug for WarehouseResultProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WarehouseResultProjection")
            .field("schema_digest", &self.schema_digest)
            .field("request_id", &self.request_id)
            .field("statement_handle", &self.statement_handle)
            .field("scope_digest", &self.scope_digest)
            .field("provider_request_id", &self.provider_request_id)
            .field("partition_count", &self.partitions.len())
            .field("row_count", &self.row_count)
            .field("byte_count", &self.byte_count)
            .field("result_digest", &self.result_digest)
            .field("completeness", &self.completeness)
            .field("bounds", &self.bounds)
            .field("provenance", &self.provenance)
            .field("native", &self.native)
            .field("first_party", &self.first_party)
            .finish_non_exhaustive()
    }
}

impl WarehouseResultProjection {
    #[allow(clippy::too_many_lines)]
    fn build(
        proposal: &QueryProposal,
        completion: &StatementCompletion,
        pages: &[PartitionPageResponse],
        provenance: TransportProvenance,
    ) -> Result<Self, ProjectionError> {
        let Some(first_page) = pages.first() else {
            return Err(ProjectionError::PartitionIncomplete);
        };
        if completion.request_id != proposal.request_id
            || completion.scope_digest != proposal.scope_digest
            || completion.schema.digest() != &first_page.schema_digest
            || completion.expected_partition_count > proposal.bounds.max_partitions
        {
            return Err(ProjectionError::ScopeOrRequestDrift);
        }
        let mut partitions = pages
            .iter()
            .flat_map(|page| page.partitions.iter())
            .collect::<Vec<_>>();
        if partitions.len() != completion.expected_partition_count as usize {
            return Err(ProjectionError::PartitionIncomplete);
        }
        partitions.sort_by_key(|partition| partition.metadata().index);
        if partitions.iter().enumerate().any(|(position, partition)| {
            partition.metadata().index != u32::try_from(position).unwrap_or(u32::MAX)
        }) {
            return Err(ProjectionError::PartitionDuplicateOrOmitted);
        }

        let mut retained_rows = Vec::new();
        let mut receipts = Vec::new();
        let mut row_count = 0_u64;
        let mut byte_count = 0_u64;
        for partition in partitions {
            let metadata = partition.metadata();
            let computed = partition_metadata(metadata.index, partition.rows());
            if computed != *metadata {
                return Err(ProjectionError::PartitionDigestMismatch);
            }
            if metadata.row_count > proposal.bounds.max_chunk_rows
                || metadata.byte_count > proposal.bounds.max_chunk_bytes
            {
                return Err(ProjectionError::BoundsExceeded);
            }
            for row in partition.rows() {
                completion.schema.validate_row(row)?;
                row_count = row_count
                    .checked_add(1)
                    .ok_or(ProjectionError::BoundsExceeded)?;
                if row_count > proposal.bounds.max_rows {
                    return Err(ProjectionError::BoundsExceeded);
                }
                byte_count = byte_count
                    .checked_add(row_canonical(row).len() as u64)
                    .ok_or(ProjectionError::BoundsExceeded)?;
                if byte_count > proposal.bounds.max_bytes {
                    return Err(ProjectionError::BoundsExceeded);
                }
                retained_rows.push(row.clone());
            }
            receipts.push(PartitionReceipt {
                index: metadata.index,
                row_count: metadata.row_count,
                byte_count: metadata.byte_count,
                content_digest: metadata.content_digest.clone(),
                chunk_digests: metadata.chunk_digests.clone(),
            });
        }
        let result_digest = Digest::from_parts(
            "snowflake-result/v1",
            &[
                ("request_id", proposal.request_id.to_string()),
                (
                    "statement_handle",
                    completion.statement_handle.as_str().to_owned(),
                ),
                ("schema_digest", completion.schema.digest().to_string()),
                (
                    "partition_digests",
                    receipts
                        .iter()
                        .map(|receipt| receipt.content_digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "row_digests",
                    retained_rows
                        .iter()
                        .map(|row| row_digest(row).to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Ok(Self {
            schema: completion.schema.clone(),
            schema_digest: completion.schema.digest().clone(),
            request_id: proposal.request_id.clone(),
            statement_handle: completion.statement_handle.clone(),
            scope_digest: proposal.scope_digest.clone(),
            provider_request_id: completion.provider_request_id.clone(),
            partitions: receipts,
            rows: retained_rows,
            row_count,
            byte_count,
            result_digest,
            completeness: if completion.truncated {
                ProjectionCompleteness::BoundedTruncated
            } else {
                ProjectionCompleteness::Complete
            },
            bounds: proposal.bounds,
            provenance,
            native: false,
            first_party: false,
        })
    }
}

/// Provenance is deliberately closed over non-native Layer-1 states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
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

/// SQL API submission request. It contains no SecretReference or credential
/// bytes; authentication resolution belongs to the future Layer-2 host seam.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitQueryRequest {
    pub request_id: RequestId,
    pub proposal_digest: Digest,
    pub scope: SnowflakeScope,
    pub canonical_sql: String,
    pub parameters: Vec<BoundParameter>,
    pub bounds: ResultBounds,
}

impl fmt::Debug for SubmitQueryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmitQueryRequest")
            .field("request_id", &self.request_id)
            .field("proposal_digest", &self.proposal_digest)
            .field("scope_digest", &self.scope.digest())
            .field(
                "sql_digest",
                &Digest::from_bytes(self.canonical_sql.as_bytes()),
            )
            .field("parameter_count", &self.parameters.len())
            .field("bounds", &self.bounds)
            .finish()
    }
}

impl SubmitQueryRequest {
    fn from_proposal(proposal: &QueryProposal) -> Self {
        Self {
            request_id: proposal.request_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope: proposal.scope.clone(),
            canonical_sql: proposal.canonical_sql.clone(),
            parameters: proposal.parameters.clone(),
            bounds: proposal.bounds,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollStatementRequest {
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadPartitionsRequest {
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
    pub schema_digest: Digest,
    pub page_token: Option<String>,
    pub bounds: ResultBounds,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcileSubmissionRequest {
    pub request_id: RequestId,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
}

/// Provider response classification for a SQL API submit request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitResponse {
    pub http_status: u16,
    pub request_id: RequestId,
    pub statement_handle: Option<StatementHandle>,
    pub provider_request_id: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub detail_digest: Option<Digest>,
}

impl SubmitResponse {
    #[must_use]
    pub fn accepted_202(
        request_id: RequestId,
        statement_handle: StatementHandle,
        provider_request_id: Option<String>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            http_status: 202,
            request_id,
            statement_handle: Some(statement_handle),
            provider_request_id,
            retry_after_ms,
            detail_digest: None,
        }
    }

    #[must_use]
    pub fn throttled_429(request_id: RequestId, retry_after_ms: Option<u64>) -> Self {
        Self {
            http_status: 429,
            request_id,
            statement_handle: None,
            provider_request_id: None,
            retry_after_ms,
            detail_digest: None,
        }
    }

    #[must_use]
    pub fn terminal_422(request_id: RequestId, detail: impl AsRef<[u8]>) -> Self {
        Self {
            http_status: 422,
            request_id,
            statement_handle: None,
            provider_request_id: None,
            retry_after_ms: None,
            detail_digest: Some(Digest::from_bytes(detail.as_ref())),
        }
    }
}

/// Query lifecycle status returned by polling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Queued,
    Running,
    Complete,
    Failed,
    Canceled,
    Expired,
}

/// SQL API poll response. Complete responses carry schema and partition count;
/// there is no cancellation operation in this Layer-1 crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollResponse {
    pub http_status: u16,
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
    pub status: QueryStatus,
    pub provider_request_id: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub schema: Option<ResultSchema>,
    pub partition_count: Option<u32>,
    pub truncated: bool,
    pub detail_digest: Option<Digest>,
}

impl PollResponse {
    #[must_use]
    pub fn running_202(
        request_id: RequestId,
        statement_handle: StatementHandle,
        scope_digest: Digest,
        status: QueryStatus,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            http_status: 202,
            request_id,
            statement_handle,
            scope_digest,
            status,
            provider_request_id: None,
            retry_after_ms,
            schema: None,
            partition_count: None,
            truncated: false,
            detail_digest: None,
        }
    }

    #[must_use]
    pub fn complete_200(
        request_id: RequestId,
        statement_handle: StatementHandle,
        scope_digest: Digest,
        schema: ResultSchema,
        partition_count: u32,
        truncated: bool,
        provider_request_id: Option<String>,
    ) -> Self {
        Self {
            http_status: 200,
            request_id,
            statement_handle,
            scope_digest,
            status: QueryStatus::Complete,
            provider_request_id,
            retry_after_ms: None,
            schema: Some(schema),
            partition_count: Some(partition_count),
            truncated,
            detail_digest: None,
        }
    }

    #[must_use]
    pub fn throttled_429(
        request_id: RequestId,
        statement_handle: StatementHandle,
        scope_digest: Digest,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            http_status: 429,
            request_id,
            statement_handle,
            scope_digest,
            status: QueryStatus::Running,
            provider_request_id: None,
            retry_after_ms,
            schema: None,
            partition_count: None,
            truncated: false,
            detail_digest: None,
        }
    }

    #[must_use]
    pub fn terminal_422(
        request_id: RequestId,
        statement_handle: StatementHandle,
        scope_digest: Digest,
        status: QueryStatus,
        detail: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            http_status: 422,
            request_id,
            statement_handle,
            scope_digest,
            status,
            provider_request_id: None,
            retry_after_ms: None,
            schema: None,
            partition_count: None,
            truncated: false,
            detail_digest: Some(Digest::from_bytes(detail.as_ref())),
        }
    }
}

/// One page of partition metadata and bounded fixture rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionPageResponse {
    pub http_status: u16,
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
    pub schema_digest: Digest,
    pub total_partitions: u32,
    pub partitions: Vec<PartitionData>,
    pub next_page_token: Option<String>,
    pub provider_request_id: Option<String>,
}

impl PartitionPageResponse {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn ok(
        request_id: RequestId,
        statement_handle: StatementHandle,
        scope_digest: Digest,
        schema_digest: Digest,
        total_partitions: u32,
        partitions: Vec<PartitionData>,
        next_page_token: Option<String>,
        provider_request_id: Option<String>,
    ) -> Self {
        Self {
            http_status: 200,
            request_id,
            statement_handle,
            scope_digest,
            schema_digest,
            total_partitions,
            partitions,
            next_page_token,
            provider_request_id,
        }
    }

    #[must_use]
    pub fn throttled(
        request_id: RequestId,
        statement_handle: StatementHandle,
        scope_digest: Digest,
    ) -> Self {
        Self {
            http_status: 429,
            request_id,
            statement_handle,
            scope_digest,
            schema_digest: Digest::from_bytes(b"throttled"),
            total_partitions: 0,
            partitions: Vec::new(),
            next_page_token: None,
            provider_request_id: None,
        }
    }
}

/// An accepted result lookup used only to reconcile an ambiguous submit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationResponse {
    Accepted(SubmitResponse),
    TerminalFailure(SubmitResponse),
    NotFound,
    ScopeMismatch,
    BlockedEnv,
}

/// Transport errors are intentionally coarse and never include SQL, secret,
/// response-body, or credential content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("transport is BLOCKED_ENV")]
    BlockedEnv,
    #[error("submission outcome is ambiguous")]
    AmbiguousSubmission,
    #[error("recording script is exhausted")]
    ScriptExhausted,
    #[error("transport response is malformed")]
    MalformedResponse,
    #[error("transport does not support reconciliation")]
    ReconciliationUnsupported,
}

/// Layer-1 provider transport seam. Implementations may only report one of
/// the closed non-native provenance states above.
pub trait SnowflakeSqlApiTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn submit(&mut self, request: &SubmitQueryRequest) -> Result<SubmitResponse, TransportError>;

    fn poll(&mut self, request: &PollStatementRequest) -> Result<PollResponse, TransportError>;

    fn read_partitions(
        &mut self,
        request: &ReadPartitionsRequest,
    ) -> Result<PartitionPageResponse, TransportError>;

    fn reconcile_submission(
        &mut self,
        _request: &ReconcileSubmissionRequest,
    ) -> Result<ReconciliationResponse, TransportError> {
        Err(TransportError::ReconciliationUnsupported)
    }
}

/// Deterministic recording transport used for contract tests and offline
/// demonstrations.
#[derive(Debug, Default)]
pub struct RecordingTransport {
    submit_responses: VecDeque<Result<SubmitResponse, TransportError>>,
    poll_responses: VecDeque<Result<PollResponse, TransportError>>,
    partition_responses: VecDeque<Result<PartitionPageResponse, TransportError>>,
    reconciliation_responses: VecDeque<Result<ReconciliationResponse, TransportError>>,
    submitted_requests: Vec<SubmitQueryRequest>,
    polled_requests: Vec<PollStatementRequest>,
    partition_requests: Vec<ReadPartitionsRequest>,
    reconciliation_requests: Vec<ReconcileSubmissionRequest>,
}

impl RecordingTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_submit_response(&mut self, response: SubmitResponse) {
        self.submit_responses.push_back(Ok(response));
    }

    pub fn push_submit_error(&mut self, error: TransportError) {
        self.submit_responses.push_back(Err(error));
    }

    pub fn push_poll_response(&mut self, response: PollResponse) {
        self.poll_responses.push_back(Ok(response));
    }

    pub fn push_poll_error(&mut self, error: TransportError) {
        self.poll_responses.push_back(Err(error));
    }

    pub fn push_partition_response(&mut self, response: PartitionPageResponse) {
        self.partition_responses.push_back(Ok(response));
    }

    pub fn push_partition_error(&mut self, error: TransportError) {
        self.partition_responses.push_back(Err(error));
    }

    pub fn push_reconciliation_response(&mut self, response: ReconciliationResponse) {
        self.reconciliation_responses.push_back(Ok(response));
    }

    pub fn push_reconciliation_error(&mut self, error: TransportError) {
        self.reconciliation_responses.push_back(Err(error));
    }

    #[must_use]
    pub fn submitted_requests(&self) -> &[SubmitQueryRequest] {
        &self.submitted_requests
    }

    #[must_use]
    pub fn polled_requests(&self) -> &[PollStatementRequest] {
        &self.polled_requests
    }

    #[must_use]
    pub fn partition_requests(&self) -> &[ReadPartitionsRequest] {
        &self.partition_requests
    }

    #[must_use]
    pub fn reconciliation_requests(&self) -> &[ReconcileSubmissionRequest] {
        &self.reconciliation_requests
    }
}

impl SnowflakeSqlApiTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn submit(&mut self, request: &SubmitQueryRequest) -> Result<SubmitResponse, TransportError> {
        self.submitted_requests.push(request.clone());
        self.submit_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ScriptExhausted))
    }

    fn poll(&mut self, request: &PollStatementRequest) -> Result<PollResponse, TransportError> {
        self.polled_requests.push(request.clone());
        self.poll_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ScriptExhausted))
    }

    fn read_partitions(
        &mut self,
        request: &ReadPartitionsRequest,
    ) -> Result<PartitionPageResponse, TransportError> {
        self.partition_requests.push(request.clone());
        self.partition_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ScriptExhausted))
    }

    fn reconcile_submission(
        &mut self,
        request: &ReconcileSubmissionRequest,
    ) -> Result<ReconciliationResponse, TransportError> {
        self.reconciliation_requests.push(request.clone());
        self.reconciliation_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ScriptExhausted))
    }
}

/// Fake transport with the same scripted behavior but distinct provenance.
#[derive(Debug, Default)]
pub struct FakeTransport {
    inner: RecordingTransport,
}

impl FakeTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_submit_response(&mut self, response: SubmitResponse) {
        self.inner.push_submit_response(response);
    }

    pub fn push_submit_error(&mut self, error: TransportError) {
        self.inner.push_submit_error(error);
    }

    pub fn push_poll_response(&mut self, response: PollResponse) {
        self.inner.push_poll_response(response);
    }

    pub fn push_partition_response(&mut self, response: PartitionPageResponse) {
        self.inner.push_partition_response(response);
    }

    pub fn push_reconciliation_response(&mut self, response: ReconciliationResponse) {
        self.inner.push_reconciliation_response(response);
    }
}

impl SnowflakeSqlApiTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn submit(&mut self, request: &SubmitQueryRequest) -> Result<SubmitResponse, TransportError> {
        self.inner.submit(request)
    }

    fn poll(&mut self, request: &PollStatementRequest) -> Result<PollResponse, TransportError> {
        self.inner.poll(request)
    }

    fn read_partitions(
        &mut self,
        request: &ReadPartitionsRequest,
    ) -> Result<PartitionPageResponse, TransportError> {
        self.inner.read_partitions(request)
    }

    fn reconcile_submission(
        &mut self,
        request: &ReconcileSubmissionRequest,
    ) -> Result<ReconciliationResponse, TransportError> {
        self.inner.reconcile_submission(request)
    }
}

/// Loopback transport is a separately named non-native test provenance.
#[derive(Debug, Default)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_submit_response(&mut self, response: SubmitResponse) {
        self.inner.push_submit_response(response);
    }

    pub fn push_poll_response(&mut self, response: PollResponse) {
        self.inner.push_poll_response(response);
    }

    pub fn push_partition_response(&mut self, response: PartitionPageResponse) {
        self.inner.push_partition_response(response);
    }
}

impl SnowflakeSqlApiTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn submit(&mut self, request: &SubmitQueryRequest) -> Result<SubmitResponse, TransportError> {
        self.inner.submit(request)
    }

    fn poll(&mut self, request: &PollStatementRequest) -> Result<PollResponse, TransportError> {
        self.inner.poll(request)
    }

    fn read_partitions(
        &mut self,
        request: &ReadPartitionsRequest,
    ) -> Result<PartitionPageResponse, TransportError> {
        self.inner.read_partitions(request)
    }
}

/// Transport that makes the honest Layer-2 environment gap explicit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl SnowflakeSqlApiTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn submit(&mut self, _request: &SubmitQueryRequest) -> Result<SubmitResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn poll(&mut self, _request: &PollStatementRequest) -> Result<PollResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn read_partitions(
        &mut self,
        _request: &ReadPartitionsRequest,
    ) -> Result<PartitionPageResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn reconcile_submission(
        &mut self,
        _request: &ReconcileSubmissionRequest,
    ) -> Result<ReconciliationResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProjectionError {
    #[error("projection response has scope or request drift")]
    ScopeOrRequestDrift,
    #[error("projection response has schema drift")]
    SchemaDrift,
    #[error("partition set is incomplete")]
    PartitionIncomplete,
    #[error("partition set has a duplicate or omitted index")]
    PartitionDuplicateOrOmitted,
    #[error("partition content digest does not match its bounded rows")]
    PartitionDigestMismatch,
    #[error("projection exceeds a declared row, byte, or chunk bound")]
    BoundsExceeded,
}

/// Provider-visible submission state. No state claims Connected or native.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum SubmissionState {
    Accepted {
        request_id: RequestId,
        statement_handle: StatementHandle,
        provider_request_id: Option<String>,
        retry_after_ms: Option<u64>,
        reconciled: bool,
    },
    Throttled {
        request_id: RequestId,
        retry_after_ms: Option<u64>,
    },
    TerminalFailure {
        request_id: RequestId,
        detail_digest: Option<Digest>,
    },
    Ambiguous {
        request_id: RequestId,
    },
    BlockedEnv {
        request_id: RequestId,
    },
}

impl SubmissionState {
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        match self {
            Self::Accepted { request_id, .. }
            | Self::Throttled { request_id, .. }
            | Self::TerminalFailure { request_id, .. }
            | Self::Ambiguous { request_id }
            | Self::BlockedEnv { request_id } => request_id,
        }
    }

    #[must_use]
    pub fn statement_handle(&self) -> Option<&StatementHandle> {
        match self {
            Self::Accepted {
                statement_handle, ..
            } => Some(statement_handle),
            Self::Throttled { .. }
            | Self::TerminalFailure { .. }
            | Self::Ambiguous { .. }
            | Self::BlockedEnv { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous { .. })
    }
}

/// Provider-visible polling state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum PollState {
    Running {
        request_id: RequestId,
        statement_handle: StatementHandle,
        status: QueryStatus,
        retry_after_ms: Option<u64>,
    },
    Throttled {
        request_id: RequestId,
        statement_handle: StatementHandle,
        retry_after_ms: Option<u64>,
    },
    Complete(StatementCompletion),
    TerminalFailure {
        request_id: RequestId,
        statement_handle: StatementHandle,
        status: QueryStatus,
        detail_digest: Option<Digest>,
    },
    BlockedEnv {
        request_id: RequestId,
        statement_handle: StatementHandle,
    },
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider binding does not match the exact registration scope or digest")]
    BindingMismatch,
    #[error("provider received a stale Mission revision")]
    StaleMissionRevision,
    #[error("provider transport is not one of the allowed Layer-1 states")]
    InvalidProvenance,
    #[error("provider transport failed")]
    Transport(TransportError),
    #[error("provider response is malformed or has a mismatched request")]
    MalformedResponse,
    #[error("ambiguous submission cannot be reconciled to this exact proposal")]
    ReconciliationMismatch,
    #[error("statement has not been accepted and cannot be polled")]
    StatementNotAccepted,
    #[error("partition read was throttled")]
    Throttled,
    #[error("statement reached terminal provider failure")]
    TerminalFailure,
    #[error("result projection verification failed")]
    Projection(ProjectionError),
    #[error("result response has provider scope or schema drift")]
    ScopeOrSchemaDrift,
    #[error("provider partition pagination is cyclic or exceeds its bound")]
    PaginationBound,
}

/// Provider-level verification is explicitly below Hartevo authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    ProviderEvidenceOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultVerification {
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub scope_digest: Digest,
    pub schema_digest: Digest,
    pub result_digest: Digest,
    pub projection_completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub disposition: EvidenceDisposition,
    pub kernel_authoritative: bool,
    pub adopted_work_product: bool,
}

fn expected_request_id(proposal: &QueryProposal) -> RequestId {
    RequestId(Digest::from_parts(
        "snowflake-request/v1",
        &[
            ("mission_revision", proposal.mission_revision.to_string()),
            ("scope_digest", proposal.scope_digest.to_string()),
            (
                "registration_digest",
                proposal.registration_digest.to_string(),
            ),
            ("template_digest", proposal.template_digest.to_string()),
            ("parameters_digest", proposal.parameters_digest.to_string()),
        ],
    ))
}

fn expected_proposal_digest(proposal: &QueryProposal) -> Digest {
    Digest::from_parts(
        "snowflake-query-proposal/v1",
        &[
            ("request_id", proposal.request_id.to_string()),
            ("canonical_sql", proposal.canonical_sql.clone()),
            ("template_digest", proposal.template_digest.to_string()),
            ("parameters_digest", proposal.parameters_digest.to_string()),
            ("scope_digest", proposal.scope_digest.to_string()),
            (
                "registration_digest",
                proposal.registration_digest.to_string(),
            ),
        ],
    )
}

fn expected_result_digest(projection: &WarehouseResultProjection) -> Digest {
    Digest::from_parts(
        "snowflake-result/v1",
        &[
            ("request_id", projection.request_id.to_string()),
            (
                "statement_handle",
                projection.statement_handle.as_str().to_owned(),
            ),
            ("schema_digest", projection.schema_digest.to_string()),
            (
                "partition_digests",
                projection
                    .partitions
                    .iter()
                    .map(|partition| partition.content_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "row_digests",
                projection
                    .rows
                    .iter()
                    .map(|row| row_digest(row).to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    )
}

/// Typed SQL API provider over an explicitly non-native transport.
pub struct SnowflakeSqlApiProvider<T = BlockedEnvTransport> {
    registration: SnowflakeOutcomeRegistration,
    transport: T,
    mounted: bool,
    last_mission_revision: BTreeMap<Digest, u64>,
    submissions: BTreeMap<RequestId, SubmissionState>,
}

impl<T: SnowflakeSqlApiTransport> fmt::Debug for SnowflakeSqlApiProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowflakeSqlApiProvider")
            .field("registration", &self.registration)
            .field("transport_provenance", &self.transport.provenance())
            .field("mounted", &self.mounted)
            .field(
                "tracked_mission_revision_count",
                &self.last_mission_revision.len(),
            )
            .field("tracked_submission_count", &self.submissions.len())
            .finish_non_exhaustive()
    }
}

impl<T: SnowflakeSqlApiTransport> SnowflakeSqlApiProvider<T> {
    pub fn new(
        registration: SnowflakeOutcomeRegistration,
        transport: T,
    ) -> Result<Self, ProviderError> {
        let provenance = transport.provenance();
        if provenance.is_native() || provenance.is_connected() || provenance.is_first_party() {
            return Err(ProviderError::InvalidProvenance);
        }
        if registration.plugin_version != PluginVersion::V1
            || registration.contract_digest.as_str() != CONTRACT_DIGEST
        {
            return Err(ProviderError::BindingMismatch);
        }
        Ok(Self {
            registration,
            transport,
            mounted: true,
            last_mission_revision: BTreeMap::new(),
            submissions: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn definition(&self) -> SnowflakeProviderDefinition {
        SnowflakeProviderDefinition {
            id: PROVIDER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            version: self.registration.plugin_version,
            contract_digest: self.registration.contract_digest.clone(),
            provenance: self.transport.provenance(),
        }
    }

    #[must_use]
    pub fn registration(&self) -> &SnowflakeOutcomeRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub const fn is_mounted(&self) -> bool {
        self.mounted
    }

    pub fn revoke(&mut self) {
        self.mounted = false;
        self.registration.revoke();
    }

    /// Reverses a local provider revocation after the host has re-authorized
    /// the same immutable registration binding.
    pub fn restore(&mut self) {
        self.registration.restore();
        self.mounted = true;
    }

    pub fn unmount(&mut self) {
        self.revoke();
    }

    pub fn submit_query(
        &mut self,
        proposal: &QueryProposal,
    ) -> Result<SubmissionState, ProviderError> {
        self.validate_proposal(proposal)?;
        if let Some(previous) = self.submissions.get(&proposal.request_id)
            && !matches!(previous, SubmissionState::Throttled { .. })
        {
            return Ok(previous.clone());
        }
        self.observe_mission_revision(proposal)?;
        let request = SubmitQueryRequest::from_proposal(proposal);
        let state = match self.transport.submit(&request) {
            Ok(response) => Self::classify_submit_response(proposal, response)?,
            Err(TransportError::AmbiguousSubmission) => SubmissionState::Ambiguous {
                request_id: proposal.request_id.clone(),
            },
            Err(TransportError::BlockedEnv) => SubmissionState::BlockedEnv {
                request_id: proposal.request_id.clone(),
            },
            Err(error) => return Err(ProviderError::Transport(error)),
        };
        self.submissions
            .insert(proposal.request_id.clone(), state.clone());
        Ok(state)
    }

    pub fn reconcile_ambiguous_submission(
        &mut self,
        proposal: &QueryProposal,
    ) -> Result<SubmissionState, ProviderError> {
        self.validate_proposal(proposal)?;
        let Some(previous) = self.submissions.get(proposal.request_id()) else {
            return Err(ProviderError::ReconciliationMismatch);
        };
        if !previous.is_ambiguous() {
            return Ok(previous.clone());
        }
        let request = ReconcileSubmissionRequest {
            request_id: proposal.request_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
        };
        let response = match self.transport.reconcile_submission(&request) {
            Ok(response) => response,
            Err(TransportError::BlockedEnv) => {
                let state = SubmissionState::BlockedEnv {
                    request_id: proposal.request_id.clone(),
                };
                self.submissions
                    .insert(proposal.request_id.clone(), state.clone());
                return Ok(state);
            }
            Err(error) => return Err(ProviderError::Transport(error)),
        };
        let state = match response {
            ReconciliationResponse::Accepted(response) => {
                let mut accepted = Self::classify_submit_response(proposal, response)?;
                if let SubmissionState::Accepted { reconciled, .. } = &mut accepted {
                    *reconciled = true;
                }
                accepted
            }
            ReconciliationResponse::TerminalFailure(response) => {
                let state = Self::classify_submit_response(proposal, response)?;
                if matches!(state, SubmissionState::TerminalFailure { .. }) {
                    state
                } else {
                    return Err(ProviderError::ReconciliationMismatch);
                }
            }
            ReconciliationResponse::NotFound => previous.clone(),
            ReconciliationResponse::ScopeMismatch => {
                return Err(ProviderError::ReconciliationMismatch);
            }
            ReconciliationResponse::BlockedEnv => SubmissionState::BlockedEnv {
                request_id: proposal.request_id.clone(),
            },
        };
        self.submissions
            .insert(proposal.request_id.clone(), state.clone());
        Ok(state)
    }

    pub fn poll_statement(
        &mut self,
        proposal: &QueryProposal,
        statement_handle: &StatementHandle,
    ) -> Result<PollState, ProviderError> {
        self.validate_proposal(proposal)?;
        let Some(submission) = self.submissions.get(proposal.request_id()) else {
            return Err(ProviderError::StatementNotAccepted);
        };
        if submission.statement_handle() != Some(statement_handle) {
            return Err(ProviderError::StatementNotAccepted);
        }
        let submit_provider_request_id = match submission {
            SubmissionState::Accepted {
                provider_request_id,
                ..
            } => provider_request_id.clone(),
            _ => None,
        };
        let request = PollStatementRequest {
            request_id: proposal.request_id.clone(),
            statement_handle: statement_handle.clone(),
            scope_digest: proposal.scope_digest.clone(),
        };
        let response = match self.transport.poll(&request) {
            Ok(response) => response,
            Err(TransportError::BlockedEnv) => {
                return Ok(PollState::BlockedEnv {
                    request_id: proposal.request_id.clone(),
                    statement_handle: statement_handle.clone(),
                });
            }
            Err(error) => return Err(ProviderError::Transport(error)),
        };
        if response.request_id != proposal.request_id
            || response.statement_handle != *statement_handle
            || response.scope_digest != proposal.scope_digest
        {
            return Err(ProviderError::ScopeOrSchemaDrift);
        }
        match response.http_status {
            202 => Ok(PollState::Running {
                request_id: proposal.request_id.clone(),
                statement_handle: statement_handle.clone(),
                status: response.status,
                retry_after_ms: response.retry_after_ms,
            }),
            429 => Ok(PollState::Throttled {
                request_id: proposal.request_id.clone(),
                statement_handle: statement_handle.clone(),
                retry_after_ms: response.retry_after_ms,
            }),
            200 if response.status == QueryStatus::Complete => {
                let schema = response.schema.ok_or(ProviderError::MalformedResponse)?;
                let partition_count = response
                    .partition_count
                    .ok_or(ProviderError::MalformedResponse)?;
                if partition_count == 0 || partition_count > proposal.bounds.max_partitions {
                    return Err(ProviderError::Projection(ProjectionError::BoundsExceeded));
                }
                Ok(PollState::Complete(StatementCompletion {
                    request_id: proposal.request_id.clone(),
                    statement_handle: statement_handle.clone(),
                    scope_digest: proposal.scope_digest.clone(),
                    schema,
                    expected_partition_count: partition_count,
                    truncated: response.truncated,
                    provider_request_id: response
                        .provider_request_id
                        .or(submit_provider_request_id),
                }))
            }
            422 | 200 => Ok(PollState::TerminalFailure {
                request_id: proposal.request_id.clone(),
                statement_handle: statement_handle.clone(),
                status: response.status,
                detail_digest: response.detail_digest,
            }),
            _ => Err(ProviderError::MalformedResponse),
        }
    }

    pub fn read_partitions(
        &mut self,
        proposal: &QueryProposal,
        completion: &StatementCompletion,
    ) -> Result<WarehouseResultProjection, ProviderError> {
        self.validate_proposal(proposal)?;
        if completion.request_id != proposal.request_id
            || completion.scope_digest != proposal.scope_digest
            || completion.expected_partition_count == 0
            || completion.expected_partition_count > proposal.bounds.max_partitions
        {
            return Err(ProviderError::ScopeOrSchemaDrift);
        }
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut pages = Vec::new();
        for _ in 0..=proposal.bounds.max_partitions {
            let request = ReadPartitionsRequest {
                request_id: proposal.request_id.clone(),
                statement_handle: completion.statement_handle.clone(),
                scope_digest: proposal.scope_digest.clone(),
                schema_digest: completion.schema.digest().clone(),
                page_token: page_token.clone(),
                bounds: proposal.bounds,
            };
            let response = match self.transport.read_partitions(&request) {
                Ok(response) => response,
                Err(TransportError::BlockedEnv) => {
                    return Err(ProviderError::Transport(TransportError::BlockedEnv));
                }
                Err(error) => return Err(ProviderError::Transport(error)),
            };
            if response.http_status == 429 {
                return Err(ProviderError::Throttled);
            }
            if response.http_status == 422 {
                return Err(ProviderError::TerminalFailure);
            }
            if response.http_status != 200
                || response.request_id != proposal.request_id
                || response.statement_handle != completion.statement_handle
                || response.scope_digest != proposal.scope_digest
                || response.schema_digest != *completion.schema.digest()
                || response.total_partitions != completion.expected_partition_count
            {
                return Err(ProviderError::ScopeOrSchemaDrift);
            }
            if pages
                .iter()
                .flat_map(|page: &PartitionPageResponse| page.partitions.iter())
                .count()
                + response.partitions.len()
                > proposal.bounds.max_partitions as usize
            {
                return Err(ProviderError::Projection(ProjectionError::BoundsExceeded));
            }
            page_token.clone_from(&response.next_page_token);
            pages.push(response);
            let Some(token) = &page_token else {
                break;
            };
            if !seen_tokens.insert(token.clone()) {
                return Err(ProviderError::PaginationBound);
            }
        }
        if page_token.is_some() {
            return Err(ProviderError::PaginationBound);
        }
        WarehouseResultProjection::build(proposal, completion, &pages, self.provenance())
            .map_err(ProviderError::Projection)
    }

    pub fn verify_result_projection(
        &self,
        proposal: &QueryProposal,
        projection: &WarehouseResultProjection,
    ) -> Result<ResultVerification, ProviderError> {
        self.validate_proposal(proposal)?;
        if projection.request_id != proposal.request_id
            || projection.scope_digest != proposal.scope_digest
            || projection.schema_digest != *projection.schema.digest()
            || projection.result_digest != expected_result_digest(projection)
            || projection.native
            || projection.first_party
            || projection.provenance.is_native()
            || projection.provenance.is_connected()
            || projection.provenance.is_first_party()
            || projection.row_count > proposal.bounds.max_rows
            || projection.byte_count > proposal.bounds.max_bytes
            || projection.partitions.len() > proposal.bounds.max_partitions as usize
        {
            return Err(ProviderError::Projection(
                ProjectionError::ScopeOrRequestDrift,
            ));
        }
        Ok(ResultVerification {
            request_id: projection.request_id.clone(),
            statement_handle: projection.statement_handle.clone(),
            scope_digest: projection.scope_digest.clone(),
            schema_digest: projection.schema_digest.clone(),
            result_digest: projection.result_digest.clone(),
            projection_completeness: projection.completeness,
            provenance: projection.provenance,
            disposition: EvidenceDisposition::ProviderEvidenceOnly,
            kernel_authoritative: false,
            adopted_work_product: false,
        })
    }

    fn validate_proposal(&self, proposal: &QueryProposal) -> Result<(), ProviderError> {
        if !self.mounted || self.registration.revoked {
            return Err(ProviderError::RegistrationRevoked);
        }
        if proposal.scope != self.registration.scope
            || proposal.scope_digest != self.registration.scope.digest()
            || proposal.registration_digest != *self.registration.digest()
            || proposal.plugin_version != self.registration.plugin_version
            || proposal.contract_digest != self.registration.contract_digest
            || proposal.provider_revision != self.registration.provider_revision
            || !self.registration.allowed_templates.is_empty()
                && !self
                    .registration
                    .allowed_templates
                    .contains_key(&proposal.template_digest)
            || proposal.parameters_digest
                != parameters_digest(&proposal.parameters)
                    .map_err(|_| ProviderError::BindingMismatch)?
            || proposal.request_id != expected_request_id(proposal)
            || proposal.proposal_digest != expected_proposal_digest(proposal)
        {
            return Err(ProviderError::BindingMismatch);
        }
        Ok(())
    }

    fn observe_mission_revision(&mut self, proposal: &QueryProposal) -> Result<(), ProviderError> {
        let key = proposal.registration_digest.clone();
        if self
            .last_mission_revision
            .get(&key)
            .is_some_and(|last| proposal.mission_revision < *last)
        {
            return Err(ProviderError::StaleMissionRevision);
        }
        self.last_mission_revision
            .entry(key)
            .and_modify(|last| *last = (*last).max(proposal.mission_revision))
            .or_insert(proposal.mission_revision);
        Ok(())
    }

    fn classify_submit_response(
        proposal: &QueryProposal,
        response: SubmitResponse,
    ) -> Result<SubmissionState, ProviderError> {
        if response.request_id != proposal.request_id {
            return Err(ProviderError::MalformedResponse);
        }
        match response.http_status {
            202 => Ok(SubmissionState::Accepted {
                request_id: proposal.request_id.clone(),
                statement_handle: response
                    .statement_handle
                    .ok_or(ProviderError::MalformedResponse)?,
                provider_request_id: response.provider_request_id,
                retry_after_ms: response.retry_after_ms,
                reconciled: false,
            }),
            429 => Ok(SubmissionState::Throttled {
                request_id: proposal.request_id.clone(),
                retry_after_ms: response.retry_after_ms,
            }),
            422 => Ok(SubmissionState::TerminalFailure {
                request_id: proposal.request_id.clone(),
                detail_digest: response.detail_digest,
            }),
            _ => Err(ProviderError::MalformedResponse),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowflakeProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub provenance: TransportProvenance,
}

impl SnowflakeOutcomeService {
    /// Constructs the provider using only a closed Layer-1 transport.
    pub fn provider<T: SnowflakeSqlApiTransport>(
        &self,
        registration: SnowflakeOutcomeRegistration,
        transport: T,
    ) -> Result<SnowflakeSqlApiProvider<T>, ProviderError> {
        SnowflakeSqlApiProvider::new(registration, transport)
    }

    #[must_use]
    pub const fn consumer(&self) -> MissionSnowflakeOutcomeConsumer {
        MissionSnowflakeOutcomeConsumer
    }
}

/// Append-only model of the durable log boundary required before evidence can
/// be marked model-visible. It is deliberately not a kernel event spine.
#[derive(Debug, Default)]
pub struct DurableEvidenceLog {
    entries: BTreeMap<Digest, DurableEvidenceReceipt>,
    next_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableEvidenceReceipt {
    pub evidence_digest: Digest,
    pub log_sequence: u64,
    pub log_digest: Digest,
}

impl DurableEvidenceLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records only evidence identity and digest metadata, never full rows.
    pub fn append(&mut self, verification: &ResultVerification) -> DurableEvidenceReceipt {
        if let Some(existing) = self.entries.get(&verification.result_digest) {
            return existing.clone();
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        let log_digest = Digest::from_parts(
            "snowflake-model-evidence-log/v1",
            &[
                ("result_digest", verification.result_digest.to_string()),
                ("request_id", verification.request_id.to_string()),
                ("schema_digest", verification.schema_digest.to_string()),
                ("log_sequence", self.next_sequence.to_string()),
            ],
        );
        let receipt = DurableEvidenceReceipt {
            evidence_digest: verification.result_digest.clone(),
            log_sequence: self.next_sequence,
            log_digest,
        };
        self.entries
            .insert(verification.result_digest.clone(), receipt.clone());
        receipt
    }

    #[must_use]
    pub fn contains(&self, evidence_digest: &Digest) -> bool {
        self.entries.contains_key(evidence_digest)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("provider verification is not provider-evidence-only")]
    WrongAuthority,
    #[error("consumer evidence does not match the exact projection")]
    ProjectionMismatch,
    #[error("evidence was not durably logged")]
    NotDurablyLogged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowflakeConsumerDefinition {
    pub id: String,
    pub service_id: String,
    pub authority: EvidenceDisposition,
}

/// Mission consumer that proposes provider evidence after a durable log
/// receipt exists. It has no adopt or kernel-authority method.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MissionSnowflakeOutcomeConsumer;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OutcomeEvidenceProposal {
    pub schema: String,
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
    pub request_id: RequestId,
    pub statement_handle: StatementHandle,
    pub provider_request_id: Option<String>,
    pub scope_digest: Digest,
    pub schema_digest: Digest,
    pub result_digest: Digest,
    pub partition_count: usize,
    pub row_count: u64,
    pub byte_count: u64,
    pub completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub disposition: EvidenceDisposition,
    pub model_visible: bool,
    pub durable_log_digest: Digest,
    pub kernel_authoritative: bool,
    pub adopted_work_product: bool,
    pub native: bool,
    pub first_party: bool,
}

impl MissionSnowflakeOutcomeConsumer {
    #[must_use]
    pub fn definition(&self) -> SnowflakeConsumerDefinition {
        SnowflakeConsumerDefinition {
            id: CONSUMER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            authority: EvidenceDisposition::ProviderEvidenceOnly,
        }
    }

    pub fn propose_outcome_evidence(
        &self,
        proposal: &QueryProposal,
        projection: &WarehouseResultProjection,
        verification: &ResultVerification,
        log_receipt: &DurableEvidenceReceipt,
        log: &DurableEvidenceLog,
    ) -> Result<OutcomeEvidenceProposal, ConsumerError> {
        if verification.disposition != EvidenceDisposition::ProviderEvidenceOnly
            || verification.kernel_authoritative
            || verification.adopted_work_product
        {
            return Err(ConsumerError::WrongAuthority);
        }
        if verification.request_id != proposal.request_id
            || verification.result_digest != projection.result_digest
            || verification.result_digest != log_receipt.evidence_digest
            || !log.contains(&log_receipt.evidence_digest)
            || projection.native
            || projection.first_party
            || projection.provenance.is_native()
            || projection.provenance.is_connected()
            || projection.provenance.is_first_party()
        {
            return Err(ConsumerError::ProjectionMismatch);
        }
        Ok(OutcomeEvidenceProposal {
            schema: "hartevo.snowflake-outcome-evidence-proposal/v1".to_owned(),
            project_id: proposal.scope.project_id.clone(),
            mission_id: proposal.scope.mission_id.clone(),
            mission_revision: proposal.mission_revision,
            request_id: proposal.request_id.clone(),
            statement_handle: projection.statement_handle.clone(),
            provider_request_id: projection.provider_request_id.clone(),
            scope_digest: proposal.scope_digest.clone(),
            schema_digest: projection.schema_digest.clone(),
            result_digest: projection.result_digest.clone(),
            partition_count: projection.partitions.len(),
            row_count: projection.row_count,
            byte_count: projection.byte_count,
            completeness: projection.completeness,
            provenance: projection.provenance,
            disposition: EvidenceDisposition::ProviderEvidenceOnly,
            model_visible: true,
            durable_log_digest: log_receipt.log_digest.clone(),
            kernel_authoritative: false,
            adopted_work_product: false,
            native: false,
            first_party: false,
        })
    }

    /// Short alias for callers that use the issue's consumer verb.
    pub fn consume(
        &self,
        proposal: &QueryProposal,
        projection: &WarehouseResultProjection,
        verification: &ResultVerification,
        log_receipt: &DurableEvidenceReceipt,
        log: &DurableEvidenceLog,
    ) -> Result<OutcomeEvidenceProposal, ConsumerError> {
        self.propose_outcome_evidence(proposal, projection, verification, log_receipt, log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> SnowflakeScope {
        SnowflakeScope::new(
            "org",
            "account",
            "https://account.snowflakecomputing.com",
            "DB",
            "SCHEMA",
            "WH",
            "ANALYST",
            "project-1",
            "mission-1",
        )
        .expect("scope")
    }

    fn template(sql: &str) -> QueryTemplate {
        QueryTemplate::new(
            "bounded-orders",
            sql,
            vec![ParameterSpec::new("customer_id", SnowflakeType::Integer).expect("parameter")],
            ResultBounds::new(10, 4_096, 4, 10, 2_048).expect("bounds"),
        )
        .expect("template")
    }

    fn registration(template: QueryTemplate) -> SnowflakeOutcomeRegistration {
        SnowflakeOutcomeRegistration::new(
            scope(),
            SecretReference::oauth("host-secret-reference", 1).expect("secret reference"),
            1,
            vec![template],
        )
        .expect("registration")
    }

    fn proposal() -> (SnowflakeOutcomeRegistration, QueryProposal) {
        let template =
            template("select id, total from orders where customer_id = :customer_id limit 2");
        let registration = registration(template.clone());
        let proposal = SnowflakeOutcomeService::new()
            .compile_query_proposal(
                &registration,
                7,
                &template,
                &[
                    BoundParameter::new("customer_id", SnowflakeValue::Integer(42))
                        .expect("binding"),
                ],
            )
            .expect("proposal");
        (registration, proposal)
    }

    #[test]
    fn secret_reference_never_serializes_or_debugs_its_handle() {
        let secret =
            SecretReference::oauth("very-sensitive-token-looking-handle", 9).expect("secret");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("very-sensitive-token-looking-handle"));
        let registration = registration(template(
            "select id from orders where customer_id = :customer_id limit 1",
        ));
        let serialized = serde_json::to_string(&registration).expect("registration serialization");
        assert!(!serialized.contains("very-sensitive"));
        assert!(!serialized.contains("secret_reference"));
    }

    #[test]
    fn canonical_query_is_stable_and_request_is_scope_bound() {
        let first = proposal().1;
        let template =
            template(" SELECT  id,total\nFROM orders WHERE customer_id=:customer_id LIMIT 2 ");
        let registration = registration(template.clone());
        let second = SnowflakeOutcomeService::new()
            .compile_query_proposal(
                &registration,
                7,
                &template,
                &[
                    BoundParameter::new("customer_id", SnowflakeValue::Integer(42))
                        .expect("binding"),
                ],
            )
            .expect("proposal");
        assert_eq!(first.canonical_sql, second.canonical_sql);
        assert_eq!(first.parameters_digest, second.parameters_digest);
        assert_eq!(first.request_id, second.request_id);
    }

    #[test]
    fn query_allowlist_rejects_mutation_comments_multiple_statements_and_identifiers() {
        for sql in [
            "select id from orders -- hidden mutation\n limit 1",
            "select id from orders; delete from orders limit 1",
            "update orders set total = 1 limit 1",
            "select id from identifier(:customer_id) limit 1",
            "select id from :customer_id limit 1",
            "select id from orders where customer_id = :customer_id",
            "select id from orders where customer_id = :customer_id limit :customer_id",
        ] {
            let template = template(sql);
            let registration = registration(template.clone());
            let error = SnowflakeOutcomeService::new()
                .compile_query_proposal(
                    &registration,
                    1,
                    &template,
                    &[
                        BoundParameter::new("customer_id", SnowflakeValue::Integer(1))
                            .expect("binding"),
                    ],
                )
                .expect_err("query must be rejected");
            assert!(matches!(error, SnowflakeOutcomeError::QueryRejected(_)));
        }
    }

    #[test]
    fn typed_parameter_mismatch_is_rejected() {
        let template =
            template("select id, total from orders where customer_id = :customer_id limit 2");
        let registration = registration(template.clone());
        let error = SnowflakeOutcomeService::new()
            .compile_query_proposal(
                &registration,
                1,
                &template,
                &[
                    BoundParameter::new("customer_id", SnowflakeValue::Text("42".to_owned()))
                        .expect("binding"),
                ],
            )
            .expect_err("type mismatch");
        assert_eq!(error, SnowflakeOutcomeError::ParameterTypeMismatch);
    }

    #[test]
    fn recording_state_machine_models_202_429_422_and_ambiguous_replay() {
        let (registration, proposal) = proposal();
        let handle = StatementHandle::new("statement-1").expect("handle");
        let mut transport = RecordingTransport::new();
        transport.push_submit_error(TransportError::AmbiguousSubmission);
        transport.push_reconciliation_response(ReconciliationResponse::Accepted(
            SubmitResponse::accepted_202(
                proposal.request_id.clone(),
                handle.clone(),
                Some("req-1".to_owned()),
                None,
            ),
        ));
        transport.push_poll_response(PollResponse::throttled_429(
            proposal.request_id.clone(),
            handle.clone(),
            proposal.scope_digest.clone(),
            Some(250),
        ));
        let mut provider =
            SnowflakeSqlApiProvider::new(registration.clone(), transport).expect("provider");
        assert!(
            provider
                .submit_query(&proposal)
                .expect("submit")
                .is_ambiguous()
        );
        let reconciled = provider
            .reconcile_ambiguous_submission(&proposal)
            .expect("reconcile");
        assert!(matches!(
            reconciled,
            SubmissionState::Accepted {
                reconciled: true,
                ..
            }
        ));
        let polled = provider.poll_statement(&proposal, &handle).expect("poll");
        assert!(matches!(
            polled,
            PollState::Throttled {
                retry_after_ms: Some(250),
                ..
            }
        ));

        let mut terminal_transport = RecordingTransport::new();
        terminal_transport.push_submit_response(SubmitResponse::terminal_422(
            proposal.request_id.clone(),
            "invalid statement",
        ));
        let mut terminal_provider = SnowflakeSqlApiProvider::new(
            proposal_registration(&proposal, &registration),
            terminal_transport,
        )
        .expect("provider");
        let terminal = terminal_provider.submit_query(&proposal).expect("terminal");
        assert!(matches!(terminal, SubmissionState::TerminalFailure { .. }));
    }

    #[test]
    fn throttled_submission_can_retry_but_accepted_submission_cannot_replay() {
        let (registration, proposal) = proposal();
        let handle = StatementHandle::new("statement-retry").expect("handle");
        let mut transport = RecordingTransport::new();
        transport.push_submit_response(SubmitResponse::throttled_429(
            proposal.request_id.clone(),
            Some(100),
        ));
        transport.push_submit_response(SubmitResponse::accepted_202(
            proposal.request_id.clone(),
            handle,
            Some("provider-retry".to_owned()),
            None,
        ));
        let mut provider = SnowflakeSqlApiProvider::new(registration, transport).expect("provider");
        assert!(matches!(
            provider.submit_query(&proposal).expect("throttle"),
            SubmissionState::Throttled { .. }
        ));
        assert!(matches!(
            provider.submit_query(&proposal).expect("retry"),
            SubmissionState::Accepted { .. }
        ));
        assert!(matches!(
            provider.submit_query(&proposal).expect("idempotent replay"),
            SubmissionState::Accepted { .. }
        ));
        assert_eq!(provider.transport().submitted_requests().len(), 2);
    }

    #[test]
    fn polling_models_202_continuation_and_complete_statement_receipt() {
        let (registration, proposal) = proposal();
        let handle = StatementHandle::new("statement-poll").expect("handle");
        let schema = ResultSchema::new(vec![
            ColumnSchema::new("ID", SnowflakeType::Integer, false, 0).expect("column"),
        ])
        .expect("schema");
        let mut transport = RecordingTransport::new();
        transport.push_submit_response(SubmitResponse::accepted_202(
            proposal.request_id.clone(),
            handle.clone(),
            Some("submit-request".to_owned()),
            None,
        ));
        transport.push_poll_response(PollResponse::running_202(
            proposal.request_id.clone(),
            handle.clone(),
            proposal.scope_digest.clone(),
            QueryStatus::Running,
            Some(50),
        ));
        transport.push_poll_response(PollResponse::complete_200(
            proposal.request_id.clone(),
            handle.clone(),
            proposal.scope_digest.clone(),
            schema,
            1,
            false,
            Some("poll-request".to_owned()),
        ));
        let mut provider = SnowflakeSqlApiProvider::new(registration, transport).expect("provider");
        assert!(matches!(
            provider.submit_query(&proposal).expect("submit"),
            SubmissionState::Accepted { .. }
        ));
        assert!(matches!(
            provider
                .poll_statement(&proposal, &handle)
                .expect("running"),
            PollState::Running {
                status: QueryStatus::Running,
                ..
            }
        ));
        let PollState::Complete(receipt) = provider
            .poll_statement(&proposal, &handle)
            .expect("complete")
        else {
            panic!("expected complete receipt");
        };
        assert_eq!(receipt.provider_request_id.as_deref(), Some("poll-request"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn partition_adversaries_and_stale_mission_revision_fail_closed() {
        let (registration, proposal) = proposal();
        let handle = StatementHandle::new("statement-adversarial").expect("handle");
        let schema = ResultSchema::new(vec![
            ColumnSchema::new("ID", SnowflakeType::Integer, false, 0).expect("column"),
        ])
        .expect("schema");
        let completion = StatementCompletion {
            request_id: proposal.request_id.clone(),
            statement_handle: handle.clone(),
            scope_digest: proposal.scope_digest.clone(),
            schema: schema.clone(),
            expected_partition_count: 2,
            truncated: false,
            provider_request_id: None,
        };
        let partition = PartitionData::new(0, vec![vec![SnowflakeValue::Integer(1)]]);
        let page = |partitions| {
            PartitionPageResponse::ok(
                proposal.request_id.clone(),
                handle.clone(),
                proposal.scope_digest.clone(),
                schema.digest().clone(),
                2,
                partitions,
                None,
                None,
            )
        };
        assert_eq!(
            WarehouseResultProjection::build(
                &proposal,
                &completion,
                &[page(vec![partition.clone()])],
                TransportProvenance::Fake
            )
            .expect_err("omitted partition"),
            ProjectionError::PartitionIncomplete
        );
        assert_eq!(
            WarehouseResultProjection::build(
                &proposal,
                &completion,
                &[page(vec![partition.clone(), partition.clone()])],
                TransportProvenance::Fake,
            )
            .expect_err("duplicate partition"),
            ProjectionError::PartitionDuplicateOrOmitted
        );
        let mut wrong_metadata = partition.metadata().clone();
        wrong_metadata.content_digest = Digest::from_bytes(b"tampered");
        assert_eq!(
            WarehouseResultProjection::build(
                &proposal,
                &StatementCompletion {
                    expected_partition_count: 1,
                    ..completion.clone()
                },
                &[page(vec![PartitionData::with_metadata(
                    wrong_metadata,
                    vec![vec![SnowflakeValue::Integer(1)]],
                )])],
                TransportProvenance::Fake,
            )
            .expect_err("tampered digest"),
            ProjectionError::PartitionDigestMismatch
        );

        let template =
            template("select id, total from orders where customer_id = :customer_id limit 2");
        let old = SnowflakeOutcomeService::new()
            .compile_query_proposal(
                &registration,
                1,
                &template,
                &[
                    BoundParameter::new("customer_id", SnowflakeValue::Integer(1))
                        .expect("binding"),
                ],
            )
            .expect("old proposal");
        let current = SnowflakeOutcomeService::new()
            .compile_query_proposal(
                &registration,
                2,
                &template,
                &[
                    BoundParameter::new("customer_id", SnowflakeValue::Integer(1))
                        .expect("binding"),
                ],
            )
            .expect("current proposal");
        let current_handle = StatementHandle::new("statement-current").expect("handle");
        let mut transport = RecordingTransport::new();
        transport.push_submit_response(SubmitResponse::accepted_202(
            current.request_id.clone(),
            current_handle,
            None,
            None,
        ));
        let mut provider = SnowflakeSqlApiProvider::new(registration, transport).expect("provider");
        provider.submit_query(&current).expect("current submit");
        assert_eq!(
            provider.submit_query(&old).expect_err("stale mission"),
            ProviderError::StaleMissionRevision
        );
    }

    fn proposal_registration(
        _proposal: &QueryProposal,
        registration: &SnowflakeOutcomeRegistration,
    ) -> SnowflakeOutcomeRegistration {
        registration.clone()
    }

    #[test]
    fn partition_order_completeness_schema_and_digest_are_verified() {
        let (registration, proposal) = proposal();
        let handle = StatementHandle::new("statement-2").expect("handle");
        let schema = ResultSchema::new(vec![
            ColumnSchema::new("ID", SnowflakeType::Integer, false, 0).expect("column"),
            ColumnSchema::new("TOTAL", SnowflakeType::Decimal, false, 1).expect("column"),
        ])
        .expect("schema");
        let partition_zero = PartitionData::new(
            0,
            vec![vec![
                SnowflakeValue::Integer(1),
                SnowflakeValue::Decimal("2.5".to_owned()),
            ]],
        );
        let partition_one = PartitionData::new(
            1,
            vec![vec![
                SnowflakeValue::Integer(2),
                SnowflakeValue::Decimal("3.5".to_owned()),
            ]],
        );
        let completion = StatementCompletion {
            request_id: proposal.request_id.clone(),
            statement_handle: handle.clone(),
            scope_digest: proposal.scope_digest.clone(),
            schema: schema.clone(),
            expected_partition_count: 2,
            truncated: false,
            provider_request_id: Some("provider-1".to_owned()),
        };
        let mut transport = RecordingTransport::new();
        transport.push_partition_response(PartitionPageResponse::ok(
            proposal.request_id.clone(),
            handle.clone(),
            proposal.scope_digest.clone(),
            schema.digest().clone(),
            2,
            vec![partition_one, partition_zero],
            None,
            Some("provider-1".to_owned()),
        ));
        let mut provider = SnowflakeSqlApiProvider::new(registration, transport).expect("provider");
        let projection = provider
            .read_partitions(&proposal, &completion)
            .expect("projection");
        assert_eq!(
            projection
                .partitions
                .iter()
                .map(|item| item.index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(projection.row_count, 2);
        let verification = provider
            .verify_result_projection(&proposal, &projection)
            .expect("verification");
        assert_eq!(
            verification.disposition,
            EvidenceDisposition::ProviderEvidenceOnly
        );
        assert!(!verification.kernel_authoritative);
    }

    #[test]
    fn scope_schema_drift_revocation_and_blocked_env_fail_closed() {
        let (mut registration, mut proposal) = proposal();
        let mut provider = SnowflakeSqlApiProvider::new(registration.clone(), BlockedEnvTransport)
            .expect("provider");
        let blocked = provider.submit_query(&proposal).expect("blocked state");
        assert!(matches!(blocked, SubmissionState::BlockedEnv { .. }));
        registration.revoke();
        let mut revoked_provider =
            SnowflakeSqlApiProvider::new(registration, RecordingTransport::new())
                .expect("provider");
        let error = revoked_provider
            .submit_query(&proposal)
            .expect_err("revoked");
        assert_eq!(error, ProviderError::RegistrationRevoked);
        proposal.scope = scope();
        proposal.scope.database = "DRIFTED".to_owned();
        let error = provider.verify_result_projection(
            &proposal,
            &WarehouseResultProjection {
                schema: ResultSchema::new(Vec::new()).expect("empty schema"),
                schema_digest: Digest::from_bytes(b"schema"),
                request_id: proposal.request_id.clone(),
                statement_handle: StatementHandle::new("h").expect("handle"),
                scope_digest: proposal.scope_digest.clone(),
                provider_request_id: None,
                partitions: Vec::new(),
                rows: Vec::new(),
                row_count: 0,
                byte_count: 0,
                result_digest: Digest::from_bytes(b"result"),
                completeness: ProjectionCompleteness::Complete,
                bounds: proposal.bounds,
                provenance: TransportProvenance::Recording,
                native: false,
                first_party: false,
            },
        );
        assert!(error.is_err());
    }

    #[test]
    fn durable_log_is_required_for_model_visible_consumer_evidence() {
        let (registration, proposal) = proposal();
        let handle = StatementHandle::new("statement-3").expect("handle");
        let schema = ResultSchema::new(vec![
            ColumnSchema::new("ID", SnowflakeType::Integer, false, 0).expect("column"),
        ])
        .expect("schema");
        let completion = StatementCompletion {
            request_id: proposal.request_id.clone(),
            statement_handle: handle.clone(),
            scope_digest: proposal.scope_digest.clone(),
            schema: schema.clone(),
            expected_partition_count: 1,
            truncated: false,
            provider_request_id: None,
        };
        let mut transport = RecordingTransport::new();
        transport.push_partition_response(PartitionPageResponse::ok(
            proposal.request_id.clone(),
            handle,
            proposal.scope_digest.clone(),
            schema.digest().clone(),
            1,
            vec![PartitionData::new(
                0,
                vec![vec![SnowflakeValue::Integer(1)]],
            )],
            None,
            None,
        ));
        let mut provider = SnowflakeSqlApiProvider::new(registration, transport).expect("provider");
        let projection = provider
            .read_partitions(&proposal, &completion)
            .expect("projection");
        let verification = provider
            .verify_result_projection(&proposal, &projection)
            .expect("verify");
        let mut log = DurableEvidenceLog::new();
        let receipt = log.append(&verification);
        let evidence = SnowflakeOutcomeService::new()
            .consumer()
            .consume(&proposal, &projection, &verification, &receipt, &log)
            .expect("consumer evidence");
        assert!(evidence.model_visible);
        assert!(!evidence.kernel_authoritative);
        assert!(!evidence.adopted_work_product);
        assert!(!evidence.native);
    }
}

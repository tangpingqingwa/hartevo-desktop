use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ClickHouseScope, Digest, ModelError, QueryMode, ResultBounds, Revision, SecretReference,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryParameterType {
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
    Bool,
    Date,
    DateTime,
    Uuid,
}

impl QueryParameterType {
    pub(crate) fn from_clickhouse_name(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "string" => Some(Self::String),
            "uint8" => Some(Self::UInt8),
            "uint16" => Some(Self::UInt16),
            "uint32" => Some(Self::UInt32),
            "uint64" => Some(Self::UInt64),
            "int8" => Some(Self::Int8),
            "int16" => Some(Self::Int16),
            "int32" => Some(Self::Int32),
            "int64" => Some(Self::Int64),
            "float32" => Some(Self::Float32),
            "float64" => Some(Self::Float64),
            "decimal" | "decimal32" | "decimal64" | "decimal128" | "decimal256" => {
                Some(Self::Decimal)
            }
            "bool" | "boolean" => Some(Self::Bool),
            "date" => Some(Self::Date),
            "datetime" | "datetime64" => Some(Self::DateTime),
            "uuid" => Some(Self::Uuid),
            _ => None,
        }
    }

    pub(crate) fn clickhouse_name(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::UInt8 => "UInt8",
            Self::UInt16 => "UInt16",
            Self::UInt32 => "UInt32",
            Self::UInt64 => "UInt64",
            Self::Int8 => "Int8",
            Self::Int16 => "Int16",
            Self::Int32 => "Int32",
            Self::Int64 => "Int64",
            Self::Float32 => "Float32",
            Self::Float64 => "Float64",
            Self::Decimal => "Decimal64",
            Self::Bool => "Bool",
            Self::Date => "Date",
            Self::DateTime => "DateTime",
            Self::Uuid => "UUID",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryParameter {
    pub name: String,
    pub parameter_type: QueryParameterType,
    pub value_digest: Digest,
}

impl QueryParameter {
    pub fn new(
        name: impl Into<String>,
        parameter_type: QueryParameterType,
        value_digest: Digest,
    ) -> Result<Self, QueryCompileError> {
        let name = name.into();
        if !valid_parameter_name(&name) {
            return Err(QueryCompileError::InvalidParameterName);
        }
        Ok(Self {
            name: name.to_ascii_lowercase(),
            parameter_type,
            value_digest,
        })
    }

    /// Hashes a caller-owned value immediately. The value is type-checked and
    /// never retained in the proposal, request, Debug output, or evidence.
    pub fn from_public_value(
        name: impl Into<String>,
        parameter_type: QueryParameterType,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, QueryCompileError> {
        let bytes = value.as_ref();
        validate_parameter_value(parameter_type, bytes)?;
        Self::new(name, parameter_type, Digest::from_text(bytes))
    }

    pub fn parameter_type(&self) -> QueryParameterType {
        self.parameter_type
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryCompileError {
    #[error("query is empty or exceeds the Layer-1 size bound")]
    EmptyOrTooLarge,
    #[error("query has an unterminated comment, string, quoted identifier, or parameter")]
    UnterminatedToken,
    #[error("query contains more than one statement")]
    MultiStatement,
    #[error("query is not an allowlisted SELECT or EXPLAIN SELECT")]
    NotSelect,
    #[error("query contains a forbidden {operation} operation")]
    ForbiddenOperation { operation: &'static str },
    #[error("query must contain at least one typed ClickHouse parameter")]
    MissingParameter,
    #[error("query uses a positional parameter; named ClickHouse parameters are required")]
    PositionalParameter,
    #[error("query references a parameter that was not bound")]
    UnboundParameter,
    #[error("query contains a parameter binding that is not referenced")]
    ExtraParameter,
    #[error("parameter name is invalid")]
    InvalidParameterName,
    #[error("parameter value does not match its declared ClickHouse type")]
    ParameterTypeMismatch,
    #[error("ClickHouse parameter type declaration is unsupported")]
    UnsupportedParameterType,
    #[error("query must contain a numeric LIMIT")]
    UnboundedRead,
    #[error("query LIMIT exceeds the requested row bound")]
    LimitExceedsBound,
    #[error("query uses a parameterized LIMIT; Layer 1 cannot prove its bound")]
    ParameterizedLimitUnsupported,
    #[error("query must contain an explicit stable ORDER BY tie-breaker")]
    StableOrderingRequired,
    #[error("query has no fully-qualified database.table reference")]
    UnqualifiedTable,
    #[error("query references a table outside the governed scope")]
    TableOutOfScope,
    #[error("query contains an unsupported table expression")]
    UnsupportedTableExpression,
    #[error("query request revision does not match the Work Product scope")]
    RevisionMismatch,
    #[error("query scope is invalid")]
    InvalidScope,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClickHouseQueryKind {
    Select,
    ExplainSelect,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ParameterizedSelect {
    canonical_query: String,
    kind: ClickHouseQueryKind,
    compiled_bounds: ResultBounds,
    parameters: BTreeMap<String, QueryParameter>,
    query_digest: Digest,
    referenced_tables: BTreeSet<QualifiedTable>,
    stable_ordering: bool,
}

pub type ClickHouseQuery = ParameterizedSelect;

impl fmt::Debug for ParameterizedSelect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParameterizedSelect")
            .field("query_digest", &self.query_digest)
            .field("kind", &self.kind)
            .field(
                "parameter_names",
                &self.parameters.keys().collect::<Vec<_>>(),
            )
            .field("referenced_tables", &self.referenced_tables)
            .field("stable_ordering", &self.stable_ordering)
            .finish_non_exhaustive()
    }
}

impl ParameterizedSelect {
    pub fn compile(
        scope: &ClickHouseScope,
        query: impl Into<String>,
        parameters: impl IntoIterator<Item = QueryParameter>,
        bounds: ResultBounds,
    ) -> Result<Self, QueryCompileError> {
        let query_text = query.into();
        if query_text.is_empty() || query_text.len() > super::model::MAX_QUERY_BYTES {
            return Err(QueryCompileError::EmptyOrTooLarge);
        }
        let tokens = lex(&query_text)?;
        let mut statement_tokens = tokens;
        if statement_tokens
            .last()
            .is_some_and(|token| matches!(token, Token::Symbol(';')))
        {
            statement_tokens.pop();
        }
        if statement_tokens
            .iter()
            .any(|token| matches!(token, Token::Symbol(';')))
        {
            return Err(QueryCompileError::MultiStatement);
        }
        let (kind, body_start) = match statement_tokens.as_slice() {
            [Token::Word(root), Token::Word(select), ..]
                if root == "explain" && select == "select" =>
            {
                (ClickHouseQueryKind::ExplainSelect, 2)
            }
            [Token::Word(root), ..] if root == "select" => (ClickHouseQueryKind::Select, 1),
            _ => return Err(QueryCompileError::NotSelect),
        };
        if body_start > statement_tokens.len() {
            return Err(QueryCompileError::NotSelect);
        }
        reject_forbidden_operations(&statement_tokens)?;

        let mut parameter_map = BTreeMap::new();
        for parameter in parameters {
            if parameter_map
                .insert(parameter.name.clone(), parameter)
                .is_some()
            {
                return Err(QueryCompileError::ExtraParameter);
            }
        }
        let mut used_parameters = BTreeSet::new();
        for token in &statement_tokens {
            if let Token::Parameter(name, declared_type) = token {
                let Some(declared_type) = QueryParameterType::from_clickhouse_name(declared_type)
                else {
                    return Err(QueryCompileError::UnsupportedParameterType);
                };
                let Some(bound) = parameter_map.get(name) else {
                    return Err(QueryCompileError::UnboundParameter);
                };
                if bound.parameter_type != declared_type {
                    return Err(QueryCompileError::ParameterTypeMismatch);
                }
                used_parameters.insert(name.clone());
            }
        }
        if used_parameters.is_empty() {
            return Err(QueryCompileError::MissingParameter);
        }
        if parameter_map
            .keys()
            .any(|name| !used_parameters.contains(name))
        {
            return Err(QueryCompileError::ExtraParameter);
        }

        validate_limit(&statement_tokens, &parameter_map, bounds)?;
        let stable_ordering = validate_stable_ordering(&statement_tokens)?;
        let referenced_tables = extract_tables(&statement_tokens)?;
        if referenced_tables.is_empty() {
            return Err(QueryCompileError::UnqualifiedTable);
        }
        if referenced_tables
            .iter()
            .any(|table| !scope.contains_table(&table.database, &table.table))
        {
            return Err(QueryCompileError::TableOutOfScope);
        }

        let canonical_query = statement_tokens
            .iter()
            .map(Token::canonical)
            .collect::<Vec<_>>()
            .join(" ");
        let parameter_digest_fields = parameter_map
            .values()
            .flat_map(|parameter| {
                [
                    parameter.name.clone(),
                    parameter.parameter_type.clickhouse_name().to_owned(),
                    parameter.value_digest.as_str().to_owned(),
                ]
            })
            .collect::<Vec<_>>();
        let mut query_digest_fields = vec![canonical_query.clone()];
        query_digest_fields.extend(parameter_digest_fields);
        let query_digest = Digest::from_fields("clickhouse-query/v1", &query_digest_fields);
        Ok(Self {
            canonical_query,
            kind,
            compiled_bounds: bounds,
            parameters: parameter_map,
            query_digest,
            referenced_tables,
            stable_ordering,
        })
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn parameter_names(&self) -> impl Iterator<Item = &str> {
        self.parameters.keys().map(String::as_str)
    }

    pub fn referenced_table_count(&self) -> usize {
        self.referenced_tables.len()
    }

    pub const fn kind(&self) -> ClickHouseQueryKind {
        self.kind
    }

    pub const fn has_stable_ordering(&self) -> bool {
        self.stable_ordering
    }

    pub fn canonical_query_digest(&self) -> Digest {
        Digest::from_fields(
            "clickhouse-query-canonical/v1",
            std::slice::from_ref(&self.canonical_query),
        )
    }

    pub(crate) const fn compiled_bounds(&self) -> ResultBounds {
        self.compiled_bounds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryProposalRequest {
    pub query: ParameterizedSelect,
    pub bounds: ResultBounds,
    pub mode: QueryMode,
    pub work_product_revision: Revision,
}

impl QueryProposalRequest {
    pub fn new(
        query: ParameterizedSelect,
        bounds: ResultBounds,
        mode: QueryMode,
        work_product_revision: Revision,
    ) -> Self {
        Self {
            query,
            bounds,
            mode,
            work_product_revision,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClickHouseQueryProposal {
    pub(crate) query: ParameterizedSelect,
    scope_digest: Digest,
    query_digest: Digest,
    config_digest: Digest,
    bounds: ResultBounds,
    mode: QueryMode,
    work_product_revision: Revision,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
}

impl fmt::Debug for ClickHouseQueryProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClickHouseQueryProposal")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("config_digest", &self.config_digest)
            .field("bounds", &self.bounds)
            .field("mode", &self.mode)
            .field("work_product_revision", &self.work_product_revision)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl ClickHouseQueryProposal {
    pub(crate) fn compile(
        scope: &ClickHouseScope,
        secret: &SecretReference,
        request: QueryProposalRequest,
    ) -> Result<Self, QueryCompileError> {
        if request.work_product_revision != scope.work_product_revision() {
            return Err(QueryCompileError::RevisionMismatch);
        }
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(QueryCompileError::InvalidScope);
        }
        if request.bounds != request.query.compiled_bounds() {
            return Err(QueryCompileError::InvalidScope);
        }
        let query_digest = request.query.query_digest().clone();
        let config_digest = Digest::from_fields(
            "clickhouse-query-config/v1",
            &[
                scope.https_host().as_str().to_owned(),
                scope.cluster().to_owned(),
                scope.database().as_str().to_owned(),
                scope.table().as_str().to_owned(),
                scope.schema().as_str().to_owned(),
                scope.schema_revision().get().to_string(),
                query_digest.as_str().to_owned(),
                format!("{:?}", request.query.kind()),
                request.bounds.max_rows().to_string(),
                request.bounds.max_bytes().to_string(),
                format!("stable_ordering={}", request.query.has_stable_ordering()),
                format!("mode={:?}", request.mode),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            query: request.query,
            scope_digest: scope.scope_digest(),
            query_digest,
            config_digest,
            bounds: request.bounds,
            mode: request.mode,
            work_product_revision: request.work_product_revision,
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub const fn bounds(&self) -> ResultBounds {
        self.bounds
    }

    pub const fn mode(&self) -> QueryMode {
        self.mode
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn query_kind(&self) -> ClickHouseQueryKind {
        self.query.kind()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct QualifiedTable {
    database: String,
    table: String,
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

fn validate_parameter_value(
    parameter_type: QueryParameterType,
    bytes: &[u8],
) -> Result<(), QueryCompileError> {
    let value = std::str::from_utf8(bytes).map_err(|_| QueryCompileError::ParameterTypeMismatch)?;
    let valid = match parameter_type {
        QueryParameterType::String => !value.chars().any(char::is_control),
        QueryParameterType::UInt8 => value.parse::<u8>().is_ok(),
        QueryParameterType::UInt16 => value.parse::<u16>().is_ok(),
        QueryParameterType::UInt32 => value.parse::<u32>().is_ok(),
        QueryParameterType::UInt64 => value.parse::<u64>().is_ok(),
        QueryParameterType::Int8 => value.parse::<i8>().is_ok(),
        QueryParameterType::Int16 => value.parse::<i16>().is_ok(),
        QueryParameterType::Int32 => value.parse::<i32>().is_ok(),
        QueryParameterType::Int64 => value.parse::<i64>().is_ok(),
        QueryParameterType::Float32 => value.parse::<f32>().is_ok_and(f32::is_finite),
        QueryParameterType::Float64 => value.parse::<f64>().is_ok_and(f64::is_finite),
        QueryParameterType::Decimal => {
            let mut parts = value.split('.');
            let integer = parts.next().is_some_and(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            });
            let fraction = parts.next().is_none_or(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            });
            integer && fraction && parts.next().is_none()
        }
        QueryParameterType::Bool => matches!(value.to_ascii_lowercase().as_str(), "true" | "false"),
        QueryParameterType::Date => valid_date(value),
        QueryParameterType::DateTime => valid_date_time(value),
        QueryParameterType::Uuid => {
            value.len() == 36
                && value.chars().enumerate().all(|(i, c)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        c == '-'
                    } else {
                        c.is_ascii_hexdigit()
                    }
                })
        }
    };
    valid
        .then_some(())
        .ok_or(QueryCompileError::ParameterTypeMismatch)
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u32>().ok();
    let month = value[5..7].parse::<u32>().ok();
    let day = value[8..10].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day)
}

fn valid_date_time(value: &str) -> bool {
    if value.len() < 19
        || !value.get(..10).is_some_and(valid_date)
        || !matches!(value.as_bytes().get(10), Some(b' ' | b'T'))
    {
        return false;
    }
    let Some(time) = value.get(11..19) else {
        return false;
    };
    if time.as_bytes().get(2) != Some(&b':')
        || time.as_bytes().get(5) != Some(&b':')
        || !time
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 2 | 5) || byte.is_ascii_digit())
    {
        return false;
    }
    let hour = time[0..2].parse::<u32>().ok();
    let minute = time[3..5].parse::<u32>().ok();
    let second = time[6..8].parse::<u32>().ok();
    if !matches!((hour, minute, second), (Some(hour), Some(minute), Some(second)) if hour < 24 && minute < 60 && second < 60)
    {
        return false;
    }
    let suffix = &value[19..];
    suffix.is_empty()
        || (suffix.starts_with('.')
            && suffix.len() > 1
            && suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Number(String),
    QuotedIdentifier(String),
    Parameter(String, String),
    StringLiteral(Digest),
    Symbol(char),
}

impl Token {
    fn word(&self) -> Option<&str> {
        match self {
            Self::Word(value) => Some(value.as_str()),
            _ => None,
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Word(value) => value.clone(),
            Self::Number(value) => value.clone(),
            Self::QuotedIdentifier(value) => format!("`{value}`"),
            Self::Parameter(name, parameter_type) => format!("{{{name}:{parameter_type}}}"),
            Self::StringLiteral(digest) => format!("<string:{}>", digest.as_str()),
            Self::Symbol(value) => value.to_string(),
        }
    }
}

fn lex(query: &str) -> Result<Vec<Token>, QueryCompileError> {
    let bytes = query.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'#' => {
                return Err(QueryCompileError::ForbiddenOperation {
                    operation: "comment",
                });
            }
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                return Err(QueryCompileError::ForbiddenOperation {
                    operation: "comment",
                });
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                return Err(QueryCompileError::ForbiddenOperation {
                    operation: "comment",
                });
            }
            b'`' | b'"' => {
                let quote = bytes[index];
                let (value, next) = read_quoted(bytes, index, quote)?;
                tokens.push(Token::QuotedIdentifier(value));
                index = next;
            }
            b'\'' => {
                let (value, next) = read_quoted(bytes, index, b'\'')?;
                tokens.push(Token::StringLiteral(Digest::from_text(value)));
                index = next;
            }
            b'{' => {
                let start = index + 1;
                let Some(offset) = bytes[start..].iter().position(|byte| *byte == b'}') else {
                    return Err(QueryCompileError::UnterminatedToken);
                };
                let end = start + offset;
                let expression = std::str::from_utf8(&bytes[start..end])
                    .map_err(|_| QueryCompileError::UnterminatedToken)?;
                let Some((name, parameter_type)) = expression.split_once(':') else {
                    return Err(QueryCompileError::UnsupportedParameterType);
                };
                if !valid_parameter_name(name) {
                    return Err(QueryCompileError::InvalidParameterName);
                }
                if parameter_type.is_empty()
                    || !parameter_type.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'(' | b')')
                    })
                {
                    return Err(QueryCompileError::UnsupportedParameterType);
                }
                tokens.push(Token::Parameter(
                    name.to_ascii_lowercase(),
                    parameter_type.to_owned(),
                ));
                index = end + 1;
            }
            b'?' => return Err(QueryCompileError::PositionalParameter),
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
                {
                    index += 1;
                }
                tokens.push(Token::Word(
                    String::from_utf8_lossy(&bytes[start..index]).to_ascii_lowercase(),
                ));
            }
            byte if byte.is_ascii_digit() => {
                let start = index;
                index += 1;
                while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.')
                {
                    index += 1;
                }
                tokens.push(Token::Number(
                    String::from_utf8_lossy(&bytes[start..index]).into_owned(),
                ));
            }
            byte => {
                tokens.push(Token::Symbol(byte as char));
                index += 1;
            }
        }
    }
    Ok(tokens)
}

fn read_quoted(
    bytes: &[u8],
    start: usize,
    quote: u8,
) -> Result<(String, usize), QueryCompileError> {
    let mut index = start + 1;
    let value_start = index;
    let mut raw = Vec::new();
    while index < bytes.len() {
        if bytes[index] == quote {
            if bytes.get(index + 1) == Some(&quote) {
                raw.extend_from_slice(&bytes[value_start..index]);
                raw.push(quote);
                index += 2;
                continue;
            }
            raw.extend_from_slice(&bytes[value_start..index]);
            return Ok((String::from_utf8_lossy(&raw).into_owned(), index + 1));
        }
        index += 1;
    }
    Err(QueryCompileError::UnterminatedToken)
}

fn reject_forbidden_operations(tokens: &[Token]) -> Result<(), QueryCompileError> {
    const FORBIDDEN: &[(&str, &str)] = &[
        ("insert", "DML"),
        ("update", "DML"),
        ("delete", "DML"),
        ("merge", "DML"),
        ("create", "DDL"),
        ("alter", "DDL"),
        ("drop", "DDL"),
        ("truncate", "DDL"),
        ("optimize", "mutation"),
        ("mutate", "mutation"),
        ("grant", "DDL"),
        ("revoke", "DDL"),
        ("set", "session mutation"),
        ("use", "session mutation"),
        ("format", "arbitrary output format"),
        ("outfile", "unbounded download"),
        ("into", "mutation or download"),
        ("file", "unbounded download"),
        ("system", "administration"),
        ("union", "unsupported AST"),
        ("intersect", "unsupported AST"),
        ("except", "unsupported AST"),
        ("with", "unsupported AST"),
        ("arrayjoin", "unsupported AST"),
        ("sample", "unsupported AST"),
        ("settings", "session mutation"),
    ];
    for token in tokens {
        if let Some(word) = token.word()
            && let Some((_, operation)) = FORBIDDEN.iter().find(|(candidate, _)| *candidate == word)
        {
            return Err(QueryCompileError::ForbiddenOperation { operation });
        }
    }
    Ok(())
}

fn validate_limit(
    tokens: &[Token],
    parameters: &BTreeMap<String, QueryParameter>,
    bounds: ResultBounds,
) -> Result<(), QueryCompileError> {
    let positions = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (token.word() == Some("limit")).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(QueryCompileError::UnboundedRead);
    }
    match tokens.get(positions[0] + 1) {
        Some(Token::Number(value)) => {
            let value = value
                .parse::<u64>()
                .map_err(|_| QueryCompileError::LimitExceedsBound)?;
            if value == 0 || value > u64::from(bounds.max_rows()) {
                Err(QueryCompileError::LimitExceedsBound)
            } else {
                Ok(())
            }
        }
        Some(Token::Parameter(_, _)) if !parameters.is_empty() => {
            Err(QueryCompileError::ParameterizedLimitUnsupported)
        }
        _ => Err(QueryCompileError::UnboundedRead),
    }
}

fn validate_stable_ordering(tokens: &[Token]) -> Result<bool, QueryCompileError> {
    let order = tokens
        .iter()
        .position(|token| token.word() == Some("order"));
    let Some(order) = order else {
        return Err(QueryCompileError::StableOrderingRequired);
    };
    if tokens.get(order + 1).and_then(Token::word) != Some("by") {
        return Err(QueryCompileError::StableOrderingRequired);
    }
    let limit = tokens
        .iter()
        .position(|token| token.word() == Some("limit"))
        .unwrap_or(tokens.len());
    let order_tokens = &tokens[order + 2..limit];
    let has_tie_breaker = order_tokens
        .iter()
        .filter(|token| matches!(token, Token::Symbol(',')))
        .count()
        > 0
        || order_tokens
            .iter()
            .any(|token| token.word() == Some("tuple"));
    has_tie_breaker
        .then_some(true)
        .ok_or(QueryCompileError::StableOrderingRequired)
}

fn extract_tables(tokens: &[Token]) -> Result<BTreeSet<QualifiedTable>, QueryCompileError> {
    let mut tables = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !matches!(token.word(), Some("from" | "join")) {
            continue;
        }
        let start = index + 1;
        if matches!(tokens.get(start), Some(Token::Symbol('('))) {
            return Err(QueryCompileError::UnsupportedTableExpression);
        }
        let (table, _) = parse_table(tokens, start)?;
        tables.insert(table);
    }
    Ok(tables)
}

fn parse_table(
    tokens: &[Token],
    start: usize,
) -> Result<(QualifiedTable, usize), QueryCompileError> {
    let mut components = Vec::new();
    let mut index = start;
    loop {
        match tokens.get(index) {
            Some(Token::Word(value) | Token::QuotedIdentifier(value)) => {
                components.extend(value.split('.').map(str::to_owned));
                index += 1;
            }
            _ => return Err(QueryCompileError::UnqualifiedTable),
        }
        if tokens.get(index) != Some(&Token::Symbol('.')) {
            break;
        }
        index += 1;
    }
    if components.len() != 2 || components.iter().any(String::is_empty) {
        return Err(QueryCompileError::UnqualifiedTable);
    }
    Ok((
        QualifiedTable {
            database: components[0].clone(),
            table: components[1].clone(),
        },
        index,
    ))
}

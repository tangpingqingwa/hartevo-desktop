use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{BigQueryScope, Digest, ModelError, ResultBounds, Revision, SecretReference};

pub use crate::model::QueryMode;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryParameterType {
    String,
    Int64,
    Numeric,
    Bool,
    Date,
    Timestamp,
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
        if valid_parameter_name(&name) {
            Ok(Self {
                name,
                parameter_type,
                value_digest,
            })
        } else {
            Err(QueryCompileError::InvalidParameterName)
        }
    }

    /// Hashes a caller-owned value immediately; the value is not retained in
    /// the proposal, provider request, Debug output, or evidence.
    pub fn from_public_value(
        name: impl Into<String>,
        parameter_type: QueryParameterType,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, QueryCompileError> {
        Self::new(name, parameter_type, Digest::from_text(value))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryCompileError {
    #[error("query is empty or exceeds the Layer-1 size bound")]
    EmptyOrTooLarge,
    #[error("query has an unterminated comment, string, or quoted identifier")]
    UnterminatedToken,
    #[error("query contains more than one statement")]
    MultiStatement,
    #[error("query is not an allowlisted SELECT")]
    NotSelect,
    #[error("query contains a forbidden {operation} operation")]
    ForbiddenOperation { operation: &'static str },
    #[error("query must contain at least one named parameter")]
    MissingParameter,
    #[error("query uses a positional parameter; named parameters are required")]
    PositionalParameter,
    #[error("query references a parameter that was not bound")]
    UnboundParameter,
    #[error("query contains a parameter binding that is not referenced")]
    ExtraParameter,
    #[error("parameter name is invalid")]
    InvalidParameterName,
    #[error("query must contain a numeric LIMIT")]
    UnboundedRead,
    #[error("query LIMIT exceeds the requested row bound")]
    LimitExceedsBound,
    #[error("query uses a parameterized LIMIT; Layer 1 cannot prove its bound")]
    ParameterizedLimitUnsupported,
    #[error("query has no fully-qualified table reference")]
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

#[derive(Clone, Eq, PartialEq)]
pub struct ParameterizedSelect {
    canonical_query: String,
    parameters: BTreeMap<String, QueryParameter>,
    query_digest: Digest,
    referenced_tables: BTreeSet<QualifiedTable>,
}

impl fmt::Debug for ParameterizedSelect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParameterizedSelect")
            .field("query_digest", &self.query_digest)
            .field(
                "parameter_names",
                &self.parameters.keys().collect::<Vec<_>>(),
            )
            .field("referenced_tables", &self.referenced_tables)
            .finish_non_exhaustive()
    }
}

impl ParameterizedSelect {
    pub fn compile(
        scope: &BigQueryScope,
        query: impl Into<String>,
        parameters: impl IntoIterator<Item = QueryParameter>,
        bounds: ResultBounds,
    ) -> Result<Self, QueryCompileError> {
        let query_text = query.into();
        if query_text.is_empty() || query_text.len() > crate::model::MAX_QUERY_BYTES {
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
        let first_word = statement_tokens.first().and_then(Token::word).unwrap_or("");
        if !matches!(first_word, "select" | "with") {
            return Err(QueryCompileError::NotSelect);
        }
        reject_forbidden_operations(&statement_tokens)?;

        let mut parameter_map = BTreeMap::new();
        for parameter in parameters {
            if !valid_parameter_name(&parameter.name) {
                return Err(QueryCompileError::InvalidParameterName);
            }
            if parameter_map
                .insert(parameter.name.clone(), parameter)
                .is_some()
            {
                return Err(QueryCompileError::ExtraParameter);
            }
        }
        let used_parameters = statement_tokens
            .iter()
            .filter_map(Token::parameter)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if used_parameters.is_empty() {
            return Err(QueryCompileError::MissingParameter);
        }
        if parameter_map
            .keys()
            .any(|name| !used_parameters.contains(name))
        {
            return Err(QueryCompileError::ExtraParameter);
        }
        if used_parameters
            .iter()
            .any(|name| !parameter_map.contains_key(name))
        {
            return Err(QueryCompileError::UnboundParameter);
        }

        validate_limit(&statement_tokens, &parameter_map, bounds)?;
        let referenced_tables = extract_tables(&statement_tokens)?;
        if referenced_tables.is_empty() {
            return Err(QueryCompileError::UnqualifiedTable);
        }
        if referenced_tables
            .iter()
            .any(|table| !scope.contains_table(&table.project, &table.dataset, &table.table))
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
                    format!("{:?}", parameter.parameter_type),
                    parameter.value_digest.as_str().to_owned(),
                ]
            })
            .collect::<Vec<_>>();
        let mut query_digest_fields = vec![canonical_query.clone()];
        query_digest_fields.extend(parameter_digest_fields);
        let query_digest = Digest::from_fields("bigquery-query/v1", &query_digest_fields);
        Ok(Self {
            canonical_query,
            parameters: parameter_map,
            query_digest,
            referenced_tables,
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

    pub fn canonical_query_digest(&self) -> Digest {
        Digest::from_fields(
            "bigquery-query-canonical/v1",
            std::slice::from_ref(&self.canonical_query),
        )
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
pub struct BigQueryQueryProposal {
    scope_digest: Digest,
    query: ParameterizedSelect,
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

impl fmt::Debug for BigQueryQueryProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BigQueryQueryProposal")
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

impl BigQueryQueryProposal {
    pub(crate) fn compile(
        scope: &BigQueryScope,
        secret: &SecretReference,
        request: QueryProposalRequest,
    ) -> Result<Self, QueryCompileError> {
        if request.work_product_revision != scope.work_product_revision() {
            return Err(QueryCompileError::RevisionMismatch);
        }
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(QueryCompileError::InvalidScope);
        }
        let query_digest = request.query.query_digest().clone();
        let config_digest = Digest::from_fields(
            "bigquery-query-config/v1",
            &[
                scope.project_id().as_str().to_owned(),
                scope.location().as_str().to_owned(),
                scope.dataset_id().as_str().to_owned(),
                query_digest.as_str().to_owned(),
                format!("{mode:?}", mode = request.mode),
                request.bounds.max_rows().to_string(),
                request.bounds.max_bytes().to_string(),
                request.bounds.max_pages().to_string(),
                request.bounds.page_size().to_string(),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                "use_legacy_sql=false".to_owned(),
                format!("dry_run={}", request.mode == QueryMode::DryRun),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest(),
            query: request.query,
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

    pub fn bounds(&self) -> ResultBounds {
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
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct QualifiedTable {
    project: String,
    dataset: String,
    table: String,
}

fn valid_parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Number(String),
    QuotedIdentifier(String),
    Parameter(String),
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

    fn parameter(&self) -> Option<&str> {
        match self {
            Self::Parameter(value) => Some(value.as_str()),
            _ => None,
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Word(value) => value.clone(),
            Self::Number(value) => value.clone(),
            Self::QuotedIdentifier(value) => format!("`{value}`"),
            Self::Parameter(value) => format!("@{value}"),
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
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut closed = false;
                while index + 1 < bytes.len() {
                    if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                        index += 2;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                if !closed {
                    return Err(QueryCompileError::UnterminatedToken);
                }
            }
            b'`' => {
                let (value, next) = read_quoted(bytes, index, b'`')?;
                tokens.push(Token::QuotedIdentifier(value));
                index = next;
            }
            b'\'' => {
                let (value, next) = read_quoted(bytes, index, b'\'')?;
                tokens.push(Token::StringLiteral(Digest::from_text(value)));
                index = next;
            }
            b'@' => {
                index += 1;
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if start == index {
                    return Err(QueryCompileError::UnboundParameter);
                }
                tokens.push(Token::Parameter(
                    String::from_utf8_lossy(&bytes[start..index]).to_ascii_lowercase(),
                ));
            }
            b'?' => {
                return Err(QueryCompileError::PositionalParameter);
            }
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
                while index < bytes.len() && bytes[index].is_ascii_digit() {
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
        ("grant", "DDL"),
        ("revoke", "DDL"),
        ("export", "script"),
        ("load", "script"),
        ("call", "script"),
        ("begin", "script"),
        ("commit", "script"),
        ("rollback", "script"),
        ("declare", "script"),
        ("set", "script"),
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
    let limit_positions = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (token.word() == Some("limit")).then_some(index))
        .collect::<Vec<_>>();
    if limit_positions.len() != 1 {
        return Err(QueryCompileError::UnboundedRead);
    }
    let limit_index = limit_positions[0];
    match tokens.get(limit_index + 1) {
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
        Some(Token::Parameter(name)) if parameters.contains_key(name) => {
            Err(QueryCompileError::ParameterizedLimitUnsupported)
        }
        _ => Err(QueryCompileError::UnboundedRead),
    }
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
    if components.len() != 3 || components.iter().any(String::is_empty) {
        return Err(QueryCompileError::UnqualifiedTable);
    }
    Ok((
        QualifiedTable {
            project: components[0].clone(),
            dataset: components[1].clone(),
            table: components[2].clone(),
        },
        index,
    ))
}

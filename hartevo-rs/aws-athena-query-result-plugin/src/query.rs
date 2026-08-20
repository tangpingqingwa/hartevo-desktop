use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use thiserror::Error;

use crate::error::Result;
use crate::model::{AwsAthenaQueryResultScope, Digest, QualifiedTable, ResultBounds};

pub use crate::model::AthenaQueryMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryParameterType {
    String,
    Integer,
    BigInt,
    Double,
    Decimal,
    Boolean,
    Date,
    Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
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
    ) -> std::result::Result<Self, QueryCompileError> {
        let name = name.into();
        if valid_parameter_name(&name) {
            value_digest
                .validate()
                .map_err(|_| QueryCompileError::InvalidParameterName)?;
            Ok(Self {
                name,
                parameter_type,
                value_digest,
            })
        } else {
            Err(QueryCompileError::InvalidParameterName)
        }
    }

    /// Hashes a caller-owned parameter immediately.  The value is not stored
    /// in the query, provider request, Debug output, or evidence.
    pub fn from_public_value(
        name: impl Into<String>,
        parameter_type: QueryParameterType,
        value: impl AsRef<[u8]>,
    ) -> std::result::Result<Self, QueryCompileError> {
        Self::new(name, parameter_type, Digest::from_text(value))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryCompileError {
    #[error("query is empty or exceeds the Layer-1 size bound")]
    EmptyOrTooLarge,
    #[error("query contains a comment; comments are not accepted by the canonical policy")]
    Comment,
    #[error("query has an unterminated string or quoted identifier")]
    UnterminatedToken,
    #[error("query contains more than one statement")]
    MultiStatement,
    #[error("query is not an allowlisted SELECT or EXPLAIN SELECT")]
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
    #[error("query contains a literal value; all values must be named parameters")]
    LiteralNotParameterized,
    #[error("EXPLAIN must be followed by SELECT")]
    ExplainRequiresSelect,
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
    #[error("query contains an unsupported table expression or subquery")]
    UnsupportedTableExpression,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ParameterizedAthenaQuery {
    scope_digest: Digest,
    canonical_query: String,
    parameters: BTreeMap<String, QueryParameter>,
    query_digest: Digest,
    referenced_tables: BTreeSet<QualifiedTable>,
    mode: AthenaQueryMode,
}

impl fmt::Debug for ParameterizedAthenaQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParameterizedAthenaQuery")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field(
                "parameter_names",
                &self.parameters.keys().collect::<Vec<_>>(),
            )
            .field("referenced_tables", &self.referenced_tables)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl ParameterizedAthenaQuery {
    pub fn compile(
        scope: &AwsAthenaQueryResultScope,
        query: impl Into<String>,
        parameters: impl IntoIterator<Item = QueryParameter>,
        bounds: ResultBounds,
    ) -> std::result::Result<Self, QueryCompileError> {
        bounds
            .validate()
            .map_err(|_| QueryCompileError::LimitExceedsBound)?;
        let query = query.into();
        if query.is_empty() || query.len() > crate::MAX_QUERY_BYTES {
            return Err(QueryCompileError::EmptyOrTooLarge);
        }
        let mut tokens = lex(&query)?;
        if tokens
            .last()
            .is_some_and(|token| matches!(token, Token::Semicolon))
        {
            tokens.pop();
        }
        if tokens.iter().any(|token| matches!(token, Token::Semicolon)) {
            return Err(QueryCompileError::MultiStatement);
        }
        let forbidden = [
            ("with", "CTE"),
            ("union", "UNION"),
            ("intersect", "INTERSECT"),
            ("except", "EXCEPT"),
            ("insert", "DML"),
            ("update", "DML"),
            ("delete", "DML"),
            ("merge", "DML"),
            ("create", "DDL"),
            ("alter", "DDL"),
            ("drop", "DDL"),
            ("truncate", "DML"),
            ("grant", "DDL"),
            ("revoke", "DDL"),
            ("ctas", "CTAS"),
            ("unload", "UNLOAD"),
            ("into", "DML"),
            ("location", "S3_OUTPUT"),
            ("show", "CATALOG_ENUMERATION"),
            ("describe", "CATALOG_ENUMERATION"),
            ("msck", "CATALOG_MUTATION"),
            ("vacuum", "CATALOG_MUTATION"),
            ("call", "PROCEDURE"),
            ("execute", "PROCEDURE"),
        ];
        for token in &tokens {
            if let Token::Word(word) = token {
                if let Some((_, operation)) = forbidden
                    .iter()
                    .find(|(candidate, _)| *candidate == word.as_str())
                {
                    return Err(QueryCompileError::ForbiddenOperation { operation });
                }
            }
        }
        let (mode, first_query_index) = match tokens.first() {
            Some(Token::Word(word)) if word == "select" => (AthenaQueryMode::Select, 0),
            Some(Token::Word(word)) if word == "explain" => {
                if !matches!(tokens.get(1), Some(Token::Word(word)) if word == "select") {
                    return Err(QueryCompileError::ExplainRequiresSelect);
                }
                (AthenaQueryMode::Explain, 1)
            }
            _ => return Err(QueryCompileError::NotSelect),
        };
        if tokens
            .iter()
            .skip(first_query_index + 1)
            .any(|token| matches!(token, Token::Word(word) if word == "select"))
        {
            return Err(QueryCompileError::UnsupportedTableExpression);
        }
        let limit = validate_literals_and_limit(&tokens)?;

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
        let used_parameters = tokens
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

        if limit == 0 {
            return Err(QueryCompileError::UnboundedRead);
        }
        if limit > bounds.max_rows {
            return Err(QueryCompileError::LimitExceedsBound);
        }

        let referenced_tables = extract_tables(&tokens)?;
        if referenced_tables.is_empty() {
            return Err(QueryCompileError::UnqualifiedTable);
        }
        if referenced_tables
            .iter()
            .any(|table| !scope.contains_table(table))
        {
            return Err(QueryCompileError::TableOutOfScope);
        }

        let canonical_query = tokens
            .iter()
            .map(Token::canonical)
            .collect::<Vec<_>>()
            .join(" ");
        let query_digest =
            Self::compute_digest(&canonical_query, &parameter_map, mode, scope.scope_digest());
        Ok(Self {
            scope_digest: scope.digest(),
            canonical_query,
            parameters: parameter_map,
            query_digest,
            referenced_tables,
            mode,
        })
    }

    pub fn compile_with_bounds(
        scope: &AwsAthenaQueryResultScope,
        query: impl Into<String>,
        parameters: impl IntoIterator<Item = QueryParameter>,
        bounds: ResultBounds,
    ) -> std::result::Result<Self, QueryCompileError> {
        Self::compile(scope, query, parameters, bounds)
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn canonical_query_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-query-canonical/v1",
            &[("query", self.canonical_query.clone())],
        )
    }

    pub fn parameter_names(&self) -> impl Iterator<Item = &str> {
        self.parameters.keys().map(String::as_str)
    }

    pub fn referenced_tables(&self) -> &BTreeSet<QualifiedTable> {
        &self.referenced_tables
    }

    pub const fn mode(&self) -> AthenaQueryMode {
        self.mode
    }

    pub const fn is_explain(&self) -> bool {
        matches!(self.mode, AthenaQueryMode::Explain)
    }

    pub(crate) fn validate_against(&self, scope: &AwsAthenaQueryResultScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self
                .referenced_tables
                .iter()
                .any(|table| !scope.contains_table(table))
            || self.query_digest
                != Self::compute_digest(
                    &self.canonical_query,
                    &self.parameters,
                    self.mode,
                    scope.scope_digest(),
                )
        {
            Err(crate::error::AwsAthenaQueryResultError::QueryDrift)
        } else {
            Ok(())
        }
    }

    fn compute_digest(
        canonical_query: &str,
        parameters: &BTreeMap<String, QueryParameter>,
        mode: AthenaQueryMode,
        scope_digest: &Digest,
    ) -> Digest {
        Digest::from_parts(
            "aws-athena-parameterized-query/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("mode", format!("{mode:?}")),
                ("canonical", canonical_query.to_owned()),
                (
                    "parameters",
                    parameters
                        .values()
                        .map(|parameter| {
                            format!(
                                "{}:{:?}:{}",
                                parameter.name,
                                parameter.parameter_type,
                                parameter.value_digest.as_str()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Parameter(String),
    Number(String),
    Dot,
    Comma,
    LParen,
    RParen,
    Operator(String),
    Star,
    Semicolon,
}

impl Token {
    fn parameter(&self) -> Option<&str> {
        match self {
            Self::Parameter(value) => Some(value),
            _ => None,
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Word(value) => value.clone(),
            Self::Parameter(value) => format!(":{value}"),
            Self::Number(value) => value.clone(),
            Self::Dot => ".".to_owned(),
            Self::Comma => ",".to_owned(),
            Self::LParen => "(".to_owned(),
            Self::RParen => ")".to_owned(),
            Self::Operator(value) => value.clone(),
            Self::Star => "*".to_owned(),
            Self::Semicolon => ";".to_owned(),
        }
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

fn lex(input: &str) -> std::result::Result<Vec<Token>, QueryCompileError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut tokens = Vec::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if byte == b'-' && bytes.get(index + 1) == Some(&b'-')
            || byte == b'/' && bytes.get(index + 1) == Some(&b'*')
        {
            return Err(QueryCompileError::Comment);
        }
        if byte == b'\'' {
            index += 1;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    index += 1;
                }
            }
            if !closed {
                return Err(QueryCompileError::UnterminatedToken);
            }
            return Err(QueryCompileError::LiteralNotParameterized);
        }
        if byte == b'`' || byte == b'"' {
            let quote = byte;
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index].is_ascii_control() {
                    return Err(QueryCompileError::UnterminatedToken);
                }
                index += 1;
            }
            if index == bytes.len() {
                return Err(QueryCompileError::UnterminatedToken);
            }
            let value = input[start..index].to_ascii_lowercase();
            index += 1;
            if !valid_identifier_fragment(&value) {
                return Err(QueryCompileError::InvalidParameterName);
            }
            tokens.push(Token::Word(value));
            continue;
        }
        if byte == b':' || byte == b'@' {
            index += 1;
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let value = &input[start..index];
            if !valid_parameter_name(value) {
                return Err(QueryCompileError::InvalidParameterName);
            }
            tokens.push(Token::Parameter(value.to_owned()));
            continue;
        }
        if byte == b'?' {
            return Err(QueryCompileError::PositionalParameter);
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
            {
                index += 1;
            }
            tokens.push(Token::Word(input[start..index].to_ascii_lowercase()));
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit() || matches!(bytes[index], b'.' | b'_'))
            {
                index += 1;
            }
            tokens.push(Token::Number(input[start..index].to_owned()));
            continue;
        }
        let token = match byte {
            b'.' => Token::Dot,
            b',' => Token::Comma,
            b'(' => Token::LParen,
            b')' => Token::RParen,
            b'*' => Token::Star,
            b';' => Token::Semicolon,
            b'=' | b'<' | b'>' | b'!' | b'+' | b'-' | b'/' | b'%' => {
                let start = index;
                index += 1;
                if index < bytes.len()
                    && matches!(bytes[index], b'=' | b'>')
                    && matches!(byte, b'<' | b'>' | b'!')
                {
                    index += 1;
                }
                Token::Operator(input[start..index].to_owned())
            }
            _ => return Err(QueryCompileError::UnsupportedTableExpression),
        };
        if !matches!(&token, Token::Operator(_)) {
            index += 1;
        }
        tokens.push(token);
    }
    Ok(tokens)
}

fn valid_identifier_fragment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'-'))
}

fn validate_literals_and_limit(tokens: &[Token]) -> std::result::Result<u32, QueryCompileError> {
    let mut limit = None;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Number(value) => {
                if !matches!(tokens.get(index.wrapping_sub(1)), Some(Token::Word(word)) if word == "limit")
                {
                    return Err(QueryCompileError::LiteralNotParameterized);
                }
                if limit.is_some() {
                    return Err(QueryCompileError::UnboundedRead);
                }
                let value = value
                    .replace('_', "")
                    .parse::<u32>()
                    .map_err(|_| QueryCompileError::LimitExceedsBound)?;
                limit = Some(value);
            }
            Token::Parameter(_)
                if matches!(
                    tokens.get(index.wrapping_sub(1)),
                    Some(Token::Word(word)) if word == "limit"
                ) =>
            {
                return Err(QueryCompileError::ParameterizedLimitUnsupported);
            }
            Token::Word(word)
                if matches!(
                    word.as_str(),
                    "true" | "false" | "null" | "current_date" | "current_timestamp"
                ) =>
            {
                return Err(QueryCompileError::LiteralNotParameterized);
            }
            Token::Parameter(_)
            | Token::Word(_)
            | Token::Dot
            | Token::Comma
            | Token::LParen
            | Token::RParen
            | Token::Operator(_)
            | Token::Star
            | Token::Semicolon => {}
        }
    }
    limit.ok_or(QueryCompileError::UnboundedRead)
}

fn extract_tables(
    tokens: &[Token],
) -> std::result::Result<BTreeSet<QualifiedTable>, QueryCompileError> {
    let mut tables = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !matches!(token, Token::Word(word) if word == "from" || word == "join") {
            continue;
        }
        let Some(Token::Word(catalog)) = tokens.get(index + 1) else {
            return Err(QueryCompileError::UnqualifiedTable);
        };
        if !matches!(tokens.get(index + 2), Some(Token::Dot)) {
            return Err(QueryCompileError::UnqualifiedTable);
        }
        let Some(Token::Word(database)) = tokens.get(index + 3) else {
            return Err(QueryCompileError::UnqualifiedTable);
        };
        if !matches!(tokens.get(index + 4), Some(Token::Dot)) {
            return Err(QueryCompileError::UnqualifiedTable);
        }
        let Some(Token::Word(table)) = tokens.get(index + 5) else {
            return Err(QueryCompileError::UnqualifiedTable);
        };
        if matches!(tokens.get(index + 6), Some(Token::Comma | Token::LParen)) {
            return Err(QueryCompileError::UnsupportedTableExpression);
        }
        let qualified = QualifiedTable::new(
            crate::model::CatalogName::new(catalog.clone())
                .map_err(|_| QueryCompileError::UnqualifiedTable)?,
            crate::model::DatabaseName::new(database.clone())
                .map_err(|_| QueryCompileError::UnqualifiedTable)?,
            crate::model::TableName::new(table.clone())
                .map_err(|_| QueryCompileError::UnqualifiedTable)?,
        )
        .map_err(|_| QueryCompileError::UnqualifiedTable)?;
        let mut trailing_index = index + 6;
        while let Some(token) = tokens.get(trailing_index) {
            if matches!(
                token,
                Token::Word(word)
                    if matches!(
                        word.as_str(),
                        "where"
                            | "group"
                            | "order"
                            | "having"
                            | "limit"
                            | "offset"
                            | "join"
                            | "left"
                            | "right"
                            | "inner"
                            | "outer"
                            | "cross"
                            | "full"
                            | "on"
                            | "qualify"
                            | "window"
                    )
            ) {
                break;
            }
            if matches!(token, Token::Comma | Token::LParen | Token::RParen) {
                return Err(QueryCompileError::UnsupportedTableExpression);
            }
            trailing_index += 1;
        }
        tables.insert(qualified);
    }
    Ok(tables)
}

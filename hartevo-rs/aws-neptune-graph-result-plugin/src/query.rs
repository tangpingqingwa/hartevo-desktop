use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::Write,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AwsNeptuneGraphScope, Digest, QueryLimits,
    error::AwsNeptuneGraphResultError,
    model::{MAX_IDENTIFIER_BYTES, MAX_PARAMETER_COUNT, MAX_PROJECTION_FIELDS},
};

type QueryResult<T> = std::result::Result<T, QueryCompileError>;

/// Query compiler failures.  The variants intentionally distinguish the
/// high-risk forms that the contract must reject.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryCompileError {
    #[error("query is empty or exceeds the Layer-1 size bound")]
    EmptyOrTooLarge,
    #[error("query contains more than one statement")]
    MultiStatement,
    #[error("query contains an unterminated string or quoted identifier")]
    UnterminatedToken,
    #[error("query contains a forbidden {operation} operation")]
    ForbiddenOperation { operation: &'static str },
    #[error("query contains an S3 or LOAD read")]
    S3Read,
    #[error("query contains a variable-length traversal")]
    VariableLengthTraversal,
    #[error("query is not one of the predeclared bounded MATCH projections")]
    ArbitraryQueryText,
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
    #[error("query contains too many parameters or projection fields")]
    TooManyFields,
    #[error("query must contain a numeric LIMIT")]
    UnboundedOutput,
    #[error("query LIMIT exceeds the requested row bound")]
    LimitExceedsBound,
    #[error("query uses a parameterized LIMIT; Layer 1 cannot prove its bound")]
    ParameterizedLimitUnsupported,
    #[error("query pattern or projection is unsupported")]
    UnsupportedPattern,
    #[error("query scope does not match the exact registered template or parameters")]
    ScopeMismatch,
    #[error(transparent)]
    Model(#[from] AwsNeptuneGraphResultError),
}

/// Direction of one fixed-length relationship pattern.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outgoing,
    Incoming,
    Undirected,
}

/// One fixed node pattern in the restricted AST.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePattern {
    alias: String,
    label: String,
    property: Option<String>,
    parameter: Option<String>,
}

impl NodePattern {
    pub fn new(
        alias: impl Into<String>,
        label: impl Into<String>,
        property: Option<String>,
        parameter: Option<String>,
    ) -> QueryResult<Self> {
        let pattern = Self {
            alias: alias.into(),
            label: label.into(),
            property,
            parameter,
        };
        pattern.validate()?;
        Ok(pattern)
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn label_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-neptune-query-label/v1",
            &[("label", self.label.clone())],
        )
    }

    pub fn property_digest(&self) -> Option<Digest> {
        self.property.as_ref().map(|property| {
            Digest::from_parts(
                "aws-neptune-query-property/v1",
                &[("property", property.clone())],
            )
        })
    }

    pub fn parameter_name(&self) -> Option<&str> {
        self.parameter.as_deref()
    }

    fn validate(&self) -> QueryResult<()> {
        if !valid_name(&self.alias)
            || !valid_name(&self.label)
            || self
                .property
                .as_ref()
                .is_some_and(|value| !valid_name(value))
            || self
                .parameter
                .as_ref()
                .is_some_and(|value| !valid_parameter_name(value))
            || self.property.is_some() != self.parameter.is_some()
        {
            Err(QueryCompileError::UnsupportedPattern)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for NodePattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePattern")
            .field("alias_digest", &Digest::from_text(&self.alias))
            .field("label_digest", &self.label_digest())
            .field("property_digest", &self.property_digest())
            .field(
                "parameter_name_digest",
                &self.parameter.as_ref().map(Digest::from_text),
            )
            .finish_non_exhaustive()
    }
}

/// One fixed-length relationship pattern in the restricted AST.
#[derive(Clone, Eq, PartialEq)]
pub struct RelationshipPattern {
    alias: Option<String>,
    relationship_type: String,
    direction: Direction,
}

impl RelationshipPattern {
    pub fn new(
        alias: Option<String>,
        relationship_type: impl Into<String>,
        direction: Direction,
    ) -> QueryResult<Self> {
        let pattern = Self {
            alias,
            relationship_type: relationship_type.into(),
            direction,
        };
        if !valid_name(&pattern.relationship_type)
            || pattern
                .alias
                .as_ref()
                .is_some_and(|alias| !valid_name(alias))
        {
            return Err(QueryCompileError::UnsupportedPattern);
        }
        Ok(pattern)
    }

    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    pub fn relationship_type_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-neptune-query-relationship-type/v1",
            &[("type", self.relationship_type.clone())],
        )
    }

    pub const fn direction(&self) -> Direction {
        self.direction
    }
}

impl fmt::Debug for RelationshipPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelationshipPattern")
            .field("alias_digest", &self.alias.as_ref().map(Digest::from_text))
            .field("relationship_type_digest", &self.relationship_type_digest())
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

/// A redacted field returned for one AST alias.
#[derive(Clone, Eq, PartialEq)]
pub struct GraphProjection {
    alias: String,
    field: Option<String>,
}

impl GraphProjection {
    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn field_digest(&self) -> Option<Digest> {
        self.field.as_ref().map(|field| {
            Digest::from_parts(
                "aws-neptune-query-return-field/v1",
                &[("field", field.clone())],
            )
        })
    }
}

impl fmt::Debug for GraphProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphProjection")
            .field("alias_digest", &Digest::from_text(&self.alias))
            .field("field_digest", &self.field_digest())
            .finish_non_exhaustive()
    }
}

/// The parsed, bounded, predeclared openCypher AST.  It supports one node
/// match or one fixed-length relationship match and a digest-only projection.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenCypherAst {
    left: NodePattern,
    relationship: Option<RelationshipPattern>,
    right: Option<NodePattern>,
    projections: Vec<GraphProjection>,
    limit: u32,
}

impl OpenCypherAst {
    pub fn is_relationship_query(&self) -> bool {
        self.relationship.is_some()
    }

    pub const fn limit(&self) -> u32 {
        self.limit
    }

    pub fn projections(&self) -> &[GraphProjection] {
        &self.projections
    }

    pub fn left(&self) -> &NodePattern {
        &self.left
    }

    pub fn right(&self) -> Option<&NodePattern> {
        self.right.as_ref()
    }

    pub fn relationship(&self) -> Option<&RelationshipPattern> {
        self.relationship.as_ref()
    }

    fn parameter_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        if let Some(parameter) = self.left.parameter_name() {
            names.insert(parameter.to_owned());
        }
        if let Some(right) = &self.right
            && let Some(parameter) = right.parameter_name()
        {
            names.insert(parameter.to_owned());
        }
        names
    }

    fn canonical(&self) -> String {
        let mut value = format!("MATCH {}", canonical_node(&self.left));
        if let (Some(relationship), Some(right)) = (&self.relationship, &self.right) {
            value.push_str(&canonical_relationship(relationship));
            value.push_str(&canonical_node(right));
        }
        value.push_str(" RETURN ");
        value.push_str(
            &self
                .projections
                .iter()
                .map(|projection| {
                    projection.field.as_ref().map_or_else(
                        || projection.alias.clone(),
                        |field| format!("{}.{}", projection.alias, field),
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        let _ = write!(value, " LIMIT {}", self.limit);
        value
    }
}

impl fmt::Debug for OpenCypherAst {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCypherAst")
            .field("template_digest", &Digest::from_text(self.canonical()))
            .field("relationship", &self.relationship.is_some())
            .field("projection_count", &self.projections.len())
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

/// Query template identity, independent of secret parameter values.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenCypherQueryTemplate {
    ast: OpenCypherAst,
    digest: Digest,
}

impl OpenCypherQueryTemplate {
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn ast(&self) -> &OpenCypherAst {
        &self.ast
    }
}

impl fmt::Debug for OpenCypherQueryTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCypherQueryTemplate")
            .field("digest", &self.digest)
            .field("ast", &self.ast)
            .finish()
    }
}

/// A typed parameter whose value is hashed at the boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    ) -> QueryResult<Self> {
        let parameter = Self {
            name: name.into(),
            parameter_type,
            value_digest,
        };
        if !valid_parameter_name(&parameter.name) {
            return Err(QueryCompileError::InvalidParameterName);
        }
        parameter
            .value_digest
            .validate()
            .map_err(QueryCompileError::Model)?;
        Ok(parameter)
    }

    /// Hash a caller-owned value immediately; it is not retained in the AST.
    pub fn from_public_value(
        name: impl Into<String>,
        parameter_type: QueryParameterType,
        value: impl AsRef<[u8]>,
    ) -> QueryResult<Self> {
        Self::new(name, parameter_type, Digest::from_text(value))
    }
}

/// Supported public parameter types for the bounded AST.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryParameterType {
    String,
    Integer,
    Float,
    Boolean,
}

/// A compiled parameterized and bounded query.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenCypherQuery {
    template: OpenCypherQueryTemplate,
    parameters: BTreeMap<String, QueryParameter>,
    limits: QueryLimits,
    parameter_digest: Digest,
    query_digest: Digest,
}

impl OpenCypherQuery {
    /// Compile only the exact restricted grammar; arbitrary query text never
    /// becomes a retained public field.
    pub fn compile(
        query: impl Into<String>,
        parameters: impl IntoIterator<Item = QueryParameter>,
        limits: QueryLimits,
    ) -> QueryResult<Self> {
        limits.validate().map_err(QueryCompileError::Model)?;
        let query = query.into();
        let ast = parse_query(&query, limits)?;
        let template_digest = Digest::from_parts(
            "aws-neptune-query-template/v1",
            &[("canonical", ast.canonical())],
        );
        let template = OpenCypherQueryTemplate {
            ast,
            digest: template_digest,
        };
        let parameter_map = collect_parameters(parameters)?;
        let used = template.ast.parameter_names();
        if used.is_empty() {
            return Err(QueryCompileError::MissingParameter);
        }
        if used.iter().any(|name| !parameter_map.contains_key(name)) {
            return Err(QueryCompileError::UnboundParameter);
        }
        if parameter_map.keys().any(|name| !used.contains(name)) {
            return Err(QueryCompileError::ExtraParameter);
        }
        let parameter_digest = digest_parameters(&parameter_map);
        let query_digest = Digest::from_parts(
            "aws-neptune-query/v1",
            &[
                ("template", template.digest.as_str().to_owned()),
                ("parameter", parameter_digest.as_str().to_owned()),
                ("rows", limits.max_rows.to_string()),
                ("bytes", limits.max_bytes.to_string()),
                ("timeout", limits.timeout_ms.to_string()),
                ("pages", limits.max_pages.to_string()),
            ],
        );
        Ok(Self {
            template,
            parameters: parameter_map,
            limits,
            parameter_digest,
            query_digest,
        })
    }

    /// Compile and require an exact registered query-template/parameter scope.
    pub fn compile_for_scope(
        scope: &AwsNeptuneGraphScope,
        query: impl Into<String>,
        parameters: impl IntoIterator<Item = QueryParameter>,
        limits: QueryLimits,
    ) -> QueryResult<Self> {
        let query = Self::compile(query, parameters, limits)?;
        query.bind_to_scope(scope)?;
        Ok(query)
    }

    pub fn template(&self) -> &OpenCypherQueryTemplate {
        &self.template
    }

    pub fn ast(&self) -> &OpenCypherAst {
        &self.template.ast
    }

    pub fn parameters(&self) -> impl Iterator<Item = &QueryParameter> {
        self.parameters.values()
    }

    pub fn parameter_names(&self) -> impl Iterator<Item = &str> {
        self.parameters.keys().map(String::as_str)
    }

    pub fn limits(&self) -> QueryLimits {
        self.limits
    }

    pub fn template_digest(&self) -> &Digest {
        &self.template.digest
    }

    pub fn parameter_digest(&self) -> &Digest {
        &self.parameter_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn canonical_query_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-neptune-canonical-query/v1",
            &[("template", self.template.digest.as_str().to_owned())],
        )
    }

    pub fn bind_to_scope(&self, scope: &AwsNeptuneGraphScope) -> QueryResult<()> {
        if self.template_digest() != scope.query_template_digest()
            || self.parameter_digest() != scope.parameter_digest()
        {
            Err(QueryCompileError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for OpenCypherQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCypherQuery")
            .field("template_digest", &self.template_digest())
            .field(
                "parameter_names",
                &self.parameters.keys().collect::<Vec<_>>(),
            )
            .field("parameter_digest", &self.parameter_digest)
            .field("query_digest", &self.query_digest)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Compatibility name for callers that prefer an explicit parameterized query.
pub type ParameterizedOpenCypher = OpenCypherQuery;

fn collect_parameters(
    parameters: impl IntoIterator<Item = QueryParameter>,
) -> QueryResult<BTreeMap<String, QueryParameter>> {
    let mut values = BTreeMap::new();
    for parameter in parameters {
        if values.len() >= MAX_PARAMETER_COUNT || !valid_parameter_name(&parameter.name) {
            return Err(QueryCompileError::InvalidParameterName);
        }
        if values.insert(parameter.name.clone(), parameter).is_some() {
            return Err(QueryCompileError::ExtraParameter);
        }
    }
    Ok(values)
}

fn digest_parameters(parameters: &BTreeMap<String, QueryParameter>) -> Digest {
    let fields = parameters
        .values()
        .map(|parameter| {
            (
                parameter.name.clone(),
                format!(
                    "{:?}:{}",
                    parameter.parameter_type,
                    parameter.value_digest.as_str()
                ),
            )
        })
        .collect::<Vec<_>>();
    Digest::from_parts(
        "aws-neptune-parameters/v1",
        &fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect::<Vec<_>>(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Parameter(String),
    Number(u32),
    Symbol(char),
}

fn parse_query(query: &str, limits: QueryLimits) -> QueryResult<OpenCypherAst> {
    if query.trim().is_empty() || query.len() > 8 * 1024 {
        return Err(QueryCompileError::EmptyOrTooLarge);
    }
    if query.contains(';') {
        return Err(QueryCompileError::MultiStatement);
    }
    let lower = query.to_ascii_lowercase();
    for (needle, operation) in [
        ("create", "CREATE"),
        ("merge", "MERGE"),
        ("delete", "DELETE"),
        ("detach", "DETACH DELETE"),
        ("set", "SET"),
        ("remove", "REMOVE"),
        ("drop", "DROP"),
        ("call", "CALL"),
        ("unwind", "UNWIND"),
    ] {
        if contains_word(&lower, needle) {
            return Err(QueryCompileError::ForbiddenOperation { operation });
        }
    }
    if contains_word(&lower, "load") || lower.contains("s3") {
        return Err(QueryCompileError::S3Read);
    }
    let tokens = lex(query)?;
    let mut parser = Parser {
        tokens: &tokens,
        index: 0,
    };
    parser.expect_word("match")?;
    let left = parser.node()?;
    let (relationship, right) = if parser.peek_symbol('<') || parser.peek_symbol('-') {
        let relationship = parser.relationship()?;
        let right = parser.node()?;
        (Some(relationship), Some(right))
    } else {
        (None, None)
    };
    parser.expect_word("return")?;
    let aliases = [
        left.alias.clone(),
        right
            .as_ref()
            .map_or_else(String::new, |node| node.alias.clone()),
        relationship
            .as_ref()
            .and_then(|value| value.alias.clone())
            .unwrap_or_default(),
    ];
    let mut projections = Vec::new();
    loop {
        let alias = parser.word()?;
        if !aliases.iter().any(|candidate| candidate == &alias) {
            return Err(QueryCompileError::UnsupportedPattern);
        }
        let field = if parser.consume_symbol('.') {
            Some(parser.word()?)
        } else {
            None
        };
        if field.as_ref().is_some_and(|value| !valid_name(value)) {
            return Err(QueryCompileError::UnsupportedPattern);
        }
        projections.push(GraphProjection { alias, field });
        if projections.len() > MAX_PROJECTION_FIELDS {
            return Err(QueryCompileError::TooManyFields);
        }
        if !parser.consume_symbol(',') {
            break;
        }
    }
    if projections.is_empty() {
        return Err(QueryCompileError::UnsupportedPattern);
    }
    match parser.next() {
        Some(Token::Word(word)) if word.eq_ignore_ascii_case("limit") => {}
        Some(Token::Parameter(_)) => return Err(QueryCompileError::ParameterizedLimitUnsupported),
        _ => return Err(QueryCompileError::UnboundedOutput),
    }
    let limit = match parser.next() {
        Some(Token::Number(value)) => value,
        Some(Token::Parameter(_)) => return Err(QueryCompileError::ParameterizedLimitUnsupported),
        _ => return Err(QueryCompileError::UnboundedOutput),
    };
    if limit == 0 {
        return Err(QueryCompileError::UnboundedOutput);
    }
    if limit > limits.max_rows {
        return Err(QueryCompileError::LimitExceedsBound);
    }
    if parser.next().is_some() {
        return Err(QueryCompileError::ArbitraryQueryText);
    }
    if left.parameter_name().is_none()
        && right
            .as_ref()
            .is_none_or(|node| node.parameter_name().is_none())
    {
        return Err(QueryCompileError::MissingParameter);
    }
    Ok(OpenCypherAst {
        left,
        relationship,
        right,
        projections,
        limit,
    })
}

fn lex(query: &str) -> QueryResult<Vec<Token>> {
    let bytes = query.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' || byte == b'`' {
            return Err(QueryCompileError::UnterminatedToken);
        }
        if byte == b'$' {
            index += 1;
            if index >= bytes.len() || bytes[index].is_ascii_digit() {
                return Err(QueryCompileError::PositionalParameter);
            }
            let start = index;
            while index < bytes.len() && is_name_byte(bytes[index]) {
                index += 1;
            }
            if start == index {
                return Err(QueryCompileError::InvalidParameterName);
            }
            tokens.push(Token::Parameter(query[start..index].to_owned()));
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            let value = query[start..index]
                .parse::<u32>()
                .map_err(|_| QueryCompileError::ArbitraryQueryText)?;
            tokens.push(Token::Number(value));
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len() && is_name_byte(bytes[index]) {
                index += 1;
            }
            tokens.push(Token::Word(query[start..index].to_owned()));
            continue;
        }
        if b"()[]{}:,.<>-*".contains(&byte) {
            tokens.push(Token::Symbol(byte as char));
            index += 1;
            continue;
        }
        return Err(QueryCompileError::ArbitraryQueryText);
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
}

impl Parser<'_> {
    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned();
        self.index += usize::from(token.is_some());
        token
    }

    fn peek_symbol(&self, symbol: char) -> bool {
        matches!(self.tokens.get(self.index), Some(Token::Symbol(value)) if *value == symbol)
    }

    fn consume_symbol(&mut self, symbol: char) -> bool {
        if self.peek_symbol(symbol) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_symbol(&mut self, symbol: char) -> QueryResult<()> {
        if self.consume_symbol(symbol) {
            Ok(())
        } else {
            Err(QueryCompileError::ArbitraryQueryText)
        }
    }

    fn expect_word(&mut self, expected: &str) -> QueryResult<()> {
        match self.next() {
            Some(Token::Word(word)) if word.eq_ignore_ascii_case(expected) => Ok(()),
            _ => Err(QueryCompileError::ArbitraryQueryText),
        }
    }

    fn word(&mut self) -> QueryResult<String> {
        match self.next() {
            Some(Token::Word(word)) if valid_name(&word) => Ok(word),
            _ => Err(QueryCompileError::ArbitraryQueryText),
        }
    }

    fn parameter(&mut self) -> QueryResult<String> {
        match self.next() {
            Some(Token::Parameter(parameter)) if valid_parameter_name(&parameter) => Ok(parameter),
            Some(Token::Parameter(_)) => Err(QueryCompileError::InvalidParameterName),
            _ => Err(QueryCompileError::ArbitraryQueryText),
        }
    }

    fn node(&mut self) -> QueryResult<NodePattern> {
        self.expect_symbol('(')?;
        let alias = self.word()?;
        self.expect_symbol(':')?;
        let label = self.word()?;
        let (property, parameter) = if self.consume_symbol('{') {
            let property = self.word()?;
            self.expect_symbol(':')?;
            let parameter = self.parameter()?;
            self.expect_symbol('}')?;
            (Some(property), Some(parameter))
        } else {
            (None, None)
        };
        self.expect_symbol(')')?;
        NodePattern::new(alias, label, property, parameter)
    }

    fn relationship(&mut self) -> QueryResult<RelationshipPattern> {
        let direction = if self.consume_symbol('<') {
            self.expect_symbol('-')?;
            Direction::Incoming
        } else {
            self.expect_symbol('-')?;
            Direction::Outgoing
        };
        self.expect_symbol('[')?;
        if self.consume_symbol('*') {
            return Err(QueryCompileError::VariableLengthTraversal);
        }
        let alias = match self.tokens.get(self.index) {
            Some(Token::Word(_)) => Some(self.word()?),
            _ => None,
        };
        self.expect_symbol(':')?;
        let relationship_type = self.word()?;
        if self.consume_symbol('*') {
            return Err(QueryCompileError::VariableLengthTraversal);
        }
        self.expect_symbol(']')?;
        self.expect_symbol('-')?;
        let direction = if self.consume_symbol('>') {
            if direction == Direction::Incoming {
                return Err(QueryCompileError::UnsupportedPattern);
            }
            Direction::Outgoing
        } else if direction == Direction::Incoming {
            Direction::Incoming
        } else {
            Direction::Undirected
        };
        RelationshipPattern::new(alias, relationship_type, direction)
    }
}

fn canonical_node(node: &NodePattern) -> String {
    let property = node
        .property
        .as_ref()
        .zip(node.parameter.as_ref())
        .map_or_else(String::new, |(property, parameter)| {
            format!(" {{{property}:${parameter}}}")
        });
    format!("({}:{}{})", node.alias, node.label, property)
}

fn canonical_relationship(relationship: &RelationshipPattern) -> String {
    let alias = relationship
        .alias
        .as_ref()
        .map_or_else(String::new, ToString::to_string);
    let open = match relationship.direction {
        Direction::Incoming => "<-",
        Direction::Outgoing | Direction::Undirected => "-",
    };
    let close = match relationship.direction {
        Direction::Outgoing => "->",
        Direction::Incoming | Direction::Undirected => "-",
    };
    format!("{open}[{alias}:{}]{close}", relationship.relationship_type)
}

fn contains_word(value: &str, needle: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|word| word == needle)
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(is_name_byte)
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
}

fn valid_parameter_name(value: &str) -> bool {
    valid_name(value) && !value.starts_with('_')
}

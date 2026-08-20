use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AggregateColumnType, AggregateSchema, AzureMonitorLogsScope, ColumnName, Digest,
    MAX_AGGREGATES, MAX_CELL_TEXT_BYTES, MAX_GROUP_BY_COLUMNS, MAX_PARAMETERS, MAX_QUERY_BYTES,
    ModelError, ParameterName, QueryBounds, QueryTemplateId, TimeWindow,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    Sum,
    Average,
    Min,
    Max,
    DistinctCount,
}

impl AggregateFunction {
    const fn requires_column(self) -> bool {
        !matches!(self, Self::Count)
    }

    const fn kql_name(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Sum => "sum",
            Self::Average => "avg",
            Self::Min => "min",
            Self::Max => "max",
            Self::DistinctCount => "dcount",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryError {
    #[error("query template is invalid")]
    InvalidTemplate,
    #[error("aggregate function requires exactly one safe column")]
    InvalidAggregate,
    #[error("query template has a duplicate column, alias, or parameter")]
    DuplicateField,
    #[error("query template exceeds the bounded AST ceiling")]
    AstTooLarge,
    #[error("query template references a parameter that is missing or unused")]
    ParameterBinding,
    #[error("query parameter is invalid or contains injection syntax")]
    InvalidParameter,
    #[error("arbitrary KQL is not accepted; construct the allowlisted AST")]
    RawKqlRejected,
    #[error("compiled KQL exceeds the bounded query ceiling")]
    QueryTooLarge,
    #[error("cross-workspace query is not explicitly registered")]
    CrossWorkspaceNotRegistered,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateSpec {
    pub function: AggregateFunction,
    pub column: Option<ColumnName>,
    pub alias: ColumnName,
}

impl AggregateSpec {
    pub fn new(
        function: AggregateFunction,
        column: Option<ColumnName>,
        alias: ColumnName,
    ) -> Result<Self, QueryError> {
        if function.requires_column() != column.is_some() {
            return Err(QueryError::InvalidAggregate);
        }
        Ok(Self {
            function,
            column,
            alias,
        })
    }

    pub fn count(alias: ColumnName) -> Result<Self, QueryError> {
        Self::new(AggregateFunction::Count, None, alias)
    }

    pub fn sum(column: ColumnName, alias: ColumnName) -> Result<Self, QueryError> {
        Self::new(AggregateFunction::Sum, Some(column), alias)
    }

    pub fn average(column: ColumnName, alias: ColumnName) -> Result<Self, QueryError> {
        Self::new(AggregateFunction::Average, Some(column), alias)
    }

    pub fn min(column: ColumnName, alias: ColumnName) -> Result<Self, QueryError> {
        Self::new(AggregateFunction::Min, Some(column), alias)
    }

    pub fn max(column: ColumnName, alias: ColumnName) -> Result<Self, QueryError> {
        Self::new(AggregateFunction::Max, Some(column), alias)
    }

    pub fn distinct_count(column: ColumnName, alias: ColumnName) -> Result<Self, QueryError> {
        Self::new(AggregateFunction::DistinctCount, Some(column), alias)
    }

    fn canonical(&self) -> String {
        format!(
            "{}:{}:{}",
            self.function.kql_name(),
            self.column.as_ref().map_or("-", ColumnName::as_str),
            self.alias.as_str()
        )
    }

    fn render(&self) -> String {
        match &self.column {
            Some(column) => format!(
                "{}={}({})",
                self.alias.as_str(),
                self.function.kql_name(),
                column.as_str()
            ),
            None => format!("{}={}()", self.alias.as_str(), self.function.kql_name()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FilterClause {
    Equals {
        column: ColumnName,
        parameter: ParameterName,
    },
    InSet {
        column: ColumnName,
        parameter: ParameterName,
    },
}

impl FilterClause {
    pub fn equals(column: ColumnName, parameter: ParameterName) -> Self {
        Self::Equals { column, parameter }
    }

    pub fn in_set(column: ColumnName, parameter: ParameterName) -> Self {
        Self::InSet { column, parameter }
    }

    fn parameter(&self) -> &ParameterName {
        match self {
            Self::Equals { parameter, .. } | Self::InSet { parameter, .. } => parameter,
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Equals { column, parameter } => {
                format!("equals:{}:{}", column.as_str(), parameter.as_str())
            }
            Self::InSet { column, parameter } => {
                format!("in_set:{}:{}", column.as_str(), parameter.as_str())
            }
        }
    }

    fn render(&self) -> String {
        match self {
            Self::Equals { column, parameter } => {
                format!("{} == @{}", column.as_str(), parameter.as_str())
            }
            Self::InSet { column, parameter } => {
                format!("{} in (@{})", column.as_str(), parameter.as_str())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryTemplate {
    pub id: QueryTemplateId,
    pub table: crate::TableName,
    pub time_column: ColumnName,
    pub group_by: Vec<ColumnName>,
    pub aggregates: Vec<AggregateSpec>,
    pub filters: Vec<FilterClause>,
    pub template_digest: Digest,
}

impl QueryTemplate {
    pub fn new(
        id: QueryTemplateId,
        table: crate::TableName,
        time_column: ColumnName,
        group_by: Vec<ColumnName>,
        aggregates: Vec<AggregateSpec>,
        filters: Vec<FilterClause>,
    ) -> Result<Self, QueryError> {
        if aggregates.is_empty()
            || aggregates.len() > MAX_AGGREGATES
            || group_by.len() > MAX_GROUP_BY_COLUMNS
            || filters.len() > MAX_PARAMETERS
        {
            return Err(QueryError::AstTooLarge);
        }

        let mut fields = BTreeSet::new();
        if !fields.insert(time_column.as_str().to_owned()) {
            return Err(QueryError::DuplicateField);
        }
        for column in &group_by {
            if !fields.insert(column.as_str().to_owned()) {
                return Err(QueryError::DuplicateField);
            }
        }

        let mut aliases = BTreeSet::new();
        for aggregate in &aggregates {
            if !aliases.insert(aggregate.alias.as_str().to_owned())
                || fields.contains(aggregate.alias.as_str())
            {
                return Err(QueryError::DuplicateField);
            }
            if let Some(column) = &aggregate.column
                && forbidden_query_column(column)
            {
                return Err(QueryError::InvalidTemplate);
            }
        }
        for filter in &filters {
            let column = match filter {
                FilterClause::Equals { column, .. } | FilterClause::InSet { column, .. } => column,
            };
            if forbidden_query_column(column) {
                return Err(QueryError::InvalidTemplate);
            }
        }

        let canonical =
            canonical_template(&id, &table, &time_column, &group_by, &aggregates, &filters);
        let template_digest =
            Digest::from_fields("azure-monitor-logs-query-template/v1", &[canonical]);
        Ok(Self {
            id,
            table,
            time_column,
            group_by,
            aggregates,
            filters,
            template_digest,
        })
    }

    /// Raw user-authored KQL is intentionally not a valid Layer-1 input.
    /// Callers construct the typed aggregate AST above; a later native layer
    /// may render this AST into the official API request body.
    pub fn from_kql(
        _id: QueryTemplateId,
        _table: crate::TableName,
        raw_kql: impl AsRef<str>,
    ) -> Result<Self, QueryError> {
        let raw_kql = raw_kql.as_ref();
        if raw_kql.is_empty()
            || raw_kql.len() > MAX_QUERY_BYTES
            || raw_kql.contains(';')
            || raw_kql.contains("//")
            || raw_kql.contains("/*")
            || raw_kql.contains("join")
            || raw_kql.contains("union")
            || raw_kql.contains("evaluate")
            || raw_kql.contains("plugin")
            || raw_kql.contains("dynamic")
            || raw_kql.contains("parse_json")
        {
            return Err(QueryError::RawKqlRejected);
        }
        Err(QueryError::RawKqlRejected)
    }

    pub fn render_kql(&self, time_window: &TimeWindow) -> String {
        let mut parts = vec![
            self.table.as_str().to_owned(),
            format!(
                "where {} between (datetime('{}') .. datetime('{}'))",
                self.time_column.as_str(),
                time_window.start.as_str(),
                time_window.end.as_str()
            ),
        ];
        parts.extend(self.filters.iter().map(FilterClause::render));
        let aggregates = self
            .aggregates
            .iter()
            .map(AggregateSpec::render)
            .collect::<Vec<_>>()
            .join(", ");
        let mut summarize = format!("summarize {aggregates}");
        if !self.group_by.is_empty() {
            summarize.push_str(" by ");
            summarize.push_str(
                &self
                    .group_by
                    .iter()
                    .map(ColumnName::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        parts.push(summarize);
        parts.join(" | ")
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "azure-monitor-logs-query-template/v1",
            &[canonical_template(
                &self.id,
                &self.table,
                &self.time_column,
                &self.group_by,
                &self.aggregates,
                &self.filters,
            )],
        );
        if expected == self.template_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.template_digest
    }
}

fn forbidden_query_column(column: &ColumnName) -> bool {
    let value = column.as_str().to_ascii_lowercase();
    value.contains("user")
        || value.contains("email")
        || value.contains("principal")
        || value.contains("identity")
        || value.contains("raw")
        || value.contains("body")
        || value.contains("message")
        || value.contains("payload")
        || value.contains("dynamic")
}

fn canonical_template(
    id: &QueryTemplateId,
    table: &crate::TableName,
    time_column: &ColumnName,
    group_by: &[ColumnName],
    aggregates: &[AggregateSpec],
    filters: &[FilterClause],
) -> String {
    let groups = group_by
        .iter()
        .map(ColumnName::as_str)
        .collect::<Vec<_>>()
        .join(",");
    let aggregates = aggregates
        .iter()
        .map(AggregateSpec::canonical)
        .collect::<Vec<_>>()
        .join(",");
    let filters = filters
        .iter()
        .map(FilterClause::canonical)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "id={};table={};time={};group={groups};aggregates={aggregates};filters={filters}",
        id.as_str(),
        table.as_str(),
        time_column.as_str()
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ParameterValue {
    Text(String),
    Integer(i64),
    Decimal(String),
    Boolean(bool),
}

impl ParameterValue {
    pub fn validate(&self) -> Result<(), QueryError> {
        match self {
            Self::Text(value) => {
                if value.is_empty()
                    || value.len() > MAX_CELL_TEXT_BYTES
                    || value.chars().any(char::is_control)
                    || value.contains('|')
                    || value.contains(';')
                    || value.contains("//")
                    || value.contains('\'')
                    || value.contains('"')
                {
                    Err(QueryError::InvalidParameter)
                } else {
                    Ok(())
                }
            }
            Self::Integer(_) | Self::Boolean(_) => Ok(()),
            Self::Decimal(value) => {
                if value.is_empty()
                    || value.len() > 64
                    || value.parse::<f64>().map_or(true, |v| !v.is_finite())
                    || value.bytes().enumerate().any(|(index, byte)| {
                        !(byte.is_ascii_digit() || byte == b'.' || (byte == b'-' && index == 0))
                    })
                {
                    Err(QueryError::InvalidParameter)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Text(value) => format!("text:{value}"),
            Self::Integer(value) => format!("integer:{value}"),
            Self::Decimal(value) => format!("decimal:{value}"),
            Self::Boolean(value) => format!("boolean:{value}"),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct QueryParameter {
    pub name: ParameterName,
    pub value: ParameterValue,
}

impl fmt::Debug for QueryParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryParameter")
            .field("name", &self.name)
            .field("value", &"<redacted bounded parameter>")
            .finish()
    }
}

impl QueryParameter {
    pub fn new(name: ParameterName, value: ParameterValue) -> Result<Self, QueryError> {
        value.validate()?;
        Ok(Self { name, value })
    }

    fn canonical(&self) -> String {
        format!("{}={}", self.name.as_str(), self.value.canonical())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct QueryPlan {
    template: QueryTemplate,
    parameters: Vec<QueryParameter>,
    time_window: TimeWindow,
    bounds: QueryBounds,
    parameter_digest: Digest,
    query_digest: Digest,
}

impl fmt::Debug for QueryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryPlan")
            .field("template", &self.template)
            .field("parameter_names", &self.parameter_names())
            .field("parameters", &"<redacted bounded parameters>")
            .field("time_window", &self.time_window)
            .field("bounds", &self.bounds)
            .field("parameter_digest", &self.parameter_digest)
            .field("query_digest", &self.query_digest)
            .finish()
    }
}

impl QueryPlan {
    pub fn new(
        template: QueryTemplate,
        parameters: Vec<QueryParameter>,
        time_window: TimeWindow,
        bounds: QueryBounds,
    ) -> Result<Self, QueryError> {
        template.validate_digest()?;
        time_window.validate_digest()?;
        if parameters.len() > MAX_PARAMETERS {
            return Err(QueryError::AstTooLarge);
        }
        let mut names = BTreeSet::new();
        for parameter in &parameters {
            if !names.insert(parameter.name.as_str().to_owned()) {
                return Err(QueryError::DuplicateField);
            }
            parameter.value.validate()?;
        }
        let referenced = template
            .filters
            .iter()
            .map(FilterClause::parameter)
            .map(ParameterName::as_str)
            .collect::<BTreeSet<_>>();
        if referenced.len() != names.len() || referenced.iter().any(|name| !names.contains(*name)) {
            return Err(QueryError::ParameterBinding);
        }
        let mut canonical = parameters
            .iter()
            .map(QueryParameter::canonical)
            .collect::<Vec<_>>();
        canonical.sort();
        let parameter_digest = Digest::from_fields("azure-monitor-logs-parameters/v1", &canonical);
        let rendered = template.render_kql(&time_window);
        if rendered.len() > bounds.max_response_bytes as usize || rendered.len() > MAX_QUERY_BYTES {
            return Err(QueryError::QueryTooLarge);
        }
        let query_digest = Digest::from_fields(
            "azure-monitor-logs-query/v1",
            &[
                template.template_digest.as_str().to_owned(),
                parameter_digest.as_str().to_owned(),
                time_window.digest.as_str().to_owned(),
                rendered,
            ],
        );
        Ok(Self {
            template,
            parameters,
            time_window,
            bounds,
            parameter_digest,
            query_digest,
        })
    }

    pub fn template(&self) -> &QueryTemplate {
        &self.template
    }

    pub fn parameters(&self) -> &[QueryParameter] {
        &self.parameters
    }

    pub fn parameter_names(&self) -> Vec<&ParameterName> {
        self.parameters
            .iter()
            .map(|parameter| &parameter.name)
            .collect()
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub const fn bounds(&self) -> QueryBounds {
        self.bounds
    }

    pub fn parameter_digest(&self) -> &Digest {
        &self.parameter_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn render_kql(&self) -> String {
        self.template.render_kql(&self.time_window)
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let mut canonical = self
            .parameters
            .iter()
            .map(QueryParameter::canonical)
            .collect::<Vec<_>>();
        canonical.sort();
        let parameter_digest = Digest::from_fields("azure-monitor-logs-parameters/v1", &canonical);
        if parameter_digest != self.parameter_digest {
            return Err(ModelError::DigestMismatch);
        }
        let query_digest = Digest::from_fields(
            "azure-monitor-logs-query/v1",
            &[
                self.template.template_digest.as_str().to_owned(),
                parameter_digest.as_str().to_owned(),
                self.time_window.digest.as_str().to_owned(),
                self.render_kql(),
            ],
        );
        if query_digest != self.query_digest {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn matches_scope(&self, scope: &AzureMonitorLogsScope) -> Result<(), QueryError> {
        if self.template.table != scope.table {
            return Err(QueryError::CrossWorkspaceNotRegistered);
        }
        Ok(())
    }

    pub fn expected_schema_for_aggregate(&self) -> Vec<(ColumnName, AggregateColumnType)> {
        let mut columns = self
            .template
            .group_by
            .iter()
            .cloned()
            .map(|column| (column, AggregateColumnType::Category))
            .collect::<Vec<_>>();
        columns.extend(self.template.aggregates.iter().map(|aggregate| {
            let column_type = match aggregate.function {
                AggregateFunction::Count | AggregateFunction::DistinctCount => {
                    AggregateColumnType::Integer
                }
                AggregateFunction::Sum
                | AggregateFunction::Average
                | AggregateFunction::Min
                | AggregateFunction::Max => AggregateColumnType::Decimal,
            };
            (aggregate.alias.clone(), column_type)
        }));
        columns
    }

    pub fn matches_schema(&self, schema: &AggregateSchema) -> bool {
        let expected = self.expected_schema_for_aggregate();
        expected.len() == schema.columns.len()
            && expected.iter().zip(&schema.columns).all(
                |((expected_name, expected_type), actual)| {
                    expected_name == &actual.name
                        && *expected_type == actual.column_type
                        && !actual.nullable
                },
            )
    }
}

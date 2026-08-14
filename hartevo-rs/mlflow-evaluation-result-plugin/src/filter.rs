use std::fmt;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    DatasetDigest, Digest, MAX_FILTER_BYTES, MetricKey, MlflowScope, ModelError, ParamKey, TagKey,
};

const MAX_CLAUSES: usize = 16;
const MAX_IN_VALUES: usize = 32;
const MAX_LITERAL_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOperator {
    Eq,
    NotEq,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
    ILike,
    In,
    IsNull,
    IsNotNull,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FilterField {
    Metric(MetricKey),
    Param(ParamKey),
    Tag(TagKey),
    DatasetName,
    DatasetDigest,
    DatasetContext,
    AttributeRunId,
    AttributeStatus,
    AttributeRunName,
    AttributeStartTime,
    AttributeEndTime,
}

impl FilterField {
    fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::Metric(_) | Self::AttributeStartTime | Self::AttributeEndTime
        )
    }

    fn is_string(&self) -> bool {
        !self.is_numeric()
    }

    fn rendered_name(&self) -> String {
        match self {
            Self::Metric(key) => format_field("metrics", key.as_str()),
            Self::Param(key) => format_field("params", key.as_str()),
            Self::Tag(key) => format_field("tags", key.as_str()),
            Self::DatasetName => "datasets.name".to_owned(),
            Self::DatasetDigest => "datasets.digest".to_owned(),
            Self::DatasetContext => "datasets.context".to_owned(),
            Self::AttributeRunId => "attributes.run_id".to_owned(),
            Self::AttributeStatus => "attributes.status".to_owned(),
            Self::AttributeRunName => "attributes.run_name".to_owned(),
            Self::AttributeStartTime => "attributes.start_time".to_owned(),
            Self::AttributeEndTime => "attributes.end_time".to_owned(),
        }
    }

    fn allowlisted(&self, scope: &MlflowScope) -> bool {
        match self {
            Self::Metric(key) => scope.allows_metric(key),
            Self::Param(key) => scope.allows_param(key),
            Self::Tag(key) => scope.allows_tag(key),
            Self::DatasetName | Self::DatasetDigest | Self::DatasetContext => true,
            Self::AttributeRunId
            | Self::AttributeStatus
            | Self::AttributeRunName
            | Self::AttributeStartTime
            | Self::AttributeEndTime => true,
        }
    }
}

fn format_field(prefix: &str, key: &str) -> String {
    if key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
    {
        format!("{prefix}.{key}")
    } else {
        format!("{prefix}.`{}`", key.replace('`', "``"))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FilterCompileError {
    #[error("filter has too many clauses")]
    TooManyClauses,
    #[error("filter field is not in the governed allowlist")]
    FieldNotAllowlisted,
    #[error("operator is not valid for this filter field")]
    UnsupportedOperator,
    #[error("filter literal is empty, too large, or contains a control sequence")]
    InvalidLiteral,
    #[error("IN requires between one and the Layer-1 maximum number of values")]
    InvalidInSet,
    #[error("filter serialization exceeds the Layer-1 bound")]
    TooLarge,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Eq, PartialEq)]
enum Literal {
    Number(String),
    Text(String),
}

#[derive(Clone, Eq, PartialEq)]
pub struct FilterValue {
    literal: Literal,
    digest: Digest,
}

impl fmt::Debug for FilterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilterValue")
            .field(
                "kind",
                &match self.literal {
                    Literal::Number(_) => "number",
                    Literal::Text(_) => "text",
                },
            )
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for FilterValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FilterValue", 2)?;
        let kind = match self.literal {
            Literal::Number(_) => "number",
            Literal::Text(_) => "text",
        };
        state.serialize_field("kind", kind)?;
        state.serialize_field("digest", &self.digest)?;
        state.end()
    }
}

impl FilterValue {
    pub fn number(value: f64) -> Result<Self, FilterCompileError> {
        if !value.is_finite() {
            return Err(FilterCompileError::InvalidLiteral);
        }
        let rendered = value.to_string();
        Ok(Self {
            digest: Digest::from_text(&rendered),
            literal: Literal::Number(rendered),
        })
    }

    pub fn text(value: impl Into<String>) -> Result<Self, FilterCompileError> {
        let value = value.into();
        validate_literal(&value)?;
        Ok(Self {
            digest: Digest::from_text(&value),
            literal: Literal::Text(value),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn is_number(&self) -> bool {
        matches!(self.literal, Literal::Number(_))
    }

    fn render(&self) -> String {
        match &self.literal {
            Literal::Number(value) => value.clone(),
            Literal::Text(value) => format!("'{}'", value.replace('\'', "''")),
        }
    }
}

fn validate_literal(value: &str) -> Result<(), FilterCompileError> {
    if value.is_empty()
        || value.len() > MAX_LITERAL_BYTES
        || value.chars().any(char::is_control)
        || value.contains(';')
        || value.contains("--")
        || value.contains("/*")
        || value.contains("*/")
    {
        Err(FilterCompileError::InvalidLiteral)
    } else {
        Ok(())
    }
}

fn validate_value_type(
    field: &FilterField,
    operator: FilterOperator,
    value: &FilterValue,
) -> Result<(), FilterCompileError> {
    if matches!(
        operator,
        FilterOperator::In | FilterOperator::IsNull | FilterOperator::IsNotNull
    ) {
        return Err(FilterCompileError::UnsupportedOperator);
    }
    if field.is_numeric() != value.is_number()
        || (field.is_numeric() && matches!(operator, FilterOperator::Like | FilterOperator::ILike))
    {
        Err(FilterCompileError::UnsupportedOperator)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilterClause {
    pub field: FilterField,
    pub operator: FilterOperator,
    pub value: Option<FilterValue>,
    pub values: Vec<FilterValue>,
}

impl FilterClause {
    pub fn new(
        field: FilterField,
        operator: FilterOperator,
        value: FilterValue,
    ) -> Result<Self, FilterCompileError> {
        if matches!(
            operator,
            FilterOperator::In | FilterOperator::IsNull | FilterOperator::IsNotNull
        ) {
            return Err(FilterCompileError::UnsupportedOperator);
        }
        validate_value_type(&field, operator, &value)?;
        Ok(Self {
            field,
            operator,
            value: Some(value),
            values: Vec::new(),
        })
    }

    pub fn in_values(
        field: FilterField,
        values: impl IntoIterator<Item = FilterValue>,
    ) -> Result<Self, FilterCompileError> {
        if !field.is_string() {
            return Err(FilterCompileError::UnsupportedOperator);
        }
        let values = values.into_iter().collect::<Vec<_>>();
        if values.is_empty()
            || values.len() > MAX_IN_VALUES
            || values.iter().any(FilterValue::is_number)
        {
            return Err(FilterCompileError::InvalidInSet);
        }
        Ok(Self {
            field,
            operator: FilterOperator::In,
            value: None,
            values,
        })
    }

    pub fn is_null(field: FilterField, not: bool) -> Self {
        Self {
            field,
            operator: if not {
                FilterOperator::IsNotNull
            } else {
                FilterOperator::IsNull
            },
            value: None,
            values: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), FilterCompileError> {
        match self.operator {
            FilterOperator::In => {
                if self.values.is_empty() || self.value.is_some() {
                    return Err(FilterCompileError::InvalidInSet);
                }
            }
            FilterOperator::IsNull | FilterOperator::IsNotNull => {
                if self.value.is_some() || !self.values.is_empty() {
                    return Err(FilterCompileError::UnsupportedOperator);
                }
            }
            _ => {
                if self.value.is_none() || !self.values.is_empty() {
                    return Err(FilterCompileError::UnsupportedOperator);
                }
            }
        }
        if self.field.is_numeric() {
            if matches!(
                self.operator,
                FilterOperator::Like | FilterOperator::ILike | FilterOperator::In
            ) {
                return Err(FilterCompileError::UnsupportedOperator);
            }
            if self.value.as_ref().is_some_and(|value| !value.is_number()) {
                return Err(FilterCompileError::UnsupportedOperator);
            }
        } else if self.value.as_ref().is_some_and(FilterValue::is_number) {
            return Err(FilterCompileError::UnsupportedOperator);
        }
        Ok(())
    }

    fn dataset_digests_are_allowlisted(&self, scope: &MlflowScope) -> bool {
        if !matches!(self.field, FilterField::DatasetDigest) {
            return true;
        }
        let mut values =
            self.value
                .iter()
                .chain(self.values.iter())
                .filter_map(|value| match &value.literal {
                    Literal::Text(text) => DatasetDigest::new(text.clone()).ok(),
                    Literal::Number(_) => None,
                });
        values.all(|digest| scope.allows_dataset_digest(&digest))
    }

    fn digest_fields(&self) -> Vec<String> {
        let mut fields = vec![self.field.rendered_name(), format!("{:?}", self.operator)];
        if let Some(value) = &self.value {
            fields.push(value.digest.as_str().to_owned());
        }
        fields.extend(
            self.values
                .iter()
                .map(|value| value.digest.as_str().to_owned()),
        );
        fields
    }

    fn render(&self) -> String {
        let operator = match self.operator {
            FilterOperator::Eq => "=",
            FilterOperator::NotEq => "!=",
            FilterOperator::Gt => ">",
            FilterOperator::Gte => ">=",
            FilterOperator::Lt => "<",
            FilterOperator::Lte => "<=",
            FilterOperator::Like => "LIKE",
            FilterOperator::ILike => "ILIKE",
            FilterOperator::In => "IN",
            FilterOperator::IsNull => "IS NULL",
            FilterOperator::IsNotNull => "IS NOT NULL",
        };
        if matches!(
            self.operator,
            FilterOperator::IsNull | FilterOperator::IsNotNull
        ) {
            format!("{} {operator}", self.field.rendered_name())
        } else if self.operator == FilterOperator::In {
            let values = self
                .values
                .iter()
                .map(FilterValue::render)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} {operator} ({values})", self.field.rendered_name())
        } else {
            format!(
                "{} {operator} {}",
                self.field.rendered_name(),
                self.value
                    .as_ref()
                    .map_or_else(|| "NULL".to_owned(), FilterValue::render)
            )
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MlflowFilter {
    scope_digest: Digest,
    clauses: Vec<FilterClause>,
    filter_digest: Digest,
    rendered_bytes: usize,
}

impl fmt::Debug for MlflowFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlflowFilter")
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("clauses", &self.clauses)
            .field("rendered_bytes", &self.rendered_bytes)
            .finish()
    }
}

impl Serialize for MlflowFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MlflowFilter", 3)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("clauses", &self.clauses)?;
        state.end()
    }
}

impl MlflowFilter {
    pub fn new(
        scope: &MlflowScope,
        clauses: impl IntoIterator<Item = FilterClause>,
    ) -> Result<Self, FilterCompileError> {
        let clauses = clauses.into_iter().collect::<Vec<_>>();
        if clauses.len() > MAX_CLAUSES {
            return Err(FilterCompileError::TooManyClauses);
        }
        for clause in &clauses {
            clause.validate()?;
            if !clause.field.allowlisted(scope) {
                return Err(FilterCompileError::FieldNotAllowlisted);
            }
            if !clause.dataset_digests_are_allowlisted(scope) {
                return Err(FilterCompileError::FieldNotAllowlisted);
            }
        }
        let rendered = clauses
            .iter()
            .map(FilterClause::render)
            .collect::<Vec<_>>()
            .join(" AND ");
        if rendered.len() > MAX_FILTER_BYTES {
            return Err(FilterCompileError::TooLarge);
        }
        let mut digest_fields = vec![scope.scope_digest().as_str().to_owned()];
        digest_fields.extend(clauses.iter().flat_map(FilterClause::digest_fields));
        let filter_digest = Digest::from_fields("mlflow-filter/v1", &digest_fields);
        Ok(Self {
            scope_digest: scope.scope_digest(),
            clauses,
            filter_digest,
            rendered_bytes: rendered.len(),
        })
    }

    pub fn empty(scope: &MlflowScope) -> Self {
        Self::new(scope, []).expect("empty filter is valid")
    }

    pub fn digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn clauses(&self) -> &[FilterClause] {
        &self.clauses
    }
}

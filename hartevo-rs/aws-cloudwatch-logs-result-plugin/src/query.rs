//! Allowlisted, parameterized CloudWatch Logs Insights query AST.
//!
//! A query is represented by a fixed template kind, typed parameter digests,
//! an allowlisted log group, and a bounded time window. There is no constructor
//! accepting arbitrary query text and no raw query text is retained.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;

use crate::{
    AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION, AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION,
    model::{
        AwsCloudWatchLogsScope, Digest, LogGroupName, MAX_PAGES, MAX_PARAMETERS,
        MAX_RESPONSE_BYTES, MAX_RESULTS, MAX_RETRIES, ModelError, PermissionAction,
        PermissionFence, QueryTemplateId, Revision, TimeWindow, digest_serialized,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryTemplateKind {
    ErrorSummary,
    ReadinessSummary,
    CorrelationSummary,
}

impl QueryTemplateKind {
    const fn field_names(self) -> &'static [&'static str] {
        match self {
            Self::ErrorSummary => &[
                "@timestamp",
                "level",
                "errorClass",
                "serviceRevision",
                "count",
            ],
            Self::ReadinessSummary => &["@timestamp", "level", "serviceRevision", "count"],
            Self::CorrelationSummary => &[
                "@timestamp",
                "requestFingerprint",
                "serviceRevision",
                "count",
            ],
        }
    }

    fn allows_parameter(self, name: &str) -> bool {
        match self {
            Self::ErrorSummary => matches!(
                name,
                "error_class" | "service_revision" | "deployment_revision"
            ),
            Self::ReadinessSummary => matches!(name, "service_revision" | "deployment_revision"),
            Self::CorrelationSummary => matches!(name, "correlation_key" | "service_revision"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryParameterType {
    Text,
    Integer,
    Boolean,
    Revision,
    DurationSeconds,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryParameter {
    pub name: String,
    pub value_type: QueryParameterType,
    pub value_digest: Digest,
}

impl fmt::Debug for QueryParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryParameter")
            .field("name", &self.name)
            .field("value_type", &self.value_type)
            .field("value_digest", &self.value_digest)
            .finish()
    }
}

impl QueryParameter {
    pub fn new(
        name: impl Into<String>,
        value_type: QueryParameterType,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 64
            || name
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        {
            return Err(ModelError::Invalid {
                field: "query parameter name",
            });
        }
        Ok(Self {
            name,
            value_type,
            value_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-logs-query-parameter/v1",
                &[
                    value_type_name(value_type).to_owned(),
                    value.as_ref().len().to_string(),
                    Digest::from_text(value).to_string(),
                ],
            ),
        })
    }

    pub fn from_public_value(
        name: impl Into<String>,
        value_type: QueryParameterType,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        Self::new(name, value_type, value)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-query-parameter-entry/v1",
            &[
                self.name.clone(),
                value_type_name(self.value_type).to_owned(),
                self.value_digest.to_string(),
            ],
        )
    }
}

fn value_type_name(value_type: QueryParameterType) -> &'static str {
    match value_type {
        QueryParameterType::Text => "text",
        QueryParameterType::Integer => "integer",
        QueryParameterType::Boolean => "boolean",
        QueryParameterType::Revision => "revision",
        QueryParameterType::DurationSeconds => "duration_seconds",
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryTemplate {
    pub id: QueryTemplateId,
    pub kind: QueryTemplateKind,
    pub field_names: Vec<String>,
    pub template_digest: Digest,
}

impl QueryTemplate {
    pub fn new(id: QueryTemplateId, kind: QueryTemplateKind) -> Result<Self, ModelError> {
        let field_names = kind
            .field_names()
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<Vec<_>>();
        let mut template = Self {
            id,
            kind,
            field_names,
            template_digest: Digest::zero(),
        };
        template.template_digest = template.recomputed_digest();
        Ok(template)
    }

    pub fn error_summary(id: QueryTemplateId) -> Result<Self, ModelError> {
        Self::new(id, QueryTemplateKind::ErrorSummary)
    }

    pub fn readiness_summary(id: QueryTemplateId) -> Result<Self, ModelError> {
        Self::new(id, QueryTemplateKind::ReadinessSummary)
    }

    pub fn correlation_summary(id: QueryTemplateId) -> Result<Self, ModelError> {
        Self::new(id, QueryTemplateKind::CorrelationSummary)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-query-template/v1",
            &[
                self.id.as_str().to_owned(),
                format!("{:?}", self.kind),
                self.field_names.join(","),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.field_names
            != self
                .kind
                .field_names()
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
            || self.template_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "query template",
            });
        }
        Ok(())
    }

    pub fn accepts_parameter(&self, name: &str) -> bool {
        self.kind.allows_parameter(name)
    }

    pub fn digest(&self) -> &Digest {
        &self.template_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    BoundedReadProposal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultBounds {
    pub max_results: u16,
    pub max_pages: u8,
    pub max_response_bytes: usize,
    pub max_retries: u8,
}

impl ResultBounds {
    pub fn new(
        max_results: u16,
        max_pages: u8,
        max_response_bytes: usize,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        if max_results == 0
            || usize::from(max_results) > MAX_RESULTS
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "query result bounds",
            });
        }
        Ok(Self {
            max_results,
            max_pages,
            max_response_bytes,
            max_retries,
        })
    }

    pub fn bounded() -> Self {
        Self {
            max_results: MAX_RESULTS as u16,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retries: MAX_RETRIES,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchLogsQuery {
    pub template: QueryTemplate,
    pub log_group: LogGroupName,
    pub parameters: Vec<QueryParameter>,
    pub window: TimeWindow,
    pub bounds: ResultBounds,
    pub mode: QueryMode,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub parameter_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub work_product_revision: Revision,
}

impl fmt::Debug for CloudWatchLogsQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchLogsQuery")
            .field("template_id", &self.template.id)
            .field("template_digest", &self.template.template_digest)
            .field("log_group", &self.log_group)
            .field("parameters", &self.parameter_digests())
            .field("parameter_digests", &self.parameter_digests())
            .field("window", &self.window)
            .field("bounds", &self.bounds)
            .field("mode", &self.mode)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("parameter_digest", &self.parameter_digest)
            .field("query_digest", &self.query_digest)
            .field("config_digest", &self.config_digest)
            .field("service_revision", &self.service_revision)
            .field("deployment_revision", &self.deployment_revision)
            .field("work_product_revision", &self.work_product_revision)
            .finish()
    }
}

impl CloudWatchLogsQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        template: QueryTemplate,
        log_group: LogGroupName,
        parameters: Vec<QueryParameter>,
        window: TimeWindow,
        bounds: ResultBounds,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        permission_required(permission)?;
        template.validate()?;
        if !scope.allows_query_template(&template.id) {
            return Err(ModelError::ScopeMismatch {
                field: "query template allowlist",
            });
        }
        if !scope.allows_log_group(&log_group) {
            return Err(ModelError::ScopeMismatch {
                field: "log group allowlist",
            });
        }
        if !scope.time_window.contains(&window) {
            return Err(ModelError::ScopeMismatch {
                field: "time window",
            });
        }
        if parameters.len() > MAX_PARAMETERS {
            return Err(ModelError::TooMany {
                field: "query parameters",
            });
        }
        let mut names = BTreeSet::new();
        for parameter in &parameters {
            if !template.accepts_parameter(&parameter.name) {
                return Err(ModelError::Unsupported {
                    field: "query parameter",
                });
            }
            if !names.insert(parameter.name.clone()) {
                return Err(ModelError::Duplicate {
                    field: "query parameter",
                });
            }
        }
        let parameter_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-query-parameters/v1",
            &parameters
                .iter()
                .map(QueryParameter::digest)
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        );
        let scope_digest = scope.digest();
        let permission_digest = permission.digest();
        let query_digest = digest_serialized(&QueryBody {
            template_digest: &template.template_digest,
            log_group: &log_group,
            parameter_digest: &parameter_digest,
            window: &window,
            bounds,
            scope_digest: &scope_digest,
            permission_digest: &permission_digest,
            work_product_revision: scope.work_product.revision,
            mode: QueryMode::BoundedReadProposal,
        });
        let config_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-query-config/v1",
            &[
                query_digest.to_string(),
                AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION.to_owned(),
                AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION.to_owned(),
                scope.service_revision.revision.get().to_string(),
                scope.deployment.revision.get().to_string(),
                scope.work_product.revision.get().to_string(),
            ],
        );
        Ok(Self {
            template,
            log_group,
            parameters,
            window,
            bounds,
            mode: QueryMode::BoundedReadProposal,
            scope_digest,
            permission_digest,
            parameter_digest,
            query_digest,
            config_digest,
            service_revision: scope.service_revision.revision,
            deployment_revision: scope.deployment.revision,
            work_product_revision: scope.work_product.revision,
        })
    }

    pub fn new(
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        template: QueryTemplate,
        log_group: LogGroupName,
        parameters: Vec<QueryParameter>,
        window: TimeWindow,
    ) -> Result<Self, ModelError> {
        Self::compile(
            scope,
            permission,
            template,
            log_group,
            parameters,
            window,
            ResultBounds::bounded(),
        )
    }

    pub fn validate_against(
        &self,
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        let expected = Self::compile(
            scope,
            permission,
            self.template.clone(),
            self.log_group.clone(),
            self.parameters.clone(),
            self.window.clone(),
            self.bounds,
        )?;
        if expected.query_digest != self.query_digest
            || expected.config_digest != self.config_digest
            || self.mode != QueryMode::BoundedReadProposal
        {
            return Err(ModelError::QueryMismatch {
                field: "query digest",
            });
        }
        Ok(())
    }

    pub fn template_id(&self) -> &QueryTemplateId {
        &self.template.id
    }

    pub fn template_digest(&self) -> &Digest {
        &self.template.template_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub fn parameter_digest(&self) -> &Digest {
        &self.parameter_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn parameter_digests(&self) -> Vec<Digest> {
        self.parameters.iter().map(QueryParameter::digest).collect()
    }

    pub fn bounds(&self) -> ResultBounds {
        self.bounds
    }

    pub fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryBody<'a> {
    template_digest: &'a Digest,
    log_group: &'a LogGroupName,
    parameter_digest: &'a Digest,
    window: &'a TimeWindow,
    bounds: ResultBounds,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    work_product_revision: Revision,
    mode: QueryMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryProposalRequest {
    pub template: QueryTemplate,
    pub log_group: LogGroupName,
    pub parameters: Vec<QueryParameter>,
    pub window: TimeWindow,
    pub bounds: ResultBounds,
}

impl QueryProposalRequest {
    pub fn new(
        template: QueryTemplate,
        log_group: LogGroupName,
        parameters: Vec<QueryParameter>,
        window: TimeWindow,
        bounds: ResultBounds,
    ) -> Self {
        Self {
            template,
            log_group,
            parameters,
            window,
            bounds,
        }
    }

    pub fn compile(
        &self,
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
    ) -> Result<CloudWatchLogsQuery, ModelError> {
        CloudWatchLogsQuery::compile(
            scope,
            permission,
            self.template.clone(),
            self.log_group.clone(),
            self.parameters.clone(),
            self.window.clone(),
            self.bounds,
        )
    }
}

fn permission_required(permission: &PermissionFence) -> Result<(), ModelError> {
    for action in [
        PermissionAction::StartQuery,
        PermissionAction::GetQueryResults,
        PermissionAction::DescribeQueries,
    ] {
        if !permission.allows(action) {
            return Err(ModelError::ScopeMismatch {
                field: "CloudWatch Logs permission",
            });
        }
    }
    Ok(())
}

pub type ParameterizedQuery = CloudWatchLogsQuery;
pub type AwsCloudWatchLogsQuery = CloudWatchLogsQuery;
pub type AwsCloudWatchLogsQueryProposal = CloudWatchLogsQuery;
pub type AwsCloudWatchLogsQueryTemplate = QueryTemplate;

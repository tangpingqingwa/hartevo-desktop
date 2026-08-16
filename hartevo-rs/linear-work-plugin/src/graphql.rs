use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use crate::ids::{
    LinearCursor, LinearCycleId, LinearIdError, LinearIssueId, LinearProjectId, LinearTeamId,
    LinearWorkflowStateId,
};
use crate::oauth::LinearAccessToken;
use crate::provider::LinearProviderProvenance;

pub const LINEAR_GRAPHQL_ENDPOINT: &str = "https://api.linear.app/graphql";
pub const LINEAR_OAUTH_PROBE_QUERY: &str = r"query LinearOAuthProbe($teamIds: [String!]!) {
  viewer { id name }
  organization { id name }
  teams(filter: { id: { in: $teamIds } }) {
    nodes { id name key }
    pageInfo { hasNextPage endCursor }
  }
}";
pub const LINEAR_ISSUES_QUERY: &str = r"query LinearIssuesPage($teamId: String!, $first: Int!, $after: String) {
  team(id: $teamId) {
    id
    issues(first: $first, after: $after) {
      nodes {
        id
        identifier
        title
        description
        priority
        createdAt
        updatedAt
        archivedAt
        state { id name type }
        project { id name }
        cycle { id name number }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}";
pub const LINEAR_PROJECTS_QUERY: &str = r"query LinearProjectsPage($teamId: String!, $first: Int!, $after: String) {
  team(id: $teamId) {
    id
    projects(first: $first, after: $after) {
      nodes { id name description state { id name type } startDate targetDate updatedAt }
      pageInfo { hasNextPage endCursor }
    }
  }
}";
pub const LINEAR_CYCLES_QUERY: &str = r"query LinearCyclesPage($teamId: String!, $first: Int!, $after: String) {
  team(id: $teamId) {
    id
    cycles(first: $first, after: $after) {
      nodes { id name number description startsAt endsAt completedAt updatedAt }
      pageInfo { hasNextPage endCursor }
    }
  }
}";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearGraphQlRequestError {
    #[error("Linear GraphQL endpoint must use HTTPS")]
    InsecureEndpoint,
    #[error("Linear GraphQL endpoint is invalid: {0}")]
    InvalidEndpoint(String),
    #[error("Linear GraphQL operation name is invalid")]
    InvalidOperationName,
    #[error("Linear GraphQL query is empty")]
    EmptyQuery,
    #[error("Linear access token is empty")]
    EmptyAccessToken,
}

#[derive(Clone)]
pub struct LinearGraphQlRequest {
    endpoint: Url,
    operation_name: String,
    query: String,
    variables: Value,
    access_token: LinearAccessToken,
}

impl fmt::Debug for LinearGraphQlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearGraphQlRequest")
            .field("endpoint", &self.endpoint)
            .field("operation_name", &self.operation_name)
            .field("query", &self.query)
            .field("variables", &self.variables)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl LinearGraphQlRequest {
    pub fn new(
        operation_name: impl Into<String>,
        query: impl Into<String>,
        variables: Value,
        access_token: LinearAccessToken,
    ) -> Result<Self, LinearGraphQlRequestError> {
        Self::with_endpoint(
            Url::parse(LINEAR_GRAPHQL_ENDPOINT).expect("official Linear endpoint is valid"),
            operation_name,
            query,
            variables,
            access_token,
        )
    }

    pub fn with_endpoint(
        endpoint: Url,
        operation_name: impl Into<String>,
        query: impl Into<String>,
        variables: Value,
        access_token: LinearAccessToken,
    ) -> Result<Self, LinearGraphQlRequestError> {
        if endpoint.scheme() != "https" {
            return Err(LinearGraphQlRequestError::InsecureEndpoint);
        }
        if endpoint.host_str().is_none() {
            return Err(LinearGraphQlRequestError::InvalidEndpoint(
                endpoint.to_string(),
            ));
        }
        if endpoint.host_str() != Some("api.linear.app")
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.port().is_some_and(|port| port != 443)
            || endpoint.path() != "/graphql"
        {
            return Err(LinearGraphQlRequestError::InvalidEndpoint(
                endpoint.to_string(),
            ));
        }
        let operation_name = operation_name.into();
        let query = query.into();
        if operation_name.is_empty()
            || !operation_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(LinearGraphQlRequestError::InvalidOperationName);
        }
        if query.trim().is_empty() {
            return Err(LinearGraphQlRequestError::EmptyQuery);
        }
        if access_token.is_empty() {
            return Err(LinearGraphQlRequestError::EmptyAccessToken);
        }
        Ok(Self {
            endpoint,
            operation_name,
            query,
            variables,
            access_token,
        })
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub fn operation_name(&self) -> &str {
        &self.operation_name
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn variables(&self) -> &Value {
        &self.variables
    }

    pub(crate) fn authorization_header(&self) -> String {
        format!("Bearer {}", self.access_token.as_str())
    }

    pub(crate) fn wire_body(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&json!({
            "operationName": self.operation_name,
            "query": self.query,
            "variables": self.variables,
        }))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearTransportError {
    #[error("Linear GraphQL request serialization failed: {0}")]
    RequestSerialization(String),
    #[error("Linear HTTPS transport failed: {0}")]
    Http(String),
    #[error("Linear GraphQL response body could not be read: {0}")]
    ResponseBody(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearGraphQlResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl LinearGraphQlResponse {
    pub fn new(status: u16, headers: BTreeMap<String, String>, body: impl Into<String>) -> Self {
        Self {
            status,
            headers,
            body: body.into(),
        }
    }
}

pub trait LinearGraphQlTransport {
    fn execute(
        &mut self,
        request: &LinearGraphQlRequest,
    ) -> Result<LinearGraphQlResponse, LinearTransportError>;
}

#[derive(Clone)]
pub struct LinearHttpsGraphQlTransport {
    agent: ureq::Agent,
}

impl fmt::Debug for LinearHttpsGraphQlTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearHttpsGraphQlTransport")
            .field("transport", &"HTTPS")
            .finish()
    }
}

impl LinearHttpsGraphQlTransport {
    pub fn new(timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .build()
            .new_agent();
        Self { agent }
    }
}

impl Default for LinearHttpsGraphQlTransport {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

impl LinearGraphQlTransport for LinearHttpsGraphQlTransport {
    fn execute(
        &mut self,
        request: &LinearGraphQlRequest,
    ) -> Result<LinearGraphQlResponse, LinearTransportError> {
        let body = request
            .wire_body()
            .map_err(|error| LinearTransportError::RequestSerialization(error.to_string()))?;
        let mut response = self
            .agent
            .post(request.endpoint().as_str())
            .header("Authorization", request.authorization_header())
            .header("Content-Type", "application/json")
            .config()
            .http_status_as_error(false)
            .build()
            .send(body)
            .map_err(|error| LinearTransportError::Http(error.to_string()))?;
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| LinearTransportError::ResponseBody(error.to_string()))?;
        Ok(LinearGraphQlResponse::new(status.into(), headers, body))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearGraphQlErrorItem {
    pub message: String,
    #[serde(default)]
    pub path: Vec<Value>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

impl LinearGraphQlErrorItem {
    pub fn code(&self) -> Option<&str> {
        self.extensions.get("code").and_then(Value::as_str)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearGraphQlDecodeError {
    #[error("Linear GraphQL response is malformed: {0}")]
    Malformed(String),
    #[error("Linear GraphQL HTTP status {status}: {message}")]
    HttpStatus {
        status: u16,
        message: String,
        rate_limit: Box<LinearRateLimitReceipt>,
    },
    #[error("Linear GraphQL errors: {message}")]
    Errors {
        message: String,
        errors: Box<Vec<LinearGraphQlErrorItem>>,
        rate_limit: Box<LinearRateLimitReceipt>,
        status: u16,
    },
    #[error("Linear GraphQL response has no data")]
    MissingData {
        rate_limit: Box<LinearRateLimitReceipt>,
        status: u16,
    },
}

impl LinearGraphQlDecodeError {
    pub fn rate_limit(&self) -> Option<&LinearRateLimitReceipt> {
        match self {
            Self::Malformed(_) => None,
            Self::HttpStatus { rate_limit, .. }
            | Self::Errors { rate_limit, .. }
            | Self::MissingData { rate_limit, .. } => Some(rate_limit),
        }
    }

    pub fn is_rate_limited(&self) -> bool {
        match self {
            Self::Errors { errors, .. } => errors.iter().any(|error| {
                error
                    .code()
                    .is_some_and(|code| code.eq_ignore_ascii_case("RATELIMITED"))
            }),
            Self::HttpStatus { status, .. } => *status == 429,
            Self::Malformed(_) | Self::MissingData { .. } => false,
        }
    }

    pub fn is_auth_failure(&self) -> bool {
        match self {
            Self::HttpStatus { status, .. } => matches!(status, 401 | 403),
            Self::Errors { errors, .. } => errors.iter().any(|error| {
                error.code().is_some_and(|code| {
                    matches!(
                        code.to_ascii_uppercase().as_str(),
                        "UNAUTHORIZED" | "FORBIDDEN" | "AUTHENTICATION_REQUIRED"
                    )
                })
            }),
            Self::Malformed(_) | Self::MissingData { .. } => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawGraphQlEnvelope<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<LinearGraphQlErrorItem>,
    #[serde(default)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRateLimitExtension {
    #[serde(default)]
    cost: Option<u64>,
    #[serde(default)]
    remaining: Option<u64>,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    reset: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinearRateLimitReceipt {
    pub requests_limit: Option<u64>,
    pub requests_remaining: Option<u64>,
    pub requests_reset_at_ms: Option<u64>,
    pub endpoint_limit: Option<u64>,
    pub endpoint_remaining: Option<u64>,
    pub endpoint_reset_at_ms: Option<u64>,
    pub graph_ql_cost: Option<u64>,
    pub graph_ql_remaining: Option<u64>,
    pub graph_ql_limit: Option<u64>,
    pub graph_ql_reset_at_ms: Option<u64>,
}

impl LinearRateLimitReceipt {
    fn from_response(
        response: &LinearGraphQlResponse,
        extensions: &BTreeMap<String, Value>,
    ) -> Self {
        let mut receipt = Self {
            requests_limit: header_number(&response.headers, "x-ratelimit-requests-limit"),
            requests_remaining: header_number(&response.headers, "x-ratelimit-requests-remaining"),
            requests_reset_at_ms: header_number(&response.headers, "x-ratelimit-requests-reset"),
            endpoint_limit: header_number(&response.headers, "x-ratelimit-endpoint-requests-limit"),
            endpoint_remaining: header_number(
                &response.headers,
                "x-ratelimit-endpoint-requests-remaining",
            ),
            endpoint_reset_at_ms: header_number(
                &response.headers,
                "x-ratelimit-endpoint-requests-reset",
            ),
            ..Self::default()
        };
        if let Some(extension) = extensions
            .get("rateLimit")
            .and_then(|value| serde_json::from_value::<RawRateLimitExtension>(value.clone()).ok())
        {
            receipt.graph_ql_cost = extension.cost;
            receipt.graph_ql_remaining = extension.remaining;
            receipt.graph_ql_limit = extension.limit;
            receipt.graph_ql_reset_at_ms = extension.reset;
        }
        receipt
    }
}

fn header_number(headers: &BTreeMap<String, String>, expected: &str) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(expected))
        .and_then(|(_, value)| value.trim().parse().ok())
}

#[derive(Clone, Debug)]
pub struct LinearGraphQlData<T> {
    pub data: T,
    pub rate_limit: LinearRateLimitReceipt,
}

pub fn decode_graphql<T: DeserializeOwned>(
    response: &LinearGraphQlResponse,
) -> Result<LinearGraphQlData<T>, LinearGraphQlDecodeError> {
    let envelope = serde_json::from_str::<RawGraphQlEnvelope<T>>(&response.body)
        .map_err(|error| LinearGraphQlDecodeError::Malformed(error.to_string()))?;
    let rate_limit = LinearRateLimitReceipt::from_response(response, &envelope.extensions);
    if !(200..300).contains(&response.status) {
        if !envelope.errors.is_empty() {
            return Err(LinearGraphQlDecodeError::Errors {
                message: join_graphql_errors(&envelope.errors),
                errors: Box::new(envelope.errors),
                rate_limit: Box::new(rate_limit),
                status: response.status,
            });
        }
        return Err(LinearGraphQlDecodeError::HttpStatus {
            status: response.status,
            message: format!("HTTP status {}", response.status),
            rate_limit: Box::new(rate_limit),
        });
    }
    if !envelope.errors.is_empty() {
        return Err(LinearGraphQlDecodeError::Errors {
            message: join_graphql_errors(&envelope.errors),
            errors: Box::new(envelope.errors),
            rate_limit: Box::new(rate_limit),
            status: response.status,
        });
    }
    let data = envelope.data.ok_or(LinearGraphQlDecodeError::MissingData {
        rate_limit: Box::new(rate_limit.clone()),
        status: response.status,
    })?;
    Ok(LinearGraphQlData { data, rate_limit })
}

fn join_graphql_errors(errors: &[LinearGraphQlErrorItem]) -> String {
    errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearPageInfo {
    pub has_next_page: bool,
    pub end_cursor: Option<LinearCursor>,
}

impl LinearPageInfo {
    pub fn validate(&self) -> Result<(), LinearGraphQlRequestError> {
        if self.has_next_page && self.end_cursor.is_none() {
            return Err(LinearGraphQlRequestError::InvalidEndpoint(
                "Linear page has next page without an end cursor".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearPageRequest {
    pub first: u16,
    pub after: Option<LinearCursor>,
}

impl LinearPageRequest {
    pub const MAX_PAGE_SIZE: u16 = 100;

    pub fn new(first: u16, after: Option<LinearCursor>) -> Result<Self, LinearIdError> {
        if !(1..=Self::MAX_PAGE_SIZE).contains(&first) {
            return Err(LinearIdError::Invalid { kind: "page size" });
        }
        Ok(Self { first, after })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearWorkflowState {
    pub id: LinearWorkflowStateId,
    pub name: String,
    #[serde(default)]
    pub r#type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearProject {
    pub id: LinearProjectId,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub state: Option<LinearProjectState>,
    #[serde(default)]
    pub start_date: Option<String>,
    #[serde(default)]
    pub target_date: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearProjectState {
    #[serde(default)]
    pub id: Option<LinearWorkflowStateId>,
    pub name: String,
    #[serde(default)]
    pub r#type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearCycle {
    pub id: LinearCycleId,
    pub name: String,
    #[serde(default)]
    pub number: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub starts_at: Option<String>,
    #[serde(default)]
    pub ends_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearIssue {
    pub id: LinearIssueId,
    #[serde(default)]
    pub identifier: Option<String>,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub archived_at: Option<String>,
    #[serde(default)]
    pub state: Option<LinearWorkflowState>,
    #[serde(default)]
    pub project: Option<LinearProjectReference>,
    #[serde(default)]
    pub cycle: Option<LinearCycleReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearProjectReference {
    pub id: LinearProjectId,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearCycleReference {
    pub id: LinearCycleId,
    pub name: String,
    #[serde(default)]
    pub number: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearTeam {
    pub id: LinearTeamId,
    pub name: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LinearViewer {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LinearOrganization {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LinearOAuthProbeData {
    pub viewer: LinearViewer,
    pub organization: LinearOrganization,
    pub teams: LinearTeamCollection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LinearTeamCollection {
    pub nodes: Vec<LinearTeam>,
    #[serde(default)]
    pub page_info: Option<LinearPageInfo>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LinearTeamPageData<T> {
    pub team: Option<LinearTeamResource<T>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LinearTeamResource<T> {
    pub id: LinearTeamId,
    pub issues: Option<LinearResourcePage<T>>,
    pub projects: Option<LinearResourcePage<T>>,
    pub cycles: Option<LinearResourcePage<T>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearResourcePage<T> {
    pub nodes: Vec<T>,
    pub page_info: LinearPageInfo,
}

pub type LinearIssuePage = LinearResourcePage<LinearIssue>;
pub type LinearProjectPage = LinearResourcePage<LinearProject>;
pub type LinearCyclePage = LinearResourcePage<LinearCycle>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LinearResourceKind {
    Issues,
    Projects,
    Cycles,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearReadReceipt {
    pub resource: LinearResourceKind,
    pub team_id: LinearTeamId,
    pub requested_first: u16,
    pub requested_after: Option<LinearCursor>,
    pub returned_count: usize,
    pub page_info: LinearPageInfo,
    pub rate_limit: LinearRateLimitReceipt,
    pub provider_provenance: LinearProviderProvenance,
    pub observed_at_ms: u64,
    pub query_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearReadPage<T> {
    pub nodes: Vec<T>,
    pub read: LinearReadReceipt,
}

impl<T> LinearReadPage<T> {
    pub(crate) fn new(nodes: Vec<T>, read: LinearReadReceipt) -> Self {
        Self { nodes, read }
    }
}

pub(crate) fn request_variables(team_id: &LinearTeamId, page: &LinearPageRequest) -> Value {
    json!({
        "teamId": team_id.as_str(),
        "first": page.first,
        "after": page.after.as_ref().map(LinearCursor::as_str),
    })
}

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::error::{AwsDataSyncTransferError, Result};
use crate::model::{
    AwsDataSyncScope, Cursor, DataSyncTaskStatus, Digest, ExecutionListFilter, ExecutionProjection,
    TaskListFilter, TaskProjection, TransferCountersInput, TransferExecutionState,
    TransferReportMetadata, TransferReportMetadataInput, TransportProvenance,
    validate_response_bytes,
};
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_PAGE_SIZE, PLUGIN_VERSION, PROVIDER_API_REVISION,
    PROVIDER_ID,
};

pub const DESCRIBE_TASK_OPERATION_PATH: &str = "/tasks/{taskDigest}";
pub const DESCRIBE_TASK_EXECUTION_OPERATION_PATH: &str = "/task-executions/{executionDigest}";
pub const LIST_TASKS_OPERATION_PATH: &str = "/tasks";
pub const LIST_TASK_EXECUTIONS_OPERATION_PATH: &str = "/task-executions";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsDataSyncOperation {
    DescribeTask,
    DescribeTaskExecution,
    ListTasks,
    ListTaskExecutions,
}

impl AwsDataSyncOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeTask => "DescribeTask",
            Self::DescribeTaskExecution => "DescribeTaskExecution",
            Self::ListTasks => "ListTasks",
            Self::ListTaskExecutions => "ListTaskExecutions",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::DescribeTask => LAYER1_PERMISSIONS[0],
            Self::DescribeTaskExecution => LAYER1_PERMISSIONS[1],
            Self::ListTasks => LAYER1_PERMISSIONS[2],
            Self::ListTaskExecutions => LAYER1_PERMISSIONS[3],
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsDataSyncTransportError {
    #[error("AWS DataSync returned HTTP 400")]
    BadRequest,
    #[error("AWS DataSync returned HTTP 401")]
    Unauthorized,
    #[error("AWS DataSync returned HTTP 403")]
    Forbidden,
    #[error("AWS DataSync returned HTTP 404")]
    NotFound,
    #[error("AWS DataSync returned HTTP 409")]
    Conflict,
    #[error("AWS DataSync returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS DataSync returned HTTP {status}")]
    ServerError { status: u16 },
    #[error("AWS DataSync request timed out")]
    Timeout,
    #[error("AWS DataSync transport is blocked by the environment")]
    BlockedEnv,
    #[error("AWS DataSync transport returned an invalid response")]
    InvalidResponse,
    #[error("AWS DataSync transport failed ({diagnostic_digest:?})")]
    Transport { diagnostic_digest: Digest },
}

impl AwsDataSyncTransportError {
    pub fn transport(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::Transport {
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::Timeout | Self::BlockedEnv | Self::InvalidResponse | Self::Transport { .. } => {
                None
            }
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout
        )
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerError { .. } => "server_error",
            Self::Timeout => "timeout",
            Self::BlockedEnv => "blocked_env",
            Self::InvalidResponse => "invalid_response",
            Self::Transport { .. } => "transport",
        }
    }

    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Transport { diagnostic_digest } => diagnostic_digest.clone(),
            _ => Digest::from_text(self.kind()),
        }
    }
}

impl From<AwsDataSyncTransportError> for AwsDataSyncTransferError {
    fn from(error: AwsDataSyncTransportError) -> Self {
        match error {
            AwsDataSyncTransportError::BlockedEnv => Self::BlockedEnv,
            AwsDataSyncTransportError::InvalidResponse => Self::TransportInvalid,
            other => Self::Transport {
                kind: other.kind(),
                digest: other.diagnostic_digest(),
            },
        }
    }
}

pub trait AwsDataSyncTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_task(
        &mut self,
        request: &DescribeTaskRequest,
    ) -> std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError>;

    fn describe_task_execution(
        &mut self,
        request: &DescribeTaskExecutionRequest,
    ) -> std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError>;

    fn list_tasks(
        &mut self,
        request: &ListTasksRequest,
    ) -> std::result::Result<ListTasksResponse, AwsDataSyncTransportError>;

    fn list_task_executions(
        &mut self,
        request: &ListTaskExecutionsRequest,
    ) -> std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsDataSyncOperation,
    pub scope_digest: Digest,
    pub task_digest: Digest,
    pub execution_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeTaskRequest {
    scope: AwsDataSyncScope,
    request_digest: Digest,
}

impl DescribeTaskRequest {
    pub fn new(scope: &AwsDataSyncScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datasync-describe-task-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("task", scope.task().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn for_scope(scope: &AwsDataSyncScope) -> Result<Self> {
        Self::new(scope)
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/tasks/{}?account={}&region={}",
            self.scope.task().digest().as_str(),
            self.scope.account().digest().as_str(),
            self.scope.region().digest().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataSyncOperation::DescribeTask,
            scope_digest: self.scope.digest(),
            task_digest: self.scope.task().digest(),
            execution_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeTaskRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeTaskRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeTaskExecutionRequest {
    scope: AwsDataSyncScope,
    execution_digest: Digest,
    request_digest: Digest,
}

impl DescribeTaskExecutionRequest {
    pub fn new(scope: &AwsDataSyncScope, execution_arn: impl Into<String>) -> Result<Self> {
        scope.validate()?;
        let execution = crate::model::DataSyncExecutionArn::new(execution_arn)?;
        Ok(Self {
            scope: scope.clone(),
            execution_digest: execution.digest(),
            request_digest: Digest::from_parts(
                "aws-datasync-describe-task-execution-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("task", scope.task().digest().as_str().to_owned()),
                    ("execution", execution.digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn for_execution(
        scope: &AwsDataSyncScope,
        execution_arn: impl Into<String>,
    ) -> Result<Self> {
        Self::new(scope, execution_arn)
    }

    pub fn from_digest(scope: &AwsDataSyncScope, execution_digest: Digest) -> Result<Self> {
        scope.validate()?;
        execution_digest.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datasync-describe-task-execution-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("task", scope.task().digest().as_str().to_owned()),
                    ("execution", execution_digest.as_str().to_owned()),
                ],
            ),
            execution_digest,
        })
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn execution_digest(&self) -> &Digest {
        &self.execution_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/task-executions/{}?task={}&account={}&region={}",
            self.execution_digest.as_str(),
            self.scope.task().digest().as_str(),
            self.scope.account().digest().as_str(),
            self.scope.region().digest().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataSyncOperation::DescribeTaskExecution,
            scope_digest: self.scope.digest(),
            task_digest: self.scope.task().digest(),
            execution_digest: Some(self.execution_digest.clone()),
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeTaskExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeTaskExecutionRequest")
            .field("scope_digest", &self.scope.digest())
            .field("execution_digest", &self.execution_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListTasksRequest {
    scope: AwsDataSyncScope,
    filter: TaskListFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListTasksRequest {
    pub fn new(scope: &AwsDataSyncScope, page_size: u16, cursor: Option<Cursor>) -> Result<Self> {
        let filter = TaskListFilter::for_scope(scope, page_size)?;
        if let Some(cursor) = &cursor {
            let expected_page = cursor.page_number();
            cursor.validate_against(scope, &filter, expected_page)?;
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datasync-list-tasks-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter.digest().as_str().to_owned()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                    ),
                    (
                        "page",
                        cursor.as_ref().map_or_else(
                            || "1".to_owned(),
                            |value| value.page_number().to_string(),
                        ),
                    ),
                ],
            ),
            filter,
            cursor,
        })
    }

    pub fn for_scope(
        scope: &AwsDataSyncScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        Self::new(scope, page_size, cursor)
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn filter(&self) -> &TaskListFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let cursor = self.cursor.as_ref().map_or_else(String::new, |value| {
            format!("&nextToken={}", value.token_digest().as_str())
        });
        format!(
            "{LIST_TASKS_OPERATION_PATH}?account={}&region={}&maxResults={}{}",
            self.scope.account().digest().as_str(),
            self.scope.region().digest().as_str(),
            self.filter.page_size,
            cursor
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataSyncOperation::ListTasks,
            scope_digest: self.scope.digest(),
            task_digest: self.scope.task().digest(),
            execution_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListTasksRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListTasksRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListTaskExecutionsRequest {
    scope: AwsDataSyncScope,
    filter: ExecutionListFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListTaskExecutionsRequest {
    pub fn new(scope: &AwsDataSyncScope, page_size: u16, cursor: Option<Cursor>) -> Result<Self> {
        let filter = ExecutionListFilter::for_scope(scope, page_size)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter, cursor.page_number())?;
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datasync-list-task-executions-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter.digest().as_str().to_owned()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                    ),
                    (
                        "page",
                        cursor.as_ref().map_or_else(
                            || "1".to_owned(),
                            |value| value.page_number().to_string(),
                        ),
                    ),
                ],
            ),
            filter,
            cursor,
        })
    }

    pub fn for_scope(
        scope: &AwsDataSyncScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        Self::new(scope, page_size, cursor)
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn filter(&self) -> &ExecutionListFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let cursor = self.cursor.as_ref().map_or_else(String::new, |value| {
            format!("&nextToken={}", value.token_digest().as_str())
        });
        format!(
            "{LIST_TASK_EXECUTIONS_OPERATION_PATH}?task={}&account={}&region={}&maxResults={}{}",
            self.scope.task().digest().as_str(),
            self.scope.account().digest().as_str(),
            self.scope.region().digest().as_str(),
            self.filter.page_size,
            cursor
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataSyncOperation::ListTaskExecutions,
            scope_digest: self.scope.digest(),
            task_digest: self.scope.task().digest(),
            execution_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListTaskExecutionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListTaskExecutionsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTaskResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub task: TaskProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl DescribeTaskResponse {
    pub fn new(
        request: &DescribeTaskRequest,
        task: TaskProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        task.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            task,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-aws-datasync-describe-task-response"),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeTaskRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.provider_receipt
            || self.provenance.is_native()
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.task.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-describe-task-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("task", self.task.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTaskExecutionResponse {
    pub scope_digest: Digest,
    pub task_digest: Digest,
    pub execution_digest: Digest,
    pub request_digest: Digest,
    pub execution: ExecutionProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl DescribeTaskExecutionResponse {
    pub fn new(
        request: &DescribeTaskExecutionRequest,
        execution: ExecutionProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        execution.validate_against(request.scope())?;
        if execution.execution_digest != *request.execution_digest() {
            return Err(AwsDataSyncTransferError::ExecutionMismatch);
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            task_digest: request.scope().task().digest(),
            execution_digest: request.execution_digest().clone(),
            request_digest: request.request_digest().clone(),
            execution,
            response_bytes,
            provenance,
            response_digest: Digest::from_text(
                "unsealed-aws-datasync-describe-task-execution-response",
            ),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeTaskExecutionRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.task_digest != request.scope().task().digest()
            || self.execution_digest != *request.execution_digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.provider_receipt
            || self.provenance.is_native()
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.execution.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-describe-task-execution-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("task", self.task_digest.as_str().to_owned()),
                ("execution", self.execution_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.execution.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTasksResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub tasks: Vec<TaskProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl ListTasksResponse {
    pub fn new(
        request: &ListTasksRequest,
        tasks: Vec<TaskProjection>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if tasks.len() > request.filter().page_size as usize {
            return Err(AwsDataSyncTransferError::ResponseItemBoundExceeded);
        }
        for task in &tasks {
            task.validate_against(request.scope())?;
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(
                request.scope(),
                request.filter(),
                request.page_number().saturating_add(1),
            )?;
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            tasks,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-aws-datasync-list-tasks-response"),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListTasksRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.tasks.len() > request.filter().page_size as usize
            || self.connected
            || self.native
            || self.provider_receipt
            || self.provenance.is_native()
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        for task in &self.tasks {
            task.validate_against(request.scope())?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(
                request.scope(),
                request.filter(),
                request.page_number().saturating_add(1),
            )?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-list-tasks-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "tasks",
                    self.tasks
                        .iter()
                        .map(TaskProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTaskExecutionsResponse {
    pub scope_digest: Digest,
    pub task_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub executions: Vec<ExecutionProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl ListTaskExecutionsResponse {
    pub fn new(
        request: &ListTaskExecutionsRequest,
        executions: Vec<ExecutionProjection>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if executions.len() > request.filter().page_size as usize {
            return Err(AwsDataSyncTransferError::ResponseItemBoundExceeded);
        }
        for execution in &executions {
            execution.validate_against(request.scope())?;
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(
                request.scope(),
                request.filter(),
                request.page_number().saturating_add(1),
            )?;
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            task_digest: request.scope().task().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            executions,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text(
                "unsealed-aws-datasync-list-task-executions-response",
            ),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListTaskExecutionsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.task_digest != request.scope().task().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.executions.len() > request.filter().page_size as usize
            || self.connected
            || self.native
            || self.provider_receipt
            || self.provenance.is_native()
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        for execution in &self.executions {
            execution.validate_against(request.scope())?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(
                request.scope(),
                request.filter(),
                request.page_number().saturating_add(1),
            )?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-list-task-executions-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("task", self.task_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "executions",
                    self.executions
                        .iter()
                        .map(ExecutionProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDataSyncProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub api_digest: Digest,
    pub contract_version: String,
    pub plugin_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_receipt: bool,
}

impl AwsDataSyncProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0
            || release.is_empty()
            || release.len() > MAX_PAGE_SIZE as usize * 2
        {
            return Err(AwsDataSyncTransferError::ProviderDrift);
        }
        let api_digest = Digest::from_parts(
            "aws-datasync-provider-api/v1",
            &[
                ("revision", PROVIDER_API_REVISION.to_owned()),
                ("describe_task", DESCRIBE_TASK_OPERATION_PATH.to_owned()),
                (
                    "describe_task_execution",
                    DESCRIBE_TASK_EXECUTION_OPERATION_PATH.to_owned(),
                ),
                ("list_tasks", LIST_TASKS_OPERATION_PATH.to_owned()),
                (
                    "list_task_executions",
                    LIST_TASK_EXECUTIONS_OPERATION_PATH.to_owned(),
                ),
            ],
        );
        let capability_digest = Digest::from_parts(
            "aws-datasync-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-datasync-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("api", api_digest.as_str().to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            api_digest,
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            durable_receipt: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.plugin_version != PLUGIN_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.durable_receipt
            || self.provider_digest != self.calculate_digest()
        {
            return Err(AwsDataSyncTransferError::ProviderDrift);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-provider/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("api_revision", self.api_revision.clone()),
                ("api", self.api_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("release", self.release.clone()),
                ("capability", self.capability_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Debug)]
pub struct AwsDataSyncProvider<T> {
    transport: T,
    definition: AwsDataSyncProviderDefinition,
}

impl<T: AwsDataSyncTransport> AwsDataSyncProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            transport,
            definition: AwsDataSyncProviderDefinition::new(provider_revision, release)?,
        })
    }

    pub fn definition(&self) -> &AwsDataSyncProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn describe_task(
        &mut self,
        request: &DescribeTaskRequest,
    ) -> std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError> {
        let response = self.transport.describe_task(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.provider_receipt
        {
            return Err(AwsDataSyncTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_task_execution(
        &mut self,
        request: &DescribeTaskExecutionRequest,
    ) -> std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError> {
        let response = self.transport.describe_task_execution(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.provider_receipt
        {
            return Err(AwsDataSyncTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn list_tasks(
        &mut self,
        request: &ListTasksRequest,
    ) -> std::result::Result<ListTasksResponse, AwsDataSyncTransportError> {
        let response = self.transport.list_tasks(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.provider_receipt
        {
            return Err(AwsDataSyncTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn list_task_executions(
        &mut self,
        request: &ListTaskExecutionsRequest,
    ) -> std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError> {
        let response = self.transport.list_task_executions(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.provider_receipt
        {
            return Err(AwsDataSyncTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl Default for AwsDataSyncProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked DataSync provider definition")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    describe_task_responses:
        VecDeque<std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError>>,
    describe_task_execution_responses:
        VecDeque<std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError>>,
    list_tasks_responses:
        VecDeque<std::result::Result<ListTasksResponse, AwsDataSyncTransportError>>,
    list_task_executions_responses:
        VecDeque<std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            describe_task_responses: VecDeque::new(),
            describe_task_execution_responses: VecDeque::new(),
            list_tasks_responses: VecDeque::new(),
            list_task_executions_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_describe_task_response(
        &mut self,
        response: std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError>,
    ) {
        self.describe_task_responses.push_back(response);
    }

    pub fn push_describe_task_execution_response(
        &mut self,
        response: std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError>,
    ) {
        self.describe_task_execution_responses.push_back(response);
    }

    pub fn push_list_tasks_response(
        &mut self,
        response: std::result::Result<ListTasksResponse, AwsDataSyncTransportError>,
    ) {
        self.list_tasks_responses.push_back(response);
    }

    pub fn push_list_task_executions_response(
        &mut self,
        response: std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError>,
    ) {
        self.list_task_executions_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsDataSyncTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_task(
        &mut self,
        request: &DescribeTaskRequest,
    ) -> std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_task_responses
            .pop_front()
            .unwrap_or(Err(AwsDataSyncTransportError::InvalidResponse))
    }

    fn describe_task_execution(
        &mut self,
        request: &DescribeTaskExecutionRequest,
    ) -> std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_task_execution_responses
            .pop_front()
            .unwrap_or(Err(AwsDataSyncTransportError::InvalidResponse))
    }

    fn list_tasks(
        &mut self,
        request: &ListTasksRequest,
    ) -> std::result::Result<ListTasksResponse, AwsDataSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.list_tasks_responses
            .pop_front()
            .unwrap_or(Err(AwsDataSyncTransportError::InvalidResponse))
    }

    fn list_task_executions(
        &mut self,
        request: &ListTaskExecutionsRequest,
    ) -> std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.list_task_executions_responses
            .pop_front()
            .unwrap_or(Err(AwsDataSyncTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsDataSyncScope,
    observed_at: DateTime<Utc>,
    execution_state: TransferExecutionState,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsDataSyncScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
            execution_state: TransferExecutionState::Success,
        }
    }

    pub fn with_execution_state(
        scope: &AwsDataSyncScope,
        observed_at: DateTime<Utc>,
        execution_state: TransferExecutionState,
    ) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
            execution_state,
        }
    }

    fn task(&self) -> TaskProjection {
        TaskProjection::for_scope(&self.scope, DataSyncTaskStatus::Available)
    }

    fn execution(&self) -> ExecutionProjection {
        let execution_digest = Digest::from_parts(
            "aws-datasync-fixture-execution/v1",
            &[("task", self.scope.task().digest().as_str().to_owned())],
        );
        let counters = TransferCountersInput {
            bytes_to_transfer: 4_096,
            bytes_transferred: 4_096,
            bytes_verified: 4_096,
            bytes_deleted: 0,
            files_to_transfer: 1,
            files_transferred: 1,
            files_verified: 1,
            files_deleted: 0,
            errors: 0,
        };
        let transfer_report = TransferReportMetadata::from_input(TransferReportMetadataInput {
            report_identifier: Some("fixture-transfer-report".to_owned()),
            report_format: Some("metadata".to_owned()),
            report_size_bytes: Some(512),
        })
        .ok()
        .flatten();
        ExecutionProjection {
            execution_digest,
            task_digest: self.scope.task().digest(),
            status: self.execution_state,
            started_at: Some(self.observed_at),
            ended_at: Some(self.observed_at),
            counters: counters.into(),
            transfer_report,
            error_digest: None,
        }
    }
}

impl AwsDataSyncTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_task(
        &mut self,
        request: &DescribeTaskRequest,
    ) -> std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError> {
        DescribeTaskResponse::new(request, self.task(), 512, self.provenance())
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }

    fn describe_task_execution(
        &mut self,
        request: &DescribeTaskExecutionRequest,
    ) -> std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError> {
        DescribeTaskExecutionResponse::new(request, self.execution(), 512, self.provenance())
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }

    fn list_tasks(
        &mut self,
        request: &ListTasksRequest,
    ) -> std::result::Result<ListTasksResponse, AwsDataSyncTransportError> {
        ListTasksResponse::new(request, vec![self.task()], None, 512, self.provenance())
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }

    fn list_task_executions(
        &mut self,
        request: &ListTaskExecutionsRequest,
    ) -> std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError> {
        ListTaskExecutionsResponse::new(
            request,
            vec![self.execution()],
            None,
            512,
            self.provenance(),
        )
        .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsDataSyncScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }

    pub fn with_execution_state(
        scope: &AwsDataSyncScope,
        observed_at: DateTime<Utc>,
        execution_state: TransferExecutionState,
    ) -> Self {
        Self {
            inner: FixtureTransport::with_execution_state(scope, observed_at, execution_state),
        }
    }
}

impl AwsDataSyncTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_task(
        &mut self,
        request: &DescribeTaskRequest,
    ) -> std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError> {
        DescribeTaskResponse::new(request, self.inner.task(), 512, self.provenance())
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }

    fn describe_task_execution(
        &mut self,
        request: &DescribeTaskExecutionRequest,
    ) -> std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError> {
        DescribeTaskExecutionResponse::new(request, self.inner.execution(), 512, self.provenance())
            .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }

    fn list_tasks(
        &mut self,
        request: &ListTasksRequest,
    ) -> std::result::Result<ListTasksResponse, AwsDataSyncTransportError> {
        ListTasksResponse::new(
            request,
            vec![self.inner.task()],
            None,
            512,
            self.provenance(),
        )
        .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }

    fn list_task_executions(
        &mut self,
        request: &ListTaskExecutionsRequest,
    ) -> std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError> {
        ListTaskExecutionsResponse::new(
            request,
            vec![self.inner.execution()],
            None,
            512,
            self.provenance(),
        )
        .map_err(|_| AwsDataSyncTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsDataSyncTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_task(
        &mut self,
        _request: &DescribeTaskRequest,
    ) -> std::result::Result<DescribeTaskResponse, AwsDataSyncTransportError> {
        Err(AwsDataSyncTransportError::BlockedEnv)
    }

    fn describe_task_execution(
        &mut self,
        _request: &DescribeTaskExecutionRequest,
    ) -> std::result::Result<DescribeTaskExecutionResponse, AwsDataSyncTransportError> {
        Err(AwsDataSyncTransportError::BlockedEnv)
    }

    fn list_tasks(
        &mut self,
        _request: &ListTasksRequest,
    ) -> std::result::Result<ListTasksResponse, AwsDataSyncTransportError> {
        Err(AwsDataSyncTransportError::BlockedEnv)
    }

    fn list_task_executions(
        &mut self,
        _request: &ListTaskExecutionsRequest,
    ) -> std::result::Result<ListTaskExecutionsResponse, AwsDataSyncTransportError> {
        Err(AwsDataSyncTransportError::BlockedEnv)
    }
}

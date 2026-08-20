//! Non-native CloudWatch Logs provider and transport seams.
//!
//! A transport receives digest-bound metadata and returns already-redacted
//! summaries. It has no credential resolver, signer, HTTP client, raw query
//! string, raw log event, or arbitrary AWS operation escape hatch.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_CLOUDWATCH_LOGS_API_REVISION, AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION,
    AWS_CLOUDWATCH_LOGS_PROVIDER_ID,
    model::{
        AwsCloudWatchLogsScope, Digest, EvidenceState, ModelError, OpaqueCursor, PermissionAction,
        PermissionFence, ProviderErrorEvidence, ProviderId, ProviderRevision, QueryExecutionStatus,
        QueryId, ResultSummary, Revision, SecretReference, TimeWindow, TransportError,
        TransportProvenance, digest_serialized,
    },
    query::CloudWatchLogsQuery,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("CloudWatch Logs provider model error: {0}")]
    Model(#[from] ModelError),
    #[error("CloudWatch Logs provider revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl AwsCloudWatchLogsProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_CLOUDWATCH_LOGS_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_CLOUDWATCH_LOGS_API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
                format!("{provenance:?}"),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-api-allowlist/v1",
            &[
                "StartQuery".to_owned(),
                "GetQueryResults".to_owned(),
                "DescribeQueries".to_owned(),
                "POST".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartQueryRequest {
    pub account_id: crate::AccountId,
    pub region: crate::AwsRegion,
    pub log_group: crate::LogGroupName,
    pub window: TimeWindow,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub template_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
}

impl StartQueryRequest {
    pub fn from_query(
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        query: &CloudWatchLogsQuery,
    ) -> Self {
        Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            log_group: query.log_group.clone(),
            window: query.window.clone(),
            query_digest: query.query_digest.clone(),
            config_digest: query.config_digest.clone(),
            template_digest: query.template_digest().clone(),
            scope_digest: query.scope_digest.clone(),
            permission_digest: permission.digest(),
            secret_reference_digest: secret.digest().clone(),
            credential_revision: secret.credential_revision(),
            service_revision: query.service_revision,
            deployment_revision: query.deployment_revision,
        }
    }

    pub fn query_fence(&self) -> QueryFence {
        QueryFence {
            query_digest: self.query_digest.clone(),
            config_digest: self.config_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            service_revision: self.service_revision,
            deployment_revision: self.deployment_revision,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetQueryResultsRequest {
    pub query_id: QueryId,
    pub page_number: u8,
    pub page_token: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub credential_revision: Revision,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub max_results: u16,
    pub max_response_bytes: usize,
}

impl fmt::Debug for GetQueryResultsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetQueryResultsRequest")
            .field("query_id", &self.query_id)
            .field("page_number", &self.page_number)
            .field(
                "page_token_digest",
                &self.page_token.as_ref().map(OpaqueCursor::digest),
            )
            .field("query_digest", &self.query_digest)
            .field("config_digest", &self.config_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("credential_revision", &self.credential_revision)
            .field("service_revision", &self.service_revision)
            .field("deployment_revision", &self.deployment_revision)
            .field("max_results", &self.max_results)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl GetQueryResultsRequest {
    pub fn from_query(
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        query: &CloudWatchLogsQuery,
        query_id: QueryId,
        page_number: u8,
        page_token: Option<OpaqueCursor>,
    ) -> Self {
        Self {
            query_id,
            page_number,
            page_token,
            query_digest: query.query_digest.clone(),
            config_digest: query.config_digest.clone(),
            scope_digest: scope.digest(),
            permission_digest: permission.digest(),
            credential_revision: secret.credential_revision(),
            service_revision: query.service_revision,
            deployment_revision: query.deployment_revision,
            max_results: query.bounds.max_results,
            max_response_bytes: query.bounds.max_response_bytes,
        }
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaqueCursor::digest)
    }

    pub fn query_fence(&self) -> QueryFence {
        QueryFence {
            query_digest: self.query_digest.clone(),
            config_digest: self.config_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            service_revision: self.service_revision,
            deployment_revision: self.deployment_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeQueriesRequest {
    pub account_id: crate::AccountId,
    pub region: crate::AwsRegion,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub credential_revision: Revision,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub max_queries: u16,
}

impl DescribeQueriesRequest {
    pub fn from_query(
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        query: &CloudWatchLogsQuery,
    ) -> Self {
        Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            scope_digest: scope.digest(),
            permission_digest: permission.digest(),
            credential_revision: secret.credential_revision(),
            service_revision: query.service_revision,
            deployment_revision: query.deployment_revision,
            max_queries: 16,
        }
    }

    pub fn fence(&self) -> QueryFence {
        QueryFence {
            query_digest: Digest::zero(),
            config_digest: Digest::zero(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            service_revision: self.service_revision,
            deployment_revision: self.deployment_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryFence {
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
}

pub trait AwsCloudWatchLogsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn start_query(
        &mut self,
        request: &StartQueryRequest,
    ) -> Result<StartQueryResponse, TransportError>;

    fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> Result<GetQueryResultsResponse, TransportError>;

    fn describe_queries(
        &mut self,
        request: &DescribeQueriesRequest,
    ) -> Result<DescribeQueriesResponse, TransportError>;
}

#[derive(Debug)]
pub struct AwsCloudWatchLogsProvider<T> {
    transport: T,
    identity: AwsCloudWatchLogsProviderIdentity,
}

impl<T: AwsCloudWatchLogsTransport> AwsCloudWatchLogsProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsCloudWatchLogsProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AwsCloudWatchLogsProviderIdentity {
        &self.identity
    }

    pub fn definition(&self) -> &AwsCloudWatchLogsProviderIdentity {
        &self.identity
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.identity.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn start_query(
        &mut self,
        request: &StartQueryRequest,
    ) -> Result<StartQueryResponse, TransportError> {
        let response = self.transport.start_query(request)?;
        response
            .validate_for(request)
            .map_err(|_| TransportError::malformed_response())?;
        Ok(response)
    }

    pub fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> Result<GetQueryResultsResponse, TransportError> {
        let response = self.transport.get_query_results(request)?;
        response
            .validate_for(request)
            .map_err(|_| TransportError::malformed_response())?;
        Ok(response)
    }

    pub fn describe_queries(
        &mut self,
        request: &DescribeQueriesRequest,
    ) -> Result<DescribeQueriesResponse, TransportError> {
        let response = self.transport.describe_queries(request)?;
        response
            .validate_for(request)
            .map_err(|_| TransportError::malformed_response())?;
        Ok(response)
    }
}

impl<T: AwsCloudWatchLogsTransport> fmt::Display for AwsCloudWatchLogsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.identity.provider_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartQueryResponse {
    pub query_id: QueryId,
    pub status: QueryExecutionStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub credential_revision: Revision,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub response_digest: Digest,
}

impl StartQueryResponse {
    pub fn new(
        request: &StartQueryRequest,
        query_id: QueryId,
        status: QueryExecutionStatus,
        started_at: DateTime<Utc>,
        finished_at: Option<DateTime<Utc>>,
    ) -> Result<Self, ModelError> {
        if let Some(finished_at) = finished_at
            && finished_at < started_at
        {
            return Err(ModelError::Invalid {
                field: "query timestamp ordering",
            });
        }
        let mut response = Self {
            query_id,
            status,
            started_at,
            finished_at,
            query_digest: request.query_digest.clone(),
            config_digest: request.config_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            credential_revision: request.credential_revision,
            service_revision: request.service_revision,
            deployment_revision: request.deployment_revision,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&StartResponseBody {
            query_id: &self.query_id,
            status: self.status,
            started_at: &self.started_at,
            finished_at: &self.finished_at,
            query_digest: &self.query_digest,
            config_digest: &self.config_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            credential_revision: self.credential_revision,
            service_revision: self.service_revision,
            deployment_revision: self.deployment_revision,
        })
    }

    pub fn validate_for(&self, request: &StartQueryRequest) -> Result<(), ModelError> {
        if self.query_digest != request.query_digest
            || self.config_digest != request.config_digest
            || self.scope_digest != request.scope_digest
            || self.permission_digest != request.permission_digest
            || self.credential_revision != request.credential_revision
            || self.service_revision != request.service_revision
            || self.deployment_revision != request.deployment_revision
            || self.response_digest != self.recomputed_digest()
            || self
                .finished_at
                .is_some_and(|value| value < self.started_at)
        {
            return Err(ModelError::ScopeMismatch {
                field: "StartQuery response binding",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartResponseBody<'a> {
    query_id: &'a QueryId,
    status: QueryExecutionStatus,
    started_at: &'a DateTime<Utc>,
    finished_at: &'a Option<DateTime<Utc>>,
    query_digest: &'a Digest,
    config_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    credential_revision: Revision,
    service_revision: Revision,
    deployment_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQueryResultsResponse {
    pub query_id: QueryId,
    pub page_number: u8,
    pub status: QueryExecutionStatus,
    pub summary: ResultSummary,
    pub next_page_token: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub credential_revision: Revision,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl GetQueryResultsResponse {
    pub fn new(
        request: &GetQueryResultsRequest,
        status: QueryExecutionStatus,
        summary: ResultSummary,
        next_page_token: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        if request.page_number == 0
            || request.page_number > crate::model::MAX_PAGES
            || response_bytes == 0
            || response_bytes > request.max_response_bytes
        {
            return Err(ModelError::Invalid {
                field: "GetQueryResults response bounds",
            });
        }
        summary.validate()?;
        let next_page_token = next_page_token.map(|cursor| cursor.bind(&request.query_digest));
        let mut response = Self {
            query_id: request.query_id.clone(),
            page_number: request.page_number,
            status,
            summary,
            next_page_token,
            query_digest: request.query_digest.clone(),
            config_digest: request.config_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            credential_revision: request.credential_revision,
            service_revision: request.service_revision,
            deployment_revision: request.deployment_revision,
            response_bytes,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&GetResultsBody {
            query_id: &self.query_id,
            page_number: self.page_number,
            status: self.status,
            summary: &self.summary,
            next_page_token: &self.next_page_token,
            query_digest: &self.query_digest,
            config_digest: &self.config_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            credential_revision: self.credential_revision,
            service_revision: self.service_revision,
            deployment_revision: self.deployment_revision,
            response_bytes: self.response_bytes,
        })
    }

    pub fn validate_for(&self, request: &GetQueryResultsRequest) -> Result<(), ModelError> {
        if self.query_id != request.query_id
            || self.page_number != request.page_number
            || self.query_digest != request.query_digest
            || self.config_digest != request.config_digest
            || self.scope_digest != request.scope_digest
            || self.permission_digest != request.permission_digest
            || self.credential_revision != request.credential_revision
            || self.service_revision != request.service_revision
            || self.deployment_revision != request.deployment_revision
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
            || self.response_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "GetQueryResults response binding",
            });
        }
        self.summary.validate()?;
        if let Some(cursor) = &self.next_page_token
            && cursor.binding_digest() != Some(&request.query_digest)
        {
            return Err(ModelError::QueryMismatch {
                field: "next page token",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetResultsBody<'a> {
    query_id: &'a QueryId,
    page_number: u8,
    status: QueryExecutionStatus,
    summary: &'a ResultSummary,
    next_page_token: &'a Option<OpaqueCursor>,
    query_digest: &'a Digest,
    config_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    credential_revision: Revision,
    service_revision: Revision,
    deployment_revision: Revision,
    response_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryExecutionSummary {
    pub query_id: QueryId,
    pub status: QueryExecutionStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub summary_digest: Digest,
}

impl QueryExecutionSummary {
    pub fn from_start(response: &StartQueryResponse) -> Self {
        Self {
            query_id: response.query_id.clone(),
            status: response.status,
            started_at: response.started_at,
            finished_at: response.finished_at,
            query_digest: response.query_digest.clone(),
            config_digest: response.config_digest.clone(),
            scope_digest: response.scope_digest.clone(),
            service_revision: response.service_revision,
            deployment_revision: response.deployment_revision,
            summary_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-logs-query-execution-summary/v1",
                &[
                    response.query_id.digest().to_string(),
                    format!("{:?}", response.status),
                    response.query_digest.to_string(),
                    response.config_digest.to_string(),
                ],
            ),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self
            .finished_at
            .is_some_and(|value| value < self.started_at)
            || self.summary_digest
                != Digest::from_parts(
                    "hartevo-aws-cloudwatch-logs-query-execution-summary/v1",
                    &[
                        self.query_id.digest().to_string(),
                        format!("{:?}", self.status),
                        self.query_digest.to_string(),
                        self.config_digest.to_string(),
                    ],
                )
        {
            return Err(ModelError::Invalid {
                field: "query execution summary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeQueriesResponse {
    pub queries: Vec<QueryExecutionSummary>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub credential_revision: Revision,
    pub service_revision: Revision,
    pub deployment_revision: Revision,
    pub response_digest: Digest,
}

impl DescribeQueriesResponse {
    pub fn new(
        request: &DescribeQueriesRequest,
        queries: Vec<QueryExecutionSummary>,
    ) -> Result<Self, ModelError> {
        if queries.len() > usize::from(request.max_queries) {
            return Err(ModelError::TooMany {
                field: "described queries",
            });
        }
        for query in &queries {
            query.validate()?;
        }
        let mut response = Self {
            queries,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            credential_revision: request.credential_revision,
            service_revision: request.service_revision,
            deployment_revision: request.deployment_revision,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&DescribeBody {
            queries: &self.queries,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            credential_revision: self.credential_revision,
            service_revision: self.service_revision,
            deployment_revision: self.deployment_revision,
        })
    }

    pub fn validate_for(&self, request: &DescribeQueriesRequest) -> Result<(), ModelError> {
        if self.scope_digest != request.scope_digest
            || self.permission_digest != request.permission_digest
            || self.credential_revision != request.credential_revision
            || self.service_revision != request.service_revision
            || self.deployment_revision != request.deployment_revision
            || self.queries.len() > usize::from(request.max_queries)
            || self.response_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeQueries response binding",
            });
        }
        for query in &self.queries {
            query.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DescribeBody<'a> {
    queries: &'a [QueryExecutionSummary],
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    credential_revision: Revision,
    service_revision: Revision,
    deployment_revision: Revision,
}

#[derive(Clone, Debug, Default)]
struct QueuedTransport {
    start_responses: VecDeque<Result<StartQueryResponse, TransportError>>,
    result_responses: VecDeque<Result<GetQueryResultsResponse, TransportError>>,
    describe_responses: VecDeque<Result<DescribeQueriesResponse, TransportError>>,
    start_requests: Vec<StartQueryRequest>,
    result_requests: Vec<GetQueryResultsRequest>,
    describe_requests: Vec<DescribeQueriesRequest>,
}

impl QueuedTransport {
    fn push_start_response(&mut self, response: Result<StartQueryResponse, TransportError>) {
        self.start_responses.push_back(response);
    }

    fn push_result_response(&mut self, response: Result<GetQueryResultsResponse, TransportError>) {
        self.result_responses.push_back(response);
    }

    fn push_describe_response(
        &mut self,
        response: Result<DescribeQueriesResponse, TransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    fn start_query(
        &mut self,
        request: &StartQueryRequest,
    ) -> Result<StartQueryResponse, TransportError> {
        self.start_requests.push(request.clone());
        self.start_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::timeout()))
    }

    fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> Result<GetQueryResultsResponse, TransportError> {
        self.result_requests.push(request.clone());
        self.result_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::timeout()))
    }

    fn describe_queries(
        &mut self,
        request: &DescribeQueriesRequest,
    ) -> Result<DescribeQueriesResponse, TransportError> {
        self.describe_requests.push(request.clone());
        self.describe_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::timeout()))
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            queue: QueuedTransport,
        }

        impl $name {
            pub fn push_start_response(
                &mut self,
                response: Result<StartQueryResponse, TransportError>,
            ) {
                self.queue.push_start_response(response);
            }

            pub fn push_get_query_results_response(
                &mut self,
                response: Result<GetQueryResultsResponse, TransportError>,
            ) {
                self.queue.push_result_response(response);
            }

            pub fn push_describe_queries_response(
                &mut self,
                response: Result<DescribeQueriesResponse, TransportError>,
            ) {
                self.queue.push_describe_response(response);
            }

            pub fn start_requests(&self) -> &[StartQueryRequest] {
                &self.queue.start_requests
            }

            pub fn get_query_results_requests(&self) -> &[GetQueryResultsRequest] {
                &self.queue.result_requests
            }

            pub fn describe_queries_requests(&self) -> &[DescribeQueriesRequest] {
                &self.queue.describe_requests
            }

            pub const fn provenance(&self) -> TransportProvenance {
                $provenance
            }
        }

        impl AwsCloudWatchLogsTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn start_query(
                &mut self,
                request: &StartQueryRequest,
            ) -> Result<StartQueryResponse, TransportError> {
                self.queue.start_query(request)
            }

            fn get_query_results(
                &mut self,
                request: &GetQueryResultsRequest,
            ) -> Result<GetQueryResultsResponse, TransportError> {
                self.queue.get_query_results(request)
            }

            fn describe_queries(
                &mut self,
                request: &DescribeQueriesRequest,
            ) -> Result<DescribeQueriesResponse, TransportError> {
                self.queue.describe_queries(request)
            }
        }
    };
}

queued_transport!(
    RecordingAwsCloudWatchLogsTransport,
    TransportProvenance::Recording
);
queued_transport!(
    FixtureAwsCloudWatchLogsTransport,
    TransportProvenance::Fixture
);
queued_transport!(
    LoopbackAwsCloudWatchLogsTransport,
    TransportProvenance::Loopback
);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsCloudWatchLogsTransport;

impl BlockedEnvAwsCloudWatchLogsTransport {
    pub const fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

impl AwsCloudWatchLogsTransport for BlockedEnvAwsCloudWatchLogsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn start_query(
        &mut self,
        _request: &StartQueryRequest,
    ) -> Result<StartQueryResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_query_results(
        &mut self,
        _request: &GetQueryResultsRequest,
    ) -> Result<GetQueryResultsResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_queries(
        &mut self,
        _request: &DescribeQueriesRequest,
    ) -> Result<DescribeQueriesResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type FakeAwsCloudWatchLogsTransport = FixtureAwsCloudWatchLogsTransport;
pub type RecordingTransport = RecordingAwsCloudWatchLogsTransport;
pub type FixtureTransport = FixtureAwsCloudWatchLogsTransport;
pub type LoopbackTransport = LoopbackAwsCloudWatchLogsTransport;
pub type BlockedEnvTransport = BlockedEnvAwsCloudWatchLogsTransport;
pub type AwsCloudWatchLogsProviderDefinition = AwsCloudWatchLogsProviderIdentity;
pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &TransportError) -> bool {
    error.kind.is_access_loss()
}

pub fn provider_error_evidence(error: &TransportError) -> ProviderErrorEvidence {
    ProviderErrorEvidence::from_error(error)
}

pub fn status_to_evidence(status: QueryExecutionStatus) -> EvidenceState {
    match status {
        QueryExecutionStatus::Complete => EvidenceState::Complete,
        QueryExecutionStatus::Scheduled | QueryExecutionStatus::Running => EvidenceState::Running,
        QueryExecutionStatus::Timeout => EvidenceState::Expired,
        QueryExecutionStatus::Failed | QueryExecutionStatus::Cancelled => EvidenceState::Failed,
        QueryExecutionStatus::Unknown => EvidenceState::ProviderUnknown,
    }
}

pub const ALLOWLISTED_ACTIONS: [PermissionAction; 3] = [
    PermissionAction::StartQuery,
    PermissionAction::GetQueryResults,
    PermissionAction::DescribeQueries,
];

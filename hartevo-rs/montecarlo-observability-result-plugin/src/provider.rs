use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    API_REVISION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    error::ModelError,
    model::{
        ALL_READ_OPERATIONS, Digest, MAX_ITEMS_PER_PAGE, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES,
        MAX_RETRY_ATTEMPTS, MAX_RETRY_DELAY_MILLIS, MonteCarloObservabilityScope, OpaqueCursor,
        ReadOperation, TransportProvenance, page_digest,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    Unauthorized,
    AccessDenied,
    NotFound,
    RateLimited,
    Server,
    Timeout,
    AccessLost,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::AccessLost | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Server | Self::Timeout)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("Monte Carlo transport failure: {failure:?}")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub retry_after_millis: Option<u32>,
    pub diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure, retry_after_millis: Option<u32>) -> Self {
        Self {
            status_code: failure.status_code(),
            retry_after_millis,
            diagnostic_digest: Digest::from_parts(
                "montecarlo-transport-error/v1",
                &[
                    ("failure", format!("{failure:?}")),
                    (
                        "retry_after",
                        retry_after_millis.map_or_else(String::new, |value| value.to_string()),
                    ),
                ],
            ),
            failure,
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv, None)
    }

    pub fn rate_limited(retry_after_millis: Option<u32>) -> Self {
        Self::new(TransportFailure::RateLimited, retry_after_millis)
    }

    pub fn access_denied() -> Self {
        Self::new(TransportFailure::AccessDenied, None)
    }

    pub fn access_lost() -> Self {
        Self::new(TransportFailure::AccessLost, None)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed, None)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("invalid Monte Carlo read request: {0}")]
    InvalidRequest(#[from] ModelError),
    #[error("Monte Carlo transport failed after bounded retries: {error}")]
    Transport {
        error: TransportError,
        retries: Vec<RetryEvidence>,
    },
    #[error("Monte Carlo response did not match the allowlisted operation")]
    UnexpectedResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_delay_millis: u32,
    pub max_delay_millis: u32,
}

impl RetryPolicy {
    pub fn bounded_default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_millis: 250,
            max_delay_millis: MAX_RETRY_DELAY_MILLIS,
        }
    }

    pub fn new(
        max_attempts: u8,
        base_delay_millis: u32,
        max_delay_millis: u32,
    ) -> Result<Self, ModelError> {
        if max_attempts == 0
            || max_attempts > MAX_RETRY_ATTEMPTS
            || base_delay_millis == 0
            || max_delay_millis < base_delay_millis
            || max_delay_millis > MAX_RETRY_DELAY_MILLIS
        {
            return Err(ModelError::InvalidBound {
                field: "retry policy",
            });
        }
        Ok(Self {
            max_attempts,
            base_delay_millis,
            max_delay_millis,
        })
    }

    pub fn delay_millis(&self, failed_attempt: u8, retry_after_millis: Option<u32>) -> u32 {
        let shift = u32::from(failed_attempt.saturating_sub(1)).min(16);
        let exponential = self
            .base_delay_millis
            .saturating_mul(1_u32.checked_shl(shift).unwrap_or(u32::MAX));
        exponential.min(self.max_delay_millis).max(
            retry_after_millis
                .unwrap_or_default()
                .min(self.max_delay_millis),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.max_attempts,
            self.base_delay_millis,
            self.max_delay_millis,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryEvidence {
    pub operation: ReadOperation,
    pub failed_attempt: u8,
    pub delay_millis: u32,
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MonteCarloReadRequest {
    pub operation: ReadOperation,
    pub organization_digest: Digest,
    pub project_digest: Digest,
    pub warehouse_digest: Digest,
    pub table_digest: Digest,
    pub incident_digest: Digest,
    pub lineage_digest: Digest,
    pub monitor_digest: Digest,
    pub time_window_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub cursor: Option<OpaqueCursor>,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub allowlisted: bool,
    pub arbitrary_query: bool,
    pub redacted: bool,
    pub path_digest: Digest,
    pub request_digest: Digest,
}

impl MonteCarloReadRequest {
    pub fn first(
        scope: &MonteCarloObservabilityScope,
        operation: ReadOperation,
    ) -> Result<Self, ModelError> {
        Self::new(scope, operation, None)
    }

    pub fn with_cursor(
        &self,
        scope: &MonteCarloObservabilityScope,
        cursor: OpaqueCursor,
    ) -> Result<Self, ModelError> {
        if cursor.query_digest() != &self.query_digest {
            return Err(ModelError::InvalidCursor);
        }
        Self::new(scope, self.operation, Some(cursor))
    }

    fn new(
        scope: &MonteCarloObservabilityScope,
        operation: ReadOperation,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if !scope.query_policy().allows(operation)
            || !scope.permissions().allows(operation.permission())
        {
            return Err(ModelError::InvalidScope);
        }
        let query_digest = Self::query_digest(scope, operation);
        if let Some(cursor) = &cursor {
            cursor.validate_for(&query_digest)?;
        }
        let path_digest = Digest::from_parts(
            "montecarlo-api-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                (
                    "organization",
                    scope.organization().digest().as_str().to_owned(),
                ),
                (
                    "project",
                    scope.monte_carlo_project().digest().as_str().to_owned(),
                ),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        );
        let mut request = Self {
            operation,
            organization_digest: scope.organization().digest(),
            project_digest: scope.monte_carlo_project().id.digest(),
            warehouse_digest: scope.warehouse().id.digest(),
            table_digest: scope.table().id.digest(),
            incident_digest: scope.incident().id.digest(),
            lineage_digest: scope.lineage().id.digest(),
            monitor_digest: scope.monitor().id.digest(),
            time_window_digest: scope.time_window().digest.clone(),
            scope_digest: scope.digest().clone(),
            query_digest,
            cursor,
            page_size: scope.query_policy().page_size,
            max_response_bytes: scope.query_policy().max_response_bytes,
            allowlisted: true,
            arbitrary_query: false,
            redacted: true,
            path_digest,
            request_digest: Digest::from_text("pending-montecarlo-request"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn query_digest(scope: &MonteCarloObservabilityScope, operation: ReadOperation) -> Digest {
        Digest::from_parts(
            "montecarlo-allowlisted-query/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                (
                    "organization",
                    scope.organization().digest().as_str().to_owned(),
                ),
                (
                    "project",
                    scope.monte_carlo_project().digest().as_str().to_owned(),
                ),
                ("warehouse", scope.warehouse().digest().as_str().to_owned()),
                ("table", scope.table().digest().as_str().to_owned()),
                ("incident", scope.incident().digest().as_str().to_owned()),
                ("lineage", scope.lineage().digest().as_str().to_owned()),
                ("monitor", scope.monitor().digest().as_str().to_owned()),
                ("window", scope.time_window().digest.as_str().to_owned()),
                ("fields", allowlisted_fields(operation)),
            ],
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "montecarlo-read-request/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("organization", self.organization_digest.as_str().to_owned()),
                ("project", self.project_digest.as_str().to_owned()),
                ("warehouse", self.warehouse_digest.as_str().to_owned()),
                ("table", self.table_digest.as_str().to_owned()),
                ("incident", self.incident_digest.as_str().to_owned()),
                ("lineage", self.lineage_digest.as_str().to_owned()),
                ("monitor", self.monitor_digest.as_str().to_owned()),
                ("window", self.time_window_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("page_size", self.page_size.to_string()),
                ("max_bytes", self.max_response_bytes.to_string()),
                ("path", self.path_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self, scope: &MonteCarloObservabilityScope) -> Result<(), ModelError> {
        scope.validate()?;
        for digest in [
            &self.organization_digest,
            &self.project_digest,
            &self.warehouse_digest,
            &self.table_digest,
            &self.incident_digest,
            &self.lineage_digest,
            &self.monitor_digest,
            &self.time_window_digest,
            &self.scope_digest,
            &self.query_digest,
            &self.path_digest,
            &self.request_digest,
        ] {
            digest.validate()?;
        }
        if self.organization_digest != scope.organization().digest()
            || self.project_digest != scope.monte_carlo_project().id.digest()
            || self.warehouse_digest != scope.warehouse().id.digest()
            || self.table_digest != scope.table().id.digest()
            || self.incident_digest != scope.incident().id.digest()
            || self.lineage_digest != scope.lineage().id.digest()
            || self.monitor_digest != scope.monitor().id.digest()
            || self.time_window_digest != scope.time_window().digest
            || self.scope_digest != *scope.digest()
            || self.query_digest != Self::query_digest(scope, self.operation)
            || !scope.query_policy().allows(self.operation)
            || !scope.permissions().allows(self.operation.permission())
            || self
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.validate_for(&self.query_digest).is_err())
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.page_size > scope.query_policy().page_size
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_response_bytes > scope.query_policy().max_response_bytes
            || !self.allowlisted
            || self.arbitrary_query
            || !self.redacted
            || self.compute_digest() != self.request_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

fn allowlisted_fields(operation: ReadOperation) -> String {
    match operation {
        ReadOperation::ReadIncidents => "id,state,severity,affectedTableId,updatedAt".to_owned(),
        ReadOperation::ReadFreshness => "tableId,freshnessState,lagSeconds,observedAt".to_owned(),
        ReadOperation::ReadLineage => {
            "tableId,upstreamCount,downstreamCount,graphDigest,observedAt".to_owned()
        }
        ReadOperation::ReadMonitors => "monitorId,state,enabled,revision,observedAt".to_owned(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderResponse {
    Incidents(crate::model::IncidentPage),
    Freshness(crate::model::FreshnessPage),
    Lineage(crate::model::LineagePage),
    Monitors(crate::model::MonitorPage),
}

impl ProviderResponse {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::Incidents(_) => ReadOperation::ReadIncidents,
            Self::Freshness(_) => ReadOperation::ReadFreshness,
            Self::Lineage(_) => ReadOperation::ReadLineage,
            Self::Monitors(_) => ReadOperation::ReadMonitors,
        }
    }

    pub fn response_digest(&self) -> &Digest {
        match self {
            Self::Incidents(page) => &page.response_digest,
            Self::Freshness(page) => &page.response_digest,
            Self::Lineage(page) => &page.response_digest,
            Self::Monitors(page) => &page.response_digest,
        }
    }

    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        match self {
            Self::Incidents(page) => page.next_cursor.as_ref(),
            Self::Freshness(page) => page.next_cursor.as_ref(),
            Self::Lineage(page) => page.next_cursor.as_ref(),
            Self::Monitors(page) => page.next_cursor.as_ref(),
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Incidents(page) => page.incidents.len(),
            Self::Freshness(page) => page.freshness.len(),
            Self::Lineage(page) => page.lineage.len(),
            Self::Monitors(page) => page.monitors.len(),
        }
    }

    pub fn response_bytes(&self) -> usize {
        match self {
            Self::Incidents(page) => page.response_bytes,
            Self::Freshness(page) => page.response_bytes,
            Self::Lineage(page) => page.response_bytes,
            Self::Monitors(page) => page.response_bytes,
        }
    }

    pub fn redacted(&self) -> bool {
        match self {
            Self::Incidents(page) => page.redacted,
            Self::Freshness(page) => page.redacted,
            Self::Lineage(page) => page.redacted,
            Self::Monitors(page) => page.redacted,
        }
    }

    pub fn validate_for(&self, request: &MonteCarloReadRequest) -> Result<(), ProviderError> {
        if self.operation() != request.operation
            || !self.redacted()
            || self.response_bytes() > request.max_response_bytes
            || self.response_bytes() == 0
            || self.item_count() > usize::from(request.page_size)
            || self.item_count() > MAX_ITEMS_PER_PAGE
        {
            return Err(ProviderError::UnexpectedResponse);
        }
        if let Some(cursor) = self.next_cursor() {
            cursor
                .validate_for(&request.query_digest)
                .map_err(|_| ProviderError::UnexpectedResponse)?;
            if cursor.page() <= request.cursor.as_ref().map_or(0, OpaqueCursor::page) {
                return Err(ProviderError::UnexpectedResponse);
            }
        }
        let scope_bound = match self {
            Self::Incidents(page) => page.incidents.iter().all(|record| {
                record.incident_digest == request.incident_digest
                    && record.affected_table_digest == request.table_digest
            }),
            Self::Freshness(page) => page
                .freshness
                .iter()
                .all(|record| record.table_digest == request.table_digest),
            Self::Lineage(page) => page.lineage.iter().all(|record| {
                record.lineage_digest == request.lineage_digest
                    && record.table_digest == request.table_digest
            }),
            Self::Monitors(page) => page
                .monitors
                .iter()
                .all(|record| record.monitor_digest == request.monitor_digest),
        };
        if !scope_bound {
            return Err(ProviderError::UnexpectedResponse);
        }
        let expected = match self {
            Self::Incidents(page) => page_digest(
                "montecarlo-incident-page/v1",
                page.incidents
                    .iter()
                    .map(crate::model::IncidentRecord::digest),
                page.next_cursor.as_ref(),
            ),
            Self::Freshness(page) => page_digest(
                "montecarlo-freshness-page/v1",
                page.freshness
                    .iter()
                    .map(crate::model::FreshnessRecord::digest),
                page.next_cursor.as_ref(),
            ),
            Self::Lineage(page) => page_digest(
                "montecarlo-lineage-page/v1",
                page.lineage.iter().map(crate::model::LineageRecord::digest),
                page.next_cursor.as_ref(),
            ),
            Self::Monitors(page) => page_digest(
                "montecarlo-monitor-page/v1",
                page.monitors
                    .iter()
                    .map(crate::model::MonitorRecord::digest),
                page.next_cursor.as_ref(),
            ),
        };
        if expected == *self.response_digest() {
            Ok(())
        } else {
            Err(ProviderError::UnexpectedResponse)
        }
    }
}

pub trait MonteCarloTransport: fmt::Debug {
    fn send(&mut self, request: &MonteCarloReadRequest)
    -> Result<ProviderResponse, TransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: String,
    pub api_revision: String,
    pub provenance: TransportProvenance,
    pub operations: Vec<ReadOperation>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub warehouse_queries: bool,
    pub raw_rows: bool,
    pub raw_lineage: bool,
    pub monitor_mutations: bool,
    pub digest: Digest,
}

impl ProviderDefinition {
    fn new(provenance: TransportProvenance) -> Self {
        let operations = ALL_READ_OPERATIONS.to_vec();
        let digest = Digest::from_parts(
            "montecarlo-provider-definition/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("service", SERVICE_ID.to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("api", API_REVISION.to_owned()),
                ("provenance", provenance.contract_name().to_owned()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            id: PROVIDER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            version: PLUGIN_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            provenance,
            operations,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            warehouse_queries: false,
            raw_rows: false,
            raw_lineage: false,
            monitor_mutations: false,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected_digest = Digest::from_parts(
            "montecarlo-provider-definition/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("service", SERVICE_ID.to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("api", API_REVISION.to_owned()),
                ("provenance", self.provenance.contract_name().to_owned()),
                (
                    "operations",
                    ALL_READ_OPERATIONS
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        if self.id != PROVIDER_ID
            || self.service_id != SERVICE_ID
            || self.version != PLUGIN_VERSION
            || self.api_revision != API_REVISION
            || self.operations != ALL_READ_OPERATIONS
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.warehouse_queries
            || self.raw_rows
            || self.raw_lineage
            || self.monitor_mutations
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.digest != expected_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRead {
    pub request_digest: Digest,
    pub response: ProviderResponse,
    pub retries: Vec<RetryEvidence>,
    pub attempts: u8,
    pub provenance: TransportProvenance,
}

pub struct MonteCarloProvider<T> {
    transport: T,
    definition: ProviderDefinition,
    retry_policy: RetryPolicy,
}

impl<T: fmt::Debug> fmt::Debug for MonteCarloProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonteCarloProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl<T: MonteCarloTransport> MonteCarloProvider<T> {
    pub fn new(transport: T, provenance: TransportProvenance) -> Self {
        Self {
            transport,
            definition: ProviderDefinition::new(provenance),
            retry_policy: RetryPolicy::bounded_default(),
        }
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Result<Self, ModelError> {
        retry_policy.validate()?;
        self.retry_policy = retry_policy;
        Ok(self)
    }

    pub fn definition(&self) -> &ProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.digest
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn read(
        &mut self,
        request: &MonteCarloReadRequest,
        scope: &MonteCarloObservabilityScope,
    ) -> Result<ProviderRead, ProviderError> {
        request.validate(scope)?;
        let mut retries = Vec::new();
        for attempt in 1..=self.retry_policy.max_attempts {
            match self.transport.send(request) {
                Ok(response) => {
                    response.validate_for(request)?;
                    return Ok(ProviderRead {
                        request_digest: request.request_digest.clone(),
                        response,
                        retries,
                        attempts: attempt,
                        provenance: self.provenance(),
                    });
                }
                Err(error)
                    if error.failure.retryable() && attempt < self.retry_policy.max_attempts =>
                {
                    retries.push(RetryEvidence {
                        operation: request.operation,
                        failed_attempt: attempt,
                        delay_millis: self
                            .retry_policy
                            .delay_millis(attempt, error.retry_after_millis),
                        failure: error.failure,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest.clone(),
                    });
                }
                Err(error) => {
                    return Err(ProviderError::Transport { error, retries });
                }
            }
        }
        Err(ProviderError::Transport {
            error: TransportError::malformed(),
            retries,
        })
    }
}

impl<T: MonteCarloTransport> MonteCarloProvider<T> {
    pub fn recording(transport: T) -> Self {
        Self::new(transport, TransportProvenance::Recording)
    }

    pub fn fixture(transport: T) -> Self {
        Self::new(transport, TransportProvenance::Fixture)
    }

    pub fn fake(transport: T) -> Self {
        Self::new(transport, TransportProvenance::Fake)
    }

    pub fn loopback(transport: T) -> Self {
        Self::new(transport, TransportProvenance::Loopback)
    }

    pub fn blocked_env(transport: T) -> Self {
        Self::new(transport, TransportProvenance::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvTransport;

impl MonteCarloTransport for BlockedEnvTransport {
    fn send(
        &mut self,
        _request: &MonteCarloReadRequest,
    ) -> Result<ProviderResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub fn blocked_env_provider() -> MonteCarloProvider<BlockedEnvTransport> {
    MonteCarloProvider::blocked_env(BlockedEnvTransport)
}

macro_rules! scripted_transport {
    ($name:ident) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            responses: VecDeque<Result<ProviderResponse, TransportError>>,
        }

        impl $name {
            pub fn new(responses: Vec<Result<ProviderResponse, TransportError>>) -> Self {
                Self {
                    responses: responses.into(),
                }
            }

            pub fn push(&mut self, response: Result<ProviderResponse, TransportError>) {
                self.responses.push_back(response);
            }

            pub fn remaining(&self) -> usize {
                self.responses.len()
            }
        }

        impl MonteCarloTransport for $name {
            fn send(
                &mut self,
                _request: &MonteCarloReadRequest,
            ) -> Result<ProviderResponse, TransportError> {
                self.responses
                    .pop_front()
                    .unwrap_or_else(|| Err(TransportError::malformed()))
            }
        }
    };
}

scripted_transport!(RecordingTransport);
scripted_transport!(FixtureTransport);
scripted_transport!(FakeTransport);
scripted_transport!(LoopbackTransport);

//! Bounded provider requests, response integrity, pagination, and transport
//! fixtures. There is intentionally no HTTP implementation in this module.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    BoundedMetricDigest, ConfluentScope, ConnectorStatus, ConnectorStatusProjection,
    ConsumerGroupLagProjection, ConsumerGroupStatus, Digest, MetricKind, MetricProjection,
    ProjectionCompleteness, ResourceIdentity, TaskStatus, TopicIdentity, TransportProvenance,
};
use crate::service::ConfluentRegistration;
use crate::{
    ConfluentStreamResultError, MAX_METRIC_POINTS, MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES, MAX_PAGES,
    MAX_PARTITIONS, MAX_RESPONSE_BYTES, Result, validate_identifier, validate_text,
};

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfluentTransportError {
    #[error("Confluent API returned 400 Bad Request")]
    BadRequest,
    #[error("Confluent API returned 401 Unauthorized")]
    Unauthorized,
    #[error("Confluent API returned 403 Forbidden")]
    Forbidden,
    #[error("Confluent API returned 404 Not Found")]
    NotFound,
    #[error("Confluent API returned 409 Conflict")]
    Conflict,
    #[error("Confluent API returned 429 Rate Limited; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u32 },
    #[error("Confluent API request timed out")]
    Timeout,
    #[error("Confluent API returned server status {status}")]
    ServerError { status: u16 },
    #[error("Confluent API requires bounded backoff")]
    BackoffRequired,
    #[error("Confluent response was malformed")]
    MalformedResponse,
    #[error("Confluent response was partial")]
    PartialResponse,
    #[error("Confluent access was lost")]
    AccessLost,
    #[error("native Confluent environment is unavailable to Layer 1")]
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfluentProviderError {
    #[error("registration is invalid or drifted")]
    InvalidRegistration,
    #[error("registration binding drifted")]
    RegistrationDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("the API-key SecretReference is revoked")]
    SecretRevoked,
    #[error("request failed its scope or idempotency tamper check")]
    RequestTampered,
    #[error("response failed its digest or provenance tamper check")]
    ResponseTampered,
    #[error("the response scope does not match the exact registration")]
    ScopeMismatch,
    #[error("organization drifted")]
    OrganizationDrift,
    #[error("environment drifted")]
    EnvironmentDrift,
    #[error("cluster drifted")]
    ClusterDrift,
    #[error("topic drifted")]
    TopicDrift,
    #[error("connector drifted")]
    ConnectorDrift,
    #[error("consumer group drifted")]
    ConsumerGroupDrift,
    #[error("partition drifted")]
    PartitionDrift,
    #[error("Project drifted")]
    ProjectDrift,
    #[error("Mission drifted")]
    MissionDrift,
    #[error("Work Product drifted")]
    WorkProductDrift,
    #[error("connector or task revision regressed")]
    ConnectorTaskMonotonicity,
    #[error("consumer-group or partition revision regressed")]
    ConsumerGroupMonotonicity,
    #[error("repeated page token")]
    PaginationLoop,
    #[error("pagination limit exceeded")]
    PaginationLimit,
    #[error("page size is outside the bound")]
    PageSizeLimit,
    #[error("response exceeded the byte bound")]
    ResponseTooLarge,
    #[error("metric window did not match the registration")]
    MetricWindowMismatch,
    #[error("metric is not allowlisted")]
    MetricNotAllowlisted,
    #[error("metric response is malformed or invalid")]
    InvalidProjection,
    #[error("transport error: {0}")]
    Transport(#[from] ConfluentTransportError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorStatusReadRequest {
    pub scope: ConfluentScope,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl ConnectorStatusReadRequest {
    pub fn new(scope: &ConfluentScope, idempotency_key: &str) -> Result<Self> {
        scope.validate()?;
        validate_text(idempotency_key, "idempotencyKey", 256)?;
        let scope_digest = scope.digest();
        let request_digest = Digest::from_parts(
            "confluent-connector-status-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("idempotency", idempotency_key.to_owned()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            scope_digest,
            request_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LagReadRequest {
    pub scope: ConfluentScope,
    pub scope_digest: Digest,
    pub page_size: usize,
    pub page_number: usize,
    pub page_token: Option<String>,
    pub request_digest: Digest,
}

impl LagReadRequest {
    pub fn new(
        scope: &ConfluentScope,
        page_size: usize,
        page_number: usize,
        page_token: Option<String>,
    ) -> Result<Self> {
        scope.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) || page_number == 0 {
            return Err(ConfluentStreamResultError::PageSizeLimit);
        }
        if page_token.as_ref().is_some_and(|token| {
            token.is_empty()
                || token.len() > MAX_PAGE_TOKEN_BYTES
                || token.trim() != token
                || token.chars().any(char::is_control)
        }) {
            return Err(ConfluentStreamResultError::InvalidText { field: "pageToken" });
        }
        let scope_digest = scope.digest();
        let request_digest = Digest::from_serialized(&(
            "confluent-consumer-group-lag-request/v1",
            &scope_digest,
            page_size,
            page_number,
            &page_token,
        ));
        Ok(Self {
            scope: scope.clone(),
            scope_digest,
            page_size,
            page_number,
            page_token,
            request_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsReadRequest {
    pub scope: ConfluentScope,
    pub scope_digest: Digest,
    pub window: crate::MetricWindow,
    pub metrics: Vec<MetricKind>,
    pub request_digest: Digest,
}

impl MetricsReadRequest {
    pub fn new(scope: &ConfluentScope, mut metrics: Vec<MetricKind>) -> Result<Self> {
        scope.validate()?;
        metrics.sort_unstable();
        metrics.dedup();
        if metrics.is_empty() || metrics.iter().any(|metric| !metric.is_allowlisted()) {
            return Err(ConfluentStreamResultError::MetricNotAllowlisted);
        }
        let scope_digest = scope.digest();
        let request_digest = Digest::from_serialized(&(
            "confluent-metrics-request/v1",
            &scope_digest,
            &scope.observation_window,
            &metrics,
        ));
        Ok(Self {
            scope: scope.clone(),
            scope_digest,
            window: scope.observation_window.clone(),
            metrics,
            request_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskStatusRecord {
    pub task_id: String,
    pub revision: u64,
    pub status: TaskStatus,
    pub diagnostic_digest: Option<Digest>,
}

impl TaskStatusRecord {
    pub fn new(
        task_id: impl Into<String>,
        revision: u64,
        status: TaskStatus,
        diagnostic_digest: Option<Digest>,
    ) -> Result<Self> {
        let task_id = task_id.into();
        validate_identifier(&task_id, "taskId")?;
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        if let Some(digest) = &diagnostic_digest {
            digest.validate()?;
        }
        Ok(Self {
            task_id,
            revision,
            status,
            diagnostic_digest,
        })
    }

    fn validate(&self) -> std::result::Result<(), ConfluentProviderError> {
        Self::new(
            self.task_id.clone(),
            self.revision,
            self.status,
            self.diagnostic_digest.clone(),
        )
        .map(|_| ())
        .map_err(|_| ConfluentProviderError::InvalidProjection)
    }

    fn projection(&self) -> crate::model::ConnectorTaskProjection {
        crate::model::ConnectorTaskProjection {
            task_id: self.task_id.clone(),
            revision: self.revision,
            status: self.status,
            diagnostic_digest: self.diagnostic_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorStatusResponse {
    pub request_digest: Digest,
    pub scope: ConfluentScope,
    pub scope_digest: Digest,
    pub connector: ResourceIdentity,
    pub observation_revision: u64,
    pub status: ConnectorStatus,
    pub tasks: Vec<TaskStatusRecord>,
    pub observed_at_epoch_seconds: i64,
    pub completeness: ProjectionCompleteness,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ConnectorStatusResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &ConfluentScope,
        observation_revision: u64,
        status: ConnectorStatus,
        tasks: Vec<TaskStatusRecord>,
        observed_at_epoch_seconds: i64,
        completeness: ProjectionCompleteness,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut response = Self {
            request_digest: Digest::from_text("unbound-confluent-connector-request"),
            scope: scope.clone(),
            scope_digest: scope.digest(),
            connector: scope.connector.clone(),
            observation_revision,
            status,
            tasks,
            observed_at_epoch_seconds,
            completeness,
            response_bytes,
            response_digest: Digest::from_text("unsealed-confluent-connector-response"),
            provenance,
        };
        response.response_digest = response.calculate_digest();
        response.validate_integrity()?;
        Ok(response)
    }

    pub fn for_scope(scope: &ConfluentScope, provenance: TransportProvenance) -> Self {
        Self::new(
            scope,
            1,
            ConnectorStatus::Running,
            vec![
                TaskStatusRecord::new("task-1", 1, TaskStatus::Running, None)
                    .expect("fixture task"),
            ],
            scope.observation_window.start_epoch_seconds + 1,
            ProjectionCompleteness::Complete,
            512,
            provenance,
        )
        .expect("fixture connector response")
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), ConfluentProviderError> {
        self.scope
            .validate()
            .map_err(|_| ConfluentProviderError::InvalidProjection)?;
        self.connector
            .validate()
            .map_err(|_| ConfluentProviderError::InvalidProjection)?;
        if self.scope_digest != self.scope.digest()
            || self.connector != self.scope.connector
            || self.observation_revision == 0
            || self.tasks.len() > MAX_PARTITIONS
            || self.observed_at_epoch_seconds <= 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.request_digest.validate().is_err()
            || self.response_digest != self.calculate_digest()
            || self.provenance.is_native()
            || self.provenance.claims_connected()
        {
            return Err(ConfluentProviderError::ResponseTampered);
        }
        let mut task_ids = BTreeSet::new();
        for task in &self.tasks {
            task.validate()?;
            if !task_ids.insert(task.task_id.clone()) {
                return Err(ConfluentProviderError::InvalidProjection);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope,
            &self.scope_digest,
            &self.connector,
            self.observation_revision,
            self.status,
            &self.tasks,
            self.observed_at_epoch_seconds,
            self.completeness,
            self.response_bytes,
            self.provenance,
        ))
    }

    fn bind_request(&mut self, request_digest: Digest) {
        self.request_digest = request_digest;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LagRecord {
    pub consumer_group: ResourceIdentity,
    pub topic: TopicIdentity,
    pub partition: crate::model::PartitionIdentity,
    pub lag_digest: Digest,
    pub observed_at_epoch_seconds: i64,
}

impl LagRecord {
    pub fn new(
        consumer_group: ResourceIdentity,
        topic: TopicIdentity,
        partition: crate::model::PartitionIdentity,
        lag_digest: Digest,
        observed_at_epoch_seconds: i64,
    ) -> Result<Self> {
        consumer_group.validate()?;
        topic.validate()?;
        partition.validate()?;
        lag_digest.validate()?;
        if observed_at_epoch_seconds <= 0 {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        Ok(Self {
            consumer_group,
            topic,
            partition,
            lag_digest,
            observed_at_epoch_seconds,
        })
    }

    pub fn for_scope(scope: &ConfluentScope, observed_at_epoch_seconds: i64) -> Self {
        Self::new(
            scope.consumer_group.clone(),
            scope.topic.clone(),
            scope.partition.clone(),
            Digest::from_text("fixture-confluent-lag"),
            observed_at_epoch_seconds,
        )
        .expect("fixture lag record")
    }

    fn validate(&self) -> std::result::Result<(), ConfluentProviderError> {
        Self::new(
            self.consumer_group.clone(),
            self.topic.clone(),
            self.partition.clone(),
            self.lag_digest.clone(),
            self.observed_at_epoch_seconds,
        )
        .map(|_| ())
        .map_err(|_| ConfluentProviderError::InvalidProjection)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LagPage {
    pub request_digest: Digest,
    pub scope: ConfluentScope,
    pub scope_digest: Digest,
    pub consumer_group: ResourceIdentity,
    pub observation_revision: u64,
    pub status: ConsumerGroupStatus,
    pub page_number: usize,
    pub entries: Vec<LagRecord>,
    pub next_page_token: Option<String>,
    pub observed_at_epoch_seconds: i64,
    pub completeness: ProjectionCompleteness,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl LagPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &ConfluentScope,
        observation_revision: u64,
        status: ConsumerGroupStatus,
        page_number: usize,
        entries: Vec<LagRecord>,
        next_page_token: Option<String>,
        observed_at_epoch_seconds: i64,
        completeness: ProjectionCompleteness,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut page = Self {
            request_digest: Digest::from_text("unbound-confluent-lag-request"),
            scope: scope.clone(),
            scope_digest: scope.digest(),
            consumer_group: scope.consumer_group.clone(),
            observation_revision,
            status,
            page_number,
            entries,
            next_page_token,
            observed_at_epoch_seconds,
            completeness,
            response_bytes,
            response_digest: Digest::from_text("unsealed-confluent-lag-response"),
            provenance,
        };
        page.response_digest = page.calculate_digest();
        page.validate_integrity()?;
        Ok(page)
    }

    pub fn for_scope(scope: &ConfluentScope, provenance: TransportProvenance) -> Self {
        Self::new(
            scope,
            1,
            ConsumerGroupStatus::Stable,
            1,
            vec![LagRecord::for_scope(
                scope,
                scope.observation_window.start_epoch_seconds + 1,
            )],
            None,
            scope.observation_window.start_epoch_seconds + 1,
            ProjectionCompleteness::Complete,
            512,
            provenance,
        )
        .expect("fixture lag page")
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), ConfluentProviderError> {
        self.scope
            .validate()
            .map_err(|_| ConfluentProviderError::InvalidProjection)?;
        if self.scope_digest != self.scope.digest()
            || self.consumer_group != self.scope.consumer_group
            || self.observation_revision == 0
            || self.page_number == 0
            || self.entries.len() > MAX_PARTITIONS
            || self.observed_at_epoch_seconds <= 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.next_page_token.as_ref().is_some_and(|token| {
                token.is_empty()
                    || token.len() > MAX_PAGE_TOKEN_BYTES
                    || token.trim() != token
                    || token.chars().any(char::is_control)
            })
            || self.request_digest.validate().is_err()
            || self.response_digest != self.calculate_digest()
            || self.provenance.is_native()
            || self.provenance.claims_connected()
        {
            return Err(ConfluentProviderError::ResponseTampered);
        }
        let mut partitions = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !partitions.insert((entry.topic.name.clone(), entry.partition.id)) {
                return Err(ConfluentProviderError::InvalidProjection);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope,
            &self.scope_digest,
            &self.consumer_group,
            self.observation_revision,
            self.status,
            self.page_number,
            &self.entries,
            &self.next_page_token,
            self.observed_at_epoch_seconds,
            self.completeness,
            self.response_bytes,
            self.provenance,
        ))
    }

    fn bind_request(&mut self, request_digest: Digest) {
        self.request_digest = request_digest;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricPoint {
    pub kind: MetricKind,
    pub value_digest: Digest,
    pub observed_at_epoch_seconds: i64,
}

impl MetricPoint {
    pub fn new(
        kind: MetricKind,
        value_digest: Digest,
        observed_at_epoch_seconds: i64,
    ) -> Result<Self> {
        BoundedMetricDigest::new(kind, value_digest.clone(), observed_at_epoch_seconds)?;
        Ok(Self {
            kind,
            value_digest,
            observed_at_epoch_seconds,
        })
    }

    fn validate(&self) -> std::result::Result<(), ConfluentProviderError> {
        Self::new(
            self.kind,
            self.value_digest.clone(),
            self.observed_at_epoch_seconds,
        )
        .map(|_| ())
        .map_err(|_| ConfluentProviderError::InvalidProjection)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsResponse {
    pub request_digest: Digest,
    pub scope: ConfluentScope,
    pub scope_digest: Digest,
    pub window: crate::MetricWindow,
    pub points: Vec<MetricPoint>,
    pub completeness: ProjectionCompleteness,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl MetricsResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &ConfluentScope,
        points: Vec<MetricPoint>,
        completeness: ProjectionCompleteness,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut response = Self {
            request_digest: Digest::from_text("unbound-confluent-metrics-request"),
            scope: scope.clone(),
            scope_digest: scope.digest(),
            window: scope.observation_window.clone(),
            points,
            completeness,
            response_bytes,
            response_digest: Digest::from_text("unsealed-confluent-metrics-response"),
            provenance,
        };
        response.response_digest = response.calculate_digest();
        response.validate_integrity()?;
        Ok(response)
    }

    pub fn for_scope(scope: &ConfluentScope, provenance: TransportProvenance) -> Self {
        let timestamp = scope.observation_window.start_epoch_seconds + 1;
        Self::new(
            scope,
            vec![
                MetricPoint::new(
                    MetricKind::Lag,
                    Digest::from_text("fixture-metric-lag"),
                    timestamp,
                )
                .expect("fixture metric"),
                MetricPoint::new(
                    MetricKind::Throughput,
                    Digest::from_text("fixture-metric-throughput"),
                    timestamp,
                )
                .expect("fixture metric"),
                MetricPoint::new(
                    MetricKind::Latency,
                    Digest::from_text("fixture-metric-latency"),
                    timestamp,
                )
                .expect("fixture metric"),
            ],
            ProjectionCompleteness::Complete,
            512,
            provenance,
        )
        .expect("fixture metrics response")
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), ConfluentProviderError> {
        self.scope
            .validate()
            .map_err(|_| ConfluentProviderError::InvalidProjection)?;
        self.window
            .validate()
            .map_err(|_| ConfluentProviderError::InvalidProjection)?;
        if self.scope_digest != self.scope.digest()
            || self.window != self.scope.observation_window
            || self.points.len() > MAX_METRIC_POINTS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.request_digest.validate().is_err()
            || self.response_digest != self.calculate_digest()
            || self.provenance.is_native()
            || self.provenance.claims_connected()
        {
            return Err(ConfluentProviderError::ResponseTampered);
        }
        let mut previous_timestamp = None;
        for point in &self.points {
            point.validate()?;
            if !self.window.contains(point.observed_at_epoch_seconds) {
                return Err(ConfluentProviderError::MetricWindowMismatch);
            }
            if previous_timestamp.is_some_and(|previous| point.observed_at_epoch_seconds < previous)
            {
                return Err(ConfluentProviderError::InvalidProjection);
            }
            previous_timestamp = Some(point.observed_at_epoch_seconds);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope,
            &self.scope_digest,
            &self.window,
            &self.points,
            self.completeness,
            self.response_bytes,
            self.provenance,
        ))
    }

    fn bind_request(&mut self, request_digest: Digest) {
        self.request_digest = request_digest;
    }
}

/// A transport has exactly three bounded reads. It cannot produce/consume,
/// mutate topics/ACLs/connectors, register events, or resolve credentials.
pub trait ConfluentTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_connector_status(
        &mut self,
        request: &ConnectorStatusReadRequest,
    ) -> std::result::Result<ConnectorStatusResponse, ConfluentTransportError>;

    fn read_consumer_group_lag(
        &mut self,
        request: &LagReadRequest,
    ) -> std::result::Result<LagPage, ConfluentTransportError>;

    fn read_metrics(
        &mut self,
        request: &MetricsReadRequest,
    ) -> std::result::Result<MetricsResponse, ConfluentTransportError>;
}

/// Provider with immutable scope fences and monotonic observation cursors.
#[derive(Debug)]
pub struct ConfluentProvider<T> {
    registration: ConfluentRegistration,
    transport: T,
    last_connector_observation_revision: Option<u64>,
    last_task_revisions: BTreeMap<String, u64>,
    last_group_observation_revision: Option<u64>,
    last_partition_revisions: BTreeMap<u32, u64>,
}

impl<T: ConfluentTransport> ConfluentProvider<T> {
    pub fn new(
        registration: ConfluentRegistration,
        transport: T,
    ) -> std::result::Result<Self, ConfluentProviderError> {
        registration
            .validate()
            .map_err(|_| ConfluentProviderError::InvalidRegistration)?;
        Ok(Self {
            registration,
            transport,
            last_connector_observation_revision: None,
            last_task_revisions: BTreeMap::new(),
            last_group_observation_revision: None,
            last_partition_revisions: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &ConfluentRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut ConfluentRegistration {
        &mut self.registration
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn ensure_ready(&self) -> std::result::Result<(), ConfluentProviderError> {
        self.registration
            .validate()
            .map_err(|_| ConfluentProviderError::RegistrationDrift)?;
        if self.registration.secret_reference().is_revoked() {
            return Err(ConfluentProviderError::SecretRevoked);
        }
        match self.registration.status() {
            crate::RegistrationStatus::Active => Ok(()),
            crate::RegistrationStatus::Revoked => Err(ConfluentProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => {
                Err(ConfluentProviderError::RegistrationReversed)
            }
        }
    }

    pub fn read_connector_status(
        &mut self,
    ) -> std::result::Result<ConnectorStatusProjection, ConfluentProviderError> {
        self.ensure_ready()?;
        let request =
            ConnectorStatusReadRequest::new(self.registration.scope(), "connector-status-read")
                .map_err(|_| ConfluentProviderError::RequestTampered)?;
        let response = self
            .transport
            .read_connector_status(&request)
            .map_err(ConfluentProviderError::Transport)?;
        response.validate_integrity()?;
        self.validate_response_scope(&response.scope)?;
        if response.request_digest != request.request_digest {
            return Err(ConfluentProviderError::RequestTampered);
        }
        if response.provenance != self.provenance() {
            return Err(ConfluentProviderError::ResponseTampered);
        }
        if self
            .last_connector_observation_revision
            .is_some_and(|previous| response.observation_revision < previous)
        {
            return Err(ConfluentProviderError::ConnectorTaskMonotonicity);
        }
        for task in &response.tasks {
            if self
                .last_task_revisions
                .get(&task.task_id)
                .is_some_and(|previous| task.revision < *previous)
            {
                return Err(ConfluentProviderError::ConnectorTaskMonotonicity);
            }
        }
        self.last_connector_observation_revision = Some(response.observation_revision);
        for task in &response.tasks {
            self.last_task_revisions
                .insert(task.task_id.clone(), task.revision);
        }
        let tasks = response
            .tasks
            .iter()
            .map(TaskStatusRecord::projection)
            .collect();
        ConnectorStatusProjection::new(
            self.registration.scope_digest().clone(),
            response.connector,
            response.observation_revision,
            response.status,
            tasks,
            response.observed_at_epoch_seconds,
            response.completeness,
            response.provenance,
        )
        .map_err(|_| ConfluentProviderError::InvalidProjection)
    }

    pub fn read_consumer_group_lag(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<ConsumerGroupLagProjection, ConfluentProviderError> {
        self.ensure_ready()?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(ConfluentProviderError::PageSizeLimit);
        }
        let scope = self.registration.scope().clone();
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_partitions = BTreeSet::new();
        let mut entries = Vec::new();
        let mut timestamps = Vec::new();
        let mut pages_read = 0;
        let mut status = ConsumerGroupStatus::Unknown;
        let mut completeness = ProjectionCompleteness::Complete;
        let mut observation_revision = None;
        loop {
            pages_read += 1;
            if pages_read > MAX_PAGES {
                return Err(ConfluentProviderError::PaginationLimit);
            }
            let request = LagReadRequest::new(&scope, page_size, pages_read, page_token.clone())
                .map_err(|_| ConfluentProviderError::RequestTampered)?;
            let mut page = self
                .transport
                .read_consumer_group_lag(&request)
                .map_err(ConfluentProviderError::Transport)?;
            page.validate_integrity()?;
            self.validate_response_scope(&page.scope)?;
            if page.request_digest != request.request_digest {
                return Err(ConfluentProviderError::RequestTampered);
            }
            if page.page_number != pages_read || page.provenance != self.provenance() {
                return Err(ConfluentProviderError::ResponseTampered);
            }
            if self
                .last_group_observation_revision
                .is_some_and(|previous| page.observation_revision < previous)
                || observation_revision.is_some_and(|previous| page.observation_revision < previous)
            {
                return Err(ConfluentProviderError::ConsumerGroupMonotonicity);
            }
            if observation_revision.is_none() {
                observation_revision = Some(page.observation_revision);
                status = page.status;
            } else if status != page.status {
                status = ConsumerGroupStatus::Unknown;
                completeness = completeness.combine(ProjectionCompleteness::Partial);
            }
            completeness = completeness.combine(page.completeness);
            for entry in &page.entries {
                if entry.consumer_group != scope.consumer_group {
                    return Err(ConfluentProviderError::ConsumerGroupDrift);
                }
                if entry.topic != scope.topic {
                    return Err(ConfluentProviderError::TopicDrift);
                }
                if entry.partition != scope.partition {
                    return Err(ConfluentProviderError::PartitionDrift);
                }
                if !seen_partitions.insert((entry.topic.name.clone(), entry.partition.id)) {
                    return Err(ConfluentProviderError::ResponseTampered);
                }
                if self
                    .last_partition_revisions
                    .get(&entry.partition.id)
                    .is_some_and(|previous| entry.partition.revision < *previous)
                {
                    return Err(ConfluentProviderError::ConsumerGroupMonotonicity);
                }
                entries.push(entry.clone());
                timestamps.push(entry.observed_at_epoch_seconds);
                if entries.len() > MAX_PARTITIONS {
                    return Err(ConfluentProviderError::PaginationLimit);
                }
            }
            self.last_group_observation_revision = Some(page.observation_revision);
            for entry in &page.entries {
                self.last_partition_revisions
                    .insert(entry.partition.id, entry.partition.revision);
            }
            match page.next_page_token.take() {
                None => break,
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(ConfluentProviderError::PaginationLoop);
                    }
                    page_token = Some(next);
                }
            }
        }
        timestamps.sort_unstable();
        let observation_revision = observation_revision.unwrap_or(1);
        let lag_digest = Digest::from_serialized(&entries);
        ConsumerGroupLagProjection::new(
            self.registration.scope_digest().clone(),
            scope.consumer_group,
            observation_revision,
            status,
            entries.len(),
            lag_digest,
            timestamps,
            pages_read,
            completeness,
            self.provenance(),
        )
        .map_err(|_| ConfluentProviderError::InvalidProjection)
    }

    pub fn read_metric_window(
        &mut self,
    ) -> std::result::Result<MetricProjection, ConfluentProviderError> {
        self.read_metrics(vec![
            MetricKind::Lag,
            MetricKind::Throughput,
            MetricKind::Latency,
        ])
    }

    pub fn read_metrics(
        &mut self,
        metrics: Vec<MetricKind>,
    ) -> std::result::Result<MetricProjection, ConfluentProviderError> {
        self.ensure_ready()?;
        let request = MetricsReadRequest::new(self.registration.scope(), metrics).map_err(
            |error| match error {
                ConfluentStreamResultError::MetricNotAllowlisted => {
                    ConfluentProviderError::MetricNotAllowlisted
                }
                _ => ConfluentProviderError::RequestTampered,
            },
        )?;
        let response = self
            .transport
            .read_metrics(&request)
            .map_err(ConfluentProviderError::Transport)?;
        response.validate_integrity()?;
        self.validate_response_scope(&response.scope)?;
        if response.request_digest != request.request_digest {
            return Err(ConfluentProviderError::RequestTampered);
        }
        if response.window != request.window {
            return Err(ConfluentProviderError::MetricWindowMismatch);
        }
        if response.provenance != self.provenance() {
            return Err(ConfluentProviderError::ResponseTampered);
        }
        let digest_for = |kind: MetricKind| {
            let points = response
                .points
                .iter()
                .filter(|point| point.kind == kind)
                .collect::<Vec<_>>();
            (!points.is_empty()).then(|| Digest::from_serialized(&points))
        };
        let timestamps = response
            .points
            .iter()
            .map(|point| point.observed_at_epoch_seconds)
            .collect::<Vec<_>>();
        MetricProjection::new(
            self.registration.scope_digest().clone(),
            response.window,
            digest_for(MetricKind::Lag),
            digest_for(MetricKind::Throughput),
            digest_for(MetricKind::Latency),
            timestamps,
            response.completeness,
            response.provenance,
        )
        .map_err(|_| ConfluentProviderError::InvalidProjection)
    }

    fn validate_response_scope(
        &self,
        actual: &ConfluentScope,
    ) -> std::result::Result<(), ConfluentProviderError> {
        let expected = self.registration.scope();
        actual
            .validate()
            .map_err(|_| ConfluentProviderError::ResponseTampered)?;
        if actual.organization != expected.organization {
            return Err(ConfluentProviderError::OrganizationDrift);
        }
        if actual.environment != expected.environment {
            return Err(ConfluentProviderError::EnvironmentDrift);
        }
        if actual.cluster != expected.cluster {
            return Err(ConfluentProviderError::ClusterDrift);
        }
        if actual.topic != expected.topic {
            return Err(ConfluentProviderError::TopicDrift);
        }
        if actual.connector != expected.connector {
            return Err(ConfluentProviderError::ConnectorDrift);
        }
        if actual.consumer_group != expected.consumer_group {
            return Err(ConfluentProviderError::ConsumerGroupDrift);
        }
        if actual.partition != expected.partition {
            return Err(ConfluentProviderError::PartitionDrift);
        }
        if actual.project != expected.project {
            return Err(ConfluentProviderError::ProjectDrift);
        }
        if actual.mission != expected.mission {
            return Err(ConfluentProviderError::MissionDrift);
        }
        if actual.work_product != expected.work_product {
            return Err(ConfluentProviderError::WorkProductDrift);
        }
        if actual.observation_window != expected.observation_window
            || actual.policy_revision != expected.policy_revision
        {
            return Err(ConfluentProviderError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct FixtureState {
    connector: Option<ConnectorStatusResponse>,
    lag_pages: VecDeque<LagPage>,
    metrics: Option<MetricsResponse>,
    connector_error: Option<ConfluentTransportError>,
    lag_error: Option<ConfluentTransportError>,
    metrics_error: Option<ConfluentTransportError>,
}

impl FixtureState {
    fn from_scope(scope: &ConfluentScope, provenance: TransportProvenance) -> Self {
        Self {
            connector: Some(ConnectorStatusResponse::for_scope(scope, provenance)),
            lag_pages: VecDeque::from([LagPage::for_scope(scope, provenance)]),
            metrics: Some(MetricsResponse::for_scope(scope, provenance)),
            connector_error: None,
            lag_error: None,
            metrics_error: None,
        }
    }

    fn read_connector(
        &mut self,
        request: &ConnectorStatusReadRequest,
    ) -> std::result::Result<ConnectorStatusResponse, ConfluentTransportError> {
        if let Some(error) = self.connector_error.clone() {
            return Err(error);
        }
        let mut response = self
            .connector
            .clone()
            .ok_or(ConfluentTransportError::NotFound)?;
        response.bind_request(request.request_digest.clone());
        Ok(response)
    }

    fn read_lag(
        &mut self,
        request: &LagReadRequest,
    ) -> std::result::Result<LagPage, ConfluentTransportError> {
        if let Some(error) = self.lag_error.clone() {
            return Err(error);
        }
        let mut page = self
            .lag_pages
            .pop_front()
            .ok_or(ConfluentTransportError::NotFound)?;
        page.bind_request(request.request_digest.clone());
        Ok(page)
    }

    fn read_metrics(
        &mut self,
        request: &MetricsReadRequest,
    ) -> std::result::Result<MetricsResponse, ConfluentTransportError> {
        if let Some(error) = self.metrics_error.clone() {
            return Err(error);
        }
        let mut response = self
            .metrics
            .clone()
            .ok_or(ConfluentTransportError::NotFound)?;
        response.bind_request(request.request_digest.clone());
        Ok(response)
    }
}

macro_rules! fixture_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            state: FixtureState,
        }

        impl $name {
            pub fn from_scope(scope: &ConfluentScope) -> Self {
                Self {
                    state: FixtureState::from_scope(scope, $provenance),
                }
            }

            pub fn new(
                connector: ConnectorStatusResponse,
                lag_pages: Vec<LagPage>,
                metrics: MetricsResponse,
            ) -> Self {
                Self {
                    state: FixtureState {
                        connector: Some(connector),
                        lag_pages: lag_pages.into_iter().collect(),
                        metrics: Some(metrics),
                        connector_error: None,
                        lag_error: None,
                        metrics_error: None,
                    },
                }
            }

            #[must_use]
            pub fn fail_connector_with(mut self, error: ConfluentTransportError) -> Self {
                self.state.connector_error = Some(error);
                self
            }

            #[must_use]
            pub fn fail_lag_with(mut self, error: ConfluentTransportError) -> Self {
                self.state.lag_error = Some(error);
                self
            }

            #[must_use]
            pub fn fail_metrics_with(mut self, error: ConfluentTransportError) -> Self {
                self.state.metrics_error = Some(error);
                self
            }

            pub fn set_connector(&mut self, response: ConnectorStatusResponse) {
                self.state.connector = Some(response);
            }

            pub fn set_lag_pages(&mut self, pages: Vec<LagPage>) {
                self.state.lag_pages = pages.into_iter().collect();
            }

            pub fn set_metrics(&mut self, response: MetricsResponse) {
                self.state.metrics = Some(response);
            }
        }

        impl ConfluentTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn read_connector_status(
                &mut self,
                request: &ConnectorStatusReadRequest,
            ) -> std::result::Result<ConnectorStatusResponse, ConfluentTransportError> {
                self.state.read_connector(request)
            }

            fn read_consumer_group_lag(
                &mut self,
                request: &LagReadRequest,
            ) -> std::result::Result<LagPage, ConfluentTransportError> {
                self.state.read_lag(request)
            }

            fn read_metrics(
                &mut self,
                request: &MetricsReadRequest,
            ) -> std::result::Result<MetricsResponse, ConfluentTransportError> {
                self.state.read_metrics(request)
            }
        }
    };
}

fixture_transport!(RecordingTransport, TransportProvenance::Recording);
fixture_transport!(FakeTransport, TransportProvenance::Fixture);
fixture_transport!(LoopbackTransport, TransportProvenance::Loopback);

/// The native gap is honest: no data path exists and every read is blocked.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl ConfluentTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_connector_status(
        &mut self,
        _request: &ConnectorStatusReadRequest,
    ) -> std::result::Result<ConnectorStatusResponse, ConfluentTransportError> {
        Err(ConfluentTransportError::BlockedEnv)
    }

    fn read_consumer_group_lag(
        &mut self,
        _request: &LagReadRequest,
    ) -> std::result::Result<LagPage, ConfluentTransportError> {
        Err(ConfluentTransportError::BlockedEnv)
    }

    fn read_metrics(
        &mut self,
        _request: &MetricsReadRequest,
    ) -> std::result::Result<MetricsResponse, ConfluentTransportError> {
        Err(ConfluentTransportError::BlockedEnv)
    }
}

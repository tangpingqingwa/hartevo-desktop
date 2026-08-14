//! Metadata-only CloudWatch provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver,
//! HTTP client, alarm mutation API, dashboard API, log API, or PutMetricData
//! path in this Layer-1 crate. Transports are recording, fixture, loopback,
//! or `BLOCKED_ENV`, and every one is permanently non-connected, non-native,
//! and non-first-party.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AlarmSnapshot, AwsCloudWatchAlarmScope, AwsCloudWatchOperation, CostReceipt, Digest,
    MetricDataAggregate, MetricIdentity, OpaqueCursor, ProviderErrorEvidence, ProviderErrorKind,
    ProviderRevision, RedactedRequestReceipt, TransportProvenance, digest_serialized,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, MAX_DATAPOINTS, MAX_METRIC_RESULTS, MAX_PAGES,
    MAX_RESPONSE_BYTES, PROVIDER_ID,
};

pub const DESCRIBE_ALARMS_OPERATION_PATH: &str = "/";
pub const GET_METRIC_DATA_OPERATION_PATH: &str = "/";
pub const LIST_METRICS_OPERATION_PATH: &str = "/";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsCloudWatchTransportError {
    #[error("CloudWatch provider returned HTTP 400")]
    BadRequest,
    #[error("CloudWatch provider rejected the request with HTTP 401")]
    Unauthenticated,
    #[error("CloudWatch provider denied the request with HTTP 403")]
    AccessDenied,
    #[error("CloudWatch alarm or metric was not found with HTTP 404")]
    NotFound,
    #[error("CloudWatch provider rate limited the request with HTTP 429")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("CloudWatch provider returned HTTP {status_code}")]
    ServerFailure { status_code: u16 },
    #[error("CloudWatch provider timed out")]
    Timeout,
    #[error("CloudWatch native transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("CloudWatch provider response was malformed")]
    MalformedResponse,
    #[error("CloudWatch provider returned an empty response")]
    EmptyResponse,
    #[error("CloudWatch provider returned a partial response")]
    PartialResponse,
    #[error("CloudWatch provider scan loop detected")]
    ScanLoop,
    #[error("CloudWatch provider returned an unknown error")]
    Unknown,
}

impl AwsCloudWatchTransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::BadRequest => ProviderErrorKind::BadRequest,
            Self::Unauthenticated => ProviderErrorKind::Unauthenticated,
            Self::AccessDenied => ProviderErrorKind::AccessDenied,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnv => ProviderErrorKind::BlockedEnvironment,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::EmptyResponse => ProviderErrorKind::EmptyResponse,
            Self::PartialResponse => ProviderErrorKind::PartialResponse,
            Self::ScanLoop => ProviderErrorKind::ScanLoop,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthenticated => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => Some(*status_code),
            Self::Timeout
            | Self::BlockedEnv
            | Self::MalformedResponse
            | Self::EmptyResponse
            | Self::PartialResponse
            | Self::ScanLoop
            | Self::Unknown => None,
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence::new(self.kind(), self.status_code(), self.retry_after_seconds())
    }

    pub const fn from_status(status_code: u16) -> Self {
        match status_code {
            400 => Self::BadRequest,
            401 => Self::Unauthenticated,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            500..=599 => Self::ServerFailure { status_code },
            _ => Self::Unknown,
        }
    }
}

pub type TransportError = AwsCloudWatchTransportError;
pub type ProviderError = AwsCloudWatchProviderError;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsCloudWatchProviderError {
    #[error("CloudWatch provider transport failed: {0}")]
    Transport(#[from] AwsCloudWatchTransportError),
    #[error("CloudWatch provider response was invalid or tampered")]
    InvalidResponse,
    #[error("CloudWatch provider request binding was invalid")]
    RequestBinding,
    #[error("CloudWatch provider identity drifted")]
    ProviderDrift,
}

pub type AwsCloudWatchOperationError = AwsCloudWatchProviderError;

/// The only provider transport trait exposed by Layer 1.
pub trait AwsCloudWatchTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_alarms(
        &mut self,
        request: &DescribeAlarmsRequest,
    ) -> Result<DescribeAlarmsResponse, AwsCloudWatchTransportError>;

    fn get_metric_data(
        &mut self,
        request: &GetMetricDataRequest,
    ) -> Result<GetMetricDataResponse, AwsCloudWatchTransportError>;

    fn list_metrics(
        &mut self,
        request: &ListMetricsRequest,
    ) -> Result<ListMetricsResponse, AwsCloudWatchTransportError>;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsCloudWatchOperation,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub path_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAlarmsRequest {
    pub scope: AwsCloudWatchAlarmScope,
    pub max_results: u16,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub request_digest: Digest,
}

impl DescribeAlarmsRequest {
    pub fn for_scope(scope: &AwsCloudWatchAlarmScope) -> Result<Self, AwsCloudWatchProviderError> {
        scope
            .validate()
            .map_err(|_| AwsCloudWatchProviderError::RequestBinding)?;
        Self::new(scope, None)
    }

    pub fn new(
        scope: &AwsCloudWatchAlarmScope,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        if let Some(cursor) = &cursor
            && cursor.page_number() == 0
        {
            return Err(AwsCloudWatchProviderError::RequestBinding);
        }
        let query_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-describe-alarms-query/v1",
            [
                ("scope", scope.digest().as_str()),
                ("alarm", scope.alarm.name.as_str()),
                ("revision", &scope.alarm.revision.get().to_string()),
                ("max_results", "1"),
            ],
        );
        let cursor = cursor.map(|cursor| cursor.bind(&query_digest));
        let request_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-describe-alarms-request/v1",
            [
                ("query", query_digest.as_str()),
                (
                    "page",
                    &cursor
                        .as_ref()
                        .map_or(1, OpaqueCursor::page_number)
                        .to_string(),
                ),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or("", |value| value.token_digest().as_str()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            max_results: 1,
            cursor,
            query_digest,
            request_digest,
        })
    }

    pub fn with_cursor(&self, cursor: OpaqueCursor) -> Result<Self, AwsCloudWatchProviderError> {
        Self::new(&self.scope, Some(cursor))
    }

    pub fn operation(&self) -> AwsCloudWatchOperation {
        AwsCloudWatchOperation::DescribeAlarms
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: self.operation(),
            scope_digest: self.scope.digest(),
            query_digest: self.query_digest.clone(),
            request_digest: self.request_digest.clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            path_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-describe-alarms-path/v1",
                [
                    ("account", self.scope.account_id.as_str()),
                    ("region", self.scope.region.as_str()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMetricDataRequest {
    pub scope: AwsCloudWatchAlarmScope,
    pub metric: MetricIdentity,
    pub window: crate::model::MetricWindow,
    pub max_datapoints: u32,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub request_digest: Digest,
}

impl GetMetricDataRequest {
    pub fn for_scope(scope: &AwsCloudWatchAlarmScope) -> Result<Self, AwsCloudWatchProviderError> {
        Self::new(scope, None)
    }

    pub fn new(
        scope: &AwsCloudWatchAlarmScope,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        scope
            .validate()
            .map_err(|_| AwsCloudWatchProviderError::RequestBinding)?;
        let query_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-get-metric-data-query/v1",
            [
                ("scope", scope.digest().as_str()),
                ("metric", scope.metric.digest().as_str()),
                ("window", scope.window.digest().as_str()),
                ("max_datapoints", &MAX_DATAPOINTS.to_string()),
            ],
        );
        let cursor = cursor.map(|cursor| cursor.bind(&query_digest));
        let request_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-get-metric-data-request/v1",
            [
                ("query", query_digest.as_str()),
                (
                    "page",
                    &cursor
                        .as_ref()
                        .map_or(1, OpaqueCursor::page_number)
                        .to_string(),
                ),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or("", |value| value.token_digest().as_str()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            metric: scope.metric.clone(),
            window: scope.window.clone(),
            max_datapoints: MAX_DATAPOINTS as u32,
            cursor,
            query_digest,
            request_digest,
        })
    }

    pub fn with_cursor(&self, cursor: OpaqueCursor) -> Result<Self, AwsCloudWatchProviderError> {
        Self::new(&self.scope, Some(cursor))
    }

    pub fn operation(&self) -> AwsCloudWatchOperation {
        AwsCloudWatchOperation::GetMetricData
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: self.operation(),
            scope_digest: self.scope.digest(),
            query_digest: self.query_digest.clone(),
            request_digest: self.request_digest.clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            path_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-get-metric-data-path/v1",
                [
                    ("account", self.scope.account_id.as_str()),
                    ("region", self.scope.region.as_str()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMetricsRequest {
    pub scope: AwsCloudWatchAlarmScope,
    pub metric: MetricIdentity,
    pub max_results: u16,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub request_digest: Digest,
}

impl ListMetricsRequest {
    pub fn for_scope(scope: &AwsCloudWatchAlarmScope) -> Result<Self, AwsCloudWatchProviderError> {
        Self::new(scope, None)
    }

    pub fn new(
        scope: &AwsCloudWatchAlarmScope,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        if !scope.allow_metric_discovery {
            return Err(AwsCloudWatchProviderError::RequestBinding);
        }
        let query_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-list-metrics-query/v1",
            [
                ("scope", scope.digest().as_str()),
                ("namespace", scope.metric.namespace.as_str()),
                ("metric", scope.metric.metric_name.as_str()),
                ("dimensions", scope.metric.dimensions_digest.as_str()),
                ("max_results", &MAX_METRIC_RESULTS.to_string()),
            ],
        );
        let cursor = cursor.map(|cursor| cursor.bind(&query_digest));
        let request_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-list-metrics-request/v1",
            [
                ("query", query_digest.as_str()),
                (
                    "page",
                    &cursor
                        .as_ref()
                        .map_or(1, OpaqueCursor::page_number)
                        .to_string(),
                ),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or("", |value| value.token_digest().as_str()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            metric: scope.metric.clone(),
            max_results: MAX_METRIC_RESULTS as u16,
            cursor,
            query_digest,
            request_digest,
        })
    }

    pub fn with_cursor(&self, cursor: OpaqueCursor) -> Result<Self, AwsCloudWatchProviderError> {
        Self::new(&self.scope, Some(cursor))
    }

    pub fn operation(&self) -> AwsCloudWatchOperation {
        AwsCloudWatchOperation::ListMetrics
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: self.operation(),
            scope_digest: self.scope.digest(),
            query_digest: self.query_digest.clone(),
            request_digest: self.request_digest.clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            path_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-list-metrics-path/v1",
                [
                    ("account", self.scope.account_id.as_str()),
                    ("region", self.scope.region.as_str()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAlarmsResponse {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub alarms: Vec<AlarmSnapshot>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub cost: CostReceipt,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeAlarmsResponse {
    pub fn new(
        request: &DescribeAlarmsRequest,
        alarms: Vec<AlarmSnapshot>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        if alarms.len() > 1 || response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        for alarm in &alarms {
            alarm
                .validate_against(&request.scope)
                .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        }
        let next_cursor = validate_next_cursor(
            next_cursor,
            request.query_digest.clone(),
            request.page_number(),
        )?;
        let cost = CostReceipt::new(request.request_digest.clone(), 1, 0, response_bytes)
            .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        let mut response = Self {
            scope_digest: request.scope.digest(),
            query_digest: request.query_digest.clone(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number(),
            alarms,
            next_cursor,
            response_bytes,
            cost,
            provenance,
            response_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeAlarmsRequest,
    ) -> Result<(), AwsCloudWatchProviderError> {
        if self.scope_digest != request.scope.digest()
            || self.query_digest != request.query_digest
            || self.request_digest != request.request_digest
            || self.page_number != request.page_number()
            || self.alarms.len() > 1
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.cost.request_digest != request.request_digest
            || self.cost.response_bytes != self.response_bytes
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.response_digest != self.recomputed_digest()
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        for alarm in &self.alarms {
            alarm
                .validate_against(&request.scope)
                .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        }
        if let Some(cursor) = &self.next_cursor
            && (cursor.binding_digest() != Some(&request.query_digest)
                || cursor.page_number() != request.page_number().saturating_add(1))
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.query_digest,
            &self.request_digest,
            self.page_number,
            &self.alarms,
            &self.next_cursor,
            self.response_bytes,
            &self.cost,
            self.provenance,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMetricDataResponse {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub aggregates: Vec<MetricDataAggregate>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub cost: CostReceipt,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetMetricDataResponse {
    pub fn new(
        request: &GetMetricDataRequest,
        aggregates: Vec<MetricDataAggregate>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        if aggregates.len() > 1 || response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        let returned_datapoints = aggregates
            .iter()
            .map(|aggregate| aggregate.datapoint_count)
            .sum::<u32>();
        if usize::try_from(returned_datapoints).unwrap_or(usize::MAX) > MAX_DATAPOINTS {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        for aggregate in &aggregates {
            aggregate
                .validate_against(&request.scope)
                .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        }
        let next_cursor = validate_next_cursor(
            next_cursor,
            request.query_digest.clone(),
            request.page_number(),
        )?;
        let cost = CostReceipt::new(
            request.request_digest.clone(),
            1,
            returned_datapoints,
            response_bytes,
        )
        .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        let mut response = Self {
            scope_digest: request.scope.digest(),
            query_digest: request.query_digest.clone(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number(),
            aggregates,
            next_cursor,
            response_bytes,
            cost,
            provenance,
            response_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &GetMetricDataRequest,
    ) -> Result<(), AwsCloudWatchProviderError> {
        let returned_datapoints = self
            .aggregates
            .iter()
            .map(|aggregate| aggregate.datapoint_count)
            .sum::<u32>();
        if self.scope_digest != request.scope.digest()
            || self.query_digest != request.query_digest
            || self.request_digest != request.request_digest
            || self.page_number != request.page_number()
            || self.aggregates.len() > 1
            || usize::try_from(returned_datapoints).unwrap_or(usize::MAX) > MAX_DATAPOINTS
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.cost.request_digest != request.request_digest
            || self.cost.response_bytes != self.response_bytes
            || self.cost.returned_datapoints != returned_datapoints
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.response_digest != self.recomputed_digest()
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        for aggregate in &self.aggregates {
            aggregate
                .validate_against(&request.scope)
                .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        }
        if let Some(cursor) = &self.next_cursor
            && (cursor.binding_digest() != Some(&request.query_digest)
                || cursor.page_number() != request.page_number().saturating_add(1))
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.query_digest,
            &self.request_digest,
            self.page_number,
            &self.aggregates,
            &self.next_cursor,
            self.response_bytes,
            &self.cost,
            self.provenance,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMetricsResponse {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub metrics: Vec<MetricIdentity>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub cost: CostReceipt,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListMetricsResponse {
    pub fn new(
        request: &ListMetricsRequest,
        metrics: Vec<MetricIdentity>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        if metrics.len() > MAX_METRIC_RESULTS
            || response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        let next_cursor = validate_next_cursor(
            next_cursor,
            request.query_digest.clone(),
            request.page_number(),
        )?;
        let cost = CostReceipt::new(request.request_digest.clone(), 1, 0, response_bytes)
            .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        let mut response = Self {
            scope_digest: request.scope.digest(),
            query_digest: request.query_digest.clone(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number(),
            metrics,
            next_cursor,
            response_bytes,
            cost,
            provenance,
            response_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &ListMetricsRequest,
    ) -> Result<(), AwsCloudWatchProviderError> {
        if self.scope_digest != request.scope.digest()
            || self.query_digest != request.query_digest
            || self.request_digest != request.request_digest
            || self.page_number != request.page_number()
            || self.metrics.len() > MAX_METRIC_RESULTS
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.cost.request_digest != request.request_digest
            || self.cost.response_bytes != self.response_bytes
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.response_digest != self.recomputed_digest()
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        if let Some(cursor) = &self.next_cursor
            && (cursor.binding_digest() != Some(&request.query_digest)
                || cursor.page_number() != request.page_number().saturating_add(1))
        {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.query_digest,
            &self.request_digest,
            self.page_number,
            &self.metrics,
            &self.next_cursor,
            self.response_bytes,
            &self.cost,
            self.provenance,
        ))
    }
}

fn validate_next_cursor(
    cursor: Option<OpaqueCursor>,
    query_digest: Digest,
    page_number: u16,
) -> Result<Option<OpaqueCursor>, AwsCloudWatchProviderError> {
    let Some(cursor) = cursor.map(|cursor| {
        if cursor.binding_digest().is_none() {
            cursor.bind(&query_digest)
        } else {
            cursor
        }
    }) else {
        return Ok(None);
    };
    if page_number >= MAX_PAGES
        || cursor.page_number() != page_number.saturating_add(1)
        || cursor.binding_digest() != Some(&query_digest)
    {
        return Err(AwsCloudWatchProviderError::InvalidResponse);
    }
    Ok(Some(cursor))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub api_revision: String,
    pub contract_version: String,
    pub capability_digest: Digest,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

pub type AwsCloudWatchProviderIdentity = AwsCloudWatchProviderDefinition;

impl AwsCloudWatchProviderDefinition {
    pub fn new(
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        let provider_revision = ProviderRevision::new(provider_revision.to_string())
            .map_err(|_| AwsCloudWatchProviderError::ProviderDrift)?;
        let release = release.into();
        if release.is_empty() || release.len() > 128 {
            return Err(AwsCloudWatchProviderError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-capabilities/v1",
            [
                ("operation", "DescribeAlarms"),
                ("operation", "GetMetricData"),
                ("operation", "ListMetrics"),
                ("writes", "false"),
            ],
        );
        let api_digest = Digest::from_text(API_REVISION);
        let provider_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-provider/v1",
            [
                ("provider_id", PROVIDER_ID),
                ("provider_version", release.as_str()),
                ("provider_revision", provider_revision.as_str()),
                ("api_revision", API_REVISION),
                ("contract_version", CONTRACT_VERSION),
                ("capability", capability_digest.as_str()),
                ("api", api_digest.as_str()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: release,
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            capability_digest,
            api_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn validate(&self) -> Result<(), AwsCloudWatchProviderError> {
        let revision = self
            .provider_revision
            .as_str()
            .parse::<u64>()
            .map_err(|_| AwsCloudWatchProviderError::ProviderDrift)?;
        let expected = Self::new(revision, self.provider_version.clone())?;
        if self != &expected {
            return Err(AwsCloudWatchProviderError::ProviderDrift);
        }
        Ok(())
    }

    pub fn provider_revision_number(&self) -> u64 {
        self.provider_revision.as_str().parse().unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct AwsCloudWatchProvider<T> {
    transport: T,
    definition: AwsCloudWatchProviderDefinition,
}

impl<T: AwsCloudWatchTransport> fmt::Debug for AwsCloudWatchProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudWatchProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsCloudWatchTransport> AwsCloudWatchProvider<T> {
    pub fn new(transport: T) -> Result<Self, AwsCloudWatchProviderError> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self, AwsCloudWatchProviderError> {
        let definition = AwsCloudWatchProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsCloudWatchProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsCloudWatchProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn describe_alarms(
        &mut self,
        request: &DescribeAlarmsRequest,
    ) -> Result<DescribeAlarmsResponse, AwsCloudWatchProviderError> {
        let response = self.transport.describe_alarms(request)?;
        response.validate_integrity(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn get_metric_data(
        &mut self,
        request: &GetMetricDataRequest,
    ) -> Result<GetMetricDataResponse, AwsCloudWatchProviderError> {
        let response = self.transport.get_metric_data(request)?;
        response.validate_integrity(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn list_metrics(
        &mut self,
        request: &ListMetricsRequest,
    ) -> Result<ListMetricsResponse, AwsCloudWatchProviderError> {
        let response = self.transport.list_metrics(request)?;
        response.validate_integrity(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsCloudWatchProviderError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsCloudWatchProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked CloudWatch provider definition")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    describe_responses: VecDeque<Result<DescribeAlarmsResponse, AwsCloudWatchTransportError>>,
    metric_responses: VecDeque<Result<GetMetricDataResponse, AwsCloudWatchTransportError>>,
    list_responses: VecDeque<Result<ListMetricsResponse, AwsCloudWatchTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(_provenance: TransportProvenance) -> Self {
        Self {
            provenance: TransportProvenance::Recording,
            describe_responses: VecDeque::new(),
            metric_responses: VecDeque::new(),
            list_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_describe_response(
        &mut self,
        response: Result<DescribeAlarmsResponse, AwsCloudWatchTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn push_metric_response(
        &mut self,
        response: Result<GetMetricDataResponse, AwsCloudWatchTransportError>,
    ) {
        self.metric_responses.push_back(response);
    }

    pub fn push_get_metric_data_response(
        &mut self,
        response: Result<GetMetricDataResponse, AwsCloudWatchTransportError>,
    ) {
        self.push_metric_response(response);
    }

    pub fn push_list_response(
        &mut self,
        response: Result<ListMetricsResponse, AwsCloudWatchTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_list_metrics_response(
        &mut self,
        response: Result<ListMetricsResponse, AwsCloudWatchTransportError>,
    ) {
        self.push_list_response(response);
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

impl AwsCloudWatchTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_alarms(
        &mut self,
        request: &DescribeAlarmsRequest,
    ) -> Result<DescribeAlarmsResponse, AwsCloudWatchTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_responses
            .pop_front()
            .unwrap_or(Err(AwsCloudWatchTransportError::MalformedResponse))
    }

    fn get_metric_data(
        &mut self,
        request: &GetMetricDataRequest,
    ) -> Result<GetMetricDataResponse, AwsCloudWatchTransportError> {
        self.requests.push(request.recorded_request());
        self.metric_responses
            .pop_front()
            .unwrap_or(Err(AwsCloudWatchTransportError::MalformedResponse))
    }

    fn list_metrics(
        &mut self,
        request: &ListMetricsRequest,
    ) -> Result<ListMetricsResponse, AwsCloudWatchTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsCloudWatchTransportError::MalformedResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsCloudWatchAlarmScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsCloudWatchAlarmScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    pub fn new(scope: &AwsCloudWatchAlarmScope, observed_at: DateTime<Utc>) -> Self {
        Self::for_scope(scope, observed_at)
    }

    fn alarm(&self) -> Result<AlarmSnapshot, AwsCloudWatchProviderError> {
        let evaluation = crate::model::EvaluationSummary::new(
            1.0,
            crate::model::ComparisonOperator::GreaterThanThreshold,
            3,
            Some(2),
            60,
            crate::model::TreatMissingData::NotBreaching,
        )
        .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)?;
        AlarmSnapshot::new(
            self.scope.alarm.clone(),
            crate::model::AlarmState::Ok,
            self.observed_at - Duration::hours(1),
            self.observed_at - Duration::hours(2),
            evaluation,
            self.scope.metric.clone(),
        )
        .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)
    }

    fn metric(&self) -> Result<MetricDataAggregate, AwsCloudWatchProviderError> {
        MetricDataAggregate::new(
            self.scope.metric.clone(),
            self.scope.window.clone(),
            3,
            1.0,
            3.0,
            6.0,
            2.0,
            Digest::from_text("fixture-datapoints"),
        )
        .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)
    }
}

impl AwsCloudWatchTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_alarms(
        &mut self,
        request: &DescribeAlarmsRequest,
    ) -> Result<DescribeAlarmsResponse, AwsCloudWatchTransportError> {
        let alarm = self
            .alarm()
            .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)?;
        DescribeAlarmsResponse::new(
            request,
            vec![alarm],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)
    }

    fn get_metric_data(
        &mut self,
        request: &GetMetricDataRequest,
    ) -> Result<GetMetricDataResponse, AwsCloudWatchTransportError> {
        let metric = self
            .metric()
            .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)?;
        GetMetricDataResponse::new(
            request,
            vec![metric],
            None,
            768,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)
    }

    fn list_metrics(
        &mut self,
        request: &ListMetricsRequest,
    ) -> Result<ListMetricsResponse, AwsCloudWatchTransportError> {
        ListMetricsResponse::new(
            request,
            vec![self.scope.metric.clone()],
            None,
            384,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsCloudWatchAlarmScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }

    pub fn new(scope: &AwsCloudWatchAlarmScope, observed_at: DateTime<Utc>) -> Self {
        Self::for_scope(scope, observed_at)
    }
}

impl AwsCloudWatchTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_alarms(
        &mut self,
        request: &DescribeAlarmsRequest,
    ) -> Result<DescribeAlarmsResponse, AwsCloudWatchTransportError> {
        let alarm = self
            .inner
            .alarm()
            .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)?;
        DescribeAlarmsResponse::new(
            request,
            vec![alarm],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)
    }

    fn get_metric_data(
        &mut self,
        request: &GetMetricDataRequest,
    ) -> Result<GetMetricDataResponse, AwsCloudWatchTransportError> {
        let metric = self
            .inner
            .metric()
            .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)?;
        GetMetricDataResponse::new(
            request,
            vec![metric],
            None,
            768,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)
    }

    fn list_metrics(
        &mut self,
        request: &ListMetricsRequest,
    ) -> Result<ListMetricsResponse, AwsCloudWatchTransportError> {
        ListMetricsResponse::new(
            request,
            vec![self.inner.scope.metric.clone()],
            None,
            384,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCloudWatchTransportError::MalformedResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsCloudWatchTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_alarms(
        &mut self,
        _request: &DescribeAlarmsRequest,
    ) -> Result<DescribeAlarmsResponse, AwsCloudWatchTransportError> {
        Err(AwsCloudWatchTransportError::BlockedEnv)
    }

    fn get_metric_data(
        &mut self,
        _request: &GetMetricDataRequest,
    ) -> Result<GetMetricDataResponse, AwsCloudWatchTransportError> {
        Err(AwsCloudWatchTransportError::BlockedEnv)
    }

    fn list_metrics(
        &mut self,
        _request: &ListMetricsRequest,
    ) -> Result<ListMetricsResponse, AwsCloudWatchTransportError> {
        Err(AwsCloudWatchTransportError::BlockedEnv)
    }
}

pub type RecordingAwsCloudWatchTransport = RecordingTransport;
pub type FixtureAwsCloudWatchTransport = FixtureTransport;
pub type LoopbackAwsCloudWatchTransport = LoopbackTransport;
pub type BlockedEnvAwsCloudWatchTransport = BlockedEnvTransport;
pub type FakeAwsCloudWatchTransport = FixtureTransport;

pub fn is_access_loss(error: &AwsCloudWatchTransportError) -> bool {
    matches!(
        error,
        AwsCloudWatchTransportError::Unauthenticated
            | AwsCloudWatchTransportError::AccessDenied
            | AwsCloudWatchTransportError::NotFound
    )
}

pub fn redacted_receipt(
    operation: AwsCloudWatchOperation,
    request_digest: Digest,
    response_digest: Digest,
    cost: &CostReceipt,
    response_bytes: usize,
    attempt: u8,
    cursor_digest: Option<Digest>,
) -> Result<RedactedRequestReceipt, AwsCloudWatchProviderError> {
    RedactedRequestReceipt::new(
        operation,
        request_digest,
        response_digest,
        cost,
        response_bytes,
        attempt,
        cursor_digest,
    )
    .map_err(|_| AwsCloudWatchProviderError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AlarmIdentity, AlarmName, AwsAccountId, AwsRegion, DeploymentBinding, Digest, MetricWindow,
        MissionBinding, PermissionId, PermissionSnapshot, ProjectBinding, Revision,
        WorkProductBinding,
    };

    fn scope() -> AwsCloudWatchAlarmScope {
        let permissions = PermissionSnapshot::readonly(
            PermissionId::new("read").expect("permission"),
            Revision::new(1).expect("revision"),
        )
        .expect("permissions");
        let metric = MetricIdentity::from_dimensions(
            crate::model::MetricNamespace::new("AWS/Lambda").expect("namespace"),
            crate::model::MetricName::new("Errors").expect("metric"),
            "Sum",
            60,
            [("FunctionName", "fixture")],
        )
        .expect("metric");
        AwsCloudWatchAlarmScope::new(
            DeploymentBinding::new(
                crate::model::DeploymentId::new("deployment").expect("deployment"),
                Revision::new(1).expect("revision"),
            ),
            MissionBinding::new(
                crate::model::MissionId::new("mission").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectBinding::new(
                crate::model::ProjectId::new("project").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            WorkProductBinding::new(
                crate::model::WorkProductId::new("work-product").expect("work product"),
                Revision::new(1).expect("revision"),
            ),
            AwsAccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            AlarmIdentity::new(
                AlarmName::new("fixture-alarm").expect("alarm"),
                Revision::new(1).expect("revision"),
            )
            .expect("alarm identity"),
            metric,
            MetricWindow::new(
                DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
                    .expect("time")
                    .with_timezone(&Utc),
                DateTime::parse_from_rfc3339("2026-08-15T01:00:00Z")
                    .expect("time")
                    .with_timezone(&Utc),
            )
            .expect("window"),
            permissions.digest(),
            false,
        )
        .expect("scope")
    }

    #[test]
    fn fixture_provider_is_always_non_native() {
        let provider =
            AwsCloudWatchProvider::new(FixtureTransport::for_scope(&scope(), Utc::now()))
                .expect("provider");
        assert!(!provider.definition().connected);
        assert!(!provider.definition().native);
        assert!(!provider.definition().first_party);
        assert!(!provider.provenance().connected());
        assert!(!provider.provenance().native());
        assert!(!provider.provenance().first_party());
    }

    #[test]
    fn declared_response_digest_tamper_is_rejected() {
        let scope = scope();
        let request = GetMetricDataRequest::for_scope(&scope).expect("request");
        let aggregate = MetricDataAggregate::new(
            scope.metric.clone(),
            scope.window.clone(),
            1,
            1.0,
            1.0,
            1.0,
            1.0,
            Digest::from_text("point"),
        )
        .expect("aggregate");
        let response = GetMetricDataResponse::new(
            &request,
            vec![aggregate],
            None,
            128,
            TransportProvenance::Recording,
        )
        .expect("response")
        .with_declared_digest(Digest::from_text("tampered"));
        assert!(response.validate_integrity(&request).is_err());
    }
}

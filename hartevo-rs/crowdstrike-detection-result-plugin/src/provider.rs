//! Allowlisted Falcon read seams and deterministic non-native transports.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    CrowdStrikeDetectionEvidence, CrowdStrikeDetectionScope, DetectionProjection,
    DetectionQueryResult, DetectionSummary, DetectionSummaryResult, Digest, FalconOperation,
    MAX_DETECTIONS_PER_PAGE, MAX_OFFSET, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RETRIES,
    MAX_TOTAL_DETECTIONS, ModelError, PermissionSnapshot, RateLimitReceipt, ReadReceipt,
    RetryReceipt, TransportProvenance,
};
use crate::service::CrowdStrikeRegistration;

pub const CROWDSTRIKE_API_REVISION: &str = "falcon-detects-query-detects-get-detect-summaries-1";
pub const QUERY_DETECTS_PATH: &str = "/detects/queries/detects/v1";
pub const GET_DETECT_SUMMARIES_PATH: &str = "/detects/entities/summaries/GET/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FalconTransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl FalconTransportFailure {
    #[must_use]
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::Server,
            _ => Self::Malformed,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Throttled | Self::Server | Self::Timeout)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("CrowdStrike Falcon transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct FalconTransportError {
    pub failure: FalconTransportFailure,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub error_digest: Digest,
    pub retry: RetryReceipt,
    pub rate_limit: RateLimitReceipt,
}

impl FalconTransportError {
    #[must_use]
    pub fn new(failure: FalconTransportFailure) -> Self {
        Self {
            status_code: failure.status_code(),
            retry_after_seconds: None,
            error_digest: Digest::from_text(match failure {
                FalconTransportFailure::BadRequest => "400",
                FalconTransportFailure::Unauthorized => "401",
                FalconTransportFailure::AccessDenied => "403",
                FalconTransportFailure::NotFound => "404",
                FalconTransportFailure::Conflict => "409",
                FalconTransportFailure::Throttled => "429",
                FalconTransportFailure::Server => "5xx",
                FalconTransportFailure::Timeout => "timeout",
                FalconTransportFailure::BlockedEnv => "BLOCKED_ENV",
                FalconTransportFailure::Malformed => "malformed",
            }),
            retry: RetryReceipt::first_attempt(FalconOperation::QueryDetects, 0),
            rate_limit: RateLimitReceipt::default(),
            failure,
        }
    }

    #[must_use]
    pub fn from_status(status: u16) -> Self {
        Self::new(FalconTransportFailure::from_status(status))
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::new(FalconTransportFailure::BlockedEnv)
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(FalconTransportFailure::Timeout)
    }

    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: RateLimitReceipt) -> Self {
        self.retry_after_seconds = rate_limit.retry_after_seconds;
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    pub fn with_retry(mut self, retry: RetryReceipt) -> Self {
        self.retry = retry;
        self
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CrowdStrikeProviderError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("transport failed: {0}")]
    Transport(#[from] FalconTransportError),
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("request scope does not match the registration")]
    ScopeMismatch,
    #[error("request permission digest does not match the registration")]
    PermissionMismatch,
    #[error("request provider or registration revision is stale")]
    StaleRequest,
    #[error("provider definition is invalid")]
    InvalidDefinition,
    #[error("provider response contains duplicate or replayed data")]
    TamperedResponse,
}

pub type ProviderError = CrowdStrikeProviderError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeFalconProviderDefinition {
    pub provider_id: String,
    pub api_revision: String,
    pub provider_revision: u64,
    pub provider_digest: Digest,
    pub query_detects_path: String,
    pub get_detect_summaries_path: String,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl CrowdStrikeFalconProviderDefinition {
    pub fn new() -> Result<Self, CrowdStrikeProviderError> {
        let permissions = PermissionSnapshot::alerts_read();
        let mut value = Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            api_revision: CROWDSTRIKE_API_REVISION.to_owned(),
            provider_revision: 1,
            provider_digest: Digest::from_text("unsealed-crowdstrike-provider"),
            query_detects_path: QUERY_DETECTS_PATH.to_owned(),
            get_detect_summaries_path: GET_DETECT_SUMMARIES_PATH.to_owned(),
            permissions: permissions.permissions,
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
        };
        value.provider_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.provider_id,
            &self.api_revision,
            self.provider_revision,
            &self.query_detects_path,
            &self.get_detect_summaries_path,
            &self.permissions,
            self.read_only,
            self.native,
            self.connected,
            self.first_party,
        ))
    }

    pub fn validate(&self) -> Result<(), CrowdStrikeProviderError> {
        let permissions = PermissionSnapshot::new(self.permissions.clone())?;
        if self.provider_id != crate::PROVIDER_ID
            || self.api_revision != CROWDSTRIKE_API_REVISION
            || self.provider_revision == 0
            || self.query_detects_path != QUERY_DETECTS_PATH
            || self.get_detect_summaries_path != GET_DETECT_SUMMARIES_PATH
            || !self.read_only
            || self.native
            || self.connected
            || self.first_party
            || self.provider_digest != self.calculate_digest()?
        {
            return Err(CrowdStrikeProviderError::InvalidDefinition);
        }
        permissions.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FalconReadBounds {
    pub offset: u32,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_retries: u8,
}

impl FalconReadBounds {
    pub fn new(
        offset: u32,
        page_size: u16,
        max_pages: u16,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        let value = Self {
            offset,
            page_size,
            max_pages,
            max_retries,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.offset > MAX_OFFSET
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(())
    }
}

pub type DetectionReadBounds = FalconReadBounds;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeDetectionReadRequest {
    pub scope_digest: Digest,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub scope_revision: u64,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: u64,
    pub fql_filter_digest: Digest,
    pub time_window_digest: Digest,
    pub bounds: FalconReadBounds,
}

impl CrowdStrikeDetectionReadRequest {
    pub fn for_registration(
        scope: &CrowdStrikeDetectionScope,
        registration: &CrowdStrikeRegistration,
        bounds: FalconReadBounds,
    ) -> Result<Self, CrowdStrikeProviderError> {
        scope.validate()?;
        bounds.validate()?;
        registration
            .validate()
            .map_err(|_| CrowdStrikeProviderError::InvalidDefinition)?;
        if registration.scope_digest() != &scope.digest() || !registration.is_active() {
            return Err(CrowdStrikeProviderError::ScopeMismatch);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            project_revision: scope.project.revision.get(),
            mission_revision: scope.mission.revision.get(),
            work_product_revision: scope.work_product.revision.get(),
            scope_revision: scope.scope_revision.get(),
            permission_digest: registration.permission_digest(),
            registration_digest: registration.registration_digest().clone(),
            provider_revision: registration.provider_revision(),
            fql_filter_digest: scope.fql_filter.digest(),
            time_window_digest: scope.time_window.digest(),
            bounds,
        })
    }

    #[must_use]
    pub fn with_offset(&self, offset: u32) -> Self {
        let mut request = self.clone();
        request.bounds.offset = offset;
        request
    }

    pub fn validate(&self) -> Result<(), CrowdStrikeProviderError> {
        self.bounds.validate()?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || self.scope_revision == 0
            || self.provider_revision == 0
        {
            return Err(CrowdStrikeProviderError::StaleRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryDetectsRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: u64,
    pub fql_filter_digest: Digest,
    pub time_window_digest: Digest,
    pub offset: u32,
    pub page_size: u16,
    pub page_number: u16,
}

impl QueryDetectsRequest {
    pub fn from_read_request(
        request: &CrowdStrikeDetectionReadRequest,
        page_number: u16,
    ) -> Result<Self, CrowdStrikeProviderError> {
        request.validate()?;
        if page_number == 0 || page_number > request.bounds.max_pages {
            return Err(CrowdStrikeProviderError::StaleRequest);
        }
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            registration_digest: request.registration_digest.clone(),
            provider_revision: request.provider_revision,
            fql_filter_digest: request.fql_filter_digest.clone(),
            time_window_digest: request.time_window_digest.clone(),
            offset: request.bounds.offset,
            page_size: request.bounds.page_size,
            page_number,
        })
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        crate::model::digest_serializable(self).expect("QueryDetectsRequest is serializable")
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "{QUERY_DETECTS_PATH}?filterDigest={}&timeWindowDigest={}&offset={}&limit={}",
            self.fql_filter_digest, self.time_window_digest, self.offset, self.page_size
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetDetectSummariesRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: u64,
    pub fql_filter_digest: Digest,
    pub time_window_digest: Digest,
    pub offset: u32,
    pub page_size: u16,
    pub page_number: u16,
}

impl GetDetectSummariesRequest {
    pub fn from_read_request(
        request: &CrowdStrikeDetectionReadRequest,
        page_number: u16,
    ) -> Result<Self, CrowdStrikeProviderError> {
        request.validate()?;
        if page_number == 0 || page_number > request.bounds.max_pages {
            return Err(CrowdStrikeProviderError::StaleRequest);
        }
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            registration_digest: request.registration_digest.clone(),
            provider_revision: request.provider_revision,
            fql_filter_digest: request.fql_filter_digest.clone(),
            time_window_digest: request.time_window_digest.clone(),
            offset: request.bounds.offset,
            page_size: request.bounds.page_size,
            page_number,
        })
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        crate::model::digest_serializable(self).expect("GetDetectSummariesRequest is serializable")
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "{GET_DETECT_SUMMARIES_PATH}?filterDigest={}&timeWindowDigest={}&offset={}&limit={}",
            self.fql_filter_digest, self.time_window_digest, self.offset, self.page_size
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryDetectsResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub offset: u32,
    pub page_size: u16,
    pub next_offset: Option<u32>,
    pub detections: Vec<DetectionProjection>,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub rate_limit: RateLimitReceipt,
    pub retry: RetryReceipt,
    pub provenance: TransportProvenance,
}

impl QueryDetectsResponse {
    pub fn new(
        request: &QueryDetectsRequest,
        detections: Vec<DetectionProjection>,
        next_offset: Option<u32>,
        response_bytes: u64,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
    ) -> Result<Self, CrowdStrikeProviderError> {
        if detections.len() > usize::from(request.page_size)
            || detections.len() > MAX_DETECTIONS_PER_PAGE
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidResponse));
        }
        if next_offset.is_some_and(|next| next <= request.offset || next > MAX_OFFSET) {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidResponse));
        }
        rate_limit.validate()?;
        let response_digest = response_digest(
            FalconOperation::QueryDetects,
            request.request_digest(),
            request.scope_digest.clone(),
            request.offset,
            request.page_size,
            next_offset,
            &detections,
            response_bytes,
            provenance,
        )?;
        Ok(Self {
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            offset: request.offset,
            page_size: request.page_size,
            next_offset,
            detections,
            response_bytes,
            response_digest,
            rate_limit,
            retry: RetryReceipt::first_attempt(FalconOperation::QueryDetects, 0),
            provenance,
        })
    }

    #[must_use]
    pub fn with_retry(mut self, retry: RetryReceipt) -> Self {
        self.retry = retry;
        self
    }

    pub fn validate_integrity(&self) -> Result<(), CrowdStrikeProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.detections.len() > usize::from(self.page_size)
            || self.next_offset.is_some_and(|next| next <= self.offset)
            || self.retry.operation != FalconOperation::QueryDetects
        {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidResponse));
        }
        self.rate_limit.validate()?;
        let rebuilt = response_digest(
            FalconOperation::QueryDetects,
            self.request_digest.clone(),
            self.scope_digest.clone(),
            self.offset,
            self.page_size,
            self.next_offset,
            &self.detections,
            self.response_bytes,
            self.provenance,
        )?;
        if rebuilt != self.response_digest {
            return Err(CrowdStrikeProviderError::TamperedResponse);
        }
        for detection in &self.detections {
            detection.validate_integrity()?;
        }
        Ok(())
    }

    pub fn into_query_result(self) -> Result<DetectionQueryResult, CrowdStrikeProviderError> {
        self.validate_integrity()?;
        let receipt = ReadReceipt {
            operation: FalconOperation::QueryDetects,
            request_digest: self.request_digest,
            response_digest: self.response_digest,
            retry: self.retry,
            rate_limit: self.rate_limit,
            provenance: self.provenance,
        };
        Ok(DetectionQueryResult::new(
            self.offset,
            self.page_size,
            self.next_offset,
            self.detections,
            receipt,
        )?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetDetectSummariesResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub offset: u32,
    pub page_size: u16,
    pub summary: DetectionSummary,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub rate_limit: RateLimitReceipt,
    pub retry: RetryReceipt,
    pub provenance: TransportProvenance,
}

impl GetDetectSummariesResponse {
    pub fn new(
        request: &GetDetectSummariesRequest,
        summary: DetectionSummary,
        response_bytes: u64,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
    ) -> Result<Self, CrowdStrikeProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidResponse));
        }
        summary.validate_integrity()?;
        rate_limit.validate()?;
        let response_digest = crate::model::digest_serializable(&(
            FalconOperation::GetDetectSummaries,
            request.request_digest(),
            &request.scope_digest,
            request.offset,
            request.page_size,
            &summary.summary_digest,
            response_bytes,
            provenance,
        ))?;
        Ok(Self {
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            offset: request.offset,
            page_size: request.page_size,
            summary,
            response_bytes,
            response_digest,
            rate_limit,
            retry: RetryReceipt::first_attempt(FalconOperation::GetDetectSummaries, 0),
            provenance,
        })
    }

    #[must_use]
    pub fn with_retry(mut self, retry: RetryReceipt) -> Self {
        self.retry = retry;
        self
    }

    pub fn validate_integrity(&self) -> Result<(), CrowdStrikeProviderError> {
        self.summary.validate_integrity()?;
        self.rate_limit.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.retry.operation != FalconOperation::GetDetectSummaries
        {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidResponse));
        }
        let rebuilt = crate::model::digest_serializable(&(
            FalconOperation::GetDetectSummaries,
            &self.request_digest,
            &self.scope_digest,
            self.offset,
            self.page_size,
            &self.summary.summary_digest,
            self.response_bytes,
            self.provenance,
        ))?;
        if rebuilt != self.response_digest {
            return Err(CrowdStrikeProviderError::TamperedResponse);
        }
        Ok(())
    }

    pub fn into_summary_result(self) -> Result<DetectionSummaryResult, CrowdStrikeProviderError> {
        self.validate_integrity()?;
        let receipt = ReadReceipt {
            operation: FalconOperation::GetDetectSummaries,
            request_digest: self.request_digest,
            response_digest: self.response_digest,
            retry: self.retry,
            rate_limit: self.rate_limit,
            provenance: self.provenance,
        };
        Ok(DetectionSummaryResult::new(
            self.offset,
            self.page_size,
            self.summary,
            receipt,
        )?)
    }
}

fn response_digest(
    operation: FalconOperation,
    request_digest: Digest,
    scope_digest: Digest,
    offset: u32,
    page_size: u16,
    next_offset: Option<u32>,
    detections: &[DetectionProjection],
    response_bytes: u64,
    provenance: TransportProvenance,
) -> Result<Digest, ModelError> {
    crate::model::digest_serializable(&(
        operation,
        request_digest,
        scope_digest,
        offset,
        page_size,
        next_offset,
        detections
            .iter()
            .map(|detection| &detection.detection_digest)
            .collect::<Vec<_>>(),
        response_bytes,
        provenance,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrowdStrikeDetectionRead {
    pub query_pages: Vec<DetectionQueryResult>,
    pub summary: DetectionSummaryResult,
    pub observed_at: DateTime<Utc>,
}

pub trait CrowdStrikeFalconTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn query_detects(
        &mut self,
        request: &QueryDetectsRequest,
    ) -> Result<QueryDetectsResponse, FalconTransportError>;

    fn get_detect_summaries(
        &mut self,
        request: &GetDetectSummariesRequest,
    ) -> Result<GetDetectSummariesResponse, FalconTransportError>;
}

/// A typed provider carrying an exact registration and no credential resolver.
pub struct CrowdStrikeFalconProvider<T> {
    transport: T,
    registration: CrowdStrikeRegistration,
    definition: CrowdStrikeFalconProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for CrowdStrikeFalconProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrowdStrikeFalconProvider")
            .field("transport", &self.transport)
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("provider_digest", &self.definition.provider_digest)
            .finish()
    }
}

impl<T: CrowdStrikeFalconTransport> CrowdStrikeFalconProvider<T> {
    pub fn new(
        transport: T,
        registration: CrowdStrikeRegistration,
    ) -> Result<Self, CrowdStrikeProviderError> {
        registration
            .validate()
            .map_err(|_| CrowdStrikeProviderError::InvalidDefinition)?;
        let definition = CrowdStrikeFalconProviderDefinition::new()?;
        if registration.provider_digest() != &definition.provider_digest {
            return Err(CrowdStrikeProviderError::InvalidDefinition);
        }
        Ok(Self {
            transport,
            registration,
            definition,
        })
    }

    pub fn from_registration(
        registration: CrowdStrikeRegistration,
        transport: T,
    ) -> Result<Self, CrowdStrikeProviderError> {
        Self::new(transport, registration)
    }

    #[must_use]
    pub fn registration(&self) -> &CrowdStrikeRegistration {
        &self.registration
    }

    #[must_use]
    pub fn definition(&self) -> &CrowdStrikeFalconProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn query_detects(
        &mut self,
        request: &QueryDetectsRequest,
        max_retries: u8,
    ) -> Result<QueryDetectsResponse, CrowdStrikeProviderError> {
        self.validate_query_fence(
            &request.scope_digest,
            &request.permission_digest,
            &request.registration_digest,
            request.provider_revision,
        )?;
        if max_retries > MAX_RETRIES {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidBounds));
        }
        let mut retries = 0;
        loop {
            match self.transport.query_detects(request) {
                Ok(response) => {
                    response.validate_integrity()?;
                    if response.request_digest != request.request_digest()
                        || response.scope_digest != request.scope_digest
                        || response.offset != request.offset
                        || response.page_size != request.page_size
                    {
                        return Err(CrowdStrikeProviderError::TamperedResponse);
                    }
                    let retry = RetryReceipt::new(
                        FalconOperation::QueryDetects,
                        retries + 1,
                        max_retries,
                        false,
                    )?;
                    return Ok(response.with_retry(retry));
                }
                Err(error) if error.failure.retryable() && retries < max_retries => {
                    retries += 1;
                }
                Err(error) => {
                    let retry = RetryReceipt::new(
                        FalconOperation::QueryDetects,
                        retries + 1,
                        max_retries,
                        error.failure.retryable(),
                    )?;
                    return Err(CrowdStrikeProviderError::Transport(error.with_retry(retry)));
                }
            }
        }
    }

    pub fn get_detect_summaries(
        &mut self,
        request: &GetDetectSummariesRequest,
        max_retries: u8,
    ) -> Result<GetDetectSummariesResponse, CrowdStrikeProviderError> {
        self.validate_query_fence(
            &request.scope_digest,
            &request.permission_digest,
            &request.registration_digest,
            request.provider_revision,
        )?;
        if max_retries > MAX_RETRIES {
            return Err(CrowdStrikeProviderError::Model(ModelError::InvalidBounds));
        }
        let mut retries = 0;
        loop {
            match self.transport.get_detect_summaries(request) {
                Ok(response) => {
                    response.validate_integrity()?;
                    if response.request_digest != request.request_digest()
                        || response.scope_digest != request.scope_digest
                        || response.offset != request.offset
                        || response.page_size != request.page_size
                    {
                        return Err(CrowdStrikeProviderError::TamperedResponse);
                    }
                    let retry = RetryReceipt::new(
                        FalconOperation::GetDetectSummaries,
                        retries + 1,
                        max_retries,
                        false,
                    )?;
                    return Ok(response.with_retry(retry));
                }
                Err(error) if error.failure.retryable() && retries < max_retries => {
                    retries += 1;
                }
                Err(error) => {
                    let retry = RetryReceipt::new(
                        FalconOperation::GetDetectSummaries,
                        retries + 1,
                        max_retries,
                        error.failure.retryable(),
                    )?;
                    return Err(CrowdStrikeProviderError::Transport(error.with_retry(retry)));
                }
            }
        }
    }

    pub fn read(
        &mut self,
        request: &CrowdStrikeDetectionReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<CrowdStrikeDetectionRead, CrowdStrikeProviderError> {
        request.validate()?;
        let mut query_pages = Vec::new();
        let mut current_offset = request.bounds.offset;
        let mut seen_offsets = BTreeSet::new();
        let mut seen_detection_ids = BTreeSet::new();
        for page_number in 1..=request.bounds.max_pages {
            if !seen_offsets.insert(current_offset) {
                return Err(CrowdStrikeProviderError::TamperedResponse);
            }
            let page_request = QueryDetectsRequest::from_read_request(
                &request.with_offset(current_offset),
                page_number,
            )?;
            let response = self.query_detects(&page_request, request.bounds.max_retries)?;
            let next_offset = response.next_offset;
            let page = response.into_query_result()?;
            if page
                .detections
                .iter()
                .any(|detection| !seen_detection_ids.insert(detection.detection_id.clone()))
            {
                return Err(CrowdStrikeProviderError::TamperedResponse);
            }
            let complete = page.complete;
            query_pages.push(page);
            if complete {
                break;
            }
            let next_offset = next_offset.ok_or(CrowdStrikeProviderError::TamperedResponse)?;
            if next_offset <= current_offset || next_offset > MAX_OFFSET {
                return Err(CrowdStrikeProviderError::TamperedResponse);
            }
            current_offset = next_offset;
            if page_number == request.bounds.max_pages {
                break;
            }
        }
        let summary_request = GetDetectSummariesRequest::from_read_request(request, 1)?;
        let summary = self
            .get_detect_summaries(&summary_request, request.bounds.max_retries)?
            .into_summary_result()?;
        Ok(CrowdStrikeDetectionRead {
            query_pages,
            summary,
            observed_at,
        })
    }

    fn validate_query_fence(
        &self,
        scope_digest: &Digest,
        permission_digest: &Digest,
        registration_digest: &Digest,
        provider_revision: u64,
    ) -> Result<(), CrowdStrikeProviderError> {
        if !self.registration.is_active() {
            return Err(CrowdStrikeProviderError::RegistrationInactive);
        }
        if scope_digest != self.registration.scope_digest() {
            return Err(CrowdStrikeProviderError::ScopeMismatch);
        }
        if permission_digest != &self.registration.permission_digest() {
            return Err(CrowdStrikeProviderError::PermissionMismatch);
        }
        if registration_digest != self.registration.registration_digest()
            || provider_revision != self.registration.provider_revision()
        {
            return Err(CrowdStrikeProviderError::StaleRequest);
        }
        Ok(())
    }
}

fn response_with_scope(
    request: &QueryDetectsRequest,
    detections: Vec<DetectionProjection>,
    next_offset: Option<u32>,
    provenance: TransportProvenance,
) -> Result<QueryDetectsResponse, FalconTransportError> {
    QueryDetectsResponse::new(
        request,
        detections,
        next_offset,
        512,
        RateLimitReceipt::new(60, Some(59), None, false)
            .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))?,
        provenance,
    )
    .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))
}

fn summary_response(
    request: &GetDetectSummariesRequest,
    detections: &[DetectionProjection],
    provenance: TransportProvenance,
) -> Result<GetDetectSummariesResponse, FalconTransportError> {
    let summary = DetectionSummary::from_detections(detections)
        .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))?;
    GetDetectSummariesResponse::new(
        request,
        summary,
        512,
        RateLimitReceipt::new(60, Some(58), None, false)
            .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))?,
        provenance,
    )
    .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    detections: Vec<DetectionProjection>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &CrowdStrikeDetectionScope) -> Result<Self, ModelError> {
        let observed = DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
            .expect("fixture timestamp")
            .with_timezone(&Utc);
        let device = crate::model::RedactedDeviceFields::from_sensitive(
            "fixture-device-001",
            Some("fixture-host.example"),
            &["fixture-group"],
            crate::model::PlatformClass::Macos,
        )?;
        let process = crate::model::RedactedProcessFields::from_sensitive(
            Some("/usr/bin/fixture-process"),
            Some("fixture process --bounded"),
            Some("/sbin/launchd"),
        );
        let technique =
            crate::model::RedactedTechniqueFields::from_sensitive("execution", "T1059")?;
        let detection = DetectionProjection::from_sensitive(
            "fixture-detection-001",
            Some("fixture-alert-001".to_owned()),
            crate::model::FalconSeverity::High,
            crate::model::FalconDetectionStatus::New,
            device,
            Some(process),
            vec![technique],
            observed,
            observed,
            1,
        )?;
        Ok(Self {
            scope_digest: scope.digest(),
            detections: vec![detection],
        })
    }

    pub fn with_detections(
        scope: &CrowdStrikeDetectionScope,
        detections: Vec<DetectionProjection>,
    ) -> Result<Self, ModelError> {
        if detections.len() > MAX_TOTAL_DETECTIONS {
            return Err(ModelError::BoundExceeded {
                field: "fixture detections",
            });
        }
        for detection in &detections {
            detection.validate_integrity()?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            detections,
        })
    }
}

impl CrowdStrikeFalconTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn query_detects(
        &mut self,
        request: &QueryDetectsRequest,
    ) -> Result<QueryDetectsResponse, FalconTransportError> {
        if request.scope_digest != self.scope_digest {
            return Err(FalconTransportError::new(FalconTransportFailure::Conflict));
        }
        let start = usize::try_from(request.offset)
            .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))?;
        let end = start.saturating_add(usize::from(request.page_size));
        let page = self
            .detections
            .get(start..end.min(self.detections.len()))
            .unwrap_or_default()
            .to_vec();
        let next = (end < self.detections.len()).then_some(end as u32);
        response_with_scope(request, page, next, self.provenance())
    }

    fn get_detect_summaries(
        &mut self,
        request: &GetDetectSummariesRequest,
    ) -> Result<GetDetectSummariesResponse, FalconTransportError> {
        if request.scope_digest != self.scope_digest {
            return Err(FalconTransportError::new(FalconTransportFailure::Conflict));
        }
        summary_response(request, &self.detections, self.provenance())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RecordedRequest {
    QueryDetects {
        request_digest: Digest,
        offset: u32,
        page_number: u16,
    },
    GetDetectSummaries {
        request_digest: Digest,
        offset: u32,
        page_number: u16,
    },
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    inner: FixtureTransport,
    requests: Vec<RecordedRequest>,
    query_responses: VecDeque<Result<QueryDetectsResponse, FalconTransportError>>,
    summary_responses: VecDeque<Result<GetDetectSummariesResponse, FalconTransportError>>,
}

impl RecordingTransport {
    pub fn for_scope(scope: &CrowdStrikeDetectionScope) -> Result<Self, ModelError> {
        Ok(Self {
            inner: FixtureTransport::for_scope(scope)?,
            requests: Vec::new(),
            query_responses: VecDeque::new(),
            summary_responses: VecDeque::new(),
        })
    }

    pub fn push_query_response(
        &mut self,
        response: Result<QueryDetectsResponse, FalconTransportError>,
    ) {
        self.query_responses.push_back(response);
    }

    pub fn push_summary_response(
        &mut self,
        response: Result<GetDetectSummariesResponse, FalconTransportError>,
    ) {
        self.summary_responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        let scope = CrowdStrikeDetectionScope {
            customer_id: crate::model::CustomerId::parse("recording-customer")
                .expect("recording customer"),
            cid: crate::model::Cid::parse("recording-cid").expect("recording cid"),
            host_group: crate::model::FalconHostGroupScope::for_host("recording-host")
                .expect("recording host"),
            detection_alert: crate::model::FalconDetectionAlertScope::new(vec![], vec![])
                .expect("recording selection"),
            severity: None,
            status: None,
            fql_filter: crate::model::FqlFilter::parse("status:'new'").expect("recording fql"),
            time_window: crate::model::DetectionTimeWindow::new(
                DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                    .expect("recording start")
                    .with_timezone(&Utc),
                DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
                    .expect("recording end")
                    .with_timezone(&Utc),
                1,
            )
            .expect("recording window"),
            project: crate::model::ProjectScope::new("recording-project", 1)
                .expect("recording project"),
            mission: crate::model::MissionScope::new("recording-mission", 1)
                .expect("recording mission"),
            work_product: crate::model::WorkProductScope::new("recording-work-product", 1)
                .expect("recording work product"),
            scope_revision: crate::model::Revision::new(1).expect("recording scope revision"),
        };
        Self::for_scope(&scope).expect("recording transport")
    }
}

impl CrowdStrikeFalconTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn query_detects(
        &mut self,
        request: &QueryDetectsRequest,
    ) -> Result<QueryDetectsResponse, FalconTransportError> {
        self.requests.push(RecordedRequest::QueryDetects {
            request_digest: request.request_digest(),
            offset: request.offset,
            page_number: request.page_number,
        });
        self.query_responses
            .pop_front()
            .unwrap_or_else(|| self.inner.query_detects(request))
    }

    fn get_detect_summaries(
        &mut self,
        request: &GetDetectSummariesRequest,
    ) -> Result<GetDetectSummariesResponse, FalconTransportError> {
        self.requests.push(RecordedRequest::GetDetectSummaries {
            request_digest: request.request_digest(),
            offset: request.offset,
            page_number: request.page_number,
        });
        self.summary_responses
            .pop_front()
            .unwrap_or_else(|| self.inner.get_detect_summaries(request))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &CrowdStrikeDetectionScope) -> Result<Self, ModelError> {
        Ok(Self {
            inner: FixtureTransport::for_scope(scope)?,
        })
    }
}

impl CrowdStrikeFalconTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn query_detects(
        &mut self,
        request: &QueryDetectsRequest,
    ) -> Result<QueryDetectsResponse, FalconTransportError> {
        let mut response = self.inner.query_detects(request)?;
        response.provenance = self.provenance();
        response.response_digest = response_digest(
            FalconOperation::QueryDetects,
            response.request_digest.clone(),
            response.scope_digest.clone(),
            response.offset,
            response.page_size,
            response.next_offset,
            &response.detections,
            response.response_bytes,
            response.provenance,
        )
        .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))?;
        Ok(response)
    }

    fn get_detect_summaries(
        &mut self,
        request: &GetDetectSummariesRequest,
    ) -> Result<GetDetectSummariesResponse, FalconTransportError> {
        let mut response = self.inner.get_detect_summaries(request)?;
        response.provenance = self.provenance();
        response.response_digest = crate::model::digest_serializable(&(
            FalconOperation::GetDetectSummaries,
            &response.request_digest,
            &response.scope_digest,
            response.offset,
            response.page_size,
            &response.summary.summary_digest,
            response.response_bytes,
            response.provenance,
        ))
        .map_err(|_| FalconTransportError::new(FalconTransportFailure::Malformed))?;
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl CrowdStrikeFalconTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn query_detects(
        &mut self,
        _request: &QueryDetectsRequest,
    ) -> Result<QueryDetectsResponse, FalconTransportError> {
        Err(FalconTransportError::blocked_env())
    }

    fn get_detect_summaries(
        &mut self,
        _request: &GetDetectSummariesRequest,
    ) -> Result<GetDetectSummariesResponse, FalconTransportError> {
        Err(FalconTransportError::blocked_env())
    }
}

pub type FixtureCrowdStrikeTransport = FixtureTransport;
pub type RecordingCrowdStrikeTransport = RecordingTransport;
pub type LoopbackCrowdStrikeTransport = LoopbackTransport;
pub type BlockedEnvCrowdStrikeTransport = BlockedEnvTransport;

#[allow(dead_code)]
fn _evidence_type_is_kept_typed(_: CrowdStrikeDetectionEvidence) {}

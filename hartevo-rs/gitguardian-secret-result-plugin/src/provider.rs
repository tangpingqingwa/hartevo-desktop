//! Allowlisted GitGuardian read requests and non-network transport seams.
//!
//! The provider owns request construction and response validation. It has no
//! HTTP client and never receives a raw credential. Fixture, recording,
//! loopback, and `BLOCKED_ENV` transports all report non-native,
//! non-Connected provenance.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, GitGuardianDetector, GitGuardianIncident, GitGuardianOccurrence, GitGuardianScope,
    MAX_INCIDENTS, MAX_OCCURRENCES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, ModelError,
    OpaqueCursor, PermissionSnapshot, RedactedRateReceipt, Revision, TransportProvenance,
};
use crate::{
    API_REVISION, DETECTOR_ENDPOINT, DETECTORS_ENDPOINT, HEALTH_ENDPOINT, INCIDENT_ENDPOINT,
    INCIDENTS_ENDPOINT, OCCURRENCE_ENDPOINT, OCCURRENCES_ENDPOINT, PLUGIN_VERSION, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    ServiceUnavailable,
    Timeout,
    ProviderUnknown,
    Partial,
    CursorLoop,
    Tampered,
    BlockedEnv,
    FixtureExhausted,
}

impl ProviderErrorKind {
    #[must_use]
    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }

    #[must_use]
    pub const fn is_rate_limited(self) -> bool {
        matches!(self, Self::RateLimited)
    }

    #[must_use]
    pub const fn fail_closed(self) -> bool {
        matches!(
            self,
            Self::Unauthorized
                | Self::Forbidden
                | Self::NotFound
                | Self::RateLimited
                | Self::ServiceUnavailable
                | Self::Timeout
                | Self::ProviderUnknown
                | Self::Partial
                | Self::CursorLoop
                | Self::Tampered
                | Self::BlockedEnv
                | Self::FixtureExhausted
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[error("GitGuardian provider error: {kind:?} ({code})")]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub code: String,
    pub response_status: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub truncated: bool,
}

impl ProviderError {
    #[must_use]
    pub fn new(kind: ProviderErrorKind, code: impl Into<String>) -> Self {
        // Provider-controlled text may accidentally echo a secret or
        // occurrence content. Retain only its digest.
        let code = Digest::from_text(code.into().as_bytes()).to_string();
        Self {
            kind,
            code,
            response_status: None,
            retry_after_seconds: None,
            truncated: false,
        }
    }

    #[must_use]
    pub const fn with_status(mut self, response_status: u16) -> Self {
        self.response_status = Some(response_status);
        self
    }

    #[must_use]
    pub const fn with_retry_after(mut self, retry_after_seconds: u32) -> Self {
        self.retry_after_seconds = Some(retry_after_seconds);
        self
    }

    #[must_use]
    pub const fn truncated(mut self) -> Self {
        self.truncated = true;
        self
    }
}

pub type GitGuardianProviderError = ProviderError;
pub type TransportError = ProviderError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitGuardianOperation {
    ListIncidents,
    GetIncident,
    ListOccurrences,
    GetOccurrence,
    GetDetector,
    GetStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianRequest {
    pub operation: GitGuardianOperation,
    pub scope_digest: Digest,
    pub incident_id: Option<String>,
    pub occurrence_id: Option<String>,
    pub detector_id: Option<String>,
    pub status_filter: String,
    pub page: u16,
    pub per_page: u16,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub endpoint_digest: Digest,
    pub request_digest: Digest,
}

pub type GitGuardianReadRequest = GitGuardianRequest;

impl GitGuardianRequest {
    pub fn list_incidents(
        scope: &GitGuardianScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        Self::list(scope, GitGuardianOperation::ListIncidents, page, cursor)
    }

    pub fn get_incident(scope: &GitGuardianScope) -> Result<Self, ProviderError> {
        Self::build(scope, GitGuardianOperation::GetIncident, 1, None)
    }

    pub fn list_occurrences(
        scope: &GitGuardianScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        Self::list(scope, GitGuardianOperation::ListOccurrences, page, cursor)
    }

    pub fn get_occurrence(scope: &GitGuardianScope) -> Result<Self, ProviderError> {
        Self::build(scope, GitGuardianOperation::GetOccurrence, 1, None)
    }

    pub fn get_detector(scope: &GitGuardianScope) -> Result<Self, ProviderError> {
        Self::build(scope, GitGuardianOperation::GetDetector, 1, None)
    }

    pub fn get_status(scope: &GitGuardianScope) -> Result<Self, ProviderError> {
        Self::build(scope, GitGuardianOperation::GetStatus, 1, None)
    }

    fn list(
        scope: &GitGuardianScope,
        operation: GitGuardianOperation,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        if page == 0 || page > scope.query.max_pages || page > MAX_PAGES {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "page_out_of_bounds",
            ));
        }
        Self::build(scope, operation, page, cursor)
    }

    fn build(
        scope: &GitGuardianScope,
        operation: GitGuardianOperation,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        scope.validate().map_err(model_error)?;
        if page == 0 || page > MAX_PAGES {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "page_out_of_bounds",
            ));
        }
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.validate().is_err())
        {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "cursor_invalid",
            ));
        }
        let query_digest = scope.query.query_digest_for_request(page, cursor.as_ref());
        let endpoint = endpoint_for(operation);
        let endpoint_digest = Digest::from_parts(
            "gitguardian-endpoint/v1",
            [endpoint.to_owned(), scope.workspace_id.as_str().to_owned()],
        );
        let incident_id = matches!(
            operation,
            GitGuardianOperation::GetIncident | GitGuardianOperation::ListOccurrences
        )
        .then(|| scope.incident_id.as_str().to_owned());
        let occurrence_id = matches!(operation, GitGuardianOperation::GetOccurrence)
            .then(|| scope.occurrence_id.as_str().to_owned());
        let detector_id = matches!(operation, GitGuardianOperation::GetDetector)
            .then(|| scope.detector_id.as_str().to_owned());
        let status_filter = scope
            .query
            .statuses
            .iter()
            .map(|status| status.as_api_value())
            .collect::<Vec<_>>()
            .join(",");
        let request_digest = Digest::from_serialized(&(
            operation,
            scope.scope_digest(),
            &incident_id,
            &occurrence_id,
            &detector_id,
            &status_filter,
            page,
            scope.query.page_size,
            &cursor,
            &query_digest,
            &endpoint_digest,
        ));
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            incident_id,
            occurrence_id,
            detector_id,
            status_filter,
            page,
            per_page: scope.query.page_size,
            cursor,
            query_digest,
            endpoint_digest,
            request_digest,
        })
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        let query = self.query_string();
        let path = self.path();
        if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        }
    }

    #[must_use]
    pub fn path(&self) -> String {
        match self.operation {
            GitGuardianOperation::ListIncidents => INCIDENTS_ENDPOINT.to_owned(),
            GitGuardianOperation::GetIncident => {
                format!(
                    "{INCIDENTS_ENDPOINT}/{}",
                    self.incident_id.as_deref().unwrap_or("_")
                )
            }
            GitGuardianOperation::ListOccurrences => OCCURRENCES_ENDPOINT.to_owned(),
            GitGuardianOperation::GetOccurrence => {
                format!(
                    "{OCCURRENCES_ENDPOINT}/{}",
                    self.occurrence_id.as_deref().unwrap_or("_")
                )
            }
            GitGuardianOperation::GetDetector => {
                format!(
                    "{DETECTOR_ENDPOINT}/{}",
                    self.detector_id.as_deref().unwrap_or("_")
                )
            }
            GitGuardianOperation::GetStatus => HEALTH_ENDPOINT.to_owned(),
        }
    }

    #[must_use]
    pub fn query_string(&self) -> String {
        let mut values = Vec::new();
        if matches!(
            self.operation,
            GitGuardianOperation::ListIncidents | GitGuardianOperation::ListOccurrences
        ) {
            values.push(format!("per_page={}", self.per_page));
            values.push(format!("page={}", self.page));
            values.push(format!("status={}", self.status_filter));
            if let Some(cursor) = &self.cursor {
                values.push(format!("cursor={}", cursor.token_digest()));
            }
            if self.operation == GitGuardianOperation::ListOccurrences
                && let Some(incident_id) = &self.incident_id
            {
                values.push(format!("incident_id={incident_id}"));
            }
        }
        values.join("&")
    }

    pub fn validate(&self, scope: &GitGuardianScope) -> Result<(), ProviderError> {
        scope.validate().map_err(model_error)?;
        if self.method() != "GET"
            || self.scope_digest != scope.digest()
            || self.per_page == 0
            || self.per_page > MAX_PAGE_SIZE
            || self.page == 0
            || self.page > MAX_PAGES
            || self
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.validate().is_err())
            || self.query_digest
                != scope
                    .query
                    .query_digest_for_request(self.page, self.cursor.as_ref())
            || self.status_filter
                != scope
                    .query
                    .statuses
                    .iter()
                    .map(|status| status.as_api_value())
                    .collect::<Vec<_>>()
                    .join(",")
        {
            return Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "request_binding_mismatch",
            ));
        }
        if self.request_digest != self.computed_digest(scope) {
            return Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "request_digest_mismatch",
            ));
        }
        Ok(())
    }

    fn computed_digest(&self, scope: &GitGuardianScope) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            scope.scope_digest(),
            &self.incident_id,
            &self.occurrence_id,
            &self.detector_id,
            &self.status_filter,
            self.page,
            self.per_page,
            &self.cursor,
            &self.query_digest,
            &self.endpoint_digest,
        ))
    }
}

fn endpoint_for(operation: GitGuardianOperation) -> &'static str {
    match operation {
        GitGuardianOperation::ListIncidents => INCIDENTS_ENDPOINT,
        GitGuardianOperation::GetIncident => INCIDENT_ENDPOINT,
        GitGuardianOperation::ListOccurrences => OCCURRENCES_ENDPOINT,
        GitGuardianOperation::GetOccurrence => OCCURRENCE_ENDPOINT,
        GitGuardianOperation::GetDetector => DETECTORS_ENDPOINT,
        GitGuardianOperation::GetStatus => HEALTH_ENDPOINT,
    }
}

fn model_error(error: ModelError) -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidRequest, error.to_string())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianIncidentPage {
    pub operation: GitGuardianOperation,
    pub page: u16,
    pub items: Vec<GitGuardianIncident>,
    pub next_cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub rate_receipt: RedactedRateReceipt,
}

pub type IncidentPage = GitGuardianIncidentPage;

impl GitGuardianIncidentPage {
    pub fn new(
        operation: GitGuardianOperation,
        page: u16,
        items: Vec<GitGuardianIncident>,
        next_cursor: Option<OpaqueCursor>,
        request_digest: Digest,
        response_bytes: u64,
        rate_receipt: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if operation != GitGuardianOperation::ListIncidents
            || page == 0
            || page > MAX_PAGES
            || items.len() > MAX_INCIDENTS
            || response_bytes > MAX_RESPONSE_BYTES
            || request_digest.validate().is_err()
        {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "incident_page_invalid",
            ));
        }
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.validate().is_err())
        {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "incident_cursor_invalid",
            ));
        }
        let response_digest = Digest::from_serialized(&(
            operation,
            page,
            &items,
            &next_cursor,
            &request_digest,
            response_bytes,
            &rate_receipt,
        ));
        Ok(Self {
            operation,
            page,
            items,
            next_cursor,
            request_digest,
            response_digest,
            response_bytes,
            rate_receipt,
        })
    }

    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        if self.operation != request.operation
            || self.page != request.page
            || self.request_digest != request.request_digest
            || self.items.len() > MAX_INCIDENTS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest != self.computed_digest()
        {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "incident_page_digest_mismatch",
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            self.page,
            &self.items,
            &self.next_cursor,
            &self.request_digest,
            self.response_bytes,
            &self.rate_receipt,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianIncidentResponse {
    pub operation: GitGuardianOperation,
    pub incident: GitGuardianIncident,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub rate_receipt: RedactedRateReceipt,
}

pub type IncidentResponse = GitGuardianIncidentResponse;

impl GitGuardianIncidentResponse {
    pub fn new(
        incident: GitGuardianIncident,
        request_digest: Digest,
        response_bytes: u64,
        rate_receipt: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if request_digest.validate().is_err() || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "incident_response_invalid",
            ));
        }
        let operation = GitGuardianOperation::GetIncident;
        let response_digest = Digest::from_serialized(&(
            operation,
            &incident,
            &request_digest,
            response_bytes,
            &rate_receipt,
        ));
        Ok(Self {
            operation,
            incident,
            request_digest,
            response_digest,
            response_bytes,
            rate_receipt,
        })
    }

    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        if request.operation != GitGuardianOperation::GetIncident
            || self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest != self.computed_digest()
        {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "incident_response_digest_mismatch",
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            &self.incident,
            &self.request_digest,
            self.response_bytes,
            &self.rate_receipt,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianOccurrencePage {
    pub operation: GitGuardianOperation,
    pub page: u16,
    pub items: Vec<GitGuardianOccurrence>,
    pub next_cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub rate_receipt: RedactedRateReceipt,
}

pub type OccurrencePage = GitGuardianOccurrencePage;

impl GitGuardianOccurrencePage {
    pub fn new(
        operation: GitGuardianOperation,
        page: u16,
        items: Vec<GitGuardianOccurrence>,
        next_cursor: Option<OpaqueCursor>,
        request_digest: Digest,
        response_bytes: u64,
        rate_receipt: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if operation != GitGuardianOperation::ListOccurrences
            || page == 0
            || page > MAX_PAGES
            || items.len() > MAX_OCCURRENCES
            || response_bytes > MAX_RESPONSE_BYTES
            || request_digest.validate().is_err()
        {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "occurrence_page_invalid",
            ));
        }
        let response_digest = Digest::from_serialized(&(
            operation,
            page,
            &items,
            &next_cursor,
            &request_digest,
            response_bytes,
            &rate_receipt,
        ));
        Ok(Self {
            operation,
            page,
            items,
            next_cursor,
            request_digest,
            response_digest,
            response_bytes,
            rate_receipt,
        })
    }

    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        if self.operation != request.operation
            || self.page != request.page
            || self.request_digest != request.request_digest
            || self.items.len() > MAX_OCCURRENCES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest != self.computed_digest()
        {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "occurrence_page_digest_mismatch",
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            self.page,
            &self.items,
            &self.next_cursor,
            &self.request_digest,
            self.response_bytes,
            &self.rate_receipt,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianOccurrenceResponse {
    pub operation: GitGuardianOperation,
    pub occurrence: GitGuardianOccurrence,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub rate_receipt: RedactedRateReceipt,
}

pub type OccurrenceResponse = GitGuardianOccurrenceResponse;

impl GitGuardianOccurrenceResponse {
    pub fn new(
        occurrence: GitGuardianOccurrence,
        request_digest: Digest,
        response_bytes: u64,
        rate_receipt: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if request_digest.validate().is_err() || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "occurrence_response_invalid",
            ));
        }
        let operation = GitGuardianOperation::GetOccurrence;
        let response_digest = Digest::from_serialized(&(
            operation,
            &occurrence,
            &request_digest,
            response_bytes,
            &rate_receipt,
        ));
        Ok(Self {
            operation,
            occurrence,
            request_digest,
            response_digest,
            response_bytes,
            rate_receipt,
        })
    }

    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        if request.operation != GitGuardianOperation::GetOccurrence
            || self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.response_digest != self.computed_digest()
        {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "occurrence_response_digest_mismatch",
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            &self.occurrence,
            &self.request_digest,
            self.response_bytes,
            &self.rate_receipt,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianDetectorResponse {
    pub operation: GitGuardianOperation,
    pub detector: GitGuardianDetector,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub rate_receipt: RedactedRateReceipt,
}

pub type DetectorResponse = GitGuardianDetectorResponse;

impl GitGuardianDetectorResponse {
    pub fn new(
        detector: GitGuardianDetector,
        request_digest: Digest,
        response_bytes: u64,
        rate_receipt: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if request_digest.validate().is_err() || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "detector_response_invalid",
            ));
        }
        let operation = GitGuardianOperation::GetDetector;
        let response_digest = Digest::from_serialized(&(
            operation,
            &detector,
            &request_digest,
            response_bytes,
            &rate_receipt,
        ));
        Ok(Self {
            operation,
            detector,
            request_digest,
            response_digest,
            response_bytes,
            rate_receipt,
        })
    }

    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        if request.operation != GitGuardianOperation::GetDetector
            || self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.response_digest != self.computed_digest()
        {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "detector_response_digest_mismatch",
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            &self.detector,
            &self.request_digest,
            self.response_bytes,
            &self.rate_receipt,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitGuardianHealth {
    Healthy,
    Maintenance,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianStatusResponse {
    pub operation: GitGuardianOperation,
    pub health: GitGuardianHealth,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub rate_receipt: RedactedRateReceipt,
}

pub type StatusResponse = GitGuardianStatusResponse;

impl GitGuardianStatusResponse {
    pub fn new(
        health: GitGuardianHealth,
        request_digest: Digest,
        response_bytes: u64,
        rate_receipt: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if request_digest.validate().is_err() || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "status_response_invalid",
            ));
        }
        let operation = GitGuardianOperation::GetStatus;
        let response_digest = Digest::from_serialized(&(
            operation,
            health,
            &request_digest,
            response_bytes,
            &rate_receipt,
        ));
        Ok(Self {
            operation,
            health,
            request_digest,
            response_digest,
            response_bytes,
            rate_receipt,
        })
    }

    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        if request.operation != GitGuardianOperation::GetStatus
            || self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.response_digest != self.computed_digest()
        {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "status_response_digest_mismatch",
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.operation,
            self.health,
            &self.request_digest,
            self.response_bytes,
            &self.rate_receipt,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum GitGuardianResponse {
    IncidentPage(GitGuardianIncidentPage),
    Incident(GitGuardianIncidentResponse),
    OccurrencePage(GitGuardianOccurrencePage),
    Occurrence(GitGuardianOccurrenceResponse),
    Detector(GitGuardianDetectorResponse),
    Status(GitGuardianStatusResponse),
}

pub type ProviderResponse = GitGuardianResponse;

impl GitGuardianResponse {
    pub fn validate(&self, request: &GitGuardianRequest) -> Result<(), ProviderError> {
        match self {
            Self::IncidentPage(response) => response.validate(request),
            Self::Incident(response) => response.validate(request),
            Self::OccurrencePage(response) => response.validate(request),
            Self::Occurrence(response) => response.validate(request),
            Self::Detector(response) => response.validate(request),
            Self::Status(response) => response.validate(request),
        }
    }

    #[must_use]
    pub const fn operation(&self) -> GitGuardianOperation {
        match self {
            Self::IncidentPage(response) => response.operation,
            Self::Incident(response) => response.operation,
            Self::OccurrencePage(response) => response.operation,
            Self::Occurrence(response) => response.operation,
            Self::Detector(response) => response.operation,
            Self::Status(response) => response.operation,
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        match self {
            Self::IncidentPage(response) => &response.request_digest,
            Self::Incident(response) => &response.request_digest,
            Self::OccurrencePage(response) => &response.request_digest,
            Self::Occurrence(response) => &response.request_digest,
            Self::Detector(response) => &response.request_digest,
            Self::Status(response) => &response.request_digest,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> &Digest {
        match self {
            Self::IncidentPage(response) => &response.response_digest,
            Self::Incident(response) => &response.response_digest,
            Self::OccurrencePage(response) => &response.response_digest,
            Self::Occurrence(response) => &response.response_digest,
            Self::Detector(response) => &response.response_digest,
            Self::Status(response) => &response.response_digest,
        }
    }

    #[must_use]
    pub fn rate_receipt(&self) -> &RedactedRateReceipt {
        match self {
            Self::IncidentPage(response) => &response.rate_receipt,
            Self::Incident(response) => &response.rate_receipt,
            Self::OccurrencePage(response) => &response.rate_receipt,
            Self::Occurrence(response) => &response.rate_receipt,
            Self::Detector(response) => &response.rate_receipt,
            Self::Status(response) => &response.rate_receipt,
        }
    }

    #[must_use]
    pub const fn response_bytes(&self) -> u64 {
        match self {
            Self::IncidentPage(response) => response.response_bytes,
            Self::Incident(response) => response.response_bytes,
            Self::OccurrencePage(response) => response.response_bytes,
            Self::Occurrence(response) => response.response_bytes,
            Self::Detector(response) => response.response_bytes,
            Self::Status(response) => response.response_bytes,
        }
    }
}

pub trait GitGuardianTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError>;

    fn provenance(&self) -> TransportProvenance;
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    responses: VecDeque<Result<GitGuardianResponse, ProviderError>>,
    requests: Vec<GitGuardianRequest>,
}

impl FixtureTransport {
    #[must_use]
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<GitGuardianResponse, ProviderError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<GitGuardianResponse, ProviderError>>,
    {
        Self::new(responses)
    }

    pub fn push_response(&mut self, response: Result<GitGuardianResponse, ProviderError>) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[GitGuardianRequest] {
        &self.requests
    }
}

impl GitGuardianTransport for FixtureTransport {
    fn execute(
        &mut self,
        request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(ProviderError::new(
                ProviderErrorKind::FixtureExhausted,
                "fixture_exhausted",
            ))
        })
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }
}

pub type FakeTransport = FixtureTransport;
pub type FixtureGitGuardianTransport = FixtureTransport;
pub type FakeGitGuardianTransport = FixtureTransport;

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    fixture: FixtureTransport,
}

impl RecordingTransport {
    #[must_use]
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<GitGuardianResponse, ProviderError>>,
    {
        Self {
            fixture: FixtureTransport::new(responses),
        }
    }

    #[must_use]
    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<GitGuardianResponse, ProviderError>>,
    {
        Self::new(responses)
    }

    #[must_use]
    pub fn requests(&self) -> &[GitGuardianRequest] {
        self.fixture.requests()
    }
}

impl GitGuardianTransport for RecordingTransport {
    fn execute(
        &mut self,
        request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError> {
        self.fixture.execute(request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }
}

pub type RecordingGitGuardianTransport = RecordingTransport;

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    #[must_use]
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<GitGuardianResponse, ProviderError>>,
    {
        Self {
            fixture: FixtureTransport::new(responses),
        }
    }

    #[must_use]
    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<GitGuardianResponse, ProviderError>>,
    {
        Self::new(responses)
    }

    #[must_use]
    pub fn requests(&self) -> &[GitGuardianRequest] {
        self.fixture.requests()
    }
}

impl GitGuardianTransport for LoopbackTransport {
    fn execute(
        &mut self,
        request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError> {
        self.fixture.execute(request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
}

pub type LoopbackGitGuardianTransport = LoopbackTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl GitGuardianTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::BlockedEnv,
            "BLOCKED_ENV",
        ))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

pub type BlockedEnvGitGuardianTransport = BlockedEnvTransport;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider permission snapshot is invalid")]
    InvalidPermissions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitGuardianProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: Revision,
    pub provider_digest: Digest,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportProvenance,
}

pub type GitGuardianProviderDefinitionAlias = GitGuardianProviderDefinition;
pub type ProviderDefinition = GitGuardianProviderDefinition;

impl GitGuardianProviderDefinition {
    pub fn new(
        provenance: TransportProvenance,
        permissions: &PermissionSnapshot,
    ) -> Result<Self, ProviderDefinitionError> {
        permissions
            .validate()
            .map_err(|_| ProviderDefinitionError::InvalidPermissions)?;
        let provider_revision = Revision::new(1).expect("constant provider revision");
        let api_digest = Digest::from_parts(
            "gitguardian-api/v1",
            [API_REVISION.to_owned(), "GET-only".to_owned()],
        );
        let permission_digest = permissions.digest();
        let provider_digest = Digest::from_parts(
            "gitguardian-provider/v1",
            [
                PROVIDER_ID.to_owned(),
                PLUGIN_VERSION.to_owned(),
                provider_revision.get().to_string(),
                api_digest.to_string(),
                permission_digest.to_string(),
                provenance.as_str().to_owned(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
                "first_party=false".to_owned(),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION.to_owned(),
            provider_revision,
            provider_digest,
            api_revision: API_REVISION.to_owned(),
            api_digest,
            permission_digest,
            provenance,
        })
    }

    pub fn validate(
        &self,
        permissions: &PermissionSnapshot,
    ) -> Result<(), ProviderDefinitionError> {
        let expected = Self::new(self.provenance, permissions)?;
        if self != &expected {
            Err(ProviderDefinitionError::InvalidPermissions)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct GitGuardianProvider<T> {
    definition: GitGuardianProviderDefinition,
    transport: T,
}

pub type GitGuardianSecretResultProvider<T> = GitGuardianProvider<T>;

impl<T: GitGuardianTransport> GitGuardianProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition = GitGuardianProviderDefinition::new(
            transport.provenance(),
            &PermissionSnapshot::least_privilege(),
        )?;
        Ok(Self {
            definition,
            transport,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &GitGuardianProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        scope: &GitGuardianScope,
        request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError> {
        request.validate(scope)?;
        let response = self.transport.execute(request)?;
        response.validate(request)?;
        Ok(response)
    }

    pub fn execute(
        &mut self,
        scope: &GitGuardianScope,
        request: &GitGuardianRequest,
    ) -> Result<GitGuardianResponse, ProviderError> {
        self.read(scope, request)
    }
}

pub type GitGuardianSecretResultProviderDefinition = GitGuardianProviderDefinition;

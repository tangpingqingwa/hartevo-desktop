use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AwsTrustedAdvisorScope, CategorySummary, Digest, MAX_CHECK_DEFINITIONS, MAX_RESPONSE_BYTES,
    PageCursor, RecommendationStatus, RefreshState, TransportProvenance, TrustedAdvisorCategory,
    TrustedAdvisorCheckDefinition, TrustedAdvisorCheckResult, TrustedAdvisorRefreshStatus,
};
use crate::{
    CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, REQUIRED_PERMISSIONS,
};

pub const DESCRIBE_CHECKS_OPERATION: &str = "DescribeTrustedAdvisorChecks";
pub const DESCRIBE_REFRESH_STATUSES_OPERATION: &str = "DescribeTrustedAdvisorCheckRefreshStatuses";
pub const DESCRIBE_RESULT_OPERATION: &str = "DescribeTrustedAdvisorCheckResult";
pub const SUPPORT_ENDPOINT_REGION: &str = "us-east-1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsTrustedAdvisorOperation {
    DescribeTrustedAdvisorChecks,
    DescribeTrustedAdvisorCheckRefreshStatuses,
    DescribeTrustedAdvisorCheckResult,
    CompileResultProposal,
    RecordObservationReceipt,
    VerifyResultProposal,
    RevokeRegistration,
    RestoreRegistration,
}

impl AwsTrustedAdvisorOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeTrustedAdvisorChecks => DESCRIBE_CHECKS_OPERATION,
            Self::DescribeTrustedAdvisorCheckRefreshStatuses => DESCRIBE_REFRESH_STATUSES_OPERATION,
            Self::DescribeTrustedAdvisorCheckResult => DESCRIBE_RESULT_OPERATION,
            Self::CompileResultProposal => "compile_result_proposal",
            Self::RecordObservationReceipt => "record_observation_receipt",
            Self::VerifyResultProposal => "verify_result_proposal",
            Self::RevokeRegistration => "revoke_registration",
            Self::RestoreRegistration => "restore_registration",
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsTrustedAdvisorTransportError {
    #[error("AWS Support returned HTTP 400")]
    BadRequest,
    #[error("AWS Support returned HTTP 401")]
    Unauthorized,
    #[error("AWS Support returned HTTP 403")]
    Forbidden,
    #[error("AWS Support returned HTTP 404")]
    NotFound,
    #[error("AWS Support returned HTTP 409")]
    Conflict,
    #[error("AWS Support returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Support returned server error HTTP {status}")]
    ServerError { status: u16 },
    #[error("AWS Support request timed out")]
    Timeout,
    #[error("AWS Support access was lost")]
    AccessLost,
    #[error("AWS Support transport is unavailable in this environment")]
    BlockedEnv,
    #[error("AWS Trusted Advisor provider response was invalid")]
    InvalidResponse,
}

impl AwsTrustedAdvisorTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::Timeout | Self::AccessLost | Self::BlockedEnv | Self::InvalidResponse => None,
        }
    }

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsTrustedAdvisorProviderError {
    #[error(transparent)]
    Transport(#[from] AwsTrustedAdvisorTransportError),
    #[error("AWS Trusted Advisor provider definition drifted")]
    ProviderDrift,
    #[error("AWS Trusted Advisor provider response failed integrity validation")]
    InvalidResponse,
}

pub trait AwsTrustedAdvisorTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_trusted_advisor_checks(
        &mut self,
        request: &DescribeTrustedAdvisorChecksRequest,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError>;

    fn describe_trusted_advisor_check_refresh_statuses(
        &mut self,
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorTransportError>;

    fn describe_trusted_advisor_check_result(
        &mut self,
        request: &DescribeTrustedAdvisorCheckResultRequest,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorTransportError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeTrustedAdvisorChecksRequest {
    scope: AwsTrustedAdvisorScope,
    request_digest: Digest,
}

impl DescribeTrustedAdvisorChecksRequest {
    pub fn for_scope(
        scope: &AwsTrustedAdvisorScope,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        scope
            .validate()
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_fields(
                "aws-trusted-advisor-describe-checks-request/v1",
                &[
                    scope.scope_digest().as_str().to_owned(),
                    SUPPORT_ENDPOINT_REGION.to_owned(),
                ],
            ),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AwsTrustedAdvisorScope {
        &self.scope
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest::new(
            AwsTrustedAdvisorOperation::DescribeTrustedAdvisorChecks,
            &self.scope,
            self.request_digest.clone(),
            None,
        )
    }
}

impl fmt::Debug for DescribeTrustedAdvisorChecksRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeTrustedAdvisorChecksRequest")
            .field("scope_digest", self.scope.scope_digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeTrustedAdvisorCheckRefreshStatusesRequest {
    scope: AwsTrustedAdvisorScope,
    request_digest: Digest,
}

impl DescribeTrustedAdvisorCheckRefreshStatusesRequest {
    pub fn for_scope(
        scope: &AwsTrustedAdvisorScope,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        scope
            .validate()
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_fields(
                "aws-trusted-advisor-refresh-statuses-request/v1",
                &[
                    scope.scope_digest().as_str().to_owned(),
                    scope.check_id().digest().as_str().to_owned(),
                    SUPPORT_ENDPOINT_REGION.to_owned(),
                ],
            ),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AwsTrustedAdvisorScope {
        &self.scope
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest::new(
            AwsTrustedAdvisorOperation::DescribeTrustedAdvisorCheckRefreshStatuses,
            &self.scope,
            self.request_digest.clone(),
            None,
        )
    }
}

impl fmt::Debug for DescribeTrustedAdvisorCheckRefreshStatusesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeTrustedAdvisorCheckRefreshStatusesRequest")
            .field("scope_digest", self.scope.scope_digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeTrustedAdvisorCheckResultRequest {
    scope: AwsTrustedAdvisorScope,
    cursor: Option<PageCursor>,
    request_digest: Digest,
}

impl DescribeTrustedAdvisorCheckResultRequest {
    pub fn for_scope(
        scope: &AwsTrustedAdvisorScope,
        cursor: Option<PageCursor>,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        scope
            .validate()
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        if let Some(cursor) = &cursor {
            cursor
                .validate_against(scope)
                .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_fields(
                "aws-trusted-advisor-result-request/v1",
                &[
                    scope.scope_digest().as_str().to_owned(),
                    scope.check_id().digest().as_str().to_owned(),
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                    SUPPORT_ENDPOINT_REGION.to_owned(),
                ],
            ),
            cursor,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AwsTrustedAdvisorScope {
        &self.scope
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, PageCursor::page_number)
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest::new(
            AwsTrustedAdvisorOperation::DescribeTrustedAdvisorCheckResult,
            &self.scope,
            self.request_digest.clone(),
            self.cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
        )
    }
}

impl fmt::Debug for DescribeTrustedAdvisorCheckResultRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeTrustedAdvisorCheckResultRequest")
            .field("scope_digest", self.scope.scope_digest())
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsTrustedAdvisorOperation,
    pub scope_digest: Digest,
    pub check_digest: Digest,
    pub category: TrustedAdvisorCategory,
    pub page_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl RecordedRequest {
    fn new(
        operation: AwsTrustedAdvisorOperation,
        scope: &AwsTrustedAdvisorScope,
        request_digest: Digest,
        page_digest: Option<Digest>,
    ) -> Self {
        Self {
            operation,
            scope_digest: scope.scope_digest().clone(),
            check_digest: scope.check_id().digest(),
            category: scope.category(),
            page_digest,
            request_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTrustedAdvisorChecksResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub definitions: Vec<TrustedAdvisorCheckDefinition>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeTrustedAdvisorChecksResponse {
    pub fn new(
        request: &DescribeTrustedAdvisorChecksRequest,
        definitions: Vec<TrustedAdvisorCheckDefinition>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        validate_response_bytes(response_bytes)?;
        if definitions.is_empty() || definitions.len() > MAX_CHECK_DEFINITIONS {
            return Err(AwsTrustedAdvisorProviderError::InvalidResponse);
        }
        for definition in &definitions {
            definition
                .validate_integrity(request.scope())
                .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        }
        let mut response = Self {
            scope_digest: request.scope().scope_digest().clone(),
            request_digest: request.request_digest().clone(),
            definitions,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-aws-trusted-advisor-checks-response"),
            connected: false,
            native: false,
            first_party: false,
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

    fn validate_integrity(
        &self,
        request: &DescribeTrustedAdvisorChecksRequest,
        provenance: TransportProvenance,
    ) -> Result<(), AwsTrustedAdvisorProviderError> {
        if self.scope_digest != *request.scope().scope_digest()
            || self.request_digest != *request.request_digest()
            || self.definitions.is_empty()
            || self.definitions.len() > MAX_CHECK_DEFINITIONS
            || self.provenance != provenance
            || self.provenance.is_native()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsTrustedAdvisorProviderError::InvalidResponse);
        }
        for definition in &self.definitions {
            definition
                .validate_integrity(request.scope())
                .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-checks-response/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                self.definitions
                    .iter()
                    .map(|definition| definition.evidence_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTrustedAdvisorCheckRefreshStatusesResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub refresh_status: TrustedAdvisorRefreshStatus,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeTrustedAdvisorCheckRefreshStatusesResponse {
    pub fn new(
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
        refresh_status: TrustedAdvisorRefreshStatus,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        validate_response_bytes(response_bytes)?;
        refresh_status
            .validate_integrity(request.scope())
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        let mut response = Self {
            scope_digest: request.scope().scope_digest().clone(),
            request_digest: request.request_digest().clone(),
            refresh_status,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-aws-trusted-advisor-refresh-response"),
            connected: false,
            native: false,
            first_party: false,
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

    fn validate_integrity(
        &self,
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
        provenance: TransportProvenance,
    ) -> Result<(), AwsTrustedAdvisorProviderError> {
        if self.scope_digest != *request.scope().scope_digest()
            || self.request_digest != *request.request_digest()
            || self.provenance != provenance
            || self.provenance.is_native()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsTrustedAdvisorProviderError::InvalidResponse);
        }
        self.refresh_status
            .validate_integrity(request.scope())
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-refresh-response/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                self.refresh_status.response_digest.as_str().to_owned(),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTrustedAdvisorCheckResultResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub result: TrustedAdvisorCheckResult,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeTrustedAdvisorCheckResultResponse {
    pub fn new(
        request: &DescribeTrustedAdvisorCheckResultRequest,
        result: TrustedAdvisorCheckResult,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        validate_response_bytes(response_bytes)?;
        result
            .validate_integrity(request.scope())
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)?;
        let mut response = Self {
            scope_digest: request.scope().scope_digest().clone(),
            request_digest: request.request_digest().clone(),
            result,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-aws-trusted-advisor-result-response"),
            connected: false,
            native: false,
            first_party: false,
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

    fn validate_integrity(
        &self,
        request: &DescribeTrustedAdvisorCheckResultRequest,
        provenance: TransportProvenance,
    ) -> Result<(), AwsTrustedAdvisorProviderError> {
        if self.scope_digest != *request.scope().scope_digest()
            || self.request_digest != *request.request_digest()
            || self.provenance != provenance
            || self.provenance.is_native()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsTrustedAdvisorProviderError::InvalidResponse);
        }
        self.result
            .validate_integrity(request.scope())
            .map_err(|_| AwsTrustedAdvisorProviderError::InvalidResponse)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-result-response/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                self.result.result_digest.as_str().to_owned(),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTrustedAdvisorProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub provider_release: String,
    pub api_revision: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsTrustedAdvisorProviderDefinition {
    pub fn new(
        provider_revision: u64,
        provider_release: impl Into<String>,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        let provider_release = provider_release.into();
        if provider_revision == 0 || provider_release.is_empty() || provider_release.len() > 128 {
            return Err(AwsTrustedAdvisorProviderError::ProviderDrift);
        }
        let capability_digest = Digest::from_fields(
            "aws-trusted-advisor-provider-capabilities/v1",
            &REQUIRED_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_fields(
            "aws-trusted-advisor-provider/v1",
            &[
                PROVIDER_ID.to_owned(),
                provider_revision.to_string(),
                provider_release.clone(),
                PROVIDER_API_REVISION.to_owned(),
                CONTRACT_VERSION.to_owned(),
                PLUGIN_VERSION.to_owned(),
                capability_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            provider_release,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<(), AwsTrustedAdvisorProviderError> {
        let expected = Self::new(self.provider_revision, self.provider_release.clone())?;
        if self != &expected {
            Err(AwsTrustedAdvisorProviderError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

pub struct AwsTrustedAdvisorProvider<T> {
    transport: T,
    definition: AwsTrustedAdvisorProviderDefinition,
}

impl<T: AwsTrustedAdvisorTransport> fmt::Debug for AwsTrustedAdvisorProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsTrustedAdvisorProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsTrustedAdvisorTransport> AwsTrustedAdvisorProvider<T> {
    pub fn new(transport: T) -> Result<Self, AwsTrustedAdvisorProviderError> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        provider_release: impl Into<String>,
    ) -> Result<Self, AwsTrustedAdvisorProviderError> {
        let definition =
            AwsTrustedAdvisorProviderDefinition::new(provider_revision, provider_release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &AwsTrustedAdvisorProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn describe_trusted_advisor_checks(
        &mut self,
        request: &DescribeTrustedAdvisorChecksRequest,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorProviderError> {
        let response = self.transport.describe_trusted_advisor_checks(request)?;
        response.validate_integrity(request, self.provenance())?;
        Ok(response)
    }

    pub fn describe_trusted_advisor_check_refresh_statuses(
        &mut self,
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorProviderError>
    {
        let response = self
            .transport
            .describe_trusted_advisor_check_refresh_statuses(request)?;
        response.validate_integrity(request, self.provenance())?;
        Ok(response)
    }

    pub fn describe_trusted_advisor_check_result(
        &mut self,
        request: &DescribeTrustedAdvisorCheckResultRequest,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorProviderError> {
        let response = self
            .transport
            .describe_trusted_advisor_check_result(request)?;
        response.validate_integrity(request, self.provenance())?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsTrustedAdvisorScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.scope_digest().clone(),
            observed_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope_digest: Digest,
    observed_at: DateTime<Utc>,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsTrustedAdvisorScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.scope_digest().clone(),
            observed_at,
        }
    }
}

fn ensure_transport_scope(
    expected: &Digest,
    scope: &AwsTrustedAdvisorScope,
) -> Result<(), AwsTrustedAdvisorTransportError> {
    if expected == scope.scope_digest() {
        Ok(())
    } else {
        Err(AwsTrustedAdvisorTransportError::AccessLost)
    }
}

fn fixture_definition(
    scope: &AwsTrustedAdvisorScope,
    provenance: TransportProvenance,
) -> Result<TrustedAdvisorCheckDefinition, AwsTrustedAdvisorTransportError> {
    TrustedAdvisorCheckDefinition::new(
        scope,
        Digest::from_text("fixture-aws-trusted-advisor-definition"),
        512,
        provenance,
    )
    .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
}

fn fixture_refresh(
    scope: &AwsTrustedAdvisorScope,
    observed_at: DateTime<Utc>,
    provenance: TransportProvenance,
) -> Result<TrustedAdvisorRefreshStatus, AwsTrustedAdvisorTransportError> {
    TrustedAdvisorRefreshStatus::new(
        scope,
        RefreshState::Complete,
        Some(observed_at - Duration::hours(1)),
        768,
        provenance,
    )
    .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
}

fn fixture_result(
    scope: &AwsTrustedAdvisorScope,
    observed_at: DateTime<Utc>,
    provenance: TransportProvenance,
    status: RecommendationStatus,
) -> Result<TrustedAdvisorCheckResult, AwsTrustedAdvisorTransportError> {
    let summary = CategorySummary::new(scope.category(), status, 2, 8)
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)?;
    let flagged_resources = vec![
        crate::model::FlaggedResourceDigest::new(
            "arn:aws:trusted-advisor:fixture:resource-1",
            scope.region().clone(),
        )
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)?,
        crate::model::FlaggedResourceDigest::new(
            "arn:aws:trusted-advisor:fixture:resource-2",
            scope.region().clone(),
        )
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)?,
    ];
    TrustedAdvisorCheckResult::new(
        scope,
        status,
        observed_at - Duration::minutes(30),
        summary,
        flagged_resources,
        None,
        1_024,
        provenance,
    )
    .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
}

impl AwsTrustedAdvisorTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_trusted_advisor_checks(
        &mut self,
        request: &DescribeTrustedAdvisorChecksRequest,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError> {
        ensure_transport_scope(&self.scope_digest, request.scope())?;
        let definition = fixture_definition(request.scope(), self.provenance())?;
        DescribeTrustedAdvisorChecksResponse::new(request, vec![definition], 512, self.provenance())
            .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
    }

    fn describe_trusted_advisor_check_refresh_statuses(
        &mut self,
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorTransportError>
    {
        ensure_transport_scope(&self.scope_digest, request.scope())?;
        let refresh = fixture_refresh(request.scope(), self.observed_at, self.provenance())?;
        DescribeTrustedAdvisorCheckRefreshStatusesResponse::new(
            request,
            refresh,
            768,
            self.provenance(),
        )
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
    }

    fn describe_trusted_advisor_check_result(
        &mut self,
        request: &DescribeTrustedAdvisorCheckResultRequest,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorTransportError> {
        ensure_transport_scope(&self.scope_digest, request.scope())?;
        let result = fixture_result(
            request.scope(),
            self.observed_at,
            self.provenance(),
            RecommendationStatus::Warning,
        )?;
        DescribeTrustedAdvisorCheckResultResponse::new(request, result, 1_024, self.provenance())
            .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
    }
}

impl AwsTrustedAdvisorTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_trusted_advisor_checks(
        &mut self,
        request: &DescribeTrustedAdvisorChecksRequest,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError> {
        ensure_transport_scope(&self.scope_digest, request.scope())?;
        DescribeTrustedAdvisorChecksResponse::new(
            request,
            vec![fixture_definition(request.scope(), self.provenance())?],
            512,
            self.provenance(),
        )
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
    }

    fn describe_trusted_advisor_check_refresh_statuses(
        &mut self,
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorTransportError>
    {
        ensure_transport_scope(&self.scope_digest, request.scope())?;
        DescribeTrustedAdvisorCheckRefreshStatusesResponse::new(
            request,
            fixture_refresh(request.scope(), self.observed_at, self.provenance())?,
            768,
            self.provenance(),
        )
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
    }

    fn describe_trusted_advisor_check_result(
        &mut self,
        request: &DescribeTrustedAdvisorCheckResultRequest,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorTransportError> {
        ensure_transport_scope(&self.scope_digest, request.scope())?;
        DescribeTrustedAdvisorCheckResultResponse::new(
            request,
            fixture_result(
                request.scope(),
                self.observed_at,
                self.provenance(),
                RecommendationStatus::Ok,
            )?,
            1_024,
            self.provenance(),
        )
        .map_err(|_| AwsTrustedAdvisorTransportError::InvalidResponse)
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    check_responses:
        VecDeque<Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError>>,
    refresh_responses: VecDeque<
        Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorTransportError>,
    >,
    result_responses: VecDeque<
        Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_checks_response(
        &mut self,
        response: Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError>,
    ) {
        self.check_responses.push_back(response);
    }

    pub fn push_refresh_response(
        &mut self,
        response: Result<
            DescribeTrustedAdvisorCheckRefreshStatusesResponse,
            AwsTrustedAdvisorTransportError,
        >,
    ) {
        self.refresh_responses.push_back(response);
    }

    pub fn push_result_response(
        &mut self,
        response: Result<
            DescribeTrustedAdvisorCheckResultResponse,
            AwsTrustedAdvisorTransportError,
        >,
    ) {
        self.result_responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl AwsTrustedAdvisorTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn describe_trusted_advisor_checks(
        &mut self,
        request: &DescribeTrustedAdvisorChecksRequest,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError> {
        self.requests.push(request.recorded_request());
        self.check_responses
            .pop_front()
            .unwrap_or(Err(AwsTrustedAdvisorTransportError::BlockedEnv))
    }

    fn describe_trusted_advisor_check_refresh_statuses(
        &mut self,
        request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorTransportError>
    {
        self.requests.push(request.recorded_request());
        self.refresh_responses
            .pop_front()
            .unwrap_or(Err(AwsTrustedAdvisorTransportError::BlockedEnv))
    }

    fn describe_trusted_advisor_check_result(
        &mut self,
        request: &DescribeTrustedAdvisorCheckResultRequest,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorTransportError> {
        self.requests.push(request.recorded_request());
        self.result_responses
            .pop_front()
            .unwrap_or(Err(AwsTrustedAdvisorTransportError::BlockedEnv))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsTrustedAdvisorTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_trusted_advisor_checks(
        &mut self,
        _request: &DescribeTrustedAdvisorChecksRequest,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorTransportError> {
        Err(AwsTrustedAdvisorTransportError::BlockedEnv)
    }

    fn describe_trusted_advisor_check_refresh_statuses(
        &mut self,
        _request: &DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorTransportError>
    {
        Err(AwsTrustedAdvisorTransportError::BlockedEnv)
    }

    fn describe_trusted_advisor_check_result(
        &mut self,
        _request: &DescribeTrustedAdvisorCheckResultRequest,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorTransportError> {
        Err(AwsTrustedAdvisorTransportError::BlockedEnv)
    }
}

pub type FixtureAwsTrustedAdvisorTransport = FixtureTransport;
pub type LoopbackAwsTrustedAdvisorTransport = LoopbackTransport;
pub type RecordingAwsTrustedAdvisorTransport = RecordingTransport;
pub type BlockedEnvAwsTrustedAdvisorTransport = BlockedEnvTransport;
pub type AwsTrustedAdvisorProviderErrorKind = AwsTrustedAdvisorTransportError;

fn validate_response_bytes(response_bytes: u64) -> Result<(), AwsTrustedAdvisorProviderError> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsTrustedAdvisorProviderError::InvalidResponse)
    } else {
        Ok(())
    }
}

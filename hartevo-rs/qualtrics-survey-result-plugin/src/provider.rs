use std::{collections::VecDeque, fmt, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    QUALTRICS_API_VERSION, QUALTRICS_PROVIDER_ID, QUALTRICS_PROVIDER_REVISION,
    QUALTRICS_SURVEY_RESULT_SERVICE_ID,
    model::{
        AnswerPage, Digest, MAX_BACKOFF_MILLISECONDS, MAX_PATH_BYTES, MAX_RETRY_ATTEMPTS,
        ModelError, OpaqueExportReference, OpaquePageToken, QualtricsPayload,
        QualtricsResultBounds, QualtricsScope, QuestionMetadata, ResponseExportProgress,
        ResponseMetadata, ResponseStatusEvidence, SurveyMetadata,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualtricsProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl QualtricsProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

pub type ProviderProvenance = QualtricsProviderProvenance;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualtricsReadOperation {
    SurveyMetadata,
    QuestionMetadata,
    ResponseMetadata,
    ResponseStatus,
    BoundedNumericChoiceAnswers,
    ResponseExportProgress,
}

impl QualtricsReadOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SurveyMetadata => "survey_metadata",
            Self::QuestionMetadata => "question_metadata",
            Self::ResponseMetadata => "response_metadata",
            Self::ResponseStatus => "response_status",
            Self::BoundedNumericChoiceAnswers => "bounded_numeric_choice_answers",
            Self::ResponseExportProgress => "response_export_progress_proposal",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty or malformed")]
    InvalidVersion,
    #[error("provider definition is not bound to the Qualtrics service")]
    ServiceMismatch,
    #[error("provider definition has an unsupported transport provenance")]
    UnsupportedProvenance,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsProviderDefinition {
    id: String,
    service_id: String,
    version: String,
    api_version: String,
    provenance: QualtricsProviderProvenance,
    digest: Digest,
}

impl QualtricsProviderDefinition {
    pub fn new(
        version: impl Into<String>,
        provenance: QualtricsProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let version = version.into();
        if version.is_empty()
            || version.len() > 64
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        let provider_id = crate::model::ProviderId::new(QUALTRICS_PROVIDER_ID)?;
        let digest = Digest::from_fields(
            "qualtrics-provider-definition/v1",
            &[
                QUALTRICS_PROVIDER_ID.to_owned(),
                QUALTRICS_SURVEY_RESULT_SERVICE_ID.to_owned(),
                version.clone(),
                QUALTRICS_API_VERSION.to_owned(),
                provenance.as_str().to_owned(),
            ],
        );
        Ok(Self {
            id: provider_id.as_str().to_owned(),
            service_id: QUALTRICS_SURVEY_RESULT_SERVICE_ID.to_owned(),
            version,
            api_version: QUALTRICS_API_VERSION.to_owned(),
            provenance,
            digest,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub const fn provenance(&self) -> QualtricsProviderProvenance {
        self.provenance
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualtricsGetRequest {
    operation: QualtricsReadOperation,
    datacenter: String,
    path: String,
    scope_digest: Digest,
    request_digest: Digest,
}

impl QualtricsGetRequest {
    fn build(
        scope: &QualtricsScope,
        operation: QualtricsReadOperation,
        path: String,
        extra_digest_fields: &[String],
    ) -> Result<Self, ModelError> {
        if path.is_empty() || path.len() > MAX_PATH_BYTES || !path.starts_with("/API/v3/") {
            return Err(ModelError::InvalidOpaqueValue);
        }
        if path.contains('?') || path.contains('#') || path.contains("//") {
            return Err(ModelError::InvalidOpaqueValue);
        }
        let mut fields = vec![
            operation.as_str().to_owned(),
            scope.datacenter().as_str().to_owned(),
            path.clone(),
            scope.scope_digest().as_str().to_owned(),
        ];
        fields.extend(extra_digest_fields.iter().cloned());
        Ok(Self {
            operation,
            datacenter: scope.datacenter().as_str().to_owned(),
            path,
            scope_digest: scope.scope_digest().clone(),
            request_digest: Digest::from_fields("qualtrics-get-request/v1", &fields),
        })
    }

    pub(crate) fn survey_metadata(scope: &QualtricsScope) -> Result<Self, ModelError> {
        Self::build(
            scope,
            QualtricsReadOperation::SurveyMetadata,
            format!("/API/v3/surveys/{}", scope.survey().as_str()),
            &[],
        )
    }

    pub(crate) fn question_metadata(scope: &QualtricsScope) -> Result<Self, ModelError> {
        let question = scope.require_question()?;
        Self::build(
            scope,
            QualtricsReadOperation::QuestionMetadata,
            format!(
                "/API/v3/surveys/{}/questions/{}",
                scope.survey().as_str(),
                question.as_str()
            ),
            &[],
        )
    }

    pub(crate) fn response_metadata(scope: &QualtricsScope) -> Result<Self, ModelError> {
        let response = scope.require_response()?;
        Self::build(
            scope,
            QualtricsReadOperation::ResponseMetadata,
            format!(
                "/API/v3/surveys/{}/responses/{}",
                scope.survey().as_str(),
                response.as_str()
            ),
            &[],
        )
    }

    pub(crate) fn response_status(scope: &QualtricsScope) -> Result<Self, ModelError> {
        let response = scope.require_response()?;
        Self::build(
            scope,
            QualtricsReadOperation::ResponseStatus,
            format!(
                "/API/v3/surveys/{}/responses/{}/status",
                scope.survey().as_str(),
                response.as_str()
            ),
            &[],
        )
    }

    pub(crate) fn answers(
        scope: &QualtricsScope,
        page_token: Option<&OpaquePageToken>,
        page_size: usize,
    ) -> Result<Self, ModelError> {
        let question = scope.require_question()?;
        let response = scope.require_response()?;
        if page_size == 0 || page_size > crate::model::MAX_PAGE_SIZE {
            return Err(ModelError::InvalidBounds);
        }
        let page_digest =
            page_token.map_or_else(String::new, |value| value.digest().as_str().to_owned());
        Self::build(
            scope,
            QualtricsReadOperation::BoundedNumericChoiceAnswers,
            format!(
                "/API/v3/surveys/{}/responses/{}/questions/{}",
                scope.survey().as_str(),
                response.as_str(),
                question.as_str()
            ),
            &[page_size.to_string(), page_digest],
        )
    }

    pub(crate) fn export_progress(
        scope: &QualtricsScope,
        export_reference: &OpaqueExportReference,
    ) -> Result<Self, ModelError> {
        Self::build(
            scope,
            QualtricsReadOperation::ResponseExportProgress,
            format!(
                "/API/v3/responseexports/{}",
                export_reference.digest().as_str()
            ),
            &[export_reference.digest().as_str().to_owned()],
        )
    }

    pub const fn operation(&self) -> QualtricsReadOperation {
        self.operation
    }

    pub const fn method(&self) -> &'static str {
        "GET"
    }

    pub fn datacenter(&self) -> &str {
        &self.datacenter
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QualtricsTransportError {
    #[error("environment is blocked from native Qualtrics access")]
    BlockedEnvironment,
    #[error("bounded Qualtrics transport is unavailable")]
    Unavailable,
    #[error("Qualtrics returned an HTTP status that is not available to Layer 1")]
    HttpStatus(u16),
    #[error("Qualtrics transport was rate limited")]
    RateLimited,
}

pub type TransportError = QualtricsTransportError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualtricsTransportResponse {
    status_code: u16,
    response_size_bytes: usize,
    provider_revision: String,
    payload: QualtricsPayload,
    response_digest: Digest,
    retry_after: Option<Duration>,
}

impl QualtricsTransportResponse {
    pub fn success(
        payload: QualtricsPayload,
        provider_revision: impl Into<String>,
        response_size_bytes: usize,
    ) -> Self {
        let response_digest = payload.digest();
        Self {
            status_code: 200,
            response_size_bytes,
            provider_revision: provider_revision.into(),
            payload,
            response_digest,
            retry_after: None,
        }
    }

    pub fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = status_code;
        self
    }

    pub fn with_response_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    pub const fn response_size_bytes(&self) -> usize {
        self.response_size_bytes
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn payload(&self) -> &QualtricsPayload {
        &self.payload
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

pub trait QualtricsGetTransport: fmt::Debug + Send {
    fn get(
        &mut self,
        request: &QualtricsGetRequest,
    ) -> Result<QualtricsTransportResponse, QualtricsTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsRequestReceipt {
    operation: QualtricsReadOperation,
    method: String,
    path_digest: Digest,
    scope_digest: Digest,
    request_digest: Digest,
}

impl QualtricsRequestReceipt {
    fn from_request(request: &QualtricsGetRequest) -> Self {
        Self {
            operation: request.operation,
            method: request.method().to_owned(),
            path_digest: Digest::from_text(request.path()),
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
        }
    }

    pub const fn operation(&self) -> QualtricsReadOperation {
        self.operation
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsRetryEvidence {
    attempts: u8,
    backoff_milliseconds: u32,
    bounded: bool,
}

impl QualtricsRetryEvidence {
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn backoff_milliseconds(&self) -> u32 {
        self.backoff_milliseconds
    }

    pub const fn bounded(&self) -> bool {
        self.bounded
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsResponseReceipt {
    status_code: u16,
    response_size_bytes: usize,
    response_digest: Digest,
    provider_revision: String,
    retry: QualtricsRetryEvidence,
}

impl QualtricsResponseReceipt {
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    pub const fn response_size_bytes(&self) -> usize {
        self.response_size_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn retry(&self) -> &QualtricsRetryEvidence {
        &self.retry
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsReadReceipt {
    request: QualtricsRequestReceipt,
    response: QualtricsResponseReceipt,
}

impl QualtricsReadReceipt {
    pub fn request(&self) -> &QualtricsRequestReceipt {
        &self.request
    }

    pub fn response(&self) -> &QualtricsResponseReceipt {
        &self.response
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QualtricsProviderError {
    #[error("provider request is out of the Qualtrics allowlist")]
    InvalidRequest,
    #[error("provider response exceeded the bounded response-size limit")]
    ResponseTooLarge,
    #[error("provider response was outside the expected typed operation")]
    UnexpectedPayload,
    #[error("provider response digest was tampered with or stale")]
    TamperedEvidence,
    #[error("provider response used an unexpected revision")]
    ProviderRevisionDrift,
    #[error("Qualtrics access was lost or denied")]
    AccessLost,
    #[error("Qualtrics provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Qualtrics rate limit remained after bounded backoff")]
    RateLimited,
    #[error("blocked environment is not native provider access")]
    BlockedEnvironment,
    #[error(transparent)]
    Transport(#[from] QualtricsTransportError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

pub struct ProviderObservation<T> {
    value: T,
    receipt: QualtricsReadReceipt,
}

impl<T: fmt::Debug> fmt::Debug for ProviderObservation<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderObservation")
            .field("value", &self.value)
            .field("receipt", &self.receipt)
            .finish()
    }
}

impl<T: Clone> Clone for ProviderObservation<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            receipt: self.receipt.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for ProviderObservation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.receipt == other.receipt
    }
}

impl<T: Eq> Eq for ProviderObservation<T> {}

impl<T> ProviderObservation<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }

    pub fn receipt(&self) -> &QualtricsReadReceipt {
        &self.receipt
    }
}

pub struct QualtricsProvider {
    transport: Box<dyn QualtricsGetTransport>,
    definition: QualtricsProviderDefinition,
    max_response_bytes: usize,
    max_retry_attempts: u8,
    max_backoff: Duration,
    receipts: Vec<QualtricsReadReceipt>,
}

impl fmt::Debug for QualtricsProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualtricsProvider")
            .field("definition", &self.definition)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_retry_attempts", &self.max_retry_attempts)
            .field("max_backoff", &self.max_backoff)
            .field("receipts", &self.receipts)
            .finish_non_exhaustive()
    }
}

impl QualtricsProvider {
    pub fn new<T: QualtricsGetTransport + 'static>(
        transport: T,
        provenance: QualtricsProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::with_version(transport, QUALTRICS_PROVIDER_REVISION, provenance)
    }

    pub fn with_version<T: QualtricsGetTransport + 'static>(
        transport: T,
        version: impl Into<String>,
        provenance: QualtricsProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = QualtricsProviderDefinition::new(version, provenance)?;
        Ok(Self {
            transport: Box::new(transport),
            definition,
            max_response_bytes: crate::model::MAX_RESPONSE_BYTES,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
            max_backoff: Duration::from_millis(u64::from(MAX_BACKOFF_MILLISECONDS)),
            receipts: Vec::new(),
        })
    }

    pub fn with_bounds(mut self, bounds: &QualtricsResultBounds) -> Result<Self, ModelError> {
        bounds.validate()?;
        self.max_response_bytes = bounds.max_response_bytes();
        self.max_retry_attempts = bounds.max_retry_attempts();
        self.max_backoff = bounds.max_backoff();
        Ok(self)
    }

    pub fn set_bounds(&mut self, bounds: &QualtricsResultBounds) -> Result<(), ModelError> {
        bounds.validate()?;
        self.max_response_bytes = bounds.max_response_bytes();
        self.max_retry_attempts = bounds.max_retry_attempts();
        self.max_backoff = bounds.max_backoff();
        Ok(())
    }

    pub fn definition(&self) -> &QualtricsProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> QualtricsProviderProvenance {
        self.definition.provenance()
    }

    pub fn provider_digest(&self) -> &Digest {
        self.definition.digest()
    }

    pub fn receipts(&self) -> &[QualtricsReadReceipt] {
        &self.receipts
    }

    pub fn take_receipts(&mut self) -> Vec<QualtricsReadReceipt> {
        std::mem::take(&mut self.receipts)
    }

    pub fn get_survey_metadata(
        &mut self,
        scope: &QualtricsScope,
    ) -> Result<ProviderObservation<SurveyMetadata>, QualtricsProviderError> {
        let request = QualtricsGetRequest::survey_metadata(scope)?;
        let observation = self.execute(scope, request)?;
        match observation.value {
            QualtricsPayload::SurveyMetadata(value) => Ok(ProviderObservation {
                value,
                receipt: observation.receipt,
            }),
            _ => Err(QualtricsProviderError::UnexpectedPayload),
        }
    }

    pub fn get_question_metadata(
        &mut self,
        scope: &QualtricsScope,
    ) -> Result<ProviderObservation<QuestionMetadata>, QualtricsProviderError> {
        let request = QualtricsGetRequest::question_metadata(scope)?;
        let observation = self.execute(scope, request)?;
        match observation.value {
            QualtricsPayload::QuestionMetadata(value) => Ok(ProviderObservation {
                value,
                receipt: observation.receipt,
            }),
            _ => Err(QualtricsProviderError::UnexpectedPayload),
        }
    }

    pub fn get_response_metadata(
        &mut self,
        scope: &QualtricsScope,
    ) -> Result<ProviderObservation<ResponseMetadata>, QualtricsProviderError> {
        let request = QualtricsGetRequest::response_metadata(scope)?;
        let observation = self.execute(scope, request)?;
        match observation.value {
            QualtricsPayload::ResponseMetadata(value) => Ok(ProviderObservation {
                value,
                receipt: observation.receipt,
            }),
            _ => Err(QualtricsProviderError::UnexpectedPayload),
        }
    }

    pub fn get_response_status(
        &mut self,
        scope: &QualtricsScope,
    ) -> Result<ProviderObservation<ResponseStatusEvidence>, QualtricsProviderError> {
        let request = QualtricsGetRequest::response_status(scope)?;
        let observation = self.execute(scope, request)?;
        match observation.value {
            QualtricsPayload::ResponseStatus(value) => Ok(ProviderObservation {
                value,
                receipt: observation.receipt,
            }),
            _ => Err(QualtricsProviderError::UnexpectedPayload),
        }
    }

    pub fn get_numeric_choice_answers(
        &mut self,
        scope: &QualtricsScope,
        page_token: Option<&OpaquePageToken>,
    ) -> Result<ProviderObservation<AnswerPage>, QualtricsProviderError> {
        self.get_numeric_choice_answers_bounded(scope, page_token, crate::model::MAX_PAGE_SIZE)
    }

    pub fn get_numeric_choice_answers_bounded(
        &mut self,
        scope: &QualtricsScope,
        page_token: Option<&OpaquePageToken>,
        page_size: usize,
    ) -> Result<ProviderObservation<AnswerPage>, QualtricsProviderError> {
        let request = QualtricsGetRequest::answers(scope, page_token, page_size)?;
        let observation = self.execute(scope, request)?;
        match observation.value {
            QualtricsPayload::AnswerPage(value) => Ok(ProviderObservation {
                value,
                receipt: observation.receipt,
            }),
            _ => Err(QualtricsProviderError::UnexpectedPayload),
        }
    }

    pub fn get_response_export_progress(
        &mut self,
        scope: &QualtricsScope,
        export_reference: &OpaqueExportReference,
    ) -> Result<ProviderObservation<ResponseExportProgress>, QualtricsProviderError> {
        let request = QualtricsGetRequest::export_progress(scope, export_reference)?;
        let observation = self.execute(scope, request)?;
        match observation.value {
            QualtricsPayload::ExportProgress(value) => Ok(ProviderObservation {
                value,
                receipt: observation.receipt,
            }),
            _ => Err(QualtricsProviderError::UnexpectedPayload),
        }
    }

    fn execute(
        &mut self,
        scope: &QualtricsScope,
        request: QualtricsGetRequest,
    ) -> Result<ProviderObservation<QualtricsPayload>, QualtricsProviderError> {
        if request.scope_digest() != scope.scope_digest() {
            return Err(QualtricsProviderError::InvalidRequest);
        }
        let request_receipt = QualtricsRequestReceipt::from_request(&request);
        let mut attempts = 0_u8;
        let mut total_backoff = 0_u32;
        loop {
            attempts = attempts.saturating_add(1);
            let response = match self.transport.get(&request) {
                Ok(response) => response,
                Err(error) => {
                    let retryable = matches!(
                        error,
                        QualtricsTransportError::Unavailable | QualtricsTransportError::RateLimited
                    );
                    if retryable && attempts < self.max_retry_attempts {
                        total_backoff = total_backoff.saturating_add(backoff_for(
                            attempts,
                            None,
                            self.max_backoff,
                        ));
                        continue;
                    }
                    let error_receipt = self.error_receipt(
                        request_receipt.clone(),
                        attempts,
                        total_backoff,
                        &error,
                    );
                    self.receipts.push(error_receipt);
                    return Err(map_transport_error(error));
                }
            };
            let status_code = response.status_code();
            let retryable = status_code == 429 || (500..=599).contains(&status_code);
            if retryable && attempts < self.max_retry_attempts {
                total_backoff = total_backoff.saturating_add(backoff_for(
                    attempts,
                    response.retry_after(),
                    self.max_backoff,
                ));
                continue;
            }
            if !(200..=299).contains(&status_code) {
                let error = if status_code == 401 || status_code == 403 {
                    QualtricsProviderError::AccessLost
                } else if status_code == 429 {
                    QualtricsProviderError::RateLimited
                } else {
                    QualtricsProviderError::ProviderUnknown
                };
                let receipt =
                    self.response_receipt(request_receipt, &response, attempts, total_backoff);
                self.receipts.push(receipt);
                return Err(error);
            }
            if response.response_size_bytes() > self.max_response_bytes {
                let receipt =
                    self.response_receipt(request_receipt, &response, attempts, total_backoff);
                self.receipts.push(receipt);
                return Err(QualtricsProviderError::ResponseTooLarge);
            }
            if response.response_digest() != &response.payload().digest() {
                let receipt =
                    self.response_receipt(request_receipt, &response, attempts, total_backoff);
                self.receipts.push(receipt);
                return Err(QualtricsProviderError::TamperedEvidence);
            }
            if response.provider_revision() != QUALTRICS_PROVIDER_REVISION
                && response.provider_revision() != self.definition.version()
            {
                let receipt =
                    self.response_receipt(request_receipt, &response, attempts, total_backoff);
                self.receipts.push(receipt);
                return Err(QualtricsProviderError::ProviderRevisionDrift);
            }
            let receipt =
                self.response_receipt(request_receipt, &response, attempts, total_backoff);
            self.receipts.push(receipt.clone());
            return Ok(ProviderObservation {
                value: response.payload().clone(),
                receipt,
            });
        }
    }

    fn response_receipt(
        &self,
        request: QualtricsRequestReceipt,
        response: &QualtricsTransportResponse,
        attempts: u8,
        total_backoff: u32,
    ) -> QualtricsReadReceipt {
        QualtricsReadReceipt {
            request,
            response: QualtricsResponseReceipt {
                status_code: response.status_code(),
                response_size_bytes: response.response_size_bytes(),
                response_digest: response.response_digest().clone(),
                provider_revision: if response.provider_revision() == QUALTRICS_PROVIDER_REVISION
                    || response.provider_revision() == self.definition.version()
                {
                    response.provider_revision().to_owned()
                } else {
                    self.definition.version().to_owned()
                },
                retry: QualtricsRetryEvidence {
                    attempts,
                    backoff_milliseconds: total_backoff,
                    bounded: attempts <= self.max_retry_attempts
                        && total_backoff <= self.max_backoff.as_millis() as u32,
                },
            },
        }
    }

    fn error_receipt(
        &self,
        request: QualtricsRequestReceipt,
        attempts: u8,
        total_backoff: u32,
        error: &QualtricsTransportError,
    ) -> QualtricsReadReceipt {
        let status_code = match error {
            QualtricsTransportError::HttpStatus(status) => *status,
            QualtricsTransportError::RateLimited => 429,
            QualtricsTransportError::BlockedEnvironment => 0,
            QualtricsTransportError::Unavailable => 503,
        };
        QualtricsReadReceipt {
            request,
            response: QualtricsResponseReceipt {
                status_code,
                response_size_bytes: 0,
                response_digest: Digest::from_fields(
                    "qualtrics-error-receipt/v1",
                    &[format!("{error:?}"), status_code.to_string()],
                ),
                provider_revision: self.definition.version().to_owned(),
                retry: QualtricsRetryEvidence {
                    attempts,
                    backoff_milliseconds: total_backoff,
                    bounded: true,
                },
            },
        }
    }
}

fn backoff_for(attempt: u8, retry_after: Option<Duration>, maximum: Duration) -> u32 {
    let exponential = 100_u32.saturating_mul(2_u32.saturating_pow(u32::from(attempt - 1)));
    let requested = retry_after.map_or(exponential, |duration| {
        duration.as_millis().min(u128::from(u32::MAX)) as u32
    });
    requested.min(maximum.as_millis().min(u128::from(u32::MAX)) as u32)
}

fn map_transport_error(error: QualtricsTransportError) -> QualtricsProviderError {
    match error {
        QualtricsTransportError::BlockedEnvironment => QualtricsProviderError::BlockedEnvironment,
        QualtricsTransportError::RateLimited => QualtricsProviderError::RateLimited,
        QualtricsTransportError::Unavailable => QualtricsProviderError::ProviderUnknown,
        QualtricsTransportError::HttpStatus(status) if status == 401 || status == 403 => {
            QualtricsProviderError::AccessLost
        }
        QualtricsTransportError::HttpStatus(429) => QualtricsProviderError::RateLimited,
        QualtricsTransportError::HttpStatus(_) => QualtricsProviderError::ProviderUnknown,
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingQualtricsTransport {
    responses: VecDeque<Result<QualtricsTransportResponse, QualtricsTransportError>>,
    requests: Vec<QualtricsGetRequest>,
}

impl RecordingQualtricsTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: QualtricsTransportResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: QualtricsTransportError) {
        self.responses.push_back(Err(error));
    }

    pub fn requests(&self) -> &[QualtricsGetRequest] {
        &self.requests
    }

    pub fn take_requests(&mut self) -> Vec<QualtricsGetRequest> {
        std::mem::take(&mut self.requests)
    }
}

impl QualtricsGetTransport for RecordingQualtricsTransport {
    fn get(
        &mut self,
        request: &QualtricsGetRequest,
    ) -> Result<QualtricsTransportResponse, QualtricsTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(QualtricsTransportError::Unavailable))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureQualtricsTransport {
    responses: VecDeque<Result<QualtricsTransportResponse, QualtricsTransportError>>,
    requests: Vec<QualtricsGetRequest>,
}

impl FixtureQualtricsTransport {
    pub fn new(responses: impl IntoIterator<Item = QualtricsTransportResponse>) -> Self {
        Self {
            responses: responses.into_iter().map(Ok).collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: QualtricsTransportResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: QualtricsTransportError) {
        self.responses.push_back(Err(error));
    }

    pub fn requests(&self) -> &[QualtricsGetRequest] {
        &self.requests
    }
}

impl QualtricsGetTransport for FixtureQualtricsTransport {
    fn get(
        &mut self,
        request: &QualtricsGetRequest,
    ) -> Result<QualtricsTransportResponse, QualtricsTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(QualtricsTransportError::Unavailable))
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackQualtricsTransport {
    responses: VecDeque<Result<QualtricsTransportResponse, QualtricsTransportError>>,
    requests: Vec<QualtricsGetRequest>,
}

impl LoopbackQualtricsTransport {
    pub fn new(responses: impl IntoIterator<Item = QualtricsTransportResponse>) -> Self {
        Self {
            responses: responses.into_iter().map(Ok).collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: QualtricsTransportResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn requests(&self) -> &[QualtricsGetRequest] {
        &self.requests
    }
}

impl QualtricsGetTransport for LoopbackQualtricsTransport {
    fn get(
        &mut self,
        request: &QualtricsGetRequest,
    ) -> Result<QualtricsTransportResponse, QualtricsTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(QualtricsTransportError::Unavailable))
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl QualtricsGetTransport for BlockedEnvTransport {
    fn get(
        &mut self,
        _request: &QualtricsGetRequest,
    ) -> Result<QualtricsTransportResponse, QualtricsTransportError> {
        Err(QualtricsTransportError::BlockedEnvironment)
    }
}

pub type RecordingTransport = RecordingQualtricsTransport;
pub type FixtureTransport = FixtureQualtricsTransport;
pub type LoopbackTransport = LoopbackQualtricsTransport;

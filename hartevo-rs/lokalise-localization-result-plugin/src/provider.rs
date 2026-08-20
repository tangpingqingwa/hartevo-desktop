use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BranchName, Digest, LokaliseHttpMethod, LokaliseLocalizationAggregate,
    LokaliseLocalizationPayload, LokaliseLocalizationScope, LokalisePermissionSet,
    LokaliseRateLimitReceipt, LokaliseReadOperation, LokaliseReadReceipt, LokaliseRegistration,
    MAX_CURSOR_BYTES, MAX_PAGE_SIZE, MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, ModelError,
    RegistrationState, SecretReference, TransportProvenance,
};

pub const LOKALISE_API_HOST: &str = "https://api.lokalise.com";

/// Safe request representation for the six allowlisted Lokalise REST v2 GET
/// seams. It contains only scope identifiers and digests; credentials and raw
/// cursors never enter this type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseRequest {
    pub operation: LokaliseReadOperation,
    pub method: LokaliseHttpMethod,
    pub host: String,
    pub path: String,
    pub team_id: String,
    pub project_id: String,
    pub branch: BranchName,
    pub file_id: String,
    pub language_id: String,
    pub limit: usize,
    pub cursor_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl LokaliseRequest {
    #[must_use]
    pub fn digest(&self) -> Digest {
        crate::canonical_digest(&(
            self.operation,
            self.method,
            &self.host,
            &self.path,
            &self.team_id,
            &self.project_id,
            &self.branch,
            &self.file_id,
            &self.language_id,
            self.limit,
            &self.cursor_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        let path_is_allowlisted = match self.operation {
            LokaliseReadOperation::ProjectMetadata => self
                .path
                .strip_prefix("/api2/projects/")
                .is_some_and(|project| !project.is_empty() && !project.contains('/')),
            LokaliseReadOperation::LanguageMetadata => self.path.ends_with("/languages"),
            LokaliseReadOperation::FileMetadata => self.path.ends_with("/files"),
            LokaliseReadOperation::TranslationItems => self.path.ends_with("/translations"),
            LokaliseReadOperation::TaskReviewStatus => self.path.ends_with("/tasks"),
            LokaliseReadOperation::ExportBuildMetadata => self.path.ends_with("/processes"),
        };
        self.method == LokaliseHttpMethod::Get
            && self.host == LOKALISE_API_HOST
            && path_is_allowlisted
            && self.limit <= MAX_PAGE_SIZE
            && self
                .cursor_digest
                .as_ref()
                .is_none_or(|digest| digest.len() == 64)
    }
}

/// A fixture response keeps raw JSON private to the provider parser. Only the
/// status, bounded rate metadata, body size and body digest are observable.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: LokaliseRateLimitReceipt,
    #[serde(skip)]
    next_cursor_digest: Option<Digest>,
}

impl fmt::Debug for LokaliseResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LokaliseResponse")
            .field("status", &self.status)
            .field("body_digest", &crate::sha256_digest(&self.body))
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .field("next_cursor_digest", &self.next_cursor_digest)
            .finish()
    }
}

impl LokaliseResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, LokaliseRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: LokaliseRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Lokalise fixture payload serializes");
        Self {
            status,
            body,
            rate_limit,
            next_cursor_digest: None,
        }
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: LokaliseRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
            next_cursor_digest: None,
        }
    }

    /// Adds a cursor only as a digest. The raw cursor is discarded before the
    /// response leaves the fixture boundary.
    pub fn with_next_cursor(mut self, cursor: &str) -> Result<Self, ModelError> {
        validate_cursor(cursor)?;
        self.next_cursor_digest = Some(crate::sha256_digest(cursor.as_bytes()));
        Ok(self)
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        crate::sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn next_cursor_digest(&self) -> Option<Digest> {
        self.next_cursor_digest.clone()
    }

    fn payload(&self) -> Result<LokaliseLocalizationPayload, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LokaliseTransportError {
    #[error("Lokalise native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Lokalise transport timed out")]
    Timeout,
    #[error("Lokalise transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. No implementation in this crate resolves a token
/// or opens native HTTPS.
pub trait LokaliseTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &LokaliseRequest,
    ) -> Result<LokaliseResponse, LokaliseTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureLokaliseTransport {
    response: LokaliseResponse,
}

impl FixtureLokaliseTransport {
    #[must_use]
    pub fn new(response: LokaliseResponse) -> Self {
        Self { response }
    }
}

impl LokaliseTransport for FixtureLokaliseTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &LokaliseRequest,
    ) -> Result<LokaliseResponse, LokaliseTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingLokaliseTransport {
    response: LokaliseResponse,
    requests: Vec<LokaliseRequest>,
}

impl RecordingLokaliseTransport {
    #[must_use]
    pub fn new(response: LokaliseResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[LokaliseRequest] {
        &self.requests
    }
}

impl LokaliseTransport for RecordingLokaliseTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &LokaliseRequest,
    ) -> Result<LokaliseResponse, LokaliseTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackLokaliseTransport {
    response: LokaliseResponse,
    requests: Vec<LokaliseRequest>,
}

impl LoopbackLokaliseTransport {
    #[must_use]
    pub fn new(response: LokaliseResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[LokaliseRequest] {
        &self.requests
    }
}

impl LokaliseTransport for LoopbackLokaliseTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &LokaliseRequest,
    ) -> Result<LokaliseResponse, LokaliseTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvLokaliseTransport;

impl LokaliseTransport for BlockedEnvLokaliseTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &LokaliseRequest,
    ) -> Result<LokaliseResponse, LokaliseTransportError> {
        Err(LokaliseTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportProvenance,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_page_size: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl LokaliseProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: TransportProvenance, permission: &LokalisePermissionSet) -> Self {
        let capability_digest = crate::canonical_digest(&(
            crate::LOKALISE_LOCALIZATION_RESULT_SCHEMA_VERSION,
            crate::LOKALISE_PROVIDER_ID,
            crate::LOKALISE_PROVIDER_API_REVISION,
            "bounded_metadata_get_only",
            LokaliseReadOperation::ProjectMetadata.path_template(),
            LokaliseReadOperation::LanguageMetadata.path_template(),
            LokaliseReadOperation::FileMetadata.path_template(),
            LokaliseReadOperation::TranslationItems.path_template(),
            LokaliseReadOperation::TaskReviewStatus.path_template(),
            LokaliseReadOperation::ExportBuildMetadata.path_template(),
        ));
        Self {
            schema_version: crate::LOKALISE_LOCALIZATION_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: crate::LOKALISE_PROVIDER_ID.to_owned(),
            provider_version: crate::LOKALISE_PROVIDER_VERSION.to_owned(),
            api_revision: crate::LOKALISE_PROVIDER_API_REVISION.to_owned(),
            capability_digest,
            permission_digest: permission.digest(),
            provenance,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_size: MAX_PAGE_SIZE,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        crate::canonical_digest(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LokaliseProviderError {
    #[error("Lokalise registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Lokalise SecretReference is revoked")]
    SecretRevoked,
    #[error("Lokalise permission set is missing the required read permission")]
    MissingPermission,
    #[error("Lokalise request is outside the bound team/project/branch/file/language scope")]
    ScopeMismatch,
    #[error("Lokalise request rate bound was exhausted")]
    RateLimited {
        request: LokaliseRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LokaliseRateLimitReceipt,
    },
    #[error("Lokalise response status is {status_code}")]
    HttpStatus {
        request: LokaliseRequest,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LokaliseRateLimitReceipt,
    },
    #[error("Lokalise response exceeded the Layer-1 response bound")]
    ResponseTooLarge {
        request: LokaliseRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LokaliseRateLimitReceipt,
    },
    #[error("Lokalise response was malformed or outside the bounded localization result model")]
    MalformedResponse {
        request: LokaliseRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LokaliseRateLimitReceipt,
    },
    #[error("Lokalise rate-limit receipt is invalid")]
    InvalidRateLimitReceipt { request: LokaliseRequest },
    #[error("Lokalise cursor is invalid")]
    InvalidCursor,
    #[error("Lokalise transport failed")]
    Transport {
        request: LokaliseRequest,
        error: LokaliseTransportError,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LokaliseRateLimitReceipt,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl LokaliseProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&LokaliseRequest> {
        match self {
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingPermission
            | Self::ScopeMismatch
            | Self::InvalidCursor
            | Self::Model(_) => None,
            Self::RateLimited { request, .. }
            | Self::HttpStatus { request, .. }
            | Self::ResponseTooLarge { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::InvalidRateLimitReceipt { request }
            | Self::Transport { request, .. } => Some(request),
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, LokaliseRateLimitReceipt, Option<u16>)> {
        match self {
            Self::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(429),
            )),
            Self::HttpStatus {
                status_code,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(*status_code),
            )),
            Self::ResponseTooLarge {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | Self::MalformedResponse {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | Self::Transport {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                None,
            )),
            Self::InvalidRateLimitReceipt { .. }
            | Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingPermission
            | Self::ScopeMismatch
            | Self::InvalidCursor
            | Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LokaliseProviderRead {
    pub aggregate: LokaliseLocalizationAggregate,
    pub receipts: Vec<LokaliseReadReceipt>,
    pub rate_limits: Vec<LokaliseRateLimitReceipt>,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub response_bytes: usize,
}

#[derive(Clone)]
pub struct LokaliseProvider<T: LokaliseTransport> {
    scope: LokaliseLocalizationScope,
    secret_reference: SecretReference,
    transport: T,
    definition: LokaliseProviderDefinition,
    registration: LokaliseRegistration,
    requests_issued: u16,
}

impl<T: LokaliseTransport> fmt::Debug for LokaliseProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LokaliseProvider")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.definition.provenance)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("requests_issued", &self.requests_issued)
            .finish_non_exhaustive()
    }
}

impl<T: LokaliseTransport> LokaliseProvider<T> {
    pub fn new(
        scope: LokaliseLocalizationScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, LokaliseProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(LokaliseProviderError::SecretRevoked);
        }
        scope.permission().validate()?;
        let definition =
            LokaliseProviderDefinition::layer1(transport.provenance(), scope.permission());
        let registration =
            LokaliseRegistration::bind(&scope, &secret_reference, definition.provider_digest());
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            requests_issued: 0,
        })
    }

    pub fn with_registration(
        scope: LokaliseLocalizationScope,
        secret_reference: SecretReference,
        transport: T,
        registration: LokaliseRegistration,
    ) -> Result<Self, LokaliseProviderError> {
        scope.validate()?;
        let definition =
            LokaliseProviderDefinition::layer1(transport.provenance(), scope.permission());
        registration
            .validate(&scope, &secret_reference, &definition.provider_digest())
            .map_err(|_| LokaliseProviderError::ScopeMismatch)?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            requests_issued: 0,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &LokaliseLocalizationScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &LokaliseProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &LokaliseRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<LokaliseProviderRead, LokaliseProviderError> {
        self.read_from_cursor(None)
    }

    pub fn read_localization_result(
        &mut self,
    ) -> Result<LokaliseProviderRead, LokaliseProviderError> {
        self.read()
    }

    pub fn read_from_cursor(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<LokaliseProviderRead, LokaliseProviderError> {
        self.ensure_ready()?;
        if let Some(cursor) = cursor {
            validate_cursor(cursor).map_err(|_| LokaliseProviderError::InvalidCursor)?;
        }
        let operations = [
            LokaliseReadOperation::ProjectMetadata,
            LokaliseReadOperation::LanguageMetadata,
            LokaliseReadOperation::FileMetadata,
            LokaliseReadOperation::TranslationItems,
            LokaliseReadOperation::TaskReviewStatus,
            LokaliseReadOperation::ExportBuildMetadata,
        ];
        let mut combined = LokaliseLocalizationPayload::empty();
        let mut raw_reads = Vec::with_capacity(operations.len());
        let mut rate_limits = Vec::with_capacity(operations.len());
        for operation in operations {
            let request = self.build_request(operation, cursor)?;
            if !request.is_allowlisted()
                || request.host != LOKALISE_API_HOST
                || request.scope_digest != *self.scope.scope_digest()
            {
                return Err(LokaliseProviderError::ScopeMismatch);
            }
            if self.requests_issued >= self.definition.max_requests_per_minute {
                return Err(LokaliseProviderError::RateLimited {
                    request,
                    response_digest: crate::sha256_digest(b"lokalise-request-rate-budget"),
                    response_bytes: 0,
                    rate_limit: LokaliseRateLimitReceipt::new(
                        self.definition.max_requests_per_minute,
                        Some(0),
                        Some(60),
                        true,
                    )
                    .expect("bounded request rate receipt"),
                });
            }
            self.requests_issued = self.requests_issued.saturating_add(1);
            let response = match self.transport.execute(&request) {
                Ok(response) => response,
                Err(error) => {
                    return Err(LokaliseProviderError::Transport {
                        request,
                        error,
                        response_digest: crate::sha256_digest(b"lokalise-transport-no-response"),
                        response_bytes: 0,
                        rate_limit: LokaliseRateLimitReceipt::default(),
                    });
                }
            };
            response.rate_limit.validate().map_err(|_| {
                LokaliseProviderError::InvalidRateLimitReceipt {
                    request: request.clone(),
                }
            })?;
            let response_digest = response.response_digest();
            let response_bytes = response.response_bytes();
            let rate_limit = response.rate_limit.clone();
            if response.status == 429 {
                return Err(LokaliseProviderError::RateLimited {
                    request,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
            if !(200..=299).contains(&response.status) {
                return Err(LokaliseProviderError::HttpStatus {
                    request,
                    status_code: response.status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
            if response_bytes > self.definition.max_response_bytes {
                return Err(LokaliseProviderError::ResponseTooLarge {
                    request,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
            let payload =
                response
                    .payload()
                    .map_err(|_| LokaliseProviderError::MalformedResponse {
                        request: request.clone(),
                        response_digest: response_digest.clone(),
                        response_bytes,
                        rate_limit: rate_limit.clone(),
                    })?;
            let projection = payload.projection(operation);
            if operation == LokaliseReadOperation::ProjectMetadata {
                combined.project = projection.project;
            } else if operation == LokaliseReadOperation::LanguageMetadata {
                combined.languages = projection.languages;
            } else if operation == LokaliseReadOperation::FileMetadata {
                combined.files = projection.files;
            } else if operation == LokaliseReadOperation::TranslationItems {
                combined.translations = projection.translations;
                if response.next_cursor_digest().is_some() {
                    combined.partial = true;
                }
            } else if operation == LokaliseReadOperation::TaskReviewStatus {
                combined.tasks = projection.tasks;
            } else if operation == LokaliseReadOperation::ExportBuildMetadata {
                combined.processes = projection.processes;
            }
            combined.partial |= projection.partial;
            rate_limits.push(rate_limit.clone());
            raw_reads.push((request, response, operation, rate_limit));
        }
        let aggregate = combined
            .normalize(&self.scope)
            .map_err(|error| match error {
                ModelError::InvalidScope(_) => LokaliseProviderError::ScopeMismatch,
                ModelError::InvalidResponse(_) | ModelError::DuplicateItem => {
                    LokaliseProviderError::MalformedResponse {
                        request: raw_reads[0].0.clone(),
                        response_digest: crate::canonical_digest(&combined),
                        response_bytes: 0,
                        rate_limit: rate_limits.first().cloned().unwrap_or_default(),
                    }
                }
                other => LokaliseProviderError::Model(other),
            })?;
        let aggregate_digest = aggregate.digest();
        let normalized_response_bytes = serde_json::to_vec(&aggregate)
            .expect("normalized Lokalise aggregate serializes")
            .len();
        let receipts = raw_reads
            .iter()
            .map(
                |(request, response, operation, rate_limit)| LokaliseReadReceipt {
                    operation: *operation,
                    method: request.method,
                    endpoint: request.path.clone(),
                    request_digest: request.request_digest.clone(),
                    response_digest: crate::canonical_digest(&(
                        "lokalise-normalized-response/v1",
                        operation,
                        &aggregate_digest,
                        rate_limit,
                    )),
                    status_code: Some(response.status),
                    response_bytes: normalized_response_bytes,
                    rate_limit_digest: rate_limit.digest(),
                    next_cursor_digest: response.next_cursor_digest(),
                },
            )
            .collect::<Vec<_>>();
        let response_digest = crate::canonical_digest(&receipts);
        let response_bytes = normalized_response_bytes;
        Ok(LokaliseProviderRead {
            aggregate,
            receipts,
            rate_limits,
            provenance: self.definition.provenance,
            response_digest,
            response_bytes,
        })
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, LokaliseProviderError> {
        self.registration
            .revoke()
            .map_err(LokaliseProviderError::Model)
    }

    pub fn restore(&mut self) -> Result<(), LokaliseProviderError> {
        self.registration
            .restore()
            .map_err(LokaliseProviderError::Model)
    }

    pub fn revoke_secret(&mut self) -> Result<(), LokaliseProviderError> {
        self.secret_reference
            .revoke()
            .map_err(LokaliseProviderError::Model)
    }

    fn ensure_ready(&self) -> Result<(), LokaliseProviderError> {
        if self.registration.state != RegistrationState::Active {
            return Err(LokaliseProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(LokaliseProviderError::SecretRevoked);
        }
        self.scope.permission().validate()?;
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| LokaliseProviderError::RegistrationRevoked)
    }

    fn build_request(
        &self,
        operation: LokaliseReadOperation,
        cursor: Option<&str>,
    ) -> Result<LokaliseRequest, LokaliseProviderError> {
        if !self.scope.permission().has(operation.permission()) {
            return Err(LokaliseProviderError::MissingPermission);
        }
        let path = match operation {
            LokaliseReadOperation::ProjectMetadata | LokaliseReadOperation::ExportBuildMetadata => {
                format!(
                    "/api2/projects/{}{}",
                    self.scope.project_id().as_str(),
                    if operation == LokaliseReadOperation::ProjectMetadata {
                        ""
                    } else {
                        "/processes"
                    }
                )
            }
            LokaliseReadOperation::LanguageMetadata => format!(
                "/api2/projects/{}:{}/languages",
                self.scope.project_id().as_str(),
                self.scope.branch().as_str()
            ),
            LokaliseReadOperation::FileMetadata => format!(
                "/api2/projects/{}:{}/files",
                self.scope.project_id().as_str(),
                self.scope.branch().as_str()
            ),
            LokaliseReadOperation::TranslationItems => format!(
                "/api2/projects/{}:{}/translations",
                self.scope.project_id().as_str(),
                self.scope.branch().as_str()
            ),
            LokaliseReadOperation::TaskReviewStatus => format!(
                "/api2/projects/{}:{}/tasks",
                self.scope.project_id().as_str(),
                self.scope.branch().as_str()
            ),
        };
        let cursor_digest = cursor.map(|value| crate::sha256_digest(value.as_bytes()));
        let mut request = LokaliseRequest {
            operation,
            method: LokaliseHttpMethod::Get,
            host: LOKALISE_API_HOST.to_owned(),
            path,
            team_id: self.scope.team_id().as_str().to_owned(),
            project_id: self.scope.project_id().as_str().to_owned(),
            branch: self.scope.branch().clone(),
            file_id: self.scope.file_id().as_str().to_owned(),
            language_id: self.scope.language().language_id().as_str().to_owned(),
            limit: if operation == LokaliseReadOperation::TranslationItems {
                MAX_PAGE_SIZE
            } else {
                MAX_PAGE_SIZE.min(100)
            },
            cursor_digest,
            scope_digest: self.scope.scope_digest().clone(),
            consent_digest: self.scope.consent().digest().clone(),
            secret_reference_digest: self.secret_reference.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        Ok(request)
    }
}

fn validate_cursor(cursor: &str) -> Result<(), ModelError> {
    if cursor.is_empty()
        || cursor.len() > MAX_CURSOR_BYTES
        || cursor.trim() != cursor
        || cursor.chars().any(char::is_control)
    {
        Err(ModelError::InvalidCursor)
    } else {
        Ok(())
    }
}

// Keep these imports in one place for downstream users that expect the
// provider module to expose the core response model names.
pub type LokaliseApiResponse = LokaliseResponse;
pub type LokaliseLocalizationResultProvider<T> = LokaliseProvider<T>;
pub type LokaliseProviderTransportError = LokaliseTransportError;
pub type LokaliseProviderReadResult = LokaliseProviderRead;

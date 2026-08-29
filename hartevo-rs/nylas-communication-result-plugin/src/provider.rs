use std::{collections::VecDeque, fmt};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    Digest, IdempotencyKey, MAX_ATTEMPTS, MAX_BACKOFF_SECONDS, MAX_ITEMS, MAX_PAGE_SIZE,
    MAX_RESPONSE_BYTES, ModelError, NylasCommunicationRequest, NylasCommunicationScope,
    NylasDeliveryStatus, NylasFieldSelection, NylasMetadataPage, NylasMetadataRecord,
    NylasPermission, NylasRateLimitReceipt, NylasReadOperation, NylasRecordKind, NylasRegistration,
    NylasResourceKind, NylasSelectedField, NylasTransportProvenance, OpaqueCursor,
    RegistrationRevocationReceipt, RegistrationState, SecretReference, canonical_digest,
    validate_digest,
};

/// HTTP methods are intentionally limited to reads in Layer 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NylasHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasProviderRequest {
    pub method: NylasHttpMethod,
    pub host: String,
    pub path: String,
    pub operation: NylasReadOperation,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub target_id_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
    pub field_selection_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub page_size: u16,
    pub attempt: u8,
    pub backoff_seconds: u32,
}

impl NylasProviderRequest {
    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == NylasHttpMethod::Get
            && self.host == "https://api.us.nylas.com"
            && self.path == self.operation.path_template()
            && self.page_size > 0
            && self.page_size <= MAX_PAGE_SIZE
            && self.attempt > 0
            && self.attempt <= MAX_ATTEMPTS
            && self.backoff_seconds <= MAX_BACKOFF_SECONDS
            && validate_digest(&self.scope_digest).is_ok()
            && validate_digest(&self.revision_digest).is_ok()
            && validate_digest(&self.permission_digest).is_ok()
            && validate_digest(&self.field_selection_digest).is_ok()
            && validate_digest(&self.idempotency_key_digest).is_ok()
            && self
                .target_id_digest
                .as_ref()
                .is_none_or(|digest| validate_digest(digest).is_ok())
            && self
                .page_token_digest
                .as_ref()
                .is_none_or(|digest| validate_digest(digest).is_ok())
            && self
                .cursor_binding_digest
                .as_ref()
                .is_none_or(|digest| validate_digest(digest).is_ok())
    }
}

/// Raw bytes are confined to the deterministic transport boundary. Debug and
/// all provider outputs expose only the response digest and byte count.
#[derive(Clone, Eq, PartialEq)]
pub struct NylasResponse {
    status: u16,
    body: Vec<u8>,
    rate_limit: NylasRateLimitReceipt,
}

impl fmt::Debug for NylasResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NylasResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl NylasResponse {
    #[must_use]
    pub const fn new(status: u16, body: Vec<u8>, rate_limit: NylasRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, NylasRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: NylasRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Nylas fixture payload serializes");
        Self::new(status, body, rate_limit)
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
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
    pub fn rate_limit(&self) -> &NylasRateLimitReceipt {
        &self.rate_limit
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NylasTransportError {
    #[error("Nylas native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Nylas transport timed out")]
    Timeout,
    #[error("Nylas provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Nylas transport returned a partial response")]
    Partial,
}

pub trait NylasTransport: fmt::Debug {
    fn provenance(&self) -> NylasTransportProvenance;

    fn execute(
        &mut self,
        request: &NylasProviderRequest,
    ) -> Result<NylasResponse, NylasTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureNylasTransport {
    response: NylasResponse,
}

impl FixtureNylasTransport {
    #[must_use]
    pub const fn new(response: NylasResponse) -> Self {
        Self { response }
    }
}

impl NylasTransport for FixtureNylasTransport {
    fn provenance(&self) -> NylasTransportProvenance {
        NylasTransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &NylasProviderRequest,
    ) -> Result<NylasResponse, NylasTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingNylasTransport {
    response: NylasResponse,
    requests: Vec<NylasProviderRequest>,
}

impl RecordingNylasTransport {
    #[must_use]
    pub const fn new(response: NylasResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[NylasProviderRequest] {
        &self.requests
    }
}

impl NylasTransport for RecordingNylasTransport {
    fn provenance(&self) -> NylasTransportProvenance {
        NylasTransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &NylasProviderRequest,
    ) -> Result<NylasResponse, NylasTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeNylasTransport {
    responses: VecDeque<Result<NylasResponse, NylasTransportError>>,
    requests: Vec<NylasProviderRequest>,
}

impl FakeNylasTransport {
    #[must_use]
    pub fn new(response: NylasResponse) -> Self {
        let mut transport = Self::default();
        transport.push_response(response);
        transport
    }

    pub fn push_response(&mut self, response: NylasResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: NylasTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[NylasProviderRequest] {
        &self.requests
    }
}

impl NylasTransport for FakeNylasTransport {
    fn provenance(&self) -> NylasTransportProvenance {
        NylasTransportProvenance::Fake
    }

    fn execute(
        &mut self,
        request: &NylasProviderRequest,
    ) -> Result<NylasResponse, NylasTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(NylasTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackNylasTransport {
    response: NylasResponse,
}

impl LoopbackNylasTransport {
    #[must_use]
    pub const fn new(response: NylasResponse) -> Self {
        Self { response }
    }
}

impl NylasTransport for LoopbackNylasTransport {
    fn provenance(&self) -> NylasTransportProvenance {
        NylasTransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &NylasProviderRequest,
    ) -> Result<NylasResponse, NylasTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvNylasTransport;

impl NylasTransport for BlockedEnvNylasTransport {
    fn provenance(&self) -> NylasTransportProvenance {
        NylasTransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &NylasProviderRequest,
    ) -> Result<NylasResponse, NylasTransportError> {
        Err(NylasTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasProviderDefinition {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub documentation: String,
    pub provenance: NylasTransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub read_allowlist: Vec<String>,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_items: usize,
    pub max_page_size: u16,
    pub read_only: bool,
}

impl NylasProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: NylasTransportProvenance) -> Self {
        Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            version: crate::PROVIDER_VERSION.to_owned(),
            api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            documentation: crate::NYLAS_API_DOCUMENTATION_URL.to_owned(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            read_allowlist: [
                NylasReadOperation::Messages,
                NylasReadOperation::Message,
                NylasReadOperation::Threads,
                NylasReadOperation::Thread,
                NylasReadOperation::Calendars,
                NylasReadOperation::Calendar,
                NylasReadOperation::Events,
                NylasReadOperation::Event,
            ]
            .into_iter()
            .map(|operation| format!("GET {}", operation.path_template()))
            .collect(),
            max_requests_per_minute: crate::MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_items: MAX_ITEMS,
            max_page_size: MAX_PAGE_SIZE,
            read_only: true,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.provider_id != crate::PROVIDER_ID
            || self.version != crate::PROVIDER_VERSION
            || self.api_revision != crate::PROVIDER_API_REVISION
            || self.documentation != crate::NYLAS_API_DOCUMENTATION_URL
            || self.connected
            || self.native
            || self.first_party
            || !self.read_only
            || self.max_requests_per_minute != crate::MAX_REQUESTS_PER_MINUTE
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || self.max_items != MAX_ITEMS
            || self.max_page_size != MAX_PAGE_SIZE
            || self.read_allowlist != Self::layer1(self.provenance).read_allowlist
        {
            Err(ModelError::InvalidScope("provider definition drift"))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasProviderFailureMetadata {
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub response_bytes: usize,
    pub rate_limit: NylasRateLimitReceipt,
    pub status: Option<u16>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NylasProviderError {
    #[error("Nylas provider definition drifted")]
    DefinitionDrift,
    #[error("Nylas registration is revoked")]
    RegistrationRevoked,
    #[error("Nylas secret reference is revoked")]
    SecretRevoked,
    #[error("Nylas request is outside the registered scope")]
    RequestInvalid,
    #[error("Nylas request revision is stale")]
    RevisionMismatch,
    #[error("Nylas provider response is too large")]
    ResponseTooLarge {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas provider rate limited the read")]
    RateLimited {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas provider read timed out")]
    Timeout {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas provider access was lost")]
    AccessLoss {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas provider is unknown or unavailable")]
    ProviderUnknown {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas provider response is partial")]
    Partial {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas native environment is unavailable: BLOCKED_ENV")]
    BlockedEnv {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas provider response failed integrity validation")]
    ResponseTampered {
        metadata: NylasProviderFailureMetadata,
    },
    #[error("Nylas model is invalid: {0}")]
    Model(String),
}

impl From<ModelError> for NylasProviderError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct NylasProviderRead {
    pub page: NylasMetadataPage,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: NylasRateLimitReceipt,
    pub status: u16,
    pub provenance: NylasTransportProvenance,
}

pub struct NylasProvider<T: NylasTransport> {
    scope: NylasCommunicationScope,
    secret_reference: SecretReference,
    transport: T,
    definition: NylasProviderDefinition,
    registration: NylasRegistration,
}

impl<T: NylasTransport> fmt::Debug for NylasProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NylasProvider")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: NylasTransport> NylasProvider<T> {
    pub fn new(
        scope: NylasCommunicationScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, NylasProviderError> {
        scope.validate()?;
        let definition = NylasProviderDefinition::layer1(transport.provenance());
        definition.validate()?;
        let registration =
            NylasRegistration::bind(&scope, &secret_reference, definition.provider_digest());
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    pub fn with_registration(
        scope: NylasCommunicationScope,
        secret_reference: SecretReference,
        transport: T,
        registration: NylasRegistration,
    ) -> Result<Self, NylasProviderError> {
        scope.validate()?;
        let definition = NylasProviderDefinition::layer1(transport.provenance());
        definition.validate()?;
        registration.validate(&scope, &secret_reference, &definition.provider_digest())?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &NylasCommunicationScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &NylasProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &NylasRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> NylasTransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        false
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<NylasProviderRead, NylasProviderError> {
        let key = IdempotencyKey::new("nylas-default-read")?;
        let request = NylasCommunicationRequest::messages(&self.scope, &key)?;
        self.read_request(&request)
    }

    pub fn read_request(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasProviderRead, NylasProviderError> {
        self.ensure_available()?;
        request.validate(&self.scope).map_err(|error| match error {
            ModelError::InvalidScope(_) => NylasProviderError::RevisionMismatch,
            _ => NylasProviderError::RequestInvalid,
        })?;
        if !self
            .scope
            .permissions()
            .has(request.operation().permission())
        {
            return Err(NylasProviderError::RequestInvalid);
        }
        let provider_request = Self::provider_request(request);
        if !provider_request.is_allowlisted() {
            return Err(NylasProviderError::RequestInvalid);
        }
        let provenance = self.transport.provenance();
        let response = match self.transport.execute(&provider_request) {
            Ok(response) => response,
            Err(error) => return Err(Self::transport_error(request, error)),
        };
        response.rate_limit().validate()?;
        let request_digest = request.request_digest();
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        let metadata = |status| NylasProviderFailureMetadata {
            request_digest: request_digest.clone(),
            response_digest: Some(response_digest.clone()),
            response_bytes,
            rate_limit: response.rate_limit().clone(),
            status,
        };
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(NylasProviderError::ResponseTooLarge {
                metadata: metadata(Some(response.status())),
            });
        }
        if response.status() == 429 {
            return Err(NylasProviderError::RateLimited {
                metadata: metadata(Some(response.status())),
            });
        }
        if response.status() == 408 || response.status() == 504 {
            return Err(NylasProviderError::Timeout {
                metadata: metadata(Some(response.status())),
            });
        }
        if response.status() == 401 || response.status() == 403 || response.status() == 404 {
            return Err(NylasProviderError::AccessLoss {
                metadata: metadata(Some(response.status())),
            });
        }
        if !(200..300).contains(&response.status()) {
            return Err(NylasProviderError::ProviderUnknown {
                metadata: metadata(Some(response.status())),
            });
        }
        let value: Value = serde_json::from_slice(&response.body).map_err(|_| {
            NylasProviderError::ResponseTampered {
                metadata: metadata(Some(response.status())),
            }
        })?;
        let page = Self::page_from_value(request, &value, response.status()).map_err(|_| {
            NylasProviderError::ResponseTampered {
                metadata: metadata(Some(response.status())),
            }
        })?;
        if response.status() == 206 || page.partial {
            return Err(NylasProviderError::Partial {
                metadata: metadata(Some(response.status())),
            });
        }
        Ok(NylasProviderRead {
            page,
            response_digest,
            response_bytes,
            rate_limit: response.rate_limit().clone(),
            status: response.status(),
            provenance,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, NylasProviderError> {
        self.registration.revoke().map_err(NylasProviderError::from)
    }

    pub fn restore(&mut self) -> Result<(), NylasProviderError> {
        self.registration
            .restore()
            .map_err(NylasProviderError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), NylasProviderError> {
        self.secret_reference
            .revoke()
            .map_err(NylasProviderError::from)
    }

    pub fn restore_secret(&mut self) -> Result<(), NylasProviderError> {
        self.secret_reference
            .restore()
            .map_err(NylasProviderError::from)
    }

    fn ensure_available(&self) -> Result<(), NylasProviderError> {
        self.definition.validate()?;
        if self.registration.state != RegistrationState::Active {
            return Err(NylasProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(NylasProviderError::SecretRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| NylasProviderError::RegistrationRevoked)
    }

    fn provider_request(request: &NylasCommunicationRequest) -> NylasProviderRequest {
        NylasProviderRequest {
            method: NylasHttpMethod::Get,
            host: "https://api.us.nylas.com".to_owned(),
            path: request.operation().path_template().to_owned(),
            operation: request.operation(),
            scope_digest: request.scope_digest().clone(),
            revision_digest: request.revision_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            target_id_digest: request.target_id_digest().cloned(),
            page_token_digest: request.page_token_digest().cloned(),
            cursor_binding_digest: request.cursor_binding().cloned(),
            field_selection_digest: request.field_selection().digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            page_size: request.page_size(),
            attempt: 1,
            backoff_seconds: 0,
        }
    }

    fn transport_error(
        request: &NylasCommunicationRequest,
        error: NylasTransportError,
    ) -> NylasProviderError {
        let metadata = || NylasProviderFailureMetadata {
            request_digest: request.request_digest(),
            response_digest: None,
            response_bytes: 0,
            rate_limit: NylasRateLimitReceipt::default(),
            status: None,
        };
        match error {
            NylasTransportError::BlockedEnv => NylasProviderError::BlockedEnv {
                metadata: metadata(),
            },
            NylasTransportError::Timeout => NylasProviderError::Timeout {
                metadata: metadata(),
            },
            NylasTransportError::ProviderUnknown => NylasProviderError::ProviderUnknown {
                metadata: metadata(),
            },
            NylasTransportError::Partial => NylasProviderError::Partial {
                metadata: metadata(),
            },
        }
    }

    fn page_from_value(
        request: &NylasCommunicationRequest,
        value: &Value,
        status: u16,
    ) -> Result<NylasMetadataPage, ModelError> {
        let values = match value.get("data") {
            Some(Value::Array(values)) => values.clone(),
            Some(object @ Value::Object(_)) if !request.operation().is_collection() => {
                vec![object.clone()]
            }
            Some(_) => return Err(ModelError::InvalidAggregate),
            None if value.is_object() && !request.operation().is_collection() => {
                vec![value.clone()]
            }
            None => return Err(ModelError::InvalidAggregate),
        };
        if values.len() > MAX_ITEMS {
            return Err(ModelError::InvalidAggregate);
        }
        let mut records = Vec::with_capacity(values.len());
        for value in values {
            records.push(Self::record_from_value(request, &value)?);
        }
        let next_cursor_digest = match value.get("next_cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(cursor))
                if !cursor.is_empty()
                    && cursor.len() <= crate::MAX_CURSOR_BYTES
                    && cursor.trim() == cursor
                    && !cursor.chars().any(char::is_control) =>
            {
                Some(crate::sha256_digest(
                    format!("nylas-cursor/v1|{cursor}").as_bytes(),
                ))
            }
            _ => return Err(ModelError::InvalidCursor),
        };
        let cursor_binding_digest = next_cursor_digest
            .as_ref()
            .map(|_| request.cursor_binding_digest());
        let partial = status == 206
            || value
                .get("partial")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let total_count = value
            .get("count")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok());
        NylasMetadataPage::new(
            request.operation(),
            records,
            total_count,
            partial,
            next_cursor_digest,
            cursor_binding_digest,
        )
    }

    fn record_from_value(
        request: &NylasCommunicationRequest,
        value: &Value,
    ) -> Result<NylasMetadataRecord, ModelError> {
        let kind = request.operation().expected_kind();
        if let Some(object) = value.get("object").and_then(Value::as_str) {
            let expected = match kind {
                NylasRecordKind::Message => "message",
                NylasRecordKind::Thread => "thread",
                NylasRecordKind::Calendar => "calendar",
                NylasRecordKind::Event => "event",
            };
            if object != expected {
                return Err(ModelError::InvalidAggregate);
            }
        }
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidAggregate)?;
        let selection = request.field_selection();
        // The record identity is always retained as a digest so every
        // projection remains addressable even when callers narrow the
        // optional metadata field set.
        let id_label = match kind {
            NylasRecordKind::Message => "message",
            NylasRecordKind::Thread => "thread",
            NylasRecordKind::Calendar => "calendar",
            NylasRecordKind::Event => "event",
        };
        let id_digest = crate::sha256_digest(format!("nylas-{id_label}-id/v1|{id}").as_bytes());
        let grant_id_digest = selected_identifier(
            value,
            "grant_id",
            selection,
            NylasSelectedField::GrantId,
            "grant",
        );
        let thread_id_digest = selected_identifier(
            value,
            "thread_id",
            selection,
            NylasSelectedField::ThreadId,
            "thread",
        );
        let calendar_id_digest = selected_identifier(
            value,
            "calendar_id",
            selection,
            NylasSelectedField::CalendarId,
            "calendar",
        );
        let event_id_digest = selected_identifier(
            value,
            "event_id",
            selection,
            NylasSelectedField::EventId,
            "event",
        );
        let occurred_at = if selection.contains(NylasSelectedField::Date) {
            value.get("date").and_then(value_as_i64).or_else(|| {
                value
                    .get("when")
                    .and_then(|when| when.get("start_time"))
                    .and_then(value_as_i64)
            })
        } else {
            None
        };
        let updated_at = selection
            .contains(NylasSelectedField::UpdatedAt)
            .then(|| value.get("updated_at").and_then(value_as_i64))
            .flatten();
        let subject_digest = selection
            .contains(NylasSelectedField::SubjectDigest)
            .then(|| {
                value
                    .get("subject")
                    .and_then(Value::as_str)
                    .or_else(|| value.get("title").and_then(Value::as_str))
                    .map(|subject| {
                        crate::sha256_digest(format!("nylas-subject/v1|{subject}").as_bytes())
                    })
            })
            .flatten();
        let status = selection
            .contains(NylasSelectedField::Status)
            .then(|| {
                value
                    .get("delivery_status")
                    .and_then(Value::as_str)
                    .or_else(|| value.get("status").and_then(Value::as_str))
                    .map(parse_status)
            })
            .flatten();
        let has_attachments = selection
            .contains(NylasSelectedField::HasAttachments)
            .then(|| {
                value
                    .get("has_attachments")
                    .and_then(Value::as_bool)
                    .or_else(|| value.get("has_attachment").and_then(Value::as_bool))
                    .or_else(|| {
                        value
                            .get("attachments")
                            .and_then(Value::as_array)
                            .map(|items| !items.is_empty())
                    })
            })
            .flatten();
        let unread = selection
            .contains(NylasSelectedField::Unread)
            .then(|| value.get("unread").and_then(Value::as_bool))
            .flatten();
        let starred = selection
            .contains(NylasSelectedField::Starred)
            .then(|| value.get("starred").and_then(Value::as_bool))
            .flatten();
        let busy = selection
            .contains(NylasSelectedField::Busy)
            .then(|| value.get("busy").and_then(Value::as_bool))
            .flatten();
        let cancelled = selection
            .contains(NylasSelectedField::Cancelled)
            .then(|| {
                value.get("cancelled").and_then(Value::as_bool).or_else(|| {
                    Some(status.is_some_and(|status| status == NylasDeliveryStatus::Cancelled))
                })
            })
            .flatten();
        let participant_count = selection
            .contains(NylasSelectedField::ParticipantCount)
            .then(|| participant_count(value))
            .flatten();
        let message_count = selection
            .contains(NylasSelectedField::MessageCount)
            .then(|| {
                value
                    .get("message_ids")
                    .and_then(Value::as_array)
                    .or_else(|| value.get("messages").and_then(Value::as_array))
                    .map(|items| items.len().min(u16::MAX as usize) as u16)
            })
            .flatten();
        let message_digest = (kind == NylasRecordKind::Message).then(|| {
            canonical_digest(&(
                "nylas-message/v1",
                &id_digest,
                &thread_id_digest,
                occurred_at,
                updated_at,
                &subject_digest,
                status,
                has_attachments,
                unread,
                starred,
            ))
        });
        let thread_digest = (kind == NylasRecordKind::Thread).then(|| {
            canonical_digest(&(
                "nylas-thread/v1",
                &id_digest,
                &grant_id_digest,
                occurred_at,
                updated_at,
                &subject_digest,
                has_attachments,
                message_count,
            ))
        });
        let event_digest = (kind == NylasRecordKind::Event).then(|| {
            canonical_digest(&(
                "nylas-event/v1",
                &id_digest,
                &calendar_id_digest,
                occurred_at,
                updated_at,
                &subject_digest,
                status,
                busy,
                cancelled,
                participant_count,
            ))
        });
        NylasMetadataRecord::new(
            kind,
            id_digest,
            grant_id_digest,
            thread_id_digest,
            calendar_id_digest,
            event_id_digest,
            occurred_at,
            updated_at,
            subject_digest,
            status,
            has_attachments,
            unread,
            starred,
            busy,
            cancelled,
            participant_count,
            message_count,
            selection.digest(),
            message_digest,
            thread_digest,
            event_digest,
        )
    }
}

fn selected_identifier(
    value: &Value,
    key: &str,
    selection: &NylasFieldSelection,
    field: NylasSelectedField,
    label: &str,
) -> Option<Digest> {
    selection
        .contains(field)
        .then(|| value.get(key).and_then(Value::as_str))
        .flatten()
        .map(|value| crate::sha256_digest(format!("nylas-{label}-id/v1|{value}").as_bytes()))
}

fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn parse_status(value: &str) -> NylasDeliveryStatus {
    match value.to_ascii_lowercase().as_str() {
        "sent" | "queued" | "scheduled" => NylasDeliveryStatus::Sent,
        "delivered" | "delivery" => NylasDeliveryStatus::Delivered,
        "bounced" | "bounce" => NylasDeliveryStatus::Bounced,
        "failed" | "failure" => NylasDeliveryStatus::Failed,
        "cancelled" | "canceled" | "cancel" => NylasDeliveryStatus::Cancelled,
        "updated" | "modified" => NylasDeliveryStatus::Updated,
        _ => NylasDeliveryStatus::Unknown,
    }
}

fn participant_count(value: &Value) -> Option<u16> {
    let mut count = 0usize;
    for key in ["from", "to", "cc", "bcc", "reply_to", "participants"] {
        if let Some(items) = value.get(key).and_then(Value::as_array) {
            count = count.saturating_add(items.len());
        }
    }
    u16::try_from(count).ok()
}

pub type NylasCommunicationProvider<T> = NylasProvider<T>;
pub type FixtureNylasProviderTransport = FixtureNylasTransport;
pub type RecordingNylasProviderTransport = RecordingNylasTransport;
pub type LoopbackNylasProviderTransport = LoopbackNylasTransport;
pub type BlockedEnvNylasProviderTransport = BlockedEnvNylasTransport;
pub type NylasPageCursor = OpaqueCursor;

// Keep these imports visible to downstream users that build a provider
// request without importing the model module directly.
pub type NylasProviderPermission = NylasPermission;
pub type NylasProviderResource = NylasResourceKind;
pub type NylasProviderFieldSelection = NylasFieldSelection;

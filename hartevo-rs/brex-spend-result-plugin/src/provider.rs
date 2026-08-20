//! Typed, non-native Brex provider seams.
//!
//! There is intentionally no Brex SDK, HTTPS client, credential resolver,
//! card mutation, payment, refund, limit update, or policy update path here.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::error::BrexSpendTransportError;
use crate::model::{
    BrexSpendObservation, BrexSpendScope, Digest, ModelError, SpendOperation, TransportProvenance,
    digest_serializable,
};
use crate::{
    MAX_ITEMS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS,
    PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error(transparent)]
    Transport(#[from] BrexSpendTransportError),
    #[error("provider request is outside the registered Brex spend scope")]
    ScopeMismatch,
    #[error("provider request operation is not allowlisted")]
    OperationNotAllowed,
    #[error("provider response failed its request or response digest fence")]
    ResponseTampered,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_seconds: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_backoff_seconds: MAX_RETRY_AFTER_SECONDS,
        }
    }
}

impl RetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_seconds: u32) -> Result<Self, ModelError> {
        if max_attempts == 0 || max_attempts > 8 || max_backoff_seconds > MAX_RETRY_AFTER_SECONDS {
            return Err(ModelError::InvalidQueryConfig);
        }
        Ok(Self {
            max_attempts,
            max_backoff_seconds,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.max_attempts, self.max_backoff_seconds).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryConfig {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_items: usize,
    pub max_response_bytes: usize,
    pub retry: RetryPolicy,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            page_size: 10,
            max_pages: MAX_PAGES,
            max_items: MAX_ITEMS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            retry: RetryPolicy::default(),
        }
    }
}

impl QueryConfig {
    pub fn new(
        page_size: usize,
        max_pages: usize,
        max_items: usize,
        max_response_bytes: usize,
        retry: RetryPolicy,
    ) -> Result<Self, ModelError> {
        let config = Self {
            page_size,
            max_pages,
            max_items,
            max_response_bytes,
            retry,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.retry.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || !(1..=MAX_ITEMS).contains(&self.max_items)
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            return Err(ModelError::InvalidQueryConfig);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("query config serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendQuery {
    Spend {
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        user_digest: Option<Digest>,
        card_digest: Option<Digest>,
    },
    Limits {
        include_utilization: bool,
    },
    Policies {
        include_active: bool,
    },
}

impl SpendQuery {
    pub fn for_operation(
        operation: SpendOperation,
        scope: &BrexSpendScope,
        now: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let query = match operation {
            SpendOperation::ReadSpend => Self::Spend {
                period_start: now - Duration::days(30),
                period_end: now,
                user_digest: None,
                card_digest: None,
            },
            SpendOperation::ReadLimits => Self::Limits {
                include_utilization: true,
            },
            SpendOperation::ReadPolicies => Self::Policies {
                include_active: true,
            },
        };
        query.validate_against(scope)?;
        Ok(query)
    }

    #[must_use]
    pub const fn operation(&self) -> SpendOperation {
        match self {
            Self::Spend { .. } => SpendOperation::ReadSpend,
            Self::Limits { .. } => SpendOperation::ReadLimits,
            Self::Policies { .. } => SpendOperation::ReadPolicies,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("spend query serializes")
    }

    pub fn validate_against(&self, scope: &BrexSpendScope) -> Result<(), ModelError> {
        match self {
            Self::Spend {
                period_start,
                period_end,
                user_digest,
                card_digest,
            } => {
                if *period_end <= *period_start
                    || *period_end - *period_start
                        > Duration::days(crate::model::MAX_QUERY_WINDOW_DAYS)
                {
                    return Err(ModelError::InvalidTimeWindow);
                }
                if user_digest
                    .as_ref()
                    .is_some_and(|digest| !scope.users.iter().any(|id| &id.digest() == digest))
                    || card_digest
                        .as_ref()
                        .is_some_and(|digest| !scope.cards.iter().any(|id| &id.digest() == digest))
                {
                    return Err(ModelError::InvalidRelationship {
                        field: "query dimension scope",
                    });
                }
            }
            Self::Limits { .. } | Self::Policies { .. } => {}
        }
        Ok(())
    }
}

/// Opaque pagination cursor. Only its digest and page number cross the
/// serialization/debug boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    token: String,
    scope_digest: Digest,
    query_digest: Digest,
    config_digest: Digest,
    page_number: usize,
}

impl PageCursor {
    pub fn new(
        token: impl Into<String>,
        scope_digest: Digest,
        query_digest: Digest,
        config_digest: Digest,
        page_number: usize,
    ) -> Result<Self, ModelError> {
        let token = token.into();
        if token.is_empty() || token.len() > 100_000 || token.trim() != token {
            return Err(ModelError::InvalidCursor);
        }
        scope_digest.validate()?;
        query_digest.validate()?;
        config_digest.validate()?;
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token,
            scope_digest,
            query_digest,
            config_digest,
            page_number,
        })
    }

    #[must_use]
    pub fn token_digest(&self) -> Digest {
        Digest::from_parts("brex-page-token/v1", &[("token", self.token.clone())])
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "brex-page-cursor/v1",
            &[
                ("token", self.token_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("config", self.config_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
            ],
        )
    }

    #[must_use]
    pub const fn page_number(&self) -> usize {
        self.page_number
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    #[must_use]
    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub fn validate(
        &self,
        scope_digest: &Digest,
        query_digest: &Digest,
        config_digest: &Digest,
    ) -> Result<(), ModelError> {
        if &self.scope_digest != scope_digest
            || &self.query_digest != query_digest
            || &self.config_digest != config_digest
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(())
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("token", &"<opaque>")
            .field("token_digest", &self.token_digest())
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("config_digest", &self.config_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for PageCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PageCursor", 5)?;
        state.serialize_field("tokenDigest", &self.token_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("queryDigest", &self.query_digest)?;
        state.serialize_field("configDigest", &self.config_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

pub type Cursor = PageCursor;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendReadRequest {
    pub operation: SpendOperation,
    pub query: SpendQuery,
    pub config: QueryConfig,
    pub cursor: Option<PageCursor>,
    pub scope_digest: Digest,
    pub scope_revision: crate::model::RevisionId,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key: Digest,
}

impl BrexSpendReadRequest {
    pub fn new(
        scope: &BrexSpendScope,
        query: SpendQuery,
        config: QueryConfig,
        cursor: Option<PageCursor>,
        secret_reference_digest: Digest,
    ) -> Result<Self, ModelError> {
        scope.verify()?;
        query.validate_against(scope)?;
        config.validate()?;
        secret_reference_digest.validate()?;
        if let Some(cursor) = &cursor {
            cursor.validate(&scope.scope_digest, &query.digest(), &config.digest())?;
        }
        let mut request = Self {
            operation: query.operation(),
            query,
            config,
            cursor,
            scope_digest: scope.scope_digest.clone(),
            scope_revision: scope.scope_revision.clone(),
            consent_digest: scope.consent.digest(),
            permission_digest: scope.permissions.permission_digest().clone(),
            secret_reference_digest,
            request_digest: Digest::from_text("pending-request-digest"),
            idempotency_key: Digest::from_text("pending-idempotency-key"),
        };
        request.request_digest = request.compute_digest();
        request.idempotency_key = Digest::from_parts(
            "brex-idempotency/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("scope_revision", request.scope_revision.as_str().to_owned()),
            ],
        );
        Ok(request)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "brex-spend-request/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("query", self.query.digest().as_str().to_owned()),
                ("config", self.config.digest().as_str().to_owned()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("scope_revision", self.scope_revision.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
            ],
        )
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> Digest {
        self.query.digest()
    }

    #[must_use]
    pub fn config_digest(&self) -> Digest {
        self.config.digest()
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.config.validate()?;
        if self.operation != self.query.operation()
            || self.request_digest != self.compute_digest()
            || self.idempotency_key
                != Digest::from_parts(
                    "brex-idempotency/v1",
                    &[
                        ("request", self.request_digest.as_str().to_owned()),
                        ("scope_revision", self.scope_revision.as_str().to_owned()),
                    ],
                )
        {
            return Err(ModelError::InvalidDigest {
                field: "request digest",
            });
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate(
                &self.scope_digest,
                &self.query.digest(),
                &self.config.digest(),
            )?;
        }
        Ok(())
    }

    pub fn next_page(&self, cursor: PageCursor) -> Result<Self, ModelError> {
        if cursor.page_number() <= self.cursor.as_ref().map_or(1, |value| value.page_number()) {
            return Err(ModelError::InvalidCursor);
        }
        cursor.validate(
            &self.scope_digest,
            &self.query.digest(),
            &self.config.digest(),
        )?;
        let mut request = self.clone();
        request.cursor = Some(cursor);
        request.request_digest = request.compute_digest();
        request.idempotency_key = Digest::from_parts(
            "brex-idempotency/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("scope_revision", request.scope_revision.as_str().to_owned()),
            ],
        );
        Ok(request)
    }

    pub fn validate_against(&self, scope: &BrexSpendScope) -> Result<(), ModelError> {
        scope.verify()?;
        self.query.validate_against(scope)?;
        self.config.validate()?;
        if self.operation != self.query.operation()
            || self.scope_digest != scope.scope_digest
            || self.scope_revision != scope.scope_revision
            || self.consent_digest != scope.consent.digest()
            || self.permission_digest != *scope.permissions.permission_digest()
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidRelationship {
                field: "request scope or digest",
            });
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate(
                &scope.scope_digest,
                &self.query.digest(),
                &self.config.digest(),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendResponse {
    pub operation: SpendOperation,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub scope_revision: crate::model::RevisionId,
    pub consent_digest: Digest,
    pub page_number: usize,
    pub observations: Vec<BrexSpendObservation>,
    pub next_cursor: Option<PageCursor>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl BrexSpendResponse {
    pub fn new(
        request: &BrexSpendReadRequest,
        observations: Vec<BrexSpendObservation>,
        next_cursor: Option<PageCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if response_bytes > request.config.max_response_bytes
            || response_bytes > MAX_RESPONSE_BYTES
            || observations.len() > request.config.page_size
        {
            return Err(ModelError::BoundExceeded {
                field: "provider response",
            });
        }
        for observation in &observations {
            observation.validate()?;
            if observation.operation() != request.operation
                || observation.scope_digest() != &request.scope_digest
            {
                return Err(ModelError::InvalidRelationship {
                    field: "response observation scope",
                });
            }
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate(
                &request.scope_digest,
                &request.query.digest(),
                &request.config.digest(),
            )?;
        }
        let mut response = Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            scope_revision: request.scope_revision.clone(),
            consent_digest: request.consent_digest.clone(),
            page_number: request.cursor.as_ref().map_or(1, PageCursor::page_number),
            observations,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("pending-response-digest"),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            self.operation,
            &self.request_digest,
            &self.scope_digest,
            &self.scope_revision,
            &self.consent_digest,
            self.page_number,
            &self.observations,
            &self.next_cursor,
            self.response_bytes,
            self.provenance,
        ))
        .expect("Brex response digest material serializes")
    }

    pub fn verify_for_request(&self, request: &BrexSpendReadRequest) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.scope_digest != request.scope_digest
            || self.scope_revision != request.scope_revision
            || self.consent_digest != request.consent_digest
            || self.page_number != request.cursor.as_ref().map_or(1, PageCursor::page_number)
            || self.response_bytes > request.config.max_response_bytes
            || self.compute_digest() != self.response_digest
        {
            return Err(ModelError::InvalidDigest {
                field: "provider response",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
            if observation.operation() != self.operation
                || observation.scope_digest() != &self.scope_digest
            {
                return Err(ModelError::InvalidObservation);
            }
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate(
                &request.scope_digest,
                &request.query.digest(),
                &request.config.digest(),
            )?;
        }
        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        if self.response_bytes > MAX_RESPONSE_BYTES || self.compute_digest() != self.response_digest
        {
            return Err(ModelError::InvalidDigest {
                field: "provider response",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
            if observation.operation() != self.operation
                || observation.scope_digest() != &self.scope_digest
            {
                return Err(ModelError::InvalidObservation);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn item_count(&self) -> usize {
        self.observations.len()
    }
}

pub type BrexSpendPage = BrexSpendResponse;
pub type BrexSpendProviderResponse = BrexSpendResponse;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub operation: SpendOperation,
    pub request_digest: Digest,
    pub idempotency_key: Digest,
    pub cursor_digest: Option<Digest>,
}

pub trait BrexSpendTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> std::result::Result<BrexSpendResponse, BrexSpendTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub allowed_operations: BTreeSet<SpendOperation>,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl Default for BrexSpendProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl BrexSpendProviderDefinition {
    #[must_use]
    pub fn new() -> Self {
        let allowed_operations = SpendOperation::ALL.into_iter().collect();
        let provider_digest = Digest::from_parts(
            "brex-provider-definition/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("version", PROVIDER_VERSION.to_owned()),
                ("api", PROVIDER_API_REVISION.to_owned()),
                (
                    "operations",
                    "read_spend,read_limits,read_policies".to_owned(),
                ),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            allowed_operations,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let expected = Self::new();
        if self.provider_id != expected.provider_id
            || self.provider_version != expected.provider_version
            || self.api_revision != expected.api_revision
            || self.allowed_operations != expected.allowed_operations
            || self.provider_digest != expected.provider_digest
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
        {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }
}

pub struct BrexSpendProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: BrexSpendProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for BrexSpendProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrexSpendProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: BrexSpendTransport> BrexSpendProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderError> {
        let provider = Self {
            transport,
            definition: BrexSpendProviderDefinition::new(),
        };
        provider.definition.validate()?;
        Ok(provider)
    }

    #[must_use]
    pub fn definition(&self) -> &BrexSpendProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest.clone()
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

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.definition.validate()
    }

    pub fn read(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> Result<BrexSpendResponse, ProviderError> {
        if !self
            .definition
            .allowed_operations
            .contains(&request.operation)
        {
            return Err(ProviderError::OperationNotAllowed);
        }
        let response = self.transport.read(request)?;
        response
            .verify_for_request(request)
            .map_err(|_| ProviderError::ResponseTampered)?;
        Ok(response)
    }

    pub fn read_spend(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> Result<BrexSpendResponse, ProviderError> {
        self.read(request)
    }

    pub fn read_limits(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> Result<BrexSpendResponse, ProviderError> {
        self.read(request)
    }

    pub fn read_policies(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> Result<BrexSpendResponse, ProviderError> {
        self.read(request)
    }
}

impl Default for BrexSpendProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Brex provider definition")
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl BrexSpendTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &BrexSpendReadRequest,
    ) -> std::result::Result<BrexSpendResponse, BrexSpendTransportError> {
        Err(BrexSpendTransportError::BlockedEnv)
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    responses: VecDeque<std::result::Result<BrexSpendResponse, BrexSpendTransportError>>,
    calls: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_response(
        &mut self,
        response: std::result::Result<BrexSpendResponse, BrexSpendTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn push_read_response(&mut self, response: BrexSpendResponse) {
        self.push_response(Ok(response));
    }

    #[must_use]
    pub fn calls(&self) -> &[RecordedRequest] {
        &self.calls
    }
}

impl BrexSpendTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> std::result::Result<BrexSpendResponse, BrexSpendTransportError> {
        self.calls.push(RecordedRequest {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            idempotency_key: request.idempotency_key.clone(),
            cursor_digest: request.cursor.as_ref().map(PageCursor::digest),
        });
        self.responses
            .pop_front()
            .unwrap_or(Err(BrexSpendTransportError::ProviderUnknown {
                status_code: None,
            }))
    }
}

#[derive(Debug, Default)]
pub struct FakeTransport {
    responses: VecDeque<std::result::Result<BrexSpendResponse, BrexSpendTransportError>>,
    calls: Vec<RecordedRequest>,
}

impl FakeTransport {
    pub fn push_response(
        &mut self,
        response: std::result::Result<BrexSpendResponse, BrexSpendTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn push_read_response(&mut self, response: BrexSpendResponse) {
        self.push_response(Ok(response));
    }

    #[must_use]
    pub fn calls(&self) -> &[RecordedRequest] {
        &self.calls
    }
}

impl BrexSpendTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> std::result::Result<BrexSpendResponse, BrexSpendTransportError> {
        self.calls.push(RecordedRequest {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            idempotency_key: request.idempotency_key.clone(),
            cursor_digest: request.cursor.as_ref().map(PageCursor::digest),
        });
        self.responses
            .pop_front()
            .unwrap_or(Err(BrexSpendTransportError::ProviderUnknown {
                status_code: None,
            }))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    limit_digest: Option<Digest>,
    policy_digest: Option<Digest>,
    now: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &BrexSpendScope, now: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.scope_digest.clone(),
            limit_digest: scope.limits.first().map(crate::model::LimitId::digest),
            policy_digest: scope.policies.first().map(crate::model::PolicyId::digest),
            now,
        }
    }
}

impl BrexSpendTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> std::result::Result<BrexSpendResponse, BrexSpendTransportError> {
        fixture_response(
            request,
            self.scope_digest.clone(),
            self.limit_digest.clone(),
            self.policy_digest.clone(),
            self.now,
            TransportProvenance::Fixture,
        )
        .map_err(|_| BrexSpendTransportError::Malformed)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope_digest: Digest,
    limit_digest: Option<Digest>,
    policy_digest: Option<Digest>,
    now: DateTime<Utc>,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &BrexSpendScope, now: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.scope_digest.clone(),
            limit_digest: scope.limits.first().map(crate::model::LimitId::digest),
            policy_digest: scope.policies.first().map(crate::model::PolicyId::digest),
            now,
        }
    }
}

impl BrexSpendTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(
        &mut self,
        request: &BrexSpendReadRequest,
    ) -> std::result::Result<BrexSpendResponse, BrexSpendTransportError> {
        fixture_response(
            request,
            self.scope_digest.clone(),
            self.limit_digest.clone(),
            self.policy_digest.clone(),
            self.now,
            TransportProvenance::Loopback,
        )
        .map_err(|_| BrexSpendTransportError::Malformed)
    }
}

fn fixture_response(
    request: &BrexSpendReadRequest,
    scope_digest: Digest,
    limit_digest: Option<Digest>,
    policy_digest: Option<Digest>,
    now: DateTime<Utc>,
    provenance: TransportProvenance,
) -> Result<BrexSpendResponse, ModelError> {
    let observations = match request.operation {
        SpendOperation::ReadSpend => vec![BrexSpendObservation::Spend(
            crate::model::SpendObservation::for_digests(
                scope_digest,
                now - Duration::hours(24),
                now,
                crate::model::Money::new("USD", 12_500)?,
                3,
                crate::model::ObservationStatus::Observed,
            )?,
        )],
        SpendOperation::ReadLimits => vec![BrexSpendObservation::Limit(
            crate::model::LimitObservation::for_digests(
                scope_digest.clone(),
                limit_digest.unwrap_or_else(|| Digest::from_text("fixture-limit")),
                now - Duration::days(30),
                now,
                crate::model::Money::new("USD", 1_000_000)?,
                crate::model::Money::new("USD", 125_000)?,
                crate::model::Money::new("USD", 875_000)?,
                crate::model::ObservationStatus::Observed,
            )?,
        )],
        SpendOperation::ReadPolicies => vec![BrexSpendObservation::Policy(
            crate::model::PolicyObservation::for_digests(
                scope_digest,
                policy_digest.unwrap_or_else(|| Digest::from_text("fixture-policy")),
                Digest::from_text("fixture-policy-revision"),
                crate::model::PolicyStatus::Active,
                2,
            )?,
        )],
    };
    BrexSpendResponse::new(request, observations, None, 512, provenance)
}

pub type BrexSpendProviderTransport = dyn BrexSpendTransport;
pub type FixtureBrexSpendTransport = FixtureTransport;
pub type RecordingBrexSpendTransport = RecordingTransport;
pub type FakeBrexSpendTransport = FakeTransport;
pub type LoopbackBrexSpendTransport = LoopbackTransport;
pub type BlockedEnvBrexSpendTransport = BlockedEnvTransport;

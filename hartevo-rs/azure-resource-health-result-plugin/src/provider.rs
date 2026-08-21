//! Layer-1 Azure Resource Health provider seams.
//!
//! The provider accepts only a transport seam. There is deliberately no
//! native HTTP client, Entra resolver, token parameter, or mutation method in
//! this crate.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use crate::model::{
    AvailabilityObservation, AvailabilityState, AzureResourceHealthOperation,
    AzureResourceHealthRegistration, AzureResourceHealthScope, Digest, EventLevel, EventStatus,
    EvidenceState, MAX_AFFECTED_RESOURCE_DIGESTS_PER_EVENT, MAX_EVENT_PROPERTY_BYTES, MAX_EVENTS,
    MAX_IDENTIFIER_BYTES, MAX_RESOURCE_ID_BYTES, MAX_RESPONSE_BYTES, ModelError, OpaquePageCursor,
    ProviderResponseReceipt, RegistrationRevocation, ResourceHealthEventSummary, SecretReference,
    TransportProvenance, api_digest, bounded_string, canonical_digest, parse_rfc3339,
};
use crate::{
    AZURE_RESOURCE_HEALTH_API_ORIGIN, AZURE_RESOURCE_HEALTH_API_REVISION,
    AZURE_RESOURCE_HEALTH_API_VERSION, AZURE_RESOURCE_HEALTH_CONTRACT_VERSION,
    AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT, AZURE_RESOURCE_HEALTH_PROVIDER_ID,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthRequest {
    pub operation: AzureResourceHealthOperation,
    pub method: String,
    pub origin: String,
    pub path: String,
    pub query: String,
    pub api_version: String,
    pub provider_revision: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub event_window_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    #[serde(skip)]
    cursor: Option<OpaquePageCursor>,
}

impl AzureResourceHealthRequest {
    #[must_use]
    pub fn path_and_query(&self) -> String {
        let mut query = self.query.clone();
        if let Some(cursor) = self.cursor.as_ref() {
            query.push_str("&$skipToken=");
            query.push_str(cursor.value());
        }
        format!("{}?{}", self.path, query)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "azure-resource-health-request/v1",
            self.operation,
            &self.method,
            &self.origin,
            &self.path,
            &self.query,
            &self.api_version,
            &self.provider_revision,
            &self.scope_digest,
            &self.permission_digest,
            &self.event_window_digest,
            &self.cursor_digest,
        ))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureResourceHealthResponse {
    pub status: u16,
    body: Vec<u8>,
}

impl AzureResourceHealthResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec(value).expect("Azure Resource Health fixture serializes");
        Self { status, body }
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        Digest::from_bytes(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for AzureResourceHealthResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureResourceHealthResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.body.len())
            .field("response_digest", &self.response_digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AzureResourceHealthTransportError {
    #[error("native Azure Resource Health transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Azure Resource Health transport timed out")]
    Timeout,
    #[error("Azure Resource Health transport failed without a native response")]
    ProviderUnknown,
}

pub type TransportError = AzureResourceHealthTransportError;

pub trait AzureResourceHealthTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &AzureResourceHealthRequest,
    ) -> Result<AzureResourceHealthResponse, AzureResourceHealthTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureAzureResourceHealthTransport {
    availability: AzureResourceHealthResponse,
    events: AzureResourceHealthResponse,
}

impl FixtureAzureResourceHealthTransport {
    #[must_use]
    pub fn new(
        availability: AzureResourceHealthResponse,
        events: AzureResourceHealthResponse,
    ) -> Self {
        Self {
            availability,
            events,
        }
    }

    #[must_use]
    pub fn from_json<A: Serialize, E: Serialize>(availability: &A, events: &E) -> Self {
        Self::new(
            AzureResourceHealthResponse::json(200, availability),
            AzureResourceHealthResponse::json(200, events),
        )
    }
}

impl AzureResourceHealthTransport for FixtureAzureResourceHealthTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &AzureResourceHealthRequest,
    ) -> Result<AzureResourceHealthResponse, AzureResourceHealthTransportError> {
        Ok(match request.operation {
            AzureResourceHealthOperation::AvailabilityStatus => self.availability.clone(),
            AzureResourceHealthOperation::EventList => self.events.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAzureResourceHealthTransport {
    inner: FixtureAzureResourceHealthTransport,
    requests: Vec<AzureResourceHealthRequest>,
}

impl RecordingAzureResourceHealthTransport {
    #[must_use]
    pub fn new(
        availability: AzureResourceHealthResponse,
        events: AzureResourceHealthResponse,
    ) -> Self {
        Self {
            inner: FixtureAzureResourceHealthTransport::new(availability, events),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn fixture(
        availability: AzureResourceHealthResponse,
        events: AzureResourceHealthResponse,
    ) -> Self {
        Self::new(availability, events)
    }

    #[must_use]
    pub fn requests(&self) -> &[AzureResourceHealthRequest] {
        &self.requests
    }
}

impl AzureResourceHealthTransport for RecordingAzureResourceHealthTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &AzureResourceHealthRequest,
    ) -> Result<AzureResourceHealthResponse, AzureResourceHealthTransportError> {
        self.requests.push(request.clone());
        self.inner.execute(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAzureResourceHealthTransport {
    inner: FixtureAzureResourceHealthTransport,
    requests: Vec<AzureResourceHealthRequest>,
}

impl LoopbackAzureResourceHealthTransport {
    #[must_use]
    pub fn new(
        availability: AzureResourceHealthResponse,
        events: AzureResourceHealthResponse,
    ) -> Self {
        Self {
            inner: FixtureAzureResourceHealthTransport::new(availability, events),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AzureResourceHealthRequest] {
        &self.requests
    }
}

impl AzureResourceHealthTransport for LoopbackAzureResourceHealthTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &AzureResourceHealthRequest,
    ) -> Result<AzureResourceHealthResponse, AzureResourceHealthTransportError> {
        self.requests.push(request.clone());
        self.inner.execute(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAzureResourceHealthTransport;

impl AzureResourceHealthTransport for BlockedEnvAzureResourceHealthTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &AzureResourceHealthRequest,
    ) -> Result<AzureResourceHealthResponse, AzureResourceHealthTransportError> {
        Err(AzureResourceHealthTransportError::BlockedEnv)
    }
}

pub type FakeAzureResourceHealthTransport = FixtureAzureResourceHealthTransport;
pub type FixtureTransport = FixtureAzureResourceHealthTransport;
pub type RecordingTransport = RecordingAzureResourceHealthTransport;
pub type LoopbackTransport = LoopbackAzureResourceHealthTransport;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportProvenance,
    pub max_response_bytes: usize,
    pub max_events: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub provider_digest: Digest,
}

impl AzureResourceHealthProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: TransportProvenance, permission_digest: &Digest) -> Self {
        let mut definition = Self {
            schema_version: crate::AZURE_RESOURCE_HEALTH_SCHEMA_VERSION.to_owned(),
            provider_id: AZURE_RESOURCE_HEALTH_PROVIDER_ID.to_owned(),
            provider_version: AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT.to_owned(),
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            api_revision: AZURE_RESOURCE_HEALTH_API_REVISION.to_owned(),
            api_digest: api_digest(),
            permission_digest: permission_digest.clone(),
            provenance,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_events: MAX_EVENTS,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            provider_digest: Digest::from_text(b"azure-resource-health-provider-uninitialized"),
        };
        definition.provider_digest = definition.compute_digest();
        definition
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.compute_digest()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.provider_id != AZURE_RESOURCE_HEALTH_PROVIDER_ID
            || self.provider_version != AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
            || self.api_version != AZURE_RESOURCE_HEALTH_API_VERSION
            || self.api_revision != AZURE_RESOURCE_HEALTH_API_REVISION
            || self.api_digest != api_digest()
            || !self.read_only
            || self.live_execution
            || self.native
            || self.connected
            || self.provider_digest != self.compute_digest()
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "azure-resource-health-provider/v1",
            &self.schema_version,
            &self.provider_id,
            &self.provider_version,
            &self.api_version,
            &self.api_revision,
            &self.api_digest,
            &self.permission_digest,
            self.provenance,
            self.max_response_bytes,
            self.max_events,
            self.read_only,
            self.live_execution,
            self.native,
            self.connected,
        ))
    }
}

pub type ProviderDefinition = AzureResourceHealthProviderDefinition;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureResourceHealthProviderError {
    #[error("Azure Resource Health registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Azure Resource Health SecretReference is revoked")]
    SecretRevoked,
    #[error("Azure Resource Health scope or permission fence does not match")]
    ScopeMismatch,
    #[error("Azure Resource Health transport failed for {operation:?}")]
    Transport {
        operation: AzureResourceHealthOperation,
        request_digest: Digest,
        error: AzureResourceHealthTransportError,
    },
    #[error("Azure Resource Health returned HTTP status {status_code} for {operation:?}")]
    HttpStatus {
        operation: AzureResourceHealthOperation,
        request_digest: Digest,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Azure Resource Health response exceeded the Layer-1 byte bound")]
    ResponseTooLarge {
        operation: AzureResourceHealthOperation,
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Azure Resource Health response was malformed or unsafe to normalize")]
    MalformedResponse {
        operation: AzureResourceHealthOperation,
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Azure Resource Health event timestamp was outside the registered window")]
    EventWindowMismatch {
        request_digest: Digest,
        event_digest: Digest,
    },
    #[error("Azure Resource Health resource revision drifted")]
    ResourceRevisionMismatch {
        expected: u64,
        observed: u64,
        request_digest: Digest,
    },
    #[error("Azure Resource Health opaque cursor was not bound to this request")]
    CursorMismatch { request_digest: Digest },
    #[error("Azure Resource Health normalized event bounds were exceeded")]
    BoundExceeded { request_digest: Digest },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl AzureResourceHealthProviderError {
    #[must_use]
    pub fn operation(&self) -> Option<AzureResourceHealthOperation> {
        match self {
            Self::Transport { operation, .. }
            | Self::HttpStatus { operation, .. }
            | Self::ResponseTooLarge { operation, .. }
            | Self::MalformedResponse { operation, .. } => Some(*operation),
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::ScopeMismatch
            | Self::EventWindowMismatch { .. }
            | Self::ResourceRevisionMismatch { .. }
            | Self::CursorMismatch { .. }
            | Self::BoundExceeded { .. }
            | Self::Model(_) => None,
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> Option<&Digest> {
        match self {
            Self::Transport { request_digest, .. }
            | Self::HttpStatus { request_digest, .. }
            | Self::ResponseTooLarge { request_digest, .. }
            | Self::MalformedResponse { request_digest, .. }
            | Self::EventWindowMismatch { request_digest, .. }
            | Self::ResourceRevisionMismatch { request_digest, .. }
            | Self::CursorMismatch { request_digest }
            | Self::BoundExceeded { request_digest } => Some(request_digest),
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::ScopeMismatch
            | Self::Model(_) => None,
        }
    }

    #[must_use]
    pub fn response_metadata(&self) -> Option<(Digest, usize, Option<u16>)> {
        match self {
            Self::HttpStatus {
                response_digest,
                response_bytes,
                status_code,
                ..
            } => Some((response_digest.clone(), *response_bytes, Some(*status_code))),
            Self::ResponseTooLarge {
                response_digest,
                response_bytes,
                ..
            }
            | Self::MalformedResponse {
                response_digest,
                response_bytes,
                ..
            } => Some((response_digest.clone(), *response_bytes, None)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AvailabilityStatusRead {
    pub observation: AvailabilityObservation,
    pub receipt: ProviderResponseReceipt,
}

#[derive(Clone, Debug)]
pub struct EventListRead {
    pub state: EvidenceState,
    pub events: Vec<ResourceHealthEventSummary>,
    pub next_cursor: Option<OpaquePageCursor>,
    pub receipt: ProviderResponseReceipt,
}

#[derive(Clone)]
pub struct AzureResourceHealthProvider<T: AzureResourceHealthTransport> {
    scope: AzureResourceHealthScope,
    secret_reference: SecretReference,
    transport: T,
    definition: AzureResourceHealthProviderDefinition,
    registration: AzureResourceHealthRegistration,
    last_cursor_digest: Option<Digest>,
}

impl<T: AzureResourceHealthTransport> fmt::Debug for AzureResourceHealthProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureResourceHealthProvider")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AzureResourceHealthTransport> AzureResourceHealthProvider<T> {
    pub fn new(
        scope: AzureResourceHealthScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, AzureResourceHealthProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(AzureResourceHealthProviderError::SecretRevoked);
        }
        if !secret_reference.matches_tenant(scope.tenant_digest()) {
            return Err(AzureResourceHealthProviderError::ScopeMismatch);
        }
        let definition = AzureResourceHealthProviderDefinition::layer1(
            transport.provenance(),
            scope.permission_digest(),
        );
        definition.validate()?;
        let registration = AzureResourceHealthRegistration::new(
            &scope,
            &secret_reference,
            &definition.provider_digest,
            &definition.api_digest,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            last_cursor_digest: None,
        })
    }

    pub fn with_registration(
        scope: AzureResourceHealthScope,
        secret_reference: SecretReference,
        transport: T,
        registration: AzureResourceHealthRegistration,
    ) -> Result<Self, AzureResourceHealthProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(AzureResourceHealthProviderError::SecretRevoked);
        }
        if !secret_reference.matches_tenant(scope.tenant_digest()) {
            return Err(AzureResourceHealthProviderError::ScopeMismatch);
        }
        let definition = AzureResourceHealthProviderDefinition::layer1(
            transport.provenance(),
            scope.permission_digest(),
        );
        definition.validate()?;
        registration.validate(
            &scope,
            &secret_reference,
            &definition.provider_digest,
            &definition.api_digest,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            last_cursor_digest: None,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AzureResourceHealthScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &AzureResourceHealthProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest.clone()
    }

    #[must_use]
    pub fn api_digest(&self) -> &Digest {
        &self.definition.api_digest
    }

    #[must_use]
    pub fn registration(&self) -> &AzureResourceHealthRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
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

    pub fn read_availability_status(
        &mut self,
    ) -> Result<AvailabilityStatusRead, AzureResourceHealthProviderError> {
        self.ensure_ready()?;
        let request = self.build_request(AzureResourceHealthOperation::AvailabilityStatus, None);
        let response = self.execute(&request)?;
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        let value = Self::parse_json(&request, &response)?;
        let observation = self.parse_availability(&request, &value)?;
        let receipt = Self::receipt(&request, &response, response_digest, response_bytes);
        Ok(AvailabilityStatusRead {
            observation,
            receipt,
        })
    }

    pub fn read_availability(
        &mut self,
    ) -> Result<AvailabilityStatusRead, AzureResourceHealthProviderError> {
        self.read_availability_status()
    }

    pub fn read_event_list(
        &mut self,
        cursor: Option<&OpaquePageCursor>,
    ) -> Result<EventListRead, AzureResourceHealthProviderError> {
        self.ensure_ready()?;
        if let Some(cursor) = cursor
            && self.last_cursor_digest.as_ref() != Some(cursor.digest())
        {
            return Err(AzureResourceHealthProviderError::CursorMismatch {
                request_digest: Digest::from_text(b"azure-resource-health-cursor-unbound"),
            });
        }
        let request = self.build_request(AzureResourceHealthOperation::EventList, cursor);
        let response = self.execute(&request)?;
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        let value = Self::parse_json(&request, &response)?;
        let (state, events, next_cursor) = self.parse_events(&request, &value)?;
        self.last_cursor_digest = next_cursor.as_ref().map(|cursor| cursor.digest().clone());
        let receipt = Self::receipt(&request, &response, response_digest, response_bytes);
        Ok(EventListRead {
            state,
            events,
            next_cursor,
            receipt,
        })
    }

    pub fn read_events(
        &mut self,
        cursor: Option<&OpaquePageCursor>,
    ) -> Result<EventListRead, AzureResourceHealthProviderError> {
        self.read_event_list(cursor)
    }

    pub fn read(
        &mut self,
    ) -> Result<crate::AzureResourceHealthEvidence, AzureResourceHealthProviderError> {
        let availability = self.read_availability_status()?;
        let events = self.read_event_list(None)?;
        let availability_state = if availability.observation.is_known() {
            EvidenceState::Complete
        } else {
            EvidenceState::Unknown
        };
        let event_list_state = events.state;
        let state = if availability_state != EvidenceState::Complete {
            EvidenceState::Unknown
        } else if event_list_state == EvidenceState::Empty {
            EvidenceState::Empty
        } else if matches!(
            event_list_state,
            EvidenceState::Complete | EvidenceState::Empty
        ) {
            EvidenceState::Complete
        } else {
            EvidenceState::Partial
        };
        let next_cursor_digest = events
            .next_cursor
            .as_ref()
            .map(|cursor| cursor.digest().clone());
        let mut evidence = crate::AzureResourceHealthEvidence {
            plugin_version: AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT),
            contract_version: AZURE_RESOURCE_HEALTH_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: AZURE_RESOURCE_HEALTH_PROVIDER_ID.to_owned(),
            provider_digest: self.provider_digest(),
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            api_digest: self.definition.api_digest.clone(),
            permission_digest: self.scope.permission_digest().clone(),
            scope_digest: self.scope.scope_digest().clone(),
            tenant_digest: self.scope.tenant_digest().clone(),
            subscription_id: self.scope.subscription_id().to_owned(),
            resource_digest: self.scope.resource_digest().clone(),
            resource_revision: self.scope.resource_revision(),
            event_window_digest: self.scope.event_window().digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provenance: self.transport_provenance(),
            state,
            availability_state,
            event_list_state,
            availability: Some(availability.observation),
            events: events.events,
            next_cursor_digest,
            receipts: vec![availability.receipt, events.receipt],
            read_only: true,
            native_provider: false,
            connected: false,
            external_write_performed: false,
            causal_authority: false,
            recovery_authority: false,
            outcome_authority: false,
            raw_provider_payload_retained: false,
            evidence_digest: Digest::from_text(b"azure-resource-health-evidence-uninitialized"),
        };
        evidence.evidence_digest = evidence.digest();
        Ok(evidence)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, AzureResourceHealthProviderError> {
        self.registration.revoke().map_err(Into::into)
    }

    pub fn restore(&mut self) -> Result<(), AzureResourceHealthProviderError> {
        self.registration.restore().map_err(Into::into)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AzureResourceHealthProviderError> {
        self.secret_reference.revoke().map_err(Into::into)
    }

    fn ensure_ready(&self) -> Result<(), AzureResourceHealthProviderError> {
        if !self.registration.is_active() {
            return Err(AzureResourceHealthProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AzureResourceHealthProviderError::SecretRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &self.provider_digest(),
                self.api_digest(),
            )
            .map_err(|_| AzureResourceHealthProviderError::RegistrationRevoked)
    }

    fn build_request(
        &self,
        operation: AzureResourceHealthOperation,
        cursor: Option<&OpaquePageCursor>,
    ) -> AzureResourceHealthRequest {
        let path = format!("{}{}", self.scope.resource_id(), operation.path_suffix());
        let mut query = format!("api-version={AZURE_RESOURCE_HEALTH_API_VERSION}");
        if operation == AzureResourceHealthOperation::EventList {
            query.push_str("&$filter=eventTimestamp ge '");
            query.push_str(&self.scope.event_window().start().to_rfc3339());
            query.push_str("' and eventTimestamp le '");
            query.push_str(&self.scope.event_window().end().to_rfc3339());
            query.push('\'');
        }
        let cursor_digest = cursor.map(|cursor| cursor.digest().clone());
        let mut request = AzureResourceHealthRequest {
            operation,
            method: "GET".to_owned(),
            origin: AZURE_RESOURCE_HEALTH_API_ORIGIN.to_owned(),
            path,
            query,
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            provider_revision: AZURE_RESOURCE_HEALTH_API_REVISION.to_owned(),
            scope_digest: self.scope.scope_digest().clone(),
            permission_digest: self.scope.permission_digest().clone(),
            event_window_digest: self.scope.event_window().digest().clone(),
            cursor_digest,
            request_digest: Digest::from_text(b"azure-resource-health-request-uninitialized"),
            cursor: cursor.cloned(),
        };
        request.request_digest = request.digest();
        request
    }

    fn execute(
        &mut self,
        request: &AzureResourceHealthRequest,
    ) -> Result<AzureResourceHealthResponse, AzureResourceHealthProviderError> {
        self.transport.execute(request).map_err(|error| {
            AzureResourceHealthProviderError::Transport {
                operation: request.operation,
                request_digest: request.request_digest.clone(),
                error,
            }
        })
    }

    fn parse_json(
        request: &AzureResourceHealthRequest,
        response: &AzureResourceHealthResponse,
    ) -> Result<serde_json::Value, AzureResourceHealthProviderError> {
        if response.response_bytes() > MAX_RESPONSE_BYTES {
            return Err(AzureResourceHealthProviderError::ResponseTooLarge {
                operation: request.operation,
                request_digest: request.request_digest.clone(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            });
        }
        if !(200..=299).contains(&response.status) {
            return Err(AzureResourceHealthProviderError::HttpStatus {
                operation: request.operation,
                request_digest: request.request_digest.clone(),
                status_code: response.status,
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            });
        }
        serde_json::from_slice(response.body()).map_err(|_| {
            AzureResourceHealthProviderError::MalformedResponse {
                operation: request.operation,
                request_digest: request.request_digest.clone(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            }
        })
    }

    fn parse_availability(
        &self,
        request: &AzureResourceHealthRequest,
        value: &serde_json::Value,
    ) -> Result<AvailabilityObservation, AzureResourceHealthProviderError> {
        let properties = value.get("properties").unwrap_or(value);
        let status = bounded_string(
            properties.get("availabilityState"),
            MAX_EVENT_PROPERTY_BYTES,
        )
        .map_or(AvailabilityState::Unknown, |value| {
            AvailabilityState::parse(&value)
        });
        let previous_status = bounded_string(
            properties
                .get("previousAvailabilityState")
                .or_else(|| properties.get("previousHealthStatus")),
            MAX_EVENT_PROPERTY_BYTES,
        )
        .map(|value| AvailabilityState::parse(&value));
        let occurred_at = parse_rfc3339(
            properties
                .get("occurredTime")
                .or_else(|| properties.get("occuredTime")),
        );
        let reported_at = parse_rfc3339(properties.get("reportedTime"));
        if let Some(id) = bounded_string(value.get("id"), MAX_RESOURCE_ID_BYTES) {
            let expected_prefix = format!(
                "{}{}",
                self.scope.resource_id(),
                AzureResourceHealthOperation::AvailabilityStatus.path_suffix()
            );
            if !id.eq_ignore_ascii_case(&expected_prefix) {
                return Err(AzureResourceHealthProviderError::ScopeMismatch);
            }
        }
        if let Some(observed_revision) = value
            .get("properties")
            .and_then(|properties| properties.get("resourceRevision"))
            .and_then(serde_json::Value::as_u64)
            && observed_revision != self.scope.resource_revision().get()
        {
            return Err(AzureResourceHealthProviderError::ResourceRevisionMismatch {
                expected: self.scope.resource_revision().get(),
                observed: observed_revision,
                request_digest: request.request_digest.clone(),
            });
        }
        let event_id_digest = bounded_string(properties.get("healthEventId"), MAX_IDENTIFIER_BYTES)
            .map(|value| Digest::from_text(value.as_bytes()));
        let status_digest = canonical_digest(&(
            "azure-resource-health-availability/v1",
            status,
            previous_status,
            occurred_at,
            reported_at,
            &event_id_digest,
            self.scope.resource_digest(),
            self.scope.resource_revision(),
        ));
        Ok(AvailabilityObservation {
            status,
            previous_status,
            occurred_at,
            reported_at,
            event_id_digest,
            resource_digest: self.scope.resource_digest().clone(),
            resource_revision: self.scope.resource_revision(),
            status_digest,
        })
    }

    fn parse_events(
        &self,
        request: &AzureResourceHealthRequest,
        value: &serde_json::Value,
    ) -> Result<
        (
            EvidenceState,
            Vec<ResourceHealthEventSummary>,
            Option<OpaquePageCursor>,
        ),
        AzureResourceHealthProviderError,
    > {
        let event_values = value
            .get("value")
            .and_then(serde_json::Value::as_array)
            .or_else(|| value.as_array())
            .ok_or_else(|| AzureResourceHealthProviderError::MalformedResponse {
                operation: request.operation,
                request_digest: request.request_digest.clone(),
                response_digest: Digest::from_text(b"azure-resource-health-events-malformed"),
                response_bytes: 0,
            })?;
        if event_values.len() > MAX_EVENTS {
            return Err(AzureResourceHealthProviderError::BoundExceeded {
                request_digest: request.request_digest.clone(),
            });
        }
        let mut events = Vec::with_capacity(event_values.len());
        for event in event_values {
            events.push(self.parse_event(request, event)?);
        }
        events.sort_by(|left, right| {
            left.event_timestamp
                .cmp(&right.event_timestamp)
                .then_with(|| left.event_id.as_str().cmp(right.event_id.as_str()))
        });
        if events
            .windows(2)
            .any(|window| window[0].event_id == window[1].event_id)
        {
            return Err(AzureResourceHealthProviderError::BoundExceeded {
                request_digest: request.request_digest.clone(),
            });
        }
        let state = if events.is_empty() {
            EvidenceState::Empty
        } else if events.iter().all(ResourceHealthEventSummary::is_known) {
            EvidenceState::Complete
        } else {
            EvidenceState::Partial
        };
        let next_cursor = self.parse_next_cursor(request, value)?;
        Ok((state, events, next_cursor))
    }

    fn parse_event(
        &self,
        request: &AzureResourceHealthRequest,
        event: &serde_json::Value,
    ) -> Result<ResourceHealthEventSummary, AzureResourceHealthProviderError> {
        let event_id = bounded_string(
            event.get("id").or_else(|| event.get("name")),
            MAX_IDENTIFIER_BYTES,
        )
        .ok_or_else(|| AzureResourceHealthProviderError::MalformedResponse {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            response_digest: Digest::from_text(b"azure-resource-health-event-id-missing"),
            response_bytes: 0,
        })?;
        let event_id = Digest::from_text(event_id.as_bytes());
        let properties = event.get("properties").unwrap_or(event);
        let event_timestamp = parse_rfc3339(
            properties
                .get("impactStartTime")
                .or_else(|| properties.get("lastUpdateTime"))
                .or_else(|| properties.get("eventTimestamp")),
        )
        .ok_or_else(|| AzureResourceHealthProviderError::MalformedResponse {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            response_digest: Digest::from_text(b"azure-resource-health-event-time-missing"),
            response_bytes: 0,
        })?;
        if event_timestamp < self.scope.event_window().start()
            || event_timestamp > self.scope.event_window().end()
        {
            return Err(AzureResourceHealthProviderError::EventWindowMismatch {
                request_digest: request.request_digest.clone(),
                event_digest: event_id,
            });
        }
        let status = bounded_string(properties.get("status"), MAX_EVENT_PROPERTY_BYTES)
            .map_or(EventStatus::Unknown, |value| EventStatus::parse(&value));
        let previous_status = bounded_string(
            properties
                .get("previousStatus")
                .or_else(|| properties.get("previousHealthStatus")),
            MAX_EVENT_PROPERTY_BYTES,
        )
        .map(|value| EventStatus::parse(&value));
        let last_update_time = parse_rfc3339(properties.get("lastUpdateTime"));
        let impact_start_time = parse_rfc3339(properties.get("impactStartTime"));
        let impact_mitigation_time = parse_rfc3339(properties.get("impactMitigationTime"));
        let level = bounded_string(properties.get("level"), MAX_EVENT_PROPERTY_BYTES)
            .or_else(|| bounded_string(properties.get("eventLevel"), MAX_EVENT_PROPERTY_BYTES))
            .map_or(EventLevel::Unknown, |value| EventLevel::parse(&value));
        let affected_resource_digests =
            self.affected_resource_digests(event, properties, &event_id, request)?;
        let transition_digest = canonical_digest(&(
            "azure-resource-health-status-transition/v1",
            &event_id,
            status,
            previous_status,
            event_timestamp,
            last_update_time,
        ));
        let event_digest = canonical_digest(&(
            "azure-resource-health-event-summary/v1",
            &event_id,
            status,
            previous_status,
            event_timestamp,
            last_update_time,
            impact_start_time,
            impact_mitigation_time,
            level,
            &affected_resource_digests,
            &transition_digest,
        ));
        Ok(ResourceHealthEventSummary {
            event_id,
            status,
            previous_status,
            event_timestamp,
            last_update_time,
            impact_start_time,
            impact_mitigation_time,
            level,
            affected_resource_digests,
            transition_digest,
            event_digest,
        })
    }

    fn affected_resource_digests(
        &self,
        event: &serde_json::Value,
        properties: &serde_json::Value,
        event_id: &Digest,
        request: &AzureResourceHealthRequest,
    ) -> Result<Vec<Digest>, AzureResourceHealthProviderError> {
        let mut references = vec![self.scope.resource_digest().clone()];
        for value in [
            event.get("resourceId"),
            properties.get("resourceId"),
            properties.get("affectedResourceId"),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(reference) = bounded_string(Some(value), MAX_RESOURCE_ID_BYTES) {
                references.push(Digest::from_text(reference.as_bytes()));
            }
        }
        if let Some(impact) = properties
            .get("impact")
            .and_then(serde_json::Value::as_array)
        {
            for item in impact {
                for key in ["impactedResources", "resourceIds", "impactedSubscriptions"] {
                    if let Some(values) = item.get(key).and_then(serde_json::Value::as_array) {
                        for value in values {
                            if let Some(reference) =
                                bounded_string(Some(value), MAX_RESOURCE_ID_BYTES)
                            {
                                references.push(Digest::from_text(reference.as_bytes()));
                            }
                        }
                    }
                }
            }
        }
        references.sort();
        references.dedup();
        if references.len() > MAX_AFFECTED_RESOURCE_DIGESTS_PER_EVENT {
            return Err(AzureResourceHealthProviderError::BoundExceeded {
                request_digest: request.request_digest.clone(),
            });
        }
        if references.is_empty() {
            return Err(AzureResourceHealthProviderError::MalformedResponse {
                operation: request.operation,
                request_digest: request.request_digest.clone(),
                response_digest: event_id.clone(),
                response_bytes: 0,
            });
        }
        Ok(references)
    }

    fn parse_next_cursor(
        &self,
        request: &AzureResourceHealthRequest,
        value: &serde_json::Value,
    ) -> Result<Option<OpaquePageCursor>, AzureResourceHealthProviderError> {
        let next_link = value
            .get("nextLink")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("nextCursor").and_then(serde_json::Value::as_str));
        let Some(next_link) = next_link else {
            return Ok(None);
        };
        let Some(token) = next_link
            .split('&')
            .find_map(|part| part.strip_prefix("$skipToken="))
            .or_else(|| next_link.strip_prefix("$skipToken="))
        else {
            return Err(AzureResourceHealthProviderError::CursorMismatch {
                request_digest: request.request_digest.clone(),
            });
        };
        if !next_link
            .to_ascii_lowercase()
            .contains(&self.scope.resource_id().to_ascii_lowercase())
            || !next_link.contains(AZURE_RESOURCE_HEALTH_API_VERSION)
        {
            return Err(AzureResourceHealthProviderError::CursorMismatch {
                request_digest: request.request_digest.clone(),
            });
        }
        let token = token.split('&').next().unwrap_or(token);
        OpaquePageCursor::new(token.to_owned())
            .map(Some)
            .map_err(|_| AzureResourceHealthProviderError::CursorMismatch {
                request_digest: request.request_digest.clone(),
            })
    }

    fn receipt(
        request: &AzureResourceHealthRequest,
        response: &AzureResourceHealthResponse,
        response_digest: Digest,
        response_bytes: usize,
    ) -> ProviderResponseReceipt {
        ProviderResponseReceipt {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            request_path_digest: Digest::from_text(request.path_and_query().as_bytes()),
            api_version: request.api_version.clone(),
            status_code: Some(response.status),
            response_bytes,
            response_digest,
            provider_revision: request.provider_revision.clone(),
            cursor_digest: request.cursor_digest.clone(),
            raw_response_retained: false,
            raw_descriptions_retained: false,
            raw_recommendations_retained: false,
            raw_tags_retained: false,
            credential_material_retained: false,
            native: false,
            connected: false,
        }
    }
}

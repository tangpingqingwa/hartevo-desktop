use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_HEALTH_EVENT_RESULT_API_REVISION, AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION,
    AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION, AWS_HEALTH_EVENT_RESULT_PROVIDER_ID,
    AWS_HEALTH_EVENT_RESULT_PROVIDER_VERSION, AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION,
    model::{
        AffectedEntityReference, AwsHealthEventDetail, AwsHealthEventRecord, AwsHealthEventScope,
        AwsHealthFailureKind, AwsHealthOperation, AwsHealthRegistration, AwsHealthTimeWindow,
        Digest, ModelError, OpaqueCursor, RegistrationState, Revision, SecretReference,
    },
};

pub use crate::model::TransportProvenance;

pub type ProviderProvenance = TransportProvenance;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("API revision is empty")]
    EmptyApiRevision,
    #[error("Layer 1 cannot register a native or connected provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthProviderDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub provider_id: crate::AwsServiceCode,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub describe_events: bool,
    pub describe_event_details: bool,
    pub describe_affected_entities: bool,
    pub native: bool,
    pub connected: bool,
    pub live_execution: bool,
}

impl AwsHealthProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::with_api_revision(
            provider_version,
            AWS_HEALTH_EVENT_RESULT_API_REVISION,
            provenance,
        )
    }

    pub fn with_api_revision(
        provider_version: impl Into<String>,
        api_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let api_revision = api_revision.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if api_revision.is_empty() {
            return Err(ProviderDefinitionError::EmptyApiRevision);
        }
        if provenance.is_native() || provenance.is_connected() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id = crate::AwsServiceCode::new(AWS_HEALTH_EVENT_RESULT_PROVIDER_ID)?;
        let capability_digest = Digest::from_fields(
            "aws-health-provider-capability/v1",
            &[
                AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION.to_owned(),
                AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION.to_owned(),
                AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION.to_owned(),
                AWS_HEALTH_EVENT_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                api_revision.clone(),
                provenance.label().to_owned(),
                "DescribeEvents".to_owned(),
                "DescribeEventDetails".to_owned(),
                "DescribeAffectedEntities".to_owned(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
                "live_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id,
            provider_version,
            api_revision,
            capability_digest,
            provenance,
            describe_events: true,
            describe_event_details: true,
            describe_affected_entities: true,
            native: false,
            connected: false,
            live_execution: false,
        })
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-health-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.plugin_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_revision.clone(),
                self.capability_digest.as_str().to_owned(),
                self.provenance.label().to_owned(),
                self.describe_events.to_string(),
                self.describe_event_details.to_string(),
                self.describe_affected_entities.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.live_execution.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("AWS Health transport returned {kind:?}")]
    Provider {
        kind: AwsHealthFailureKind,
        status_code: Option<u16>,
        retryable: bool,
        diagnostic_digest: Digest,
    },
}

impl TransportError {
    #[must_use]
    pub fn new(
        kind: AwsHealthFailureKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            AwsHealthFailureKind::Throttled
                | AwsHealthFailureKind::ServerFailure
                | AwsHealthFailureKind::Timeout
        );
        Self::Provider {
            kind,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(AwsHealthFailureKind::BadRequest, Some(400), "bad-request")
    }

    #[must_use]
    pub fn unauthorized() -> Self {
        Self::new(
            AwsHealthFailureKind::Unauthorized,
            Some(401),
            "unauthorized",
        )
    }

    #[must_use]
    pub fn access_denied() -> Self {
        Self::new(
            AwsHealthFailureKind::AccessDenied,
            Some(403),
            "access-denied",
        )
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(AwsHealthFailureKind::NotFound, Some(404), "not-found")
    }

    #[must_use]
    pub fn conflict() -> Self {
        Self::new(AwsHealthFailureKind::Conflict, Some(409), "conflict")
    }

    #[must_use]
    pub fn throttled() -> Self {
        Self::new(AwsHealthFailureKind::Throttled, Some(429), "throttled")
    }

    #[must_use]
    pub fn server_failure() -> Self {
        Self::new(
            AwsHealthFailureKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(AwsHealthFailureKind::Timeout, None, "timeout")
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::new(AwsHealthFailureKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    #[must_use]
    pub fn kind(&self) -> AwsHealthFailureKind {
        match self {
            Self::Provider { kind, .. } => *kind,
        }
    }

    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Provider { status_code, .. } => *status_code,
        }
    }

    #[must_use]
    pub fn retryable(&self) -> bool {
        match self {
            Self::Provider { retryable, .. } => *retryable,
        }
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> &Digest {
        match self {
            Self::Provider {
                diagnostic_digest, ..
            } => diagnostic_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsHealthProviderError {
    #[error("AWS Health registration is revoked or mismatched")]
    RegistrationRevoked,
    #[error("AWS Health SecretReference is revoked or mismatched")]
    SecretRevoked,
    #[error("AWS Health permission fence does not allow this operation")]
    PermissionDenied,
    #[error("AWS Health request is outside the exact scope")]
    ScopeMismatch,
    #[error("AWS Health response is malformed or outside a Layer-1 bound")]
    InvalidResponse,
    #[error("AWS Health event detail is required for this operation")]
    MissingEventArn,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Definition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeEventsRequest {
    pub account_id: crate::AwsAccountId,
    pub region: crate::AwsRegion,
    pub service_code: crate::AwsServiceCode,
    pub event_arn: Option<crate::AwsEventArn>,
    pub event_type_codes: std::collections::BTreeSet<crate::AwsEventTypeCode>,
    pub statuses: std::collections::BTreeSet<crate::AwsHealthEventStatus>,
    pub time_window: AwsHealthTimeWindow,
    pub max_events: u16,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    #[serde(skip_serializing)]
    cursor: Option<OpaqueCursor>,
}

impl DescribeEventsRequest {
    pub(crate) fn from_scope(scope: &AwsHealthEventScope, secret: &SecretReference) -> Self {
        Self {
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            service_code: scope.service_code().clone(),
            event_arn: scope.event_arn().cloned(),
            event_type_codes: scope.event_type_codes().clone(),
            statuses: scope.statuses().clone(),
            time_window: scope.time_window().clone(),
            max_events: crate::MAX_EVENTS as u16,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_fence().digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            cursor: None,
        }
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: OpaqueCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<Digest> {
        self.cursor.as_ref().map(OpaqueCursor::digest)
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        digest_request(
            "DescribeEvents",
            &serde_json::to_string(self).expect("DescribeEvents request serializes"),
            self.cursor_digest(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeEventDetailsRequest {
    pub account_id: crate::AwsAccountId,
    pub region: crate::AwsRegion,
    pub service_code: crate::AwsServiceCode,
    pub event_arn: crate::AwsEventArn,
    pub time_window: AwsHealthTimeWindow,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
}

impl DescribeEventDetailsRequest {
    pub(crate) fn from_scope(
        scope: &AwsHealthEventScope,
        secret: &SecretReference,
    ) -> Result<Self, AwsHealthProviderError> {
        Ok(Self {
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            service_code: scope.service_code().clone(),
            event_arn: scope
                .event_arn()
                .cloned()
                .ok_or(AwsHealthProviderError::MissingEventArn)?,
            time_window: scope.time_window().clone(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_fence().digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
        })
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        digest_request(
            "DescribeEventDetails",
            &serde_json::to_string(self).expect("DescribeEventDetails request serializes"),
            None,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeAffectedEntitiesRequest {
    pub account_id: crate::AwsAccountId,
    pub region: crate::AwsRegion,
    pub service_code: crate::AwsServiceCode,
    pub event_arn: crate::AwsEventArn,
    pub time_window: AwsHealthTimeWindow,
    pub max_entities: u16,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    #[serde(skip_serializing)]
    cursor: Option<OpaqueCursor>,
}

impl DescribeAffectedEntitiesRequest {
    pub(crate) fn from_scope(
        scope: &AwsHealthEventScope,
        secret: &SecretReference,
    ) -> Result<Self, AwsHealthProviderError> {
        Ok(Self {
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            service_code: scope.service_code().clone(),
            event_arn: scope
                .event_arn()
                .cloned()
                .ok_or(AwsHealthProviderError::MissingEventArn)?,
            time_window: scope.time_window().clone(),
            max_entities: crate::MAX_AFFECTED_ENTITIES as u16,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_fence().digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            cursor: None,
        })
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: OpaqueCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<Digest> {
        self.cursor.as_ref().map(OpaqueCursor::digest)
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        digest_request(
            "DescribeAffectedEntities",
            &serde_json::to_string(self).expect("DescribeAffectedEntities request serializes"),
            self.cursor_digest(),
        )
    }
}

fn digest_request(operation: &str, serialized: &str, cursor_digest: Option<Digest>) -> Digest {
    Digest::from_fields(
        "aws-health-request/v1",
        &[
            operation.to_owned(),
            serialized.to_owned(),
            cursor_digest.map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeEventsResponse {
    pub events: Vec<AwsHealthEventRecord>,
    pub failed_events: Vec<crate::AwsHealthFailedEvent>,
    pub next_cursor_digest: Option<Digest>,
    pub truncated: bool,
    pub response_digest: Digest,
}

impl DescribeEventsResponse {
    pub fn new(
        events: Vec<AwsHealthEventRecord>,
        failed_events: Vec<crate::AwsHealthFailedEvent>,
        next_cursor: Option<OpaqueCursor>,
        truncated: bool,
    ) -> Result<Self, ModelError> {
        if events.len() > crate::MAX_EVENTS || failed_events.len() > crate::MAX_FAILED_SET {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for event in &events {
            event.validate()?;
        }
        let next_cursor_digest = next_cursor.map(|cursor| cursor.digest());
        let response_digest = response_digest(
            "DescribeEvents",
            &events,
            &failed_events,
            next_cursor_digest.as_ref(),
            truncated,
        );
        Ok(Self {
            events,
            failed_events,
            next_cursor_digest,
            truncated,
            response_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.events.len() > crate::MAX_EVENTS || self.failed_events.len() > crate::MAX_FAILED_SET
        {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for event in &self.events {
            event.validate()?;
        }
        if response_digest(
            "DescribeEvents",
            &self.events,
            &self.failed_events,
            self.next_cursor_digest.as_ref(),
            self.truncated,
        ) == self.response_digest
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeEventDetailsResponse {
    pub details: Vec<AwsHealthEventDetail>,
    pub failed_events: Vec<crate::AwsHealthFailedEvent>,
    pub response_digest: Digest,
}

impl DescribeEventDetailsResponse {
    pub fn new(
        details: Vec<AwsHealthEventDetail>,
        failed_events: Vec<crate::AwsHealthFailedEvent>,
    ) -> Result<Self, ModelError> {
        if details.len() > crate::MAX_EVENTS || failed_events.len() > crate::MAX_FAILED_SET {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for detail in &details {
            detail.validate()?;
        }
        let response_digest = response_digest(
            "DescribeEventDetails",
            &details,
            &failed_events,
            None,
            false,
        );
        Ok(Self {
            details,
            failed_events,
            response_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.details.len() > crate::MAX_EVENTS
            || self.failed_events.len() > crate::MAX_FAILED_SET
        {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for detail in &self.details {
            detail.validate()?;
        }
        if response_digest(
            "DescribeEventDetails",
            &self.details,
            &self.failed_events,
            None,
            false,
        ) == self.response_digest
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeAffectedEntitiesResponse {
    pub event_arn_digest: Digest,
    pub entities: Vec<AffectedEntityReference>,
    pub failed_events: Vec<crate::AwsHealthFailedEvent>,
    pub next_cursor_digest: Option<Digest>,
    pub truncated: bool,
    pub response_digest: Digest,
}

impl DescribeAffectedEntitiesResponse {
    pub fn new(
        event_arn: &crate::AwsEventArn,
        entities: Vec<AffectedEntityReference>,
        failed_events: Vec<crate::AwsHealthFailedEvent>,
        next_cursor: Option<OpaqueCursor>,
        truncated: bool,
    ) -> Result<Self, ModelError> {
        if entities.len() > crate::MAX_AFFECTED_ENTITIES
            || failed_events.len() > crate::MAX_FAILED_SET
        {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for entity in &entities {
            entity.validate()?;
        }
        let event_arn_digest = event_arn.digest();
        let next_cursor_digest = next_cursor.map(|cursor| cursor.digest());
        let response_digest = response_digest(
            "DescribeAffectedEntities",
            &entities,
            &failed_events,
            next_cursor_digest.as_ref(),
            truncated,
        );
        Ok(Self {
            event_arn_digest,
            entities,
            failed_events,
            next_cursor_digest,
            truncated,
            response_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.entities.len() > crate::MAX_AFFECTED_ENTITIES
            || self.failed_events.len() > crate::MAX_FAILED_SET
        {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for entity in &self.entities {
            entity.validate()?;
        }
        if response_digest(
            "DescribeAffectedEntities",
            &self.entities,
            &self.failed_events,
            self.next_cursor_digest.as_ref(),
            self.truncated,
        ) == self.response_digest
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

fn response_digest<T: Serialize>(
    operation: &str,
    values: &[T],
    failed_events: &[crate::AwsHealthFailedEvent],
    next_cursor_digest: Option<&Digest>,
    truncated: bool,
) -> Digest {
    Digest::from_fields(
        "aws-health-response/v1",
        &[
            operation.to_owned(),
            serde_json::to_string(values).expect("typed response values serialize"),
            serde_json::to_string(failed_events).expect("typed failed events serialize"),
            serde_json::to_string(&next_cursor_digest).expect("cursor digest serializes"),
            truncated.to_string(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransportCall {
    pub operation: AwsHealthOperation,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region: crate::AwsRegion,
    pub service_code: crate::AwsServiceCode,
}

impl TransportCall {
    fn events(request: &DescribeEventsRequest) -> Self {
        Self {
            operation: AwsHealthOperation::DescribeEvents,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            account_digest: request.account_id.digest(),
            region: request.region.clone(),
            service_code: request.service_code.clone(),
        }
    }

    fn details(request: &DescribeEventDetailsRequest) -> Self {
        Self {
            operation: AwsHealthOperation::DescribeEventDetails,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            account_digest: request.account_id.digest(),
            region: request.region.clone(),
            service_code: request.service_code.clone(),
        }
    }

    fn entities(request: &DescribeAffectedEntitiesRequest) -> Self {
        Self {
            operation: AwsHealthOperation::DescribeAffectedEntities,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            account_digest: request.account_id.digest(),
            region: request.region.clone(),
            service_code: request.service_code.clone(),
        }
    }
}

pub enum AwsHealthProviderRead {
    Events {
        request: DescribeEventsRequest,
        response: DescribeEventsResponse,
    },
    Details {
        request: DescribeEventDetailsRequest,
        response: DescribeEventDetailsResponse,
    },
    AffectedEntities {
        request: DescribeAffectedEntitiesRequest,
        response: DescribeAffectedEntitiesResponse,
    },
}

impl fmt::Debug for AwsHealthProviderRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsHealthProviderRead")
            .finish_non_exhaustive()
    }
}

pub trait AwsHealthTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsResponse, TransportError>;

    fn describe_event_details(
        &mut self,
        request: &DescribeEventDetailsRequest,
    ) -> Result<DescribeEventDetailsResponse, TransportError>;

    fn describe_affected_entities(
        &mut self,
        request: &DescribeAffectedEntitiesRequest,
    ) -> Result<DescribeAffectedEntitiesResponse, TransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureAwsHealthTransport {
    events: Result<DescribeEventsResponse, TransportError>,
    details: Result<DescribeEventDetailsResponse, TransportError>,
    entities: Result<DescribeAffectedEntitiesResponse, TransportError>,
}

impl FixtureAwsHealthTransport {
    #[must_use]
    pub fn new(events: DescribeEventsResponse) -> Self {
        Self {
            events: Ok(events),
            details: Err(TransportError::not_found()),
            entities: Err(TransportError::not_found()),
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: DescribeEventDetailsResponse) -> Self {
        self.details = Ok(details);
        self
    }

    #[must_use]
    pub fn with_affected_entities(mut self, entities: DescribeAffectedEntitiesResponse) -> Self {
        self.entities = Ok(entities);
        self
    }
}

impl AwsHealthTransport for FixtureAwsHealthTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn describe_events(
        &mut self,
        _request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsResponse, TransportError> {
        self.events.clone()
    }

    fn describe_event_details(
        &mut self,
        _request: &DescribeEventDetailsRequest,
    ) -> Result<DescribeEventDetailsResponse, TransportError> {
        self.details.clone()
    }

    fn describe_affected_entities(
        &mut self,
        _request: &DescribeAffectedEntitiesRequest,
    ) -> Result<DescribeAffectedEntitiesResponse, TransportError> {
        self.entities.clone()
    }
}

pub type FakeAwsHealthTransport = FixtureAwsHealthTransport;

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsHealthTransport {
    events: VecDeque<Result<DescribeEventsResponse, TransportError>>,
    details: VecDeque<Result<DescribeEventDetailsResponse, TransportError>>,
    entities: VecDeque<Result<DescribeAffectedEntitiesResponse, TransportError>>,
    calls: Vec<TransportCall>,
}

impl RecordingAwsHealthTransport {
    #[must_use]
    pub fn new(events: DescribeEventsResponse) -> Self {
        let mut transport = Self::default();
        transport.events.push_back(Ok(events));
        transport
    }

    pub fn push_events(&mut self, response: Result<DescribeEventsResponse, TransportError>) {
        self.events.push_back(response);
    }

    pub fn push_details(&mut self, response: Result<DescribeEventDetailsResponse, TransportError>) {
        self.details.push_back(response);
    }

    pub fn push_affected_entities(
        &mut self,
        response: Result<DescribeAffectedEntitiesResponse, TransportError>,
    ) {
        self.entities.push_back(response);
    }

    #[must_use]
    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn pop<T>(queue: &mut VecDeque<Result<T, TransportError>>) -> Result<T, TransportError> {
        queue.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                AwsHealthFailureKind::MalformedResponse,
                None,
                "fixture queue empty",
            ))
        })
    }
}

impl AwsHealthTransport for RecordingAwsHealthTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsResponse, TransportError> {
        self.calls.push(TransportCall::events(request));
        Self::pop(&mut self.events)
    }

    fn describe_event_details(
        &mut self,
        request: &DescribeEventDetailsRequest,
    ) -> Result<DescribeEventDetailsResponse, TransportError> {
        self.calls.push(TransportCall::details(request));
        Self::pop(&mut self.details)
    }

    fn describe_affected_entities(
        &mut self,
        request: &DescribeAffectedEntitiesRequest,
    ) -> Result<DescribeAffectedEntitiesResponse, TransportError> {
        self.calls.push(TransportCall::entities(request));
        Self::pop(&mut self.entities)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsHealthTransport {
    inner: FixtureAwsHealthTransport,
}

impl LoopbackAwsHealthTransport {
    #[must_use]
    pub fn new(events: DescribeEventsResponse) -> Self {
        Self {
            inner: FixtureAwsHealthTransport::new(events),
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: DescribeEventDetailsResponse) -> Self {
        self.inner = self.inner.with_details(details);
        self
    }

    #[must_use]
    pub fn with_affected_entities(mut self, entities: DescribeAffectedEntitiesResponse) -> Self {
        self.inner = self.inner.with_affected_entities(entities);
        self
    }
}

impl AwsHealthTransport for LoopbackAwsHealthTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsResponse, TransportError> {
        self.inner.describe_events(request)
    }

    fn describe_event_details(
        &mut self,
        request: &DescribeEventDetailsRequest,
    ) -> Result<DescribeEventDetailsResponse, TransportError> {
        self.inner.describe_event_details(request)
    }

    fn describe_affected_entities(
        &mut self,
        request: &DescribeAffectedEntitiesRequest,
    ) -> Result<DescribeAffectedEntitiesResponse, TransportError> {
        self.inner.describe_affected_entities(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsHealthTransport;

impl AwsHealthTransport for BlockedEnvAwsHealthTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn describe_events(
        &mut self,
        _request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_event_details(
        &mut self,
        _request: &DescribeEventDetailsRequest,
    ) -> Result<DescribeEventDetailsResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_affected_entities(
        &mut self,
        _request: &DescribeAffectedEntitiesRequest,
    ) -> Result<DescribeAffectedEntitiesResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type BlockedEnvTransport = BlockedEnvAwsHealthTransport;

pub struct AwsHealthProvider<T: AwsHealthTransport> {
    scope: AwsHealthEventScope,
    secret_reference: SecretReference,
    definition: AwsHealthProviderDefinition,
    registration: AwsHealthRegistration,
    transport: T,
}

impl<T: AwsHealthTransport> fmt::Debug for AwsHealthProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsHealthProvider")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("transport_provenance", &self.transport.provenance())
            .finish_non_exhaustive()
    }
}

impl<T: AwsHealthTransport> AwsHealthProvider<T> {
    pub fn new(
        scope: AwsHealthEventScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, AwsHealthProviderError> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.scope_digest() {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        let definition = AwsHealthProviderDefinition::new(
            AWS_HEALTH_EVENT_RESULT_PROVIDER_VERSION,
            transport.provenance(),
        )?;
        Self::with_definition(scope, secret_reference, definition, transport)
    }

    pub fn with_definition(
        scope: AwsHealthEventScope,
        secret_reference: SecretReference,
        definition: AwsHealthProviderDefinition,
        transport: T,
    ) -> Result<Self, AwsHealthProviderError> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.scope_digest()
            || definition.provenance != transport.provenance()
            || definition.native
            || definition.connected
            || definition.live_execution
        {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        let registration = AwsHealthRegistration::new(
            &scope,
            &definition.provider_version,
            &definition.api_revision,
            definition.provider_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AwsHealthEventScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &AwsHealthProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &AwsHealthRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn events_request(&self) -> DescribeEventsRequest {
        DescribeEventsRequest::from_scope(&self.scope, &self.secret_reference)
    }

    pub fn details_request(&self) -> Result<DescribeEventDetailsRequest, AwsHealthProviderError> {
        DescribeEventDetailsRequest::from_scope(&self.scope, &self.secret_reference)
    }

    pub fn affected_entities_request(
        &self,
    ) -> Result<DescribeAffectedEntitiesRequest, AwsHealthProviderError> {
        DescribeAffectedEntitiesRequest::from_scope(&self.scope, &self.secret_reference)
    }

    pub fn describe_events(
        &mut self,
        request: DescribeEventsRequest,
    ) -> Result<DescribeEventsResponse, AwsHealthProviderError> {
        self.prepare(AwsHealthOperation::DescribeEvents)?;
        self.validate_events_request(&request)?;
        let response = self.transport.describe_events(&request)?;
        response
            .validate()
            .map_err(|_| AwsHealthProviderError::InvalidResponse)?;
        self.validate_event_records(&response.events)?;
        Ok(response)
    }

    pub fn describe_event_details(
        &mut self,
        request: DescribeEventDetailsRequest,
    ) -> Result<DescribeEventDetailsResponse, AwsHealthProviderError> {
        self.prepare(AwsHealthOperation::DescribeEventDetails)?;
        self.validate_details_request(&request)?;
        let response = self.transport.describe_event_details(&request)?;
        response
            .validate()
            .map_err(|_| AwsHealthProviderError::InvalidResponse)?;
        for detail in &response.details {
            self.validate_event_record(detail.record())?;
        }
        Ok(response)
    }

    pub fn describe_affected_entities(
        &mut self,
        request: DescribeAffectedEntitiesRequest,
    ) -> Result<DescribeAffectedEntitiesResponse, AwsHealthProviderError> {
        self.prepare(AwsHealthOperation::DescribeAffectedEntities)?;
        self.validate_entities_request(&request)?;
        let response = self.transport.describe_affected_entities(&request)?;
        response
            .validate()
            .map_err(|_| AwsHealthProviderError::InvalidResponse)?;
        if response.event_arn_digest != request.event_arn.digest() {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        Ok(response)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, AwsHealthProviderError> {
        Ok(self.registration.revoke()?)
    }

    pub fn restore(&mut self) -> Result<(), AwsHealthProviderError> {
        Ok(self.registration.restore()?)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AwsHealthProviderError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    fn prepare(&self, operation: AwsHealthOperation) -> Result<(), AwsHealthProviderError> {
        self.registration
            .validate(&self.scope, &self.provider_digest())
            .map_err(|_| AwsHealthProviderError::RegistrationRevoked)?;
        if self.registration.state != RegistrationState::Active {
            return Err(AwsHealthProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsHealthProviderError::SecretRevoked);
        }
        if !self
            .scope
            .permission_fence()
            .contains(operation.required_permission())
        {
            return Err(AwsHealthProviderError::PermissionDenied);
        }
        Ok(())
    }

    fn validate_event_records(
        &self,
        events: &[AwsHealthEventRecord],
    ) -> Result<(), AwsHealthProviderError> {
        for event in events {
            self.validate_event_record(event)?;
        }
        Ok(())
    }

    fn validate_event_record(
        &self,
        event: &AwsHealthEventRecord,
    ) -> Result<(), AwsHealthProviderError> {
        if event.service_code() != self.scope.service_code()
            || event.region() != self.scope.region()
            || self
                .scope
                .event_arn()
                .is_some_and(|event_arn| event.event_arn() != event_arn)
            || self
                .scope
                .event_type_code()
                .is_some_and(|event_type| event.event_type_code() != event_type)
            || (!self.scope.statuses().is_empty()
                && !self.scope.statuses().contains(&event.status()))
            || event.started_at() < self.scope.time_window().start_time()
            || event.started_at() > self.scope.time_window().end_time()
            || event.last_updated_at() < self.scope.time_window().start_time()
            || event.last_updated_at() > self.scope.time_window().end_time()
        {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_events_request(
        &self,
        request: &DescribeEventsRequest,
    ) -> Result<(), AwsHealthProviderError> {
        if request.account_id != *self.scope.account_id()
            || request.region != *self.scope.region()
            || request.service_code != *self.scope.service_code()
            || request.event_arn != self.scope.event_arn().cloned()
            || request.event_type_codes != *self.scope.event_type_codes()
            || request.statuses != *self.scope.statuses()
            || request.time_window != *self.scope.time_window()
            || request.scope_digest != *self.scope.scope_digest()
            || request.permission_digest != *self.scope.permission_fence().digest()
            || request.secret_reference_digest != *self.secret_reference.reference_digest()
            || request.credential_revision != self.secret_reference.credential_revision()
            || request.max_events == 0
            || usize::from(request.max_events) > crate::MAX_EVENTS
        {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_details_request(
        &self,
        request: &DescribeEventDetailsRequest,
    ) -> Result<(), AwsHealthProviderError> {
        if request.account_id != *self.scope.account_id()
            || request.region != *self.scope.region()
            || request.service_code != *self.scope.service_code()
            || self.scope.event_arn() != Some(&request.event_arn)
            || request.time_window != *self.scope.time_window()
            || request.scope_digest != *self.scope.scope_digest()
            || request.permission_digest != *self.scope.permission_fence().digest()
            || request.secret_reference_digest != *self.secret_reference.reference_digest()
            || request.credential_revision != self.secret_reference.credential_revision()
        {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_entities_request(
        &self,
        request: &DescribeAffectedEntitiesRequest,
    ) -> Result<(), AwsHealthProviderError> {
        if !self.scope.includes_affected_entities() {
            return Err(AwsHealthProviderError::PermissionDenied);
        }
        if request.account_id != *self.scope.account_id()
            || request.region != *self.scope.region()
            || request.service_code != *self.scope.service_code()
            || self.scope.event_arn() != Some(&request.event_arn)
            || request.time_window != *self.scope.time_window()
            || request.scope_digest != *self.scope.scope_digest()
            || request.permission_digest != *self.scope.permission_fence().digest()
            || request.secret_reference_digest != *self.secret_reference.reference_digest()
            || request.credential_revision != self.secret_reference.credential_revision()
            || request.max_entities == 0
            || usize::from(request.max_entities) > crate::MAX_AFFECTED_ENTITIES
        {
            return Err(AwsHealthProviderError::ScopeMismatch);
        }
        Ok(())
    }
}

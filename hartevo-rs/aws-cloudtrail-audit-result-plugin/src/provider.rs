//! Bounded provider and LookupEvents read/record/verify seams.
//!
//! `AwsCloudTrailProvider` accepts only safe query metadata and returns only
//! redacted event projections.  There is no native HTTP client, credential
//! resolver, trail writer, event-store writer, SQL executor, or raw response
//! retention in this Layer-1 crate.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AuditProjection, AuditQuery, Digest, LookupAttribute, ModelError, RedactedEventMetadata,
    Revision,
};
use crate::{
    AWS_CLOUDTRAIL_API_VERSION, AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID,
    AWS_CLOUDTRAIL_AUDIT_PROVIDER_SCHEMA, AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION,
};

/// Opaque continuation token.  Its value is retained only inside the provider
/// transport seam and is never serialised or included in `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    value: String,
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > crate::model::MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidText {
                field: "opaque cursor",
            });
        }
        let digest = Digest::from_serializable(&("hartevo:aws-cloudtrail-cursor:v1", &value));
        Ok(Self { value, digest })
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// A safe provider failure.  Diagnostics are represented only by a digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    RetentionUnavailable,
    AccessDenied,
    CredentialRevoked,
    RateLimited,
    BlockedEnv,
    ProviderUnknown,
    InvalidResponse,
    ReplayDetected,
}

impl ProviderFailureClass {
    pub const fn projection(self) -> AuditProjection {
        match self {
            Self::RetentionUnavailable => AuditProjection::RetentionUnavailable,
            Self::AccessDenied | Self::CredentialRevoked => AuditProjection::AccessLost,
            Self::RateLimited => AuditProjection::Partial(crate::model::PartialReason::RateLimited),
            Self::BlockedEnv
            | Self::ProviderUnknown
            | Self::InvalidResponse
            | Self::ReplayDetected => AuditProjection::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsCloudTrailProviderError {
    #[error("CloudTrail provider request is invalid")]
    InvalidRequest,
    #[error("CloudTrail provider definition drifted")]
    DefinitionDrift,
    #[error("CloudTrail provider returned a page bound to a different request")]
    RequestMismatch,
    #[error("CloudTrail provider returned a page with invalid safe metadata")]
    InvalidResponse,
    #[error("CloudTrail provider replay was detected")]
    ReplayDetected,
    #[error("CloudTrail provider failure: {class:?}")]
    Failure {
        class: ProviderFailureClass,
        status_code: Option<u16>,
        diagnostic_digest: Digest,
    },
}

impl AwsCloudTrailProviderError {
    pub fn failure(class: ProviderFailureClass, status_code: Option<u16>) -> Self {
        Self::Failure {
            class,
            status_code,
            diagnostic_digest: Digest::from_text(format!(
                "hartevo:aws-cloudtrail-provider-failure:{class:?}:{status_code:?}"
            )),
        }
    }

    pub fn class(&self) -> ProviderFailureClass {
        match self {
            Self::InvalidRequest | Self::DefinitionDrift | Self::RequestMismatch => {
                ProviderFailureClass::InvalidResponse
            }
            Self::InvalidResponse => ProviderFailureClass::InvalidResponse,
            Self::ReplayDetected => ProviderFailureClass::ReplayDetected,
            Self::Failure { class, .. } => *class,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Failure { status_code, .. } => *status_code,
            _ => None,
        }
    }

    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Failure {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::InvalidRequest => Digest::from_text("aws-cloudtrail-invalid-request"),
            Self::DefinitionDrift => Digest::from_text("aws-cloudtrail-definition-drift"),
            Self::RequestMismatch => Digest::from_text("aws-cloudtrail-request-mismatch"),
            Self::InvalidResponse => Digest::from_text("aws-cloudtrail-invalid-response"),
            Self::ReplayDetected => Digest::from_text("aws-cloudtrail-replay-detected"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("provider revision is empty")]
    EmptyRevision,
    #[error("native CloudTrail providers are forbidden in Layer 1")]
    NativeProviderForbidden,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCloudTrailProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub lookup_events: bool,
    pub management_events_only: bool,
    pub live_execution: bool,
}

impl AwsCloudTrailProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let provider_revision = provider_revision.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provider_revision.is_empty() {
            return Err(ProviderDefinitionError::EmptyRevision);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_serializable(&(
            AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION,
            AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID,
            &provider_version,
            &provider_revision,
            provenance,
            AWS_CLOUDTRAIL_API_VERSION,
            "cloudtrail:LookupEvents",
            true,
            false,
        ));
        Ok(Self {
            schema_version: AWS_CLOUDTRAIL_AUDIT_PROVIDER_SCHEMA.to_owned(),
            provider_id: AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision,
            capability_digest,
            provenance,
            lookup_events: true,
            management_events_only: true,
            live_execution: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Bounded safe request.  `query` contains the exact audit scope.  The
/// provider does not accept arbitrary CloudTrail/Lake query text.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookupEventsRequest {
    pub api_version: String,
    pub query: AuditQuery,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub page_number: u16,
    pub max_results: u16,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    #[serde(skip)]
    cursor: Option<OpaqueCursor>,
}

impl fmt::Debug for LookupEventsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupEventsRequest")
            .field("api_version", &self.api_version)
            .field("query", &self.query)
            .field("provider_digest", &self.provider_digest)
            .field("provider_revision", &self.provider_revision)
            .field("page_number", &self.page_number)
            .field("max_results", &self.max_results)
            .field("cursor_digest", &self.cursor_digest)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl LookupEventsRequest {
    pub fn new(
        query: AuditQuery,
        provider_digest: Digest,
        provider_revision: impl Into<String>,
        page_number: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, AwsCloudTrailProviderError> {
        if page_number == 0
            || page_number > query.bounds.max_pages
            || query.bounds.page_size == 0
            || query.bounds.page_size
                > u16::try_from(crate::model::MAX_EVENTS_PER_PAGE).expect("page bound fits u16")
        {
            return Err(AwsCloudTrailProviderError::InvalidRequest);
        }
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty() {
            return Err(AwsCloudTrailProviderError::InvalidRequest);
        }
        let cursor_digest = cursor.as_ref().map(OpaqueCursor::digest);
        let mut request = Self {
            api_version: AWS_CLOUDTRAIL_API_VERSION.to_owned(),
            query,
            provider_digest,
            provider_revision,
            page_number,
            max_results: 0,
            cursor_digest,
            request_digest: Digest::from_text("placeholder"),
            cursor,
        };
        request.max_results = request.query.bounds.page_size;
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn canonical(&self) -> (&str, &AuditQuery, &Digest, &str, u16, u16, &Option<Digest>) {
        (
            &self.api_version,
            &self.query,
            &self.provider_digest,
            &self.provider_revision,
            self.page_number,
            self.max_results,
            &self.cursor_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self) -> bool {
        self.request_digest == self.compute_digest()
            && self.cursor_digest == self.cursor.as_ref().map(OpaqueCursor::digest)
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn lookup_attribute(&self) -> LookupAttribute {
        self.query.lookup_attribute
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupResponseStatus {
    Complete,
    Partial,
    Warning,
}

/// Safe page result.  It carries no response body, raw event, request
/// parameter, source IP, identity ARN, or raw continuation token serialization.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookupEventsPage {
    pub page_number: u16,
    pub request_digest: Digest,
    pub provider_revision: String,
    pub response_status: LookupResponseStatus,
    pub events: Vec<RedactedEventMetadata>,
    pub next_cursor_digest: Option<Digest>,
    pub response_digest: Digest,
    #[serde(skip)]
    next_cursor: Option<OpaqueCursor>,
}

impl fmt::Debug for LookupEventsPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupEventsPage")
            .field("page_number", &self.page_number)
            .field("request_digest", &self.request_digest)
            .field("provider_revision", &self.provider_revision)
            .field("response_status", &self.response_status)
            .field("event_count", &self.events.len())
            .field("next_cursor_digest", &self.next_cursor_digest)
            .field("response_digest", &self.response_digest)
            .finish_non_exhaustive()
    }
}

impl LookupEventsPage {
    pub fn new(
        request: &LookupEventsRequest,
        events: Vec<RedactedEventMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_status: LookupResponseStatus,
    ) -> Result<Self, AwsCloudTrailProviderError> {
        if events.len() > usize::from(request.max_results)
            || events.iter().any(|event| !event.verify_digest())
        {
            return Err(AwsCloudTrailProviderError::InvalidResponse);
        }
        let next_cursor_digest = next_cursor.as_ref().map(OpaqueCursor::digest);
        let mut page = Self {
            page_number: request.page_number,
            request_digest: request.request_digest.clone(),
            provider_revision: request.provider_revision.clone(),
            response_status,
            events,
            next_cursor_digest,
            response_digest: Digest::from_text("placeholder"),
            next_cursor,
        };
        page.response_digest = page.compute_digest();
        Ok(page)
    }

    fn canonical(
        &self,
    ) -> (
        u16,
        &Digest,
        &str,
        LookupResponseStatus,
        &Vec<RedactedEventMetadata>,
        &Option<Digest>,
    ) {
        (
            self.page_number,
            &self.request_digest,
            &self.provider_revision,
            self.response_status,
            &self.events,
            &self.next_cursor_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self, request: &LookupEventsRequest) -> bool {
        self.request_digest == request.request_digest
            && self.page_number == request.page_number
            && self.provider_revision == request.provider_revision
            && self.next_cursor_digest == self.next_cursor.as_ref().map(OpaqueCursor::digest)
            && self.events.iter().all(RedactedEventMetadata::verify_digest)
            && self.response_digest == self.compute_digest()
    }

    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        self.next_cursor.as_ref()
    }
}

/// Proposal metadata is safe to record; the request's cursor is kept only in
/// memory behind `OpaqueCursor` and is never serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct LookupEventsProposal {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub query: AuditQuery,
    pub request_digest: Digest,
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
    pub proposal_digest: Digest,
    request: LookupEventsRequest,
}

impl fmt::Debug for LookupEventsProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupEventsProposal")
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provider_revision", &self.provider_revision)
            .field("query", &self.query)
            .field("request_digest", &self.request_digest)
            .field("page_number", &self.page_number)
            .field("cursor_digest", &self.cursor_digest)
            .field("proposal_digest", &self.proposal_digest)
            .finish_non_exhaustive()
    }
}

impl LookupEventsProposal {
    pub fn new(
        registration_digest: Digest,
        registration_revision: Revision,
        request: LookupEventsRequest,
    ) -> Self {
        let mut proposal = Self {
            registration_digest,
            registration_revision,
            provider_digest: request.provider_digest.clone(),
            provider_revision: request.provider_revision.clone(),
            query: request.query.clone(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number,
            cursor_digest: request.cursor_digest.clone(),
            proposal_digest: Digest::from_text("placeholder"),
            request,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn canonical(
        &self,
    ) -> (
        &Digest,
        Revision,
        &Digest,
        &str,
        &AuditQuery,
        &Digest,
        u16,
        &Option<Digest>,
    ) {
        (
            &self.registration_digest,
            self.registration_revision,
            &self.provider_digest,
            &self.provider_revision,
            &self.query,
            &self.request_digest,
            self.page_number,
            &self.cursor_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self) -> bool {
        self.proposal_digest == self.compute_digest()
            && self.request.verify_digest()
            && self.request_digest == self.request.request_digest
            && self.cursor_digest == self.request.cursor_digest
    }

    pub fn request(&self) -> &LookupEventsRequest {
        &self.request
    }
}

/// Safe record emitted after a proposal has been fulfilled and its page has
/// passed request/response verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookupEventsRecord {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub page_number: u16,
    pub response_status: LookupResponseStatus,
    pub events: Vec<RedactedEventMetadata>,
    pub next_cursor_digest: Option<Digest>,
    pub record_digest: Digest,
}

impl LookupEventsRecord {
    pub fn from_parts(
        proposal: &LookupEventsProposal,
        page: &LookupEventsPage,
    ) -> Result<Self, AwsCloudTrailProviderError> {
        if !proposal.verify_digest()
            || !page.verify_digest(proposal.request())
            || page.request_digest != proposal.request_digest
        {
            return Err(AwsCloudTrailProviderError::RequestMismatch);
        }
        let mut record = Self {
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            provider_digest: proposal.provider_digest.clone(),
            provider_revision: proposal.provider_revision.clone(),
            query_digest: proposal.query.query_digest.clone(),
            scope_digest: proposal.query.scope_digest.clone(),
            permission_digest: proposal.query.permission_digest.clone(),
            secret_reference_digest: proposal.query.secret_reference_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            response_digest: page.response_digest.clone(),
            page_number: page.page_number,
            response_status: page.response_status,
            events: page.events.clone(),
            next_cursor_digest: page.next_cursor_digest.clone(),
            record_digest: Digest::from_text("placeholder"),
        };
        record.record_digest = record.compute_digest();
        Ok(record)
    }

    fn canonical(
        &self,
    ) -> (
        &Digest,
        Revision,
        &Digest,
        &str,
        &Digest,
        &Digest,
        &Digest,
        &Digest,
        &Digest,
        &Digest,
        u16,
        LookupResponseStatus,
        &Vec<RedactedEventMetadata>,
        &Option<Digest>,
    ) {
        (
            &self.registration_digest,
            self.registration_revision,
            &self.provider_digest,
            &self.provider_revision,
            &self.query_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
            &self.request_digest,
            &self.response_digest,
            self.page_number,
            self.response_status,
            &self.events,
            &self.next_cursor_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_integrity(&self) -> bool {
        self.events.iter().all(RedactedEventMetadata::verify_digest)
            && self.record_digest == self.compute_digest()
    }
}

pub trait AwsCloudTrailLookupTransport: fmt::Debug {
    fn lookup_events(
        &mut self,
        request: &LookupEventsRequest,
    ) -> Result<LookupEventsPage, AwsCloudTrailProviderError>;

    fn provenance(&self) -> ProviderProvenance;
}

/// Typed provider wrapper.  The generic transport is intentionally a seam for
/// fixtures and a later host integration; this type never becomes Connected or
/// a native AWS authority in Layer 1.
pub struct AwsCloudTrailProvider<T>
where
    T: AwsCloudTrailLookupTransport,
{
    transport: T,
    definition: AwsCloudTrailProviderDefinition,
    seen_request_digests: BTreeSet<Digest>,
}

impl<T> fmt::Debug for AwsCloudTrailProvider<T>
where
    T: AwsCloudTrailLookupTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudTrailProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .field("seen_request_count", &self.seen_request_digests.len())
            .finish_non_exhaustive()
    }
}

impl<T> AwsCloudTrailProvider<T>
where
    T: AwsCloudTrailLookupTransport,
{
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        Ok(Self {
            transport,
            definition: AwsCloudTrailProviderDefinition::new(
                provider_version,
                provider_revision,
                provenance,
            )?,
            seen_request_digests: BTreeSet::new(),
        })
    }

    pub fn definition(&self) -> &AwsCloudTrailProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn read(
        &mut self,
        request: &LookupEventsRequest,
    ) -> Result<LookupEventsPage, AwsCloudTrailProviderError> {
        if !request.verify_digest()
            || request.provider_digest != self.definition.provider_digest()
            || request.provider_revision != self.definition.provider_revision
            || request.api_version != AWS_CLOUDTRAIL_API_VERSION
        {
            return Err(AwsCloudTrailProviderError::DefinitionDrift);
        }
        if !self
            .seen_request_digests
            .insert(request.request_digest.clone())
        {
            return Err(AwsCloudTrailProviderError::ReplayDetected);
        }
        let page = self.transport.lookup_events(request)?;
        if !page.verify_digest(request) {
            return Err(AwsCloudTrailProviderError::InvalidResponse);
        }
        Ok(page)
    }

    pub fn record(
        &self,
        proposal: &LookupEventsProposal,
        page: &LookupEventsPage,
    ) -> Result<LookupEventsRecord, AwsCloudTrailProviderError> {
        LookupEventsRecord::from_parts(proposal, page)
    }

    pub fn verify(
        &self,
        proposal: &LookupEventsProposal,
        record: &LookupEventsRecord,
    ) -> Result<(), AwsCloudTrailProviderError> {
        if !proposal.verify_digest()
            || !record.verify_integrity()
            || record.registration_digest != proposal.registration_digest
            || record.registration_revision != proposal.registration_revision
            || record.provider_digest != self.definition.provider_digest()
            || record.provider_revision != self.definition.provider_revision
            || record.request_digest != proposal.request_digest
            || record.query_digest != proposal.query.query_digest
        {
            return Err(AwsCloudTrailProviderError::RequestMismatch);
        }
        Ok(())
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// A deterministic safe fixture transport.  It retains only redacted event
/// metadata and safe request metadata, never raw provider payloads.
#[derive(Clone, Debug)]
pub struct FakeAwsCloudTrailTransport {
    events: Vec<RedactedEventMetadata>,
    requests: Vec<LookupEventsRequest>,
    next_failure: Option<AwsCloudTrailProviderError>,
}

impl FakeAwsCloudTrailTransport {
    pub fn new(events: impl IntoIterator<Item = RedactedEventMetadata>) -> Self {
        Self {
            events: events.into_iter().collect(),
            requests: Vec::new(),
            next_failure: None,
        }
    }

    pub fn push_failure(&mut self, error: AwsCloudTrailProviderError) {
        self.next_failure = Some(error);
    }

    pub fn requests(&self) -> &[LookupEventsRequest] {
        &self.requests
    }

    pub fn events(&self) -> &[RedactedEventMetadata] {
        &self.events
    }
}

impl AwsCloudTrailLookupTransport for FakeAwsCloudTrailTransport {
    fn lookup_events(
        &mut self,
        request: &LookupEventsRequest,
    ) -> Result<LookupEventsPage, AwsCloudTrailProviderError> {
        self.requests.push(request.clone());
        if let Some(error) = self.next_failure.take() {
            return Err(error);
        }
        let expected_cursor = if request.page_number == 1 {
            None
        } else {
            Some(
                fake_cursor_for_page(request.page_number)
                    .map_err(|_| AwsCloudTrailProviderError::InvalidRequest)?,
            )
        };
        if request.cursor_digest != expected_cursor.as_ref().map(OpaqueCursor::digest) {
            return Err(AwsCloudTrailProviderError::RequestMismatch);
        }
        let mut matches: Vec<_> = self
            .events
            .iter()
            .filter(|event| {
                event.event_source == request.query.event_source
                    && event.event_name == request.query.event_name
                    && event.resource_type == request.query.resource_type
                    && event.resource_digest == request.query.resource_digest
                    && request.query.time_window.contains(event.event_time)
            })
            .cloned()
            .collect();
        let page_size = usize::from(request.max_results);
        let page_start = usize::from(request.page_number.saturating_sub(1)) * page_size;
        if page_start > matches.len() {
            matches.clear();
        } else {
            matches = matches
                .into_iter()
                .skip(page_start)
                .take(page_size)
                .collect();
        }
        let total_matches = self
            .events
            .iter()
            .filter(|event| {
                event.event_source == request.query.event_source
                    && event.event_name == request.query.event_name
                    && event.resource_type == request.query.resource_type
                    && event.resource_digest == request.query.resource_digest
                    && request.query.time_window.contains(event.event_time)
            })
            .count();
        let has_more = page_start.saturating_add(matches.len()) < total_matches;
        let next_cursor = has_more
            .then(|| OpaqueCursor::new(format!("fake-page:{}", request.page_number + 1)))
            .transpose()
            .map_err(|_| AwsCloudTrailProviderError::InvalidResponse)?;
        LookupEventsPage::new(
            request,
            matches,
            next_cursor,
            LookupResponseStatus::Complete,
        )
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }
}

pub type LoopbackAwsCloudTrailTransport = FakeAwsCloudTrailTransport;

#[derive(Clone, Debug)]
pub struct RecordingAwsCloudTrailTransport {
    responses: VecDeque<Result<LookupEventsPage, AwsCloudTrailProviderError>>,
    requests: Vec<LookupEventsRequest>,
    provenance: ProviderProvenance,
}

impl RecordingAwsCloudTrailTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<LookupEventsPage, AwsCloudTrailProviderError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(
        &mut self,
        response: Result<LookupEventsPage, AwsCloudTrailProviderError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[LookupEventsRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl AwsCloudTrailLookupTransport for RecordingAwsCloudTrailTransport {
    fn lookup_events(
        &mut self,
        request: &LookupEventsRequest,
    ) -> Result<LookupEventsPage, AwsCloudTrailProviderError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(AwsCloudTrailProviderError::failure(
                ProviderFailureClass::ProviderUnknown,
                None,
            ))
        })
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsCloudTrailTransport;

impl AwsCloudTrailLookupTransport for BlockedEnvAwsCloudTrailTransport {
    fn lookup_events(
        &mut self,
        _request: &LookupEventsRequest,
    ) -> Result<LookupEventsPage, AwsCloudTrailProviderError> {
        Err(AwsCloudTrailProviderError::failure(
            ProviderFailureClass::BlockedEnv,
            None,
        ))
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

pub type FakeAwsCloudTrailProvider = AwsCloudTrailProvider<FakeAwsCloudTrailTransport>;

/// Helper for tests and host adapters that need a deterministic page cursor
/// without ever exposing its token value.
pub fn fake_cursor_for_page(page: u16) -> Result<OpaqueCursor, ModelError> {
    OpaqueCursor::new(format!("fake-page:{page}"))
}

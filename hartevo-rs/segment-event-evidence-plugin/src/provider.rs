use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    SEGMENT_EVENT_EVIDENCE_PROVIDER_ID, SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION,
    model::{
        DeliveryEvidence, DestinationEvidence, Digest, EventSchemaEvidence, EvidenceBounds,
        EvidenceWindow, FreshnessState, ModelError, PluginVersion, RetentionState, Revision,
        SegmentScope, SourceEvidence, TrackingPlanEvidence, ViolationEvidence,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    OfficialReadOnlyApi,
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        matches!(
            self,
            Self::Fixture | Self::Recording | Self::Loopback | Self::BlockedEnv
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("the provider API revision is empty or malformed")]
    InvalidApiRevision,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
}

impl SegmentProviderDefinition {
    pub fn new(
        provider_version: PluginVersion,
        api_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let api_revision = api_revision.into();
        if api_revision.is_empty()
            || api_revision.len() > 128
            || api_revision.chars().any(char::is_control)
        {
            return Err(ProviderDefinitionError::InvalidApiRevision);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_fields(
            "segment-provider-capability/v1",
            [
                SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION.to_owned(),
                SEGMENT_EVENT_EVIDENCE_PROVIDER_ID.to_owned(),
                provider_version.to_string(),
                api_revision.clone(),
                format!("{provenance:?}"),
                "tracking_plan.read".to_owned(),
                "event_schema.read".to_owned(),
                "violations.read".to_owned(),
                "source.read".to_owned(),
                "destination.read".to_owned(),
                "delivery.read".to_owned(),
                "writes=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION.to_owned(),
            provider_id: SEGMENT_EVENT_EVIDENCE_PROVIDER_ID.to_owned(),
            provider_version,
            api_revision,
            capability_digest,
            provenance,
            read_only: true,
            live_execution: false,
            native: false,
        })
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "segment-provider-definition/v1",
            [
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_version.to_string(),
                self.api_revision.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.read_only.to_string(),
                self.live_execution.to_string(),
                self.native.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("Segment returned HTTP 401")]
    Unauthorized401,
    #[error("Segment returned HTTP 403")]
    Forbidden403,
    #[error("Segment returned HTTP 404")]
    NotFound404,
    #[error("Segment returned HTTP 409")]
    Conflict409,
    #[error("Segment returned HTTP 429")]
    RateLimited429,
    #[error("Segment returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("the Segment read timed out")]
    Timeout,
    #[error("BLOCKED_ENV: native Segment credentials or host wiring are unavailable")]
    BlockedEnv,
    #[error("the official Segment API transport is a Layer-2 native gap")]
    NativeUnavailable,
    #[error("the provider returned an invalid bounded response")]
    InvalidResponse,
}

impl TransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized401 => Some(401),
            Self::Forbidden403 => Some(403),
            Self::NotFound404 => Some(404),
            Self::Conflict409 => Some(409),
            Self::RateLimited429 => Some(429),
            Self::Server5xx { status } => Some(*status),
            Self::Timeout | Self::BlockedEnv | Self::NativeUnavailable | Self::InvalidResponse => {
                None
            }
        }
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> Digest {
        Digest::from_text(self.to_string())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentReadOperation {
    Describe,
    TrackingPlan,
    EventSchema,
    Violations,
    Sources,
    Destinations,
    Delivery,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentReadRequest {
    pub operation: SegmentReadOperation,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub plan_revision: Revision,
    pub window: EvidenceWindow,
    pub page_number: u16,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub request_digest: Digest,
}

impl SegmentReadRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &SegmentScope,
        operation: SegmentReadOperation,
        window: EvidenceWindow,
        bounds: &EvidenceBounds,
        provider_digest: Digest,
        contract_digest: Digest,
        secret_reference_digest: Digest,
        credential_revision: Revision,
        page_number: u16,
        page_size: u16,
        cursor_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if page_number == 0
            || page_number > bounds.max_pages()
            || page_size == 0
            || page_size > bounds.max_page_size()
            || cursor_digest
                .as_ref()
                .is_some_and(|digest| digest.as_str().len() > bounds.max_cursor_bytes())
        {
            return Err(ModelError::InvalidBounds);
        }
        let request_digest = Digest::from_fields(
            "segment-read-request/v1",
            [
                format!("{operation:?}"),
                scope.scope_digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                scope.plan_revision().get().to_string(),
                window.start_unix_seconds().to_string(),
                window.end_unix_seconds().to_string(),
                page_number.to_string(),
                page_size.to_string(),
                cursor_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                secret_reference_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            operation,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            provider_digest,
            contract_digest,
            plan_revision: scope.plan_revision(),
            window,
            page_number,
            page_size,
            cursor_digest,
            secret_reference_digest,
            credential_revision,
            request_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageStatus {
    Complete,
    Partial,
    ProviderUnknown,
}

pub type SegmentPageStatus = PageStatus;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum SegmentRecord {
    TrackingPlan(TrackingPlanEvidence),
    EventSchema(EventSchemaEvidence),
    Violation(ViolationEvidence),
    Source(SourceEvidence),
    Destination(DestinationEvidence),
    Delivery(DeliveryEvidence),
    Empty,
}

impl SegmentRecord {
    #[must_use]
    pub fn digest(&self) -> Digest {
        match self {
            Self::TrackingPlan(value) => value.plan_digest.clone(),
            Self::EventSchema(value) => value.digest(),
            Self::Violation(value) => value.digest(),
            Self::Source(value) => value.digest(),
            Self::Destination(value) => value.digest(),
            Self::Delivery(value) => value.delivery_digest.clone(),
            Self::Empty => Digest::from_text("segment-empty-record/v1"),
        }
    }

    #[must_use]
    pub(crate) const fn is_allowed_for(
        self_operation: SegmentReadOperation,
        record: &Self,
    ) -> bool {
        matches!(
            (self_operation, record),
            (SegmentReadOperation::Describe, _)
                | (SegmentReadOperation::TrackingPlan, Self::TrackingPlan(_))
                | (SegmentReadOperation::EventSchema, Self::EventSchema(_))
                | (SegmentReadOperation::Violations, Self::Violation(_))
                | (SegmentReadOperation::Sources, Self::Source(_))
                | (SegmentReadOperation::Destinations, Self::Destination(_))
                | (SegmentReadOperation::Delivery, Self::Delivery(_))
                | (_, Self::Empty)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentReadPage {
    pub operation: SegmentReadOperation,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub plan_revision: Revision,
    pub window: EvidenceWindow,
    pub page_number: u16,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub next_cursor_digest: Option<Digest>,
    pub records: Vec<SegmentRecord>,
    pub freshness: FreshnessState,
    pub retention: RetentionState,
    pub status: PageStatus,
    pub request_digest: Digest,
    pub response_digest: Digest,
}

impl SegmentReadPage {
    pub fn new(
        request: &SegmentReadRequest,
        records: Vec<SegmentRecord>,
        next_cursor_digest: Option<Digest>,
        freshness: FreshnessState,
        retention: RetentionState,
        status: PageStatus,
    ) -> Result<Self, ModelError> {
        if records.len() > usize::from(request.page_size)
            || records
                .iter()
                .any(|record| !SegmentRecord::is_allowed_for(request.operation, record))
        {
            return Err(ModelError::BoundExceeded);
        }
        let response_digest = compute_page_digest(
            request.operation,
            &request.scope_digest,
            &request.permission_digest,
            &request.provider_digest,
            &request.contract_digest,
            request.plan_revision,
            request.window,
            request.page_number,
            request.page_size,
            request.cursor_digest.as_ref(),
            next_cursor_digest.as_ref(),
            &records,
            freshness,
            retention,
            status,
            &request.request_digest,
        );
        Ok(Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            provider_digest: request.provider_digest.clone(),
            contract_digest: request.contract_digest.clone(),
            plan_revision: request.plan_revision,
            window: request.window,
            page_number: request.page_number,
            page_size: request.page_size,
            cursor_digest: request.cursor_digest.clone(),
            next_cursor_digest,
            records,
            freshness,
            retention,
            status,
            request_digest: request.request_digest.clone(),
            response_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = compute_page_digest(
            self.operation,
            &self.scope_digest,
            &self.permission_digest,
            &self.provider_digest,
            &self.contract_digest,
            self.plan_revision,
            self.window,
            self.page_number,
            self.page_size,
            self.cursor_digest.as_ref(),
            self.next_cursor_digest.as_ref(),
            &self.records,
            self.freshness,
            self.retention,
            self.status,
            &self.request_digest,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    #[must_use]
    pub fn page_digest(&self) -> &Digest {
        &self.response_digest
    }
}

fn compute_page_digest(
    operation: SegmentReadOperation,
    scope_digest: &Digest,
    permission_digest: &Digest,
    provider_digest: &Digest,
    contract_digest: &Digest,
    plan_revision: Revision,
    window: EvidenceWindow,
    page_number: u16,
    page_size: u16,
    cursor_digest: Option<&Digest>,
    next_cursor_digest: Option<&Digest>,
    records: &[SegmentRecord],
    freshness: FreshnessState,
    retention: RetentionState,
    status: PageStatus,
    request_digest: &Digest,
) -> Digest {
    Digest::from_fields(
        "segment-read-page/v1",
        [
            format!("{operation:?}"),
            scope_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
            contract_digest.as_str().to_owned(),
            plan_revision.get().to_string(),
            window.start_unix_seconds().to_string(),
            window.end_unix_seconds().to_string(),
            page_number.to_string(),
            page_size.to_string(),
            cursor_digest.map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            next_cursor_digest.map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            records
                .iter()
                .map(|record| record.digest().as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            format!("{freshness:?}"),
            format!("{retention:?}"),
            format!("{status:?}"),
            request_digest.as_str().to_owned(),
        ],
    )
}

pub trait SegmentReadTransport: fmt::Debug {
    fn read_page(
        &mut self,
        request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError>;
}

#[derive(Debug)]
pub struct SegmentProvider<T = RecordingSegmentTransport> {
    transport: T,
    definition: SegmentProviderDefinition,
}

impl<T: SegmentReadTransport> SegmentProvider<T> {
    pub fn new(
        transport: T,
        provider_version: PluginVersion,
        api_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: SegmentProviderDefinition::new(provider_version, api_revision, provenance)?,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &SegmentProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read_page(
        &mut self,
        request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError> {
        self.transport.read_page(request)
    }
}

impl SegmentProvider<RecordingSegmentTransport> {
    pub fn recording(
        pages: impl IntoIterator<Item = Result<SegmentReadPage, TransportError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            RecordingSegmentTransport::from_pages(pages),
            PluginVersion::V1,
            "protocols-public-api/v1",
            ProviderProvenance::Recording,
        )
    }

    pub fn fixture(
        pages: impl IntoIterator<Item = Result<SegmentReadPage, TransportError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            RecordingSegmentTransport::from_pages(pages),
            PluginVersion::V1,
            "protocols-fixture/v1",
            ProviderProvenance::Fixture,
        )
    }

    pub fn loopback(
        pages: impl IntoIterator<Item = Result<SegmentReadPage, TransportError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            RecordingSegmentTransport::from_pages(pages),
            PluginVersion::V1,
            "protocols-loopback/v1",
            ProviderProvenance::Loopback,
        )
    }
}

impl SegmentProvider<BlockedEnvSegmentTransport> {
    pub fn blocked_env() -> Result<Self, ProviderDefinitionError> {
        Self::new(
            BlockedEnvSegmentTransport,
            PluginVersion::V1,
            "protocols-public-api/v1",
            ProviderProvenance::BlockedEnv,
        )
    }
}

impl SegmentProvider<OfficialSegmentApiTransport> {
    pub fn official_api() -> Result<Self, ProviderDefinitionError> {
        Self::new(
            OfficialSegmentApiTransport,
            PluginVersion::V1,
            "protocols-public-api/v1",
            ProviderProvenance::OfficialReadOnlyApi,
        )
    }
}

#[derive(Debug, Default)]
pub struct RecordingSegmentTransport {
    responses: VecDeque<Result<SegmentReadPage, TransportError>>,
    calls: usize,
}

impl RecordingSegmentTransport {
    #[must_use]
    pub fn from_pages(
        pages: impl IntoIterator<Item = Result<SegmentReadPage, TransportError>>,
    ) -> Self {
        Self {
            responses: pages.into_iter().collect(),
            calls: 0,
        }
    }

    pub fn push_page_response(&mut self, response: Result<SegmentReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub const fn calls(&self) -> usize {
        self.calls
    }
}

impl SegmentReadTransport for RecordingSegmentTransport {
    fn read_page(
        &mut self,
        _request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError> {
        self.calls = self.calls.saturating_add(1);
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::BlockedEnv))
    }
}

pub type FixtureSegmentTransport = RecordingSegmentTransport;
pub type LoopbackSegmentTransport = RecordingSegmentTransport;

#[derive(Debug, Default)]
pub struct BlockedEnvSegmentTransport;

impl SegmentReadTransport for BlockedEnvSegmentTransport {
    fn read_page(
        &mut self,
        _request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

/// The official Protocols/public API seam is deliberately a native Layer-2
/// exit in this crate. It defines no network client and never handles a token.
#[derive(Debug, Default)]
pub struct OfficialSegmentApiTransport;

impl SegmentReadTransport for OfficialSegmentApiTransport {
    fn read_page(
        &mut self,
        _request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError> {
        Err(TransportError::NativeUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DestinationId, EventSpecId, FreshnessState, MissionId, PermissionSnapshot, ProjectId,
        SourceId, TrackingPlanId, WorkProductId, WorkspaceId,
    };

    fn scope() -> SegmentScope {
        SegmentScope::new(
            WorkspaceId::new("workspace").unwrap(),
            SourceId::new("source").unwrap(),
            TrackingPlanId::new("plan").unwrap(),
            Revision::new(1).unwrap(),
            EventSpecId::new("event").unwrap(),
            DestinationId::new("destination").unwrap(),
            ProjectId::new("project").unwrap(),
            Revision::new(1).unwrap(),
            MissionId::new("mission").unwrap(),
            Revision::new(1).unwrap(),
            WorkProductId::new("work-product").unwrap(),
            Revision::new(1).unwrap(),
            PermissionSnapshot::read_only().digest().clone(),
        )
        .unwrap()
    }

    #[test]
    fn page_digest_detects_tamper_and_transport_is_bounded() {
        let scope = scope();
        let bounds = EvidenceBounds::default();
        let request = SegmentReadRequest::new(
            &scope,
            SegmentReadOperation::Describe,
            EvidenceWindow::new(1, 2).unwrap(),
            &bounds,
            Digest::from_text("provider"),
            Digest::from_text("contract"),
            Digest::from_text("secret"),
            Revision::new(1).unwrap(),
            1,
            1,
            None,
        )
        .unwrap();
        let mut page = SegmentReadPage::new(
            &request,
            vec![],
            None,
            FreshnessState::Fresh,
            RetentionState::Complete,
            PageStatus::Complete,
        )
        .unwrap();
        assert!(page.validate_digest().is_ok());
        page.page_size = 2;
        assert!(page.validate_digest().is_err());
    }
}

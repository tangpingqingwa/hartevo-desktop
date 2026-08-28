use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION, SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION,
    SEGMENT_EVENT_EVIDENCE_SERVICE_ID,
    model::{
        DeliveryEvidence, DeliveryHealth, DestinationEvidence, Digest, EventSchemaEvidence,
        EvidenceBounds, EvidenceStatus, EvidenceWindow, FreshnessState, MAX_DESTINATIONS,
        MAX_SOURCES, ModelError, RegistrationState, RetentionState, Revision, SegmentRegistration,
        SegmentScope, SourceEvidence, TrackingPlanEvidence, ViolationEvidence,
    },
    provider::{
        PageStatus, ProviderProvenance, SegmentProvider, SegmentProviderDefinition,
        SegmentReadOperation, SegmentReadPage, SegmentReadRequest, SegmentReadTransport,
        SegmentRecord, TransportError,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentEventEvidenceServiceDefinition {
    pub schema_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub version: Revision,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
}

impl SegmentEventEvidenceServiceDefinition {
    #[must_use]
    pub fn current() -> Self {
        Self {
            schema_version: SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION.to_owned(),
            service_id: SEGMENT_EVENT_EVIDENCE_SERVICE_ID.to_owned(),
            provider_id: crate::SEGMENT_EVENT_EVIDENCE_PROVIDER_ID.to_owned(),
            consumer_id: crate::SEGMENT_EVENT_EVIDENCE_CONSUMER_ID.to_owned(),
            version: Revision::new(1).expect("service version is non-zero"),
            contract_version: SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::segment_event_evidence_contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
        }
    }
}

impl Default for SegmentEventEvidenceServiceDefinition {
    fn default() -> Self {
        Self::current()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("the Segment service registration is inactive")]
    RegistrationInactive,
    #[error("the Segment secret reference is revoked")]
    SecretRevoked,
    #[error("the secret reference is bound to another scope")]
    SecretScopeMismatch,
    #[error("the provider definition is not a read-only Layer-1 definition")]
    InvalidProviderDefinition,
    #[error("the provider definition drifted from the registration")]
    ProviderDrift,
    #[error("the contract digest drifted from the registration")]
    ContractDrift,
    #[error("the response scope digest drifted")]
    ScopeDrift,
    #[error("the response permission digest drifted")]
    PermissionDrift,
    #[error("the tracking-plan revision drifted")]
    PlanDrift,
    #[error("the response operation or window drifted")]
    WindowOrOperationDrift,
    #[error("the provider page number or page size was invalid")]
    PageBounds,
    #[error("the provider repeated an opaque cursor")]
    CursorLoop,
    #[error("the provider exceeded the bounded page count")]
    PageLimit,
    #[error("the provider reported a retention gap")]
    RetentionGap,
    #[error("the provider page was tampered or had an invalid digest")]
    TamperedEvidence,
    #[error("the provider returned an invalid bounded response")]
    InvalidResponse,
    #[error("the evidence proposal is not bound to this service registration")]
    ProposalBindingMismatch,
    #[error("the evidence proposal digest is invalid")]
    ProposalDigestMismatch,
    #[error("the evidence status is not recordable: {0:?}")]
    NotRecordable(EvidenceStatus),
    #[error("the evidence status is not verifiable: {0:?}")]
    NotVerifiable(EvidenceStatus),
    #[error("the provider transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentReadEvidence {
    pub operation: SegmentReadOperation,
    pub window: EvidenceWindow,
    pub records: Vec<SegmentRecord>,
    pub pages_observed: u16,
    pub cursor_digests: Vec<Digest>,
    pub high_water_cursor_digest: Option<Digest>,
    pub freshness: FreshnessState,
    pub retention: RetentionState,
    pub status: EvidenceStatus,
    pub response_digest: Digest,
    pub request_receipt_digest: Digest,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentEvidenceDigests {
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub plan_digest: Digest,
    pub violation_digest: Digest,
    pub delivery_digest: Digest,
    pub response_digest: Digest,
    pub request_receipt_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentEventEvidence {
    pub status: EvidenceStatus,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub provider_version: crate::PluginVersion,
    pub window: EvidenceWindow,
    pub plan: Option<TrackingPlanEvidence>,
    pub event_schemas: Vec<EventSchemaEvidence>,
    pub violations: Vec<ViolationEvidence>,
    pub sources: Vec<SourceEvidence>,
    pub destinations: Vec<DestinationEvidence>,
    pub deliveries: Vec<DeliveryEvidence>,
    pub pages_observed: u16,
    pub cursor_digests: Vec<Digest>,
    pub high_water_cursor_digest: Option<Digest>,
    pub request_receipt_digest: Digest,
    pub freshness: FreshnessState,
    pub retention: RetentionState,
    pub provenance: ProviderProvenance,
    pub digests: SegmentEvidenceDigests,
}

impl SegmentEventEvidence {
    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    #[must_use]
    pub const fn is_adoptable_candidate(&self) -> bool {
        matches!(
            self.status,
            EvidenceStatus::Conforming
                | EvidenceStatus::Violation
                | EvidenceStatus::DeliveryDegraded
        )
    }

    #[must_use]
    pub fn recompute_evidence_digest(&self) -> Digest {
        let plan_digest = self.plan.as_ref().map_or_else(
            || Digest::from_text("segment-plan-absent"),
            |value| value.plan_digest.clone(),
        );
        let violation_digest = Digest::from_fields(
            "segment-violations/v1",
            self.violations
                .iter()
                .map(|value| value.digest().as_str().to_owned()),
        );
        let delivery_digest = Digest::from_fields(
            "segment-deliveries/v1",
            self.deliveries
                .iter()
                .map(|value| value.delivery_digest.as_str().to_owned()),
        );
        let mut fields = vec![
            format!("{:?}", self.status),
            self.scope_digest.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            self.contract_digest.as_str().to_owned(),
            self.provider_version.to_string(),
            self.window.start_unix_seconds().to_string(),
            self.window.end_unix_seconds().to_string(),
            plan_digest.as_str().to_owned(),
            violation_digest.as_str().to_owned(),
            delivery_digest.as_str().to_owned(),
            self.digests.response_digest.as_str().to_owned(),
            self.pages_observed.to_string(),
            format!("{:?}", self.freshness),
            format!("{:?}", self.retention),
            format!("{:?}", self.provenance),
        ];
        fields.push(
            self.high_water_cursor_digest
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
        );
        fields.push(self.request_receipt_digest.as_str().to_owned());
        fields.extend(
            self.cursor_digests
                .iter()
                .map(|value| value.as_str().to_owned()),
        );
        fields.extend(
            self.event_schemas
                .iter()
                .map(EventSchemaEvidence::digest)
                .map(|value| value.as_str().to_owned()),
        );
        fields.extend(
            self.sources
                .iter()
                .map(SourceEvidence::digest)
                .map(|value| value.as_str().to_owned()),
        );
        fields.extend(
            self.destinations
                .iter()
                .map(DestinationEvidence::digest)
                .map(|value| value.as_str().to_owned()),
        );
        Digest::from_fields("segment-event-evidence/v1", fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentEventEvidenceProposal {
    pub evidence: SegmentEventEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub proposal_digest: Digest,
}

impl SegmentEventEvidenceProposal {
    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentEvidenceReceipt {
    pub evidence: SegmentEventEvidence,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub receipt_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedSegmentEvidence {
    pub evidence: SegmentEventEvidence,
    pub receipt_digest: Digest,
    pub verification_digest: Digest,
    pub native: bool,
    pub authority: &'static str,
}

pub trait SegmentProviderAccess: fmt::Debug {
    fn definition(&self) -> &SegmentProviderDefinition;
    fn provider_digest(&self) -> Digest;
    fn read_page(
        &mut self,
        request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError>;
}

impl<T: SegmentReadTransport> SegmentProviderAccess for SegmentProvider<T> {
    fn definition(&self) -> &SegmentProviderDefinition {
        self.definition()
    }

    fn provider_digest(&self) -> Digest {
        self.provider_digest()
    }

    fn read_page(
        &mut self,
        request: &SegmentReadRequest,
    ) -> Result<SegmentReadPage, TransportError> {
        self.read_page(request)
    }
}

pub struct SegmentEventEvidenceService<P = SegmentProvider<crate::RecordingSegmentTransport>> {
    scope: SegmentScope,
    secret: crate::SecretReference,
    bounds: EvidenceBounds,
    definition: SegmentEventEvidenceServiceDefinition,
    registration: SegmentRegistration,
    provider: P,
    active: bool,
}

impl<P: fmt::Debug> fmt::Debug for SegmentEventEvidenceService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SegmentEventEvidenceService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("bounds", &self.bounds)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl<P: SegmentProviderAccess> SegmentEventEvidenceService<P> {
    pub fn new(
        scope: SegmentScope,
        secret: crate::SecretReference,
        provider: P,
        bounds: EvidenceBounds,
    ) -> Result<Self, ServiceError> {
        if secret.scope_digest() != scope.scope_digest() {
            return Err(ServiceError::SecretScopeMismatch);
        }
        if secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        let provider_definition = provider.definition();
        if !provider_definition.read_only
            || provider_definition.live_execution
            || provider_definition.native
        {
            return Err(ServiceError::InvalidProviderDefinition);
        }
        let definition = SegmentEventEvidenceServiceDefinition::current();
        let registration = SegmentRegistration::new(
            provider_definition.provider_version,
            provider_definition.api_revision.clone(),
            provider.provider_digest(),
            &scope,
            definition.contract_digest.clone(),
            definition.version,
        )?;
        Ok(Self {
            scope,
            secret,
            bounds,
            definition,
            registration,
            provider,
            active: true,
        })
    }

    pub fn register(
        scope: SegmentScope,
        secret: crate::SecretReference,
        provider: P,
        bounds: EvidenceBounds,
    ) -> Result<Self, ServiceError> {
        Self::new(scope, secret, provider, bounds)
    }

    #[must_use]
    pub fn definition(&self) -> &SegmentEventEvidenceServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn registration(&self) -> &SegmentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &SegmentScope {
        &self.scope
    }

    #[must_use]
    pub fn bounds(&self) -> &EvidenceBounds {
        &self.bounds
    }

    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ServiceError> {
        if !self.active {
            return Err(ServiceError::RegistrationInactive);
        }
        self.active = false;
        self.registration.revoke()?;
        self.secret.revoke()?;
        Ok(())
    }

    pub fn describe(
        &mut self,
        window: EvidenceWindow,
    ) -> Result<SegmentReadEvidence, ServiceError> {
        self.read(SegmentReadOperation::Describe, window)
    }

    pub fn read(
        &mut self,
        operation: SegmentReadOperation,
        window: EvidenceWindow,
    ) -> Result<SegmentReadEvidence, ServiceError> {
        self.ensure_active()?;
        let mut records = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut cursor_digest = None;
        let mut freshness = FreshnessState::Fresh;
        let mut retention = RetentionState::Complete;
        let mut page_status = PageStatus::Complete;
        let mut response_page_digests = Vec::new();
        let mut request_digests = Vec::new();

        for page_number in 1..=self.bounds.max_pages() {
            let request = SegmentReadRequest::new(
                &self.scope,
                operation,
                window,
                &self.bounds,
                self.registration.provider_digest.clone(),
                self.registration.contract_digest.clone(),
                self.secret.reference_digest().clone(),
                self.secret.credential_revision(),
                page_number,
                self.bounds.max_page_size(),
                cursor_digest.clone(),
            )?;
            request_digests.push(request.request_digest.clone());
            let page = self.provider.read_page(&request)?;
            self.validate_page(&request, &page)?;
            response_page_digests.push(page.response_digest.clone());
            records.extend(page.records.clone());
            cursor_digests.extend(page.next_cursor_digest.iter().cloned());
            freshness = combine_freshness(freshness, page.freshness);
            retention = combine_retention(retention, page.retention);
            page_status = combine_page_status(page_status, page.status);
            if page.retention == RetentionState::Gap {
                return Err(ServiceError::RetentionGap);
            }
            match page.next_cursor_digest {
                None => {
                    let status = project_read_status(&records, page_status, freshness, retention);
                    let response_digest = Digest::from_fields(
                        "segment-read-responses/v1",
                        response_page_digests
                            .iter()
                            .map(|value| value.as_str().to_owned()),
                    );
                    let request_receipt_digest = Digest::from_fields(
                        "segment-read-requests/v1",
                        request_digests
                            .iter()
                            .map(|value| value.as_str().to_owned()),
                    );
                    let high_water_cursor_digest = cursor_digests.last().cloned();
                    return Ok(SegmentReadEvidence {
                        operation,
                        window,
                        records,
                        pages_observed: page_number,
                        cursor_digests,
                        high_water_cursor_digest,
                        freshness,
                        retention,
                        status,
                        response_digest,
                        request_receipt_digest,
                        provenance: self.provider.definition().provenance,
                    });
                }
                Some(next_cursor) => {
                    if !seen_cursors.insert(next_cursor.clone()) {
                        return Err(ServiceError::CursorLoop);
                    }
                    cursor_digest = Some(next_cursor);
                }
            }
        }
        Err(ServiceError::PageLimit)
    }

    pub fn compile_evidence_proposal(
        &mut self,
        window: EvidenceWindow,
    ) -> Result<SegmentEventEvidenceProposal, ServiceError> {
        let read = self.describe(window)?;
        let mut plan = None;
        let mut event_schemas = Vec::new();
        let mut violations = Vec::new();
        let mut sources = Vec::new();
        let mut destinations = Vec::new();
        let mut deliveries = Vec::new();
        for record in &read.records {
            match record {
                SegmentRecord::TrackingPlan(value) => {
                    if value.tracking_plan_id != *self.scope.tracking_plan_id()
                        || value.plan_revision != self.scope.plan_revision()
                    {
                        return Err(ServiceError::PlanDrift);
                    }
                    plan = Some(value.clone());
                }
                SegmentRecord::EventSchema(value) => {
                    if value.event_spec_id != *self.scope.event_spec_id()
                        || value.plan_revision != self.scope.plan_revision()
                    {
                        return Err(ServiceError::PlanDrift);
                    }
                    event_schemas.push(value.clone());
                }
                SegmentRecord::Violation(value) => violations.push(value.clone()),
                SegmentRecord::Source(value) => {
                    if value.source_id != *self.scope.source_id()
                        || value.plan_revision != self.scope.plan_revision()
                    {
                        return Err(ServiceError::ScopeDrift);
                    }
                    sources.push(value.clone());
                }
                SegmentRecord::Destination(value) => {
                    if value.destination_id != *self.scope.destination_id()
                        || value.source_id != *self.scope.source_id()
                    {
                        return Err(ServiceError::ScopeDrift);
                    }
                    destinations.push(value.clone());
                }
                SegmentRecord::Delivery(value) => {
                    if value.destination_id != *self.scope.destination_id() {
                        return Err(ServiceError::ScopeDrift);
                    }
                    deliveries.push(value.clone());
                }
                SegmentRecord::Empty => {}
            }
        }
        if event_schemas.len()
            > usize::from(self.bounds.max_pages()) * usize::from(self.bounds.max_page_size())
            || sources.len() > MAX_SOURCES
            || destinations.len() > MAX_DESTINATIONS
        {
            return Err(ServiceError::InvalidResponse);
        }
        let status = project_evidence_status(
            read.status,
            plan.as_ref(),
            &deliveries,
            &violations,
            read.freshness,
            read.retention,
        );
        let plan_digest = plan.as_ref().map_or_else(
            || Digest::from_text("segment-plan-absent"),
            |value| value.plan_digest.clone(),
        );
        let violation_digest = Digest::from_fields(
            "segment-violations/v1",
            violations
                .iter()
                .map(|value| value.digest().as_str().to_owned()),
        );
        let delivery_digest = Digest::from_fields(
            "segment-deliveries/v1",
            deliveries
                .iter()
                .map(|value| value.delivery_digest.as_str().to_owned()),
        );
        let response_digest = read.response_digest.clone();
        let mut evidence_fields = vec![
            format!("{status:?}"),
            self.registration.scope_digest.as_str().to_owned(),
            self.registration.provider_digest.as_str().to_owned(),
            self.registration.contract_digest.as_str().to_owned(),
            self.registration.provider_version.to_string(),
            window.start_unix_seconds().to_string(),
            window.end_unix_seconds().to_string(),
            plan_digest.as_str().to_owned(),
            violation_digest.as_str().to_owned(),
            delivery_digest.as_str().to_owned(),
            response_digest.as_str().to_owned(),
            read.pages_observed.to_string(),
            format!("{:?}", read.freshness),
            format!("{:?}", read.retention),
            format!("{:?}", self.provider.definition().provenance),
        ];
        evidence_fields.push(
            read.high_water_cursor_digest
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
        );
        evidence_fields.push(read.request_receipt_digest.as_str().to_owned());
        evidence_fields.extend(
            read.cursor_digests
                .iter()
                .map(|value| value.as_str().to_owned()),
        );
        evidence_fields.extend(
            event_schemas
                .iter()
                .map(EventSchemaEvidence::digest)
                .map(|value| value.as_str().to_owned()),
        );
        evidence_fields.extend(
            sources
                .iter()
                .map(SourceEvidence::digest)
                .map(|value| value.as_str().to_owned()),
        );
        evidence_fields.extend(
            destinations
                .iter()
                .map(DestinationEvidence::digest)
                .map(|value| value.as_str().to_owned()),
        );
        let evidence_digest = Digest::from_fields("segment-event-evidence/v1", evidence_fields);
        let evidence = SegmentEventEvidence {
            status,
            scope_digest: self.registration.scope_digest.clone(),
            provider_digest: self.registration.provider_digest.clone(),
            contract_digest: self.registration.contract_digest.clone(),
            provider_version: self.registration.provider_version,
            window,
            plan,
            event_schemas,
            violations,
            sources,
            destinations,
            deliveries,
            pages_observed: read.pages_observed,
            cursor_digests: read.cursor_digests,
            high_water_cursor_digest: read.high_water_cursor_digest,
            request_receipt_digest: read.request_receipt_digest.clone(),
            freshness: read.freshness,
            retention: read.retention,
            provenance: self.provider.definition().provenance,
            digests: SegmentEvidenceDigests {
                scope_digest: self.registration.scope_digest.clone(),
                provider_digest: self.registration.provider_digest.clone(),
                contract_digest: self.registration.contract_digest.clone(),
                plan_digest,
                violation_digest,
                delivery_digest,
                response_digest,
                request_receipt_digest: read.request_receipt_digest,
                evidence_digest: evidence_digest.clone(),
            },
        };
        let proposal_digest = Digest::from_fields(
            "segment-event-evidence-proposal/v1",
            [
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                evidence_digest.as_str().to_owned(),
            ],
        );
        Ok(SegmentEventEvidenceProposal {
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            proposal_digest,
        })
    }

    pub fn compile_evidence_proposal_for_window(
        &mut self,
        window: EvidenceWindow,
    ) -> Result<SegmentEventEvidenceProposal, ServiceError> {
        self.compile_evidence_proposal(window)
    }

    pub fn record(
        &self,
        proposal: &SegmentEventEvidenceProposal,
    ) -> Result<SegmentEvidenceReceipt, ServiceError> {
        self.ensure_active()?;
        self.validate_proposal(proposal)?;
        if !proposal.evidence.is_adoptable_candidate() {
            return Err(ServiceError::NotRecordable(proposal.evidence.status));
        }
        let receipt_digest = Digest::from_fields(
            "segment-evidence-receipt-candidate/v1",
            [
                proposal.proposal_digest.as_str().to_owned(),
                proposal.evidence.evidence_digest().as_str().to_owned(),
                self.registration.registration_digest.as_str().to_owned(),
            ],
        );
        Ok(SegmentEvidenceReceipt {
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            receipt_digest,
        })
    }

    pub fn record_evidence(
        &self,
        proposal: &SegmentEventEvidenceProposal,
    ) -> Result<SegmentEvidenceReceipt, ServiceError> {
        self.record(proposal)
    }

    pub fn verify(
        &self,
        receipt: &SegmentEvidenceReceipt,
    ) -> Result<VerifiedSegmentEvidence, ServiceError> {
        self.ensure_active()?;
        if receipt.registration_digest != self.registration.registration_digest {
            return Err(ServiceError::ProposalBindingMismatch);
        }
        let receipt_proposal = SegmentEventEvidenceProposal {
            evidence: receipt.evidence.clone(),
            registration_digest: receipt.registration_digest.clone(),
            registration_revision: self.registration.revision,
            proposal_digest: receipt.proposal_digest.clone(),
        };
        self.validate_proposal(&receipt_proposal)?;
        if !receipt.evidence.is_adoptable_candidate() {
            return Err(ServiceError::NotVerifiable(receipt.evidence.status));
        }
        let expected_receipt_digest = Digest::from_fields(
            "segment-evidence-receipt-candidate/v1",
            [
                receipt.proposal_digest.as_str().to_owned(),
                receipt.evidence.evidence_digest().as_str().to_owned(),
                receipt.registration_digest.as_str().to_owned(),
            ],
        );
        if expected_receipt_digest != receipt.receipt_digest {
            return Err(ServiceError::ProposalDigestMismatch);
        }
        let verification_digest = Digest::from_fields(
            "segment-evidence-verification/v1",
            [
                receipt.receipt_digest.as_str().to_owned(),
                receipt.evidence.evidence_digest().as_str().to_owned(),
                self.registration.scope_digest.as_str().to_owned(),
            ],
        );
        Ok(VerifiedSegmentEvidence {
            evidence: receipt.evidence.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            verification_digest,
            native: false,
            authority: "read_only_observational_evidence",
        })
    }

    pub fn verify_evidence(
        &self,
        receipt: &SegmentEvidenceReceipt,
    ) -> Result<VerifiedSegmentEvidence, ServiceError> {
        self.verify(receipt)
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        if self.active
            && self.registration.state == RegistrationState::Active
            && !self.secret.is_revoked()
        {
            Ok(())
        } else {
            Err(ServiceError::RegistrationInactive)
        }
    }

    fn validate_page(
        &self,
        request: &SegmentReadRequest,
        page: &SegmentReadPage,
    ) -> Result<(), ServiceError> {
        page.validate_digest()
            .map_err(|_| ServiceError::TamperedEvidence)?;
        if page.request_digest != request.request_digest {
            return Err(ServiceError::TamperedEvidence);
        }
        if page.scope_digest != request.scope_digest {
            return Err(ServiceError::ScopeDrift);
        }
        if page.permission_digest != request.permission_digest {
            return Err(ServiceError::PermissionDrift);
        }
        if page.provider_digest != request.provider_digest {
            return Err(ServiceError::ProviderDrift);
        }
        if page.contract_digest != request.contract_digest {
            return Err(ServiceError::ContractDrift);
        }
        if page.plan_revision != request.plan_revision {
            return Err(ServiceError::PlanDrift);
        }
        if page.operation != request.operation
            || page.window != request.window
            || page.page_number != request.page_number
            || page.page_size != request.page_size
            || page.cursor_digest != request.cursor_digest
        {
            return Err(ServiceError::WindowOrOperationDrift);
        }
        if page.page_number == 0
            || page.page_number > self.bounds.max_pages()
            || page.page_size == 0
            || page.page_size > self.bounds.max_page_size()
            || page.records.len() > usize::from(page.page_size)
        {
            return Err(ServiceError::PageBounds);
        }
        if page
            .next_cursor_digest
            .as_ref()
            .is_some_and(|value| value.as_str().len() > self.bounds.max_cursor_bytes())
        {
            return Err(ServiceError::PageBounds);
        }
        if page
            .records
            .iter()
            .any(|record| !SegmentRecord::is_allowed_for(page.operation, record))
        {
            return Err(ServiceError::InvalidResponse);
        }
        Ok(())
    }

    fn validate_proposal(
        &self,
        proposal: &SegmentEventEvidenceProposal,
    ) -> Result<(), ServiceError> {
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ServiceError::ProposalBindingMismatch);
        }
        if proposal.evidence.scope_digest != self.registration.scope_digest
            || proposal.evidence.provider_digest != self.registration.provider_digest
            || proposal.evidence.contract_digest != self.registration.contract_digest
            || proposal.evidence.digests.evidence_digest
                != proposal.evidence.recompute_evidence_digest()
        {
            return Err(ServiceError::ProposalBindingMismatch);
        }
        let expected_proposal_digest = Digest::from_fields(
            "segment-event-evidence-proposal/v1",
            [
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                proposal.evidence.evidence_digest().as_str().to_owned(),
            ],
        );
        if expected_proposal_digest != proposal.proposal_digest {
            return Err(ServiceError::ProposalDigestMismatch);
        }
        Ok(())
    }
}

fn combine_freshness(current: FreshnessState, incoming: FreshnessState) -> FreshnessState {
    match (current, incoming) {
        (FreshnessState::Stale, _) | (_, FreshnessState::Stale) => FreshnessState::Stale,
        (FreshnessState::Unknown, _) | (_, FreshnessState::Unknown) => FreshnessState::Unknown,
        _ => FreshnessState::Fresh,
    }
}

fn combine_retention(current: RetentionState, incoming: RetentionState) -> RetentionState {
    match (current, incoming) {
        (RetentionState::Gap, _) | (_, RetentionState::Gap) => RetentionState::Gap,
        (RetentionState::Unknown, _) | (_, RetentionState::Unknown) => RetentionState::Unknown,
        _ => RetentionState::Complete,
    }
}

fn combine_page_status(current: PageStatus, incoming: PageStatus) -> PageStatus {
    match (current, incoming) {
        (PageStatus::ProviderUnknown, _) | (_, PageStatus::ProviderUnknown) => {
            PageStatus::ProviderUnknown
        }
        (PageStatus::Partial, _) | (_, PageStatus::Partial) => PageStatus::Partial,
        _ => PageStatus::Complete,
    }
}

fn project_read_status(
    records: &[SegmentRecord],
    page_status: PageStatus,
    freshness: FreshnessState,
    retention: RetentionState,
) -> EvidenceStatus {
    if matches!(page_status, PageStatus::ProviderUnknown) {
        EvidenceStatus::ProviderUnknown
    } else if matches!(page_status, PageStatus::Partial) {
        EvidenceStatus::Partial
    } else if matches!(retention, RetentionState::Gap) {
        EvidenceStatus::Unavailable
    } else if matches!(freshness, FreshnessState::Stale) {
        EvidenceStatus::Stale
    } else if records.is_empty()
        || records
            .iter()
            .all(|record| matches!(record, SegmentRecord::Empty))
    {
        EvidenceStatus::Empty
    } else {
        EvidenceStatus::Conforming
    }
}

fn project_evidence_status(
    read_status: EvidenceStatus,
    plan: Option<&TrackingPlanEvidence>,
    deliveries: &[DeliveryEvidence],
    violations: &[ViolationEvidence],
    freshness: FreshnessState,
    retention: RetentionState,
) -> EvidenceStatus {
    if matches!(read_status, EvidenceStatus::Empty) {
        return EvidenceStatus::Empty;
    }
    if matches!(read_status, EvidenceStatus::ProviderUnknown) {
        return EvidenceStatus::ProviderUnknown;
    }
    if matches!(read_status, EvidenceStatus::Partial) {
        return EvidenceStatus::Partial;
    }
    if matches!(retention, RetentionState::Gap) {
        return EvidenceStatus::Unavailable;
    }
    if matches!(freshness, FreshnessState::Stale)
        || deliveries
            .iter()
            .any(|delivery| matches!(delivery.freshness, FreshnessState::Stale))
    {
        return EvidenceStatus::Stale;
    }
    if plan.is_none() || deliveries.is_empty() {
        return EvidenceStatus::Unavailable;
    }
    if deliveries.iter().any(|delivery| {
        matches!(
            delivery.health,
            DeliveryHealth::Degraded | DeliveryHealth::Failed
        )
    }) {
        return EvidenceStatus::DeliveryDegraded;
    }
    if deliveries
        .iter()
        .any(|delivery| matches!(delivery.health, DeliveryHealth::Unknown))
    {
        return EvidenceStatus::ProviderUnknown;
    }
    if violations.iter().any(|violation| violation.count > 0) {
        EvidenceStatus::Violation
    } else {
        EvidenceStatus::Conforming
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{
            DestinationId, EventSchemaEvidence, EventSpecId, MissionId, PermissionSnapshot,
            ProjectId, SecretKind, SourceId, TrackingPlanId, WorkProductId, WorkspaceId,
        },
        provider::{
            PageStatus, RecordingSegmentTransport, SegmentProvider, SegmentReadOperation,
            SegmentReadPage, SegmentReadRequest,
        },
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

    fn request(
        scope: &SegmentScope,
        provider_digest: Digest,
        secret_digest: Digest,
    ) -> SegmentReadRequest {
        SegmentReadRequest::new(
            scope,
            SegmentReadOperation::Describe,
            EvidenceWindow::new(1, 2).unwrap(),
            &EvidenceBounds::default(),
            provider_digest,
            crate::segment_event_evidence_contract_digest(),
            secret_digest,
            Revision::new(1).unwrap(),
            1,
            100,
            None,
        )
        .unwrap()
    }

    #[test]
    fn contract_digest_is_stable_and_read_page_is_projected() {
        let scope = scope();
        let provider_digest = Digest::from_text("provider");
        let secret_digest = Digest::from_text("secret");
        let request = request(&scope, provider_digest.clone(), secret_digest.clone());
        let plan = TrackingPlanEvidence::new(
            TrackingPlanId::new("plan").unwrap(),
            Revision::new(1).unwrap(),
            1,
            Digest::from_text("schema"),
        )
        .unwrap();
        let event_schema = EventSchemaEvidence::new(
            EventSpecId::new("event").unwrap(),
            Revision::new(1).unwrap(),
            Digest::from_text("event-schema"),
            3,
        );
        let page = SegmentReadPage::new(
            &request,
            vec![
                SegmentRecord::TrackingPlan(plan),
                SegmentRecord::EventSchema(event_schema),
            ],
            None,
            FreshnessState::Fresh,
            RetentionState::Complete,
            PageStatus::Complete,
        )
        .unwrap();
        let provider = SegmentProvider::new(
            RecordingSegmentTransport::from_pages([Ok(page)]),
            crate::PluginVersion::V1,
            "protocols-fixture/v1",
            ProviderProvenance::Fixture,
        )
        .unwrap();
        let secret =
            crate::SecretReference::new("secret-ref", &scope, 1, SecretKind::PublicApiToken)
                .unwrap();
        let service =
            SegmentEventEvidenceService::new(scope, secret, provider, EvidenceBounds::default())
                .unwrap();
        assert_eq!(
            service.definition().contract_digest,
            crate::segment_event_evidence_contract_digest()
        );
        assert!(!service.provider().definition().native);
    }
}

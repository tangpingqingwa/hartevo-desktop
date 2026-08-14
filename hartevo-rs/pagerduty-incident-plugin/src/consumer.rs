//! Mission-facing consumer seam.

use std::fmt;

use crate::{
    model::{
        CapabilityDescription, IncidentProjection, IncidentState, PagerDutyScope,
        ResolutionEvidenceProposal, ResponseIntent, ResponseProposal, TimelineBounds,
        TimelineProjection, Timestamp, WebhookSecretMaterial,
    },
    provider::{IncidentReadResult, ProviderError},
    transport::ProbeReceipt,
    webhook::{VerifiedWebhookEnvelope, WebhookEnvelope},
};

/// The typed service boundary consumed by a Mission.  It exposes read and
/// proposal operations only; no method can execute a PagerDuty mutation,
/// accept a live webhook, or adopt an Outcome.
pub trait PagerDutyIncidentService {
    fn describe_capabilities(&self) -> CapabilityDescription;

    fn probe_registration(&mut self) -> Result<ProbeReceipt, ProviderError>;

    fn read_incident(
        &mut self,
        previous: Option<&IncidentProjection>,
    ) -> Result<IncidentReadResult, ProviderError>;

    fn read_incident_timeline(
        &mut self,
        bounds: TimelineBounds,
    ) -> Result<TimelineProjection, ProviderError>;

    fn compile_response_proposal(
        &self,
        mission_revision: u64,
        expected_state: IncidentState,
        intent: ResponseIntent,
        idempotency_key: &str,
    ) -> Result<ResponseProposal, ProviderError>;

    fn verify_resolution_projection(
        &self,
        mission_revision: u64,
        incident: &IncidentProjection,
        timeline: &TimelineProjection,
        selected_entry_ids: &[String],
    ) -> Result<ResolutionEvidenceProposal, ProviderError>;

    fn verify_webhook_envelope(
        &mut self,
        envelope: &WebhookEnvelope,
        raw_body: &[u8],
        secret: &WebhookSecretMaterial,
        now: Timestamp,
    ) -> Result<VerifiedWebhookEnvelope, ProviderError>;
}

/// A Mission-scoped adapter around the typed PagerDuty service.
pub struct MissionPagerDutyIncidentConsumer<S> {
    service: S,
    scope: PagerDutyScope,
    mission_revision: u64,
}

impl<S> fmt::Debug for MissionPagerDutyIncidentConsumer<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionPagerDutyIncidentConsumer")
            .field("service", &self.service)
            .field("scope", &self.scope)
            .field("mission_revision", &self.mission_revision)
            .finish()
    }
}

impl<S> MissionPagerDutyIncidentConsumer<S>
where
    S: PagerDutyIncidentService,
{
    pub fn new(
        service: S,
        scope: PagerDutyScope,
        mission_revision: u64,
    ) -> Result<Self, ProviderError> {
        if mission_revision == 0 {
            return Err(ProviderError::InvalidMissionRevision);
        }
        Ok(Self {
            service,
            scope,
            mission_revision,
        })
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut S {
        &mut self.service
    }

    pub fn scope(&self) -> &PagerDutyScope {
        &self.scope
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        self.service.describe_capabilities()
    }

    pub fn probe_registration(&mut self) -> Result<ProbeReceipt, ProviderError> {
        let receipt = self.service.probe_registration()?;
        if receipt.scope_digest != self.scope.digest() {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(receipt)
    }

    pub fn read_incident(
        &mut self,
        previous: Option<&IncidentProjection>,
    ) -> Result<IncidentReadResult, ProviderError> {
        let result = self.service.read_incident(previous)?;
        if result
            .incident
            .as_ref()
            .is_some_and(|projection| projection.scope_digest != self.scope.digest())
        {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(result)
    }

    pub fn read_incident_timeline(
        &mut self,
        bounds: TimelineBounds,
    ) -> Result<TimelineProjection, ProviderError> {
        let projection = self.service.read_incident_timeline(bounds)?;
        if projection.scope_digest != self.scope.digest() {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(projection)
    }

    pub fn compile_response_proposal(
        &self,
        expected_state: IncidentState,
        intent: ResponseIntent,
        idempotency_key: &str,
    ) -> Result<ResponseProposal, ProviderError> {
        let proposal = self.service.compile_response_proposal(
            self.mission_revision,
            expected_state,
            intent,
            idempotency_key,
        )?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != self.scope.mission_id
            || proposal.project_id != self.scope.project_id
            || proposal.mission_revision != self.mission_revision
        {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(proposal)
    }

    pub fn verify_resolution_projection(
        &self,
        incident: &IncidentProjection,
        timeline: &TimelineProjection,
        selected_entry_ids: &[String],
    ) -> Result<ResolutionEvidenceProposal, ProviderError> {
        let proposal = self.service.verify_resolution_projection(
            self.mission_revision,
            incident,
            timeline,
            selected_entry_ids,
        )?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != self.scope.mission_id
            || proposal.project_id != self.scope.project_id
            || proposal.mission_revision != self.mission_revision
        {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(proposal)
    }

    pub fn verify_webhook_envelope(
        &mut self,
        envelope: &WebhookEnvelope,
        raw_body: &[u8],
        secret: &WebhookSecretMaterial,
        now: Timestamp,
    ) -> Result<VerifiedWebhookEnvelope, ProviderError> {
        let verified = self
            .service
            .verify_webhook_envelope(envelope, raw_body, secret, now)?;
        if verified.subscription_id != self.scope.webhook_subscription_id {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(verified)
    }
}

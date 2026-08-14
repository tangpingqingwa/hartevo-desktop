//! Typed PagerDuty incident service and provider implementation.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{
        AlertProjection, CapabilityDescription, Digest, IncidentProjection, IncidentState,
        ProjectionBounds, Provenance, RateLimitReceipt, ResolutionEvidenceProposal, ResponseIntent,
        ResponseProposal, SecretKind, SelectedTimelineEvidence, TimelineBounds,
        TimelineEntryProjection, TimelinePageReceipt, TimelineProjection, TimelineReceipt,
        TimelineStopReason, Timestamp, WebhookSecretMaterial, canonical_digest,
    },
    registration::{
        CONSUMER_ID, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, PLUGIN_ID, PROVIDER_ID,
        PagerDutyRegistration, RegistrationError, SERVICE_ID, contract_digest,
    },
    transport::{
        IncidentRequest, PagerDutyIncidentTransport, ProbeReceipt, ProbeRequest,
        TimelinePageRequest, TransportError,
    },
    webhook::{
        VerifiedWebhookEnvelope, WebhookEnvelope as Envelope, WebhookError, WebhookReplayFence,
    },
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("model error: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("webhook error: {0}")]
    Webhook(#[from] WebhookError),
    #[error("registration is revoked or its secret reference is revoked")]
    RegistrationRevoked,
    #[error("request scope does not exactly match the registration")]
    ScopeMismatch,
    #[error("provider revision mismatch: expected {expected}, observed {observed}")]
    ProviderRevisionMismatch { expected: u64, observed: u64 },
    #[error("provider response exceeded a Layer-1 bound")]
    ResponseBoundExceeded,
    #[error("provider returned more than one incident for an exact incident read")]
    MultipleIncidentResults,
    #[error("provider incident response identity did not match the exact scope")]
    IncidentIdentityMismatch,
    #[error("previous incident projection is from a different scope or incident")]
    PreviousProjectionMismatch,
    #[error("provider returned a stale incident revision")]
    StaleIncidentRevision,
    #[error("timeline cursor repeated before the read completed")]
    TimelineCursorLoop,
    #[error("timeline entry identifier repeated across pages: {0}")]
    DuplicateTimelineEntry(String),
    #[error("timeline result is incomplete")]
    IncompleteTimeline,
    #[error("selected timeline entry is absent from the bounded projection: {0}")]
    MissingTimelineEntry(String),
    #[error("resolution evidence requires a resolved incident")]
    IncidentNotResolved,
    #[error("resolution evidence is missing a resolved timestamp")]
    MissingResolvedTimestamp,
    #[error("mission revision must be greater than zero")]
    InvalidMissionRevision,
    #[error("idempotency key must be non-empty and bounded")]
    InvalidIdempotencyKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncidentReadResult {
    pub incident: Option<IncidentProjection>,
    pub rate_limit: RateLimitReceipt,
    pub empty_result: bool,
    pub empty_result_health_claim: bool,
    pub provenance: Provenance,
}

/// The typed provider for PagerDuty incident reads and proposal compilation.
/// `T` is always an explicit recording, fake, or blocked environment seam in
/// Layer 1; no native HTTP implementation is supplied here.
pub struct PagerDutyIncidentProvider<T> {
    transport: T,
    registration: PagerDutyRegistration,
    bounds: ProjectionBounds,
    replay_fence: WebhookReplayFence,
}

impl<T> fmt::Debug for PagerDutyIncidentProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PagerDutyIncidentProvider")
            .field("transport", &self.transport)
            .field("registration", &self.registration)
            .field("bounds", &self.bounds)
            .field("replay_fence", &self.replay_fence)
            .finish()
    }
}

impl<T> PagerDutyIncidentProvider<T>
where
    T: PagerDutyIncidentTransport,
{
    pub fn new(
        transport: T,
        registration: PagerDutyRegistration,
        bounds: ProjectionBounds,
    ) -> Result<Self, ProviderError> {
        bounds.validate()?;
        registration.validate_integrity()?;
        if registration.provider_id != PROVIDER_ID
            || registration.contract_digest != contract_digest()
            || !registration.lifecycle.is_active()
            || !registration.secret_reference.is_active()
            || !matches!(
                registration.secret_reference.kind(),
                SecretKind::ApiToken | SecretKind::OAuthAccessToken
            )
        {
            return Err(ProviderError::RegistrationRevoked);
        }
        Ok(Self {
            transport,
            registration,
            bounds,
            replay_fence: WebhookReplayFence::new(900)?,
        })
    }

    pub fn registration(&self) -> &PagerDutyRegistration {
        &self.registration
    }

    pub fn bounds(&self) -> &ProjectionBounds {
        &self.bounds
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "probe_registration".to_owned(),
                "read_incident".to_owned(),
                "read_incident_timeline".to_owned(),
                "compile_response_proposal".to_owned(),
                "verify_resolution_projection".to_owned(),
                "verify_webhook_envelope".to_owned(),
            ],
            exact_scope_fields: vec![
                "api_region".to_owned(),
                "account_id".to_owned(),
                "team_id".to_owned(),
                "service_id".to_owned(),
                "escalation_policy_id".to_owned(),
                "incident_id".to_owned(),
                "incident_number".to_owned(),
                "mission_id".to_owned(),
                "project_id".to_owned(),
                "consent_reference".to_owned(),
                "webhook_subscription_id".to_owned(),
            ],
            read_only: true,
            executes_mutations: false,
            accepts_live_webhooks: false,
            adopts_outcomes: false,
        }
    }

    pub fn probe_registration(&mut self) -> Result<ProbeReceipt, ProviderError> {
        self.ensure_usable()?;
        let scope = &self.registration.scope;
        let response = self.transport.probe(&ProbeRequest::from_scope(scope))?;
        if response.payload.api_region != scope.api_region
            || response.payload.account_id != scope.account_id
            || response.payload.team_id != scope.team_id
            || response.payload.service_id != scope.service_id
            || response.payload.escalation_policy_id != scope.escalation_policy_id
        {
            return Err(ProviderError::ScopeMismatch);
        }
        self.ensure_provider_revision(response.payload.provider_revision)?;
        let provenance = self.transport.provenance();
        Ok(ProbeReceipt {
            scope_digest: scope.digest(),
            provider_revision: response.payload.provider_revision,
            rate_limit: response.rate_limit,
            provenance,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn read_incident(
        &mut self,
        previous: Option<&IncidentProjection>,
    ) -> Result<IncidentReadResult, ProviderError> {
        self.ensure_usable()?;
        let scope = &self.registration.scope;
        if let Some(previous) = previous {
            if previous.scope_digest != scope.digest() || previous.incident != scope.incident {
                return Err(ProviderError::PreviousProjectionMismatch);
            }
            if previous.provider_revision > self.registration.provider_revision {
                return Err(ProviderError::StaleIncidentRevision);
            }
        }
        let response = self
            .transport
            .read_incident(&IncidentRequest::from_scope(scope))?;
        if response.rate_limit.response_bytes > self.bounds.max_response_bytes {
            return Err(ProviderError::ResponseBoundExceeded);
        }
        if response.items.len() > 1 {
            return Err(ProviderError::MultipleIncidentResults);
        }
        let provenance = self.transport.provenance();
        let Some(raw) = response.items.into_iter().next() else {
            return Ok(IncidentReadResult {
                incident: None,
                rate_limit: response.rate_limit,
                empty_result: true,
                empty_result_health_claim: false,
                provenance,
            });
        };
        if raw.api_region != scope.api_region
            || raw.account_id != scope.account_id
            || raw.team_id != scope.team_id
            || raw.service_id != scope.service_id
            || raw.escalation_policy_id != scope.escalation_policy_id
            || raw.incident != scope.incident
        {
            return Err(ProviderError::IncidentIdentityMismatch);
        }
        self.ensure_provider_revision(raw.provider_revision)?;
        if previous.is_some_and(|projection| raw.provider_revision < projection.provider_revision) {
            return Err(ProviderError::StaleIncidentRevision);
        }
        let projection =
            IncidentProjection::from_raw(scope, &raw, previous, provenance, &self.bounds)?;
        Ok(IncidentReadResult {
            incident: Some(projection),
            rate_limit: response.rate_limit,
            empty_result: false,
            empty_result_health_claim: false,
            provenance,
        })
    }

    pub fn read_incident_timeline(
        &mut self,
        bounds: TimelineBounds,
    ) -> Result<TimelineProjection, ProviderError> {
        self.ensure_usable()?;
        bounds.validate(&self.bounds)?;
        let scope = &self.registration.scope;
        let provenance = self.transport.provenance();
        let mut cursor: Option<String> = None;
        let mut cursors = BTreeSet::new();
        let mut entry_ids = BTreeSet::new();
        let mut entries: Vec<TimelineEntryProjection> = Vec::new();
        let mut pages = Vec::new();
        let mut total_items = 0usize;
        let mut total_bytes = 0usize;
        let mut reordered = false;
        let mut stop_reason = TimelineStopReason::Complete;
        let mut complete = false;

        for page_index in 0..bounds.max_pages {
            let cursor_digest = cursor.as_ref().map(canonical_digest);
            if !cursors.insert(cursor_digest.clone()) {
                return Err(ProviderError::TimelineCursorLoop);
            }
            let response = self
                .transport
                .read_timeline_page(&TimelinePageRequest::new(
                    scope,
                    cursor.clone(),
                    bounds.clone(),
                ))?;
            let page_bytes = response.rate_limit.response_bytes;
            total_bytes = total_bytes
                .checked_add(page_bytes)
                .ok_or(ProviderError::ResponseBoundExceeded)?;
            if total_bytes > bounds.max_response_bytes {
                return Err(ProviderError::ResponseBoundExceeded);
            }
            total_items = total_items
                .checked_add(response.items.len())
                .ok_or(ProviderError::ResponseBoundExceeded)?;
            if total_items > bounds.max_items {
                stop_reason = TimelineStopReason::ItemLimit;
                pages.push(page_receipt(page_index, cursor_digest, &response));
                break;
            }
            for item in &response.items {
                if !entry_ids.insert(item.entry_id.clone()) {
                    return Err(ProviderError::DuplicateTimelineEntry(item.entry_id.clone()));
                }
                if item.occurred_at.unix_seconds() < bounds.window.from.unix_seconds()
                    || item.occurred_at.unix_seconds() > bounds.window.to.unix_seconds()
                {
                    continue;
                }
                if let Some(previous) = entries.last()
                    && (previous.occurred_at > item.occurred_at
                        || (previous.occurred_at == item.occurred_at
                            && previous.entry_id > item.entry_id))
                {
                    reordered = true;
                }
                entries.push(TimelineEntryProjection {
                    entry_id: item.entry_id.clone(),
                    kind: item.kind,
                    occurred_at: item.occurred_at,
                    actor_reference_digest: Digest::from_text(&item.actor_reference),
                    content_digest: Digest::from_bytes(&item.content),
                });
            }
            let next_cursor = response.next_cursor.clone();
            pages.push(page_receipt(page_index, cursor_digest, &response));
            if entries.len() >= bounds.max_items {
                stop_reason = TimelineStopReason::ItemLimit;
                break;
            }
            let Some(next_cursor_value) = next_cursor else {
                complete = true;
                break;
            };
            cursor = Some(next_cursor_value);
        }
        if !complete && pages.len() == bounds.max_pages && cursor.is_some() {
            stop_reason = TimelineStopReason::PageLimit;
        }
        entries.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.entry_id.cmp(&right.entry_id))
        });
        let receipt = TimelineReceipt {
            page_count: pages.len(),
            item_count: total_items,
            response_bytes: total_bytes,
            complete,
            stop_reason,
            reordered,
            pages,
        };
        Ok(TimelineProjection {
            scope_digest: scope.digest(),
            incident: scope.incident.clone(),
            provider_revision: self.registration.provider_revision,
            entries,
            receipt,
            provenance,
        })
    }

    pub fn compile_response_proposal(
        &self,
        mission_revision: u64,
        expected_state: IncidentState,
        intent: ResponseIntent,
        idempotency_key: &str,
    ) -> Result<ResponseProposal, ProviderError> {
        self.ensure_usable()?;
        if mission_revision == 0 {
            return Err(ProviderError::InvalidMissionRevision);
        }
        if idempotency_key.is_empty() || idempotency_key.len() > 256 {
            return Err(ProviderError::InvalidIdempotencyKey);
        }
        let scope = &self.registration.scope;
        let idempotency_fingerprint = Digest::from_text(idempotency_key);
        let material = ResponseProposalMaterial {
            scope_digest: &scope.digest(),
            mission_id: &scope.mission_id,
            project_id: &scope.project_id,
            mission_revision,
            consent: &scope.consent,
            incident: &scope.incident,
            expected_state,
            expected_provider_revision: self.registration.provider_revision,
            intent: &intent,
            idempotency_fingerprint: &idempotency_fingerprint,
        };
        let proposal_digest = canonical_digest(&material);
        Ok(ResponseProposal {
            scope_digest: scope.digest(),
            mission_id: scope.mission_id.clone(),
            project_id: scope.project_id.clone(),
            mission_revision,
            consent: scope.consent.clone(),
            incident: scope.incident.clone(),
            expected_state,
            expected_provider_revision: self.registration.provider_revision,
            intent,
            idempotency_fingerprint,
            proposal_digest,
            mutating_effect_allowed: false,
            executed: false,
            exact_readback_required: true,
            provenance: self.transport.provenance(),
        })
    }

    pub fn verify_resolution_projection(
        &self,
        mission_revision: u64,
        incident: &IncidentProjection,
        timeline: &TimelineProjection,
        selected_entry_ids: &[String],
    ) -> Result<ResolutionEvidenceProposal, ProviderError> {
        self.ensure_usable()?;
        if mission_revision == 0 {
            return Err(ProviderError::InvalidMissionRevision);
        }
        let scope = &self.registration.scope;
        if incident.scope_digest != scope.digest()
            || incident.incident != scope.incident
            || timeline.scope_digest != scope.digest()
            || timeline.incident != scope.incident
            || incident.provider_revision != self.registration.provider_revision
            || timeline.provider_revision != self.registration.provider_revision
        {
            return Err(ProviderError::ScopeMismatch);
        }
        if !incident.state.is_resolved() {
            return Err(ProviderError::IncidentNotResolved);
        }
        let resolved_at = incident
            .resolved_at
            .ok_or(ProviderError::MissingResolvedTimestamp)?;
        if !timeline.receipt.complete {
            return Err(ProviderError::IncompleteTimeline);
        }
        let mut selected = Vec::new();
        for entry_id in selected_entry_ids {
            let entry = timeline
                .entries
                .iter()
                .find(|entry| &entry.entry_id == entry_id)
                .ok_or_else(|| ProviderError::MissingTimelineEntry(entry_id.clone()))?;
            selected.push(SelectedTimelineEvidence {
                entry_id: entry.entry_id.clone(),
                occurred_at: entry.occurred_at,
                content_digest: entry.content_digest.clone(),
                actor_reference_digest: entry.actor_reference_digest.clone(),
            });
        }
        selected.sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
        let assignment_digests = incident
            .assignments
            .iter()
            .map(canonical_digest)
            .collect::<Vec<_>>();
        let material = ResolutionEvidenceMaterial {
            scope_digest: &scope.digest(),
            mission_id: &scope.mission_id,
            project_id: &scope.project_id,
            mission_revision,
            consent: &scope.consent,
            incident: &incident.incident,
            incident_digest: &incident.incident_digest,
            incident_state: incident.state,
            provider_revision: incident.provider_revision,
            resolved_at,
            assignment_digests: &assignment_digests,
            selected_timeline: &selected,
        };
        let evidence_digest = canonical_digest(&material);
        Ok(ResolutionEvidenceProposal {
            scope_digest: scope.digest(),
            mission_id: scope.mission_id.clone(),
            project_id: scope.project_id.clone(),
            mission_revision,
            consent: scope.consent.clone(),
            incident: incident.incident.clone(),
            incident_digest: incident.incident_digest.clone(),
            incident_state: incident.state,
            provider_revision: incident.provider_revision,
            resolved_at,
            assignment_digests,
            selected_timeline: selected,
            evidence_digest,
            adopted_outcome: false,
            provenance: self.transport.provenance(),
        })
    }

    pub fn verify_webhook_envelope(
        &mut self,
        envelope: &Envelope,
        raw_body: &[u8],
        secret: &WebhookSecretMaterial,
        now: Timestamp,
    ) -> Result<VerifiedWebhookEnvelope, ProviderError> {
        self.ensure_usable()?;
        let expected_subscription = &self.registration.scope.webhook_subscription_id;
        Ok(self.replay_fence.verify(
            expected_subscription,
            envelope,
            raw_body,
            secret,
            now,
            self.transport.provenance(),
        )?)
    }

    fn ensure_usable(&self) -> Result<(), ProviderError> {
        if self.registration.provider_id != PROVIDER_ID
            || self.registration.contract_digest != contract_digest()
            || !self.registration.lifecycle.is_active()
            || !self.registration.secret_reference.is_active()
        {
            return Err(ProviderError::RegistrationRevoked);
        }
        Ok(())
    }

    fn ensure_provider_revision(&self, observed: u64) -> Result<(), ProviderError> {
        if observed == self.registration.provider_revision {
            Ok(())
        } else {
            Err(ProviderError::ProviderRevisionMismatch {
                expected: self.registration.provider_revision,
                observed,
            })
        }
    }
}

impl<T> crate::PagerDutyIncidentService for PagerDutyIncidentProvider<T>
where
    T: PagerDutyIncidentTransport,
{
    fn describe_capabilities(&self) -> CapabilityDescription {
        Self::describe_capabilities(self)
    }

    fn probe_registration(&mut self) -> Result<ProbeReceipt, ProviderError> {
        Self::probe_registration(self)
    }

    fn read_incident(
        &mut self,
        previous: Option<&IncidentProjection>,
    ) -> Result<IncidentReadResult, ProviderError> {
        Self::read_incident(self, previous)
    }

    fn read_incident_timeline(
        &mut self,
        bounds: TimelineBounds,
    ) -> Result<TimelineProjection, ProviderError> {
        Self::read_incident_timeline(self, bounds)
    }

    fn compile_response_proposal(
        &self,
        mission_revision: u64,
        expected_state: IncidentState,
        intent: ResponseIntent,
        idempotency_key: &str,
    ) -> Result<ResponseProposal, ProviderError> {
        Self::compile_response_proposal(
            self,
            mission_revision,
            expected_state,
            intent,
            idempotency_key,
        )
    }

    fn verify_resolution_projection(
        &self,
        mission_revision: u64,
        incident: &IncidentProjection,
        timeline: &TimelineProjection,
        selected_entry_ids: &[String],
    ) -> Result<ResolutionEvidenceProposal, ProviderError> {
        Self::verify_resolution_projection(
            self,
            mission_revision,
            incident,
            timeline,
            selected_entry_ids,
        )
    }

    fn verify_webhook_envelope(
        &mut self,
        envelope: &Envelope,
        raw_body: &[u8],
        secret: &WebhookSecretMaterial,
        now: Timestamp,
    ) -> Result<VerifiedWebhookEnvelope, ProviderError> {
        Self::verify_webhook_envelope(self, envelope, raw_body, secret, now)
    }
}

fn page_receipt(
    page_index: usize,
    cursor_digest: Option<Digest>,
    response: &crate::transport::TimelinePageResponse,
) -> TimelinePageReceipt {
    TimelinePageReceipt {
        page_index,
        cursor_digest,
        item_count: response.items.len(),
        response_bytes: response.rate_limit.response_bytes,
        next_cursor_digest: response.next_cursor.as_ref().map(canonical_digest),
        rate_limit: response.rate_limit.clone(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseProposalMaterial<'a> {
    scope_digest: &'a Digest,
    mission_id: &'a crate::model::MissionId,
    project_id: &'a crate::model::ProjectId,
    mission_revision: u64,
    consent: &'a crate::model::ConsentReference,
    incident: &'a crate::model::IncidentIdentity,
    expected_state: IncidentState,
    expected_provider_revision: u64,
    intent: &'a ResponseIntent,
    idempotency_fingerprint: &'a Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionEvidenceMaterial<'a> {
    scope_digest: &'a Digest,
    mission_id: &'a crate::model::MissionId,
    project_id: &'a crate::model::ProjectId,
    mission_revision: u64,
    consent: &'a crate::model::ConsentReference,
    incident: &'a crate::model::IncidentIdentity,
    incident_digest: &'a Digest,
    incident_state: IncidentState,
    provider_revision: u64,
    resolved_at: Timestamp,
    assignment_digests: &'a [Digest],
    selected_timeline: &'a [SelectedTimelineEvidence],
}

#[allow(dead_code)]
const _CONTRACT_METADATA: (&str, &str, &str, &str) = (
    PLUGIN_ID,
    CONTRACT_SCHEMA_VERSION,
    CONTRACT_VERSION,
    SERVICE_ID,
);

#[allow(dead_code)]
fn _alert_status_is_not_incident_status(alert: AlertProjection) -> bool {
    matches!(
        alert.status,
        crate::model::AlertStatus::Triggered | crate::model::AlertStatus::Resolved
    )
}

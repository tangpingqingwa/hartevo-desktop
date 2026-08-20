use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_HEALTH_EVENT_RESULT_API_REVISION, AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION,
    AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION, AWS_HEALTH_EVENT_RESULT_SERVICE_ID,
    model::{
        AwsHealthEventDetail, AwsHealthEventEvidence, AwsHealthEventRecord, AwsHealthEventScope,
        AwsHealthEvidenceClassification, AwsHealthEvidenceDigests, AwsHealthEvidenceState,
        AwsHealthFailureKind, AwsHealthOperation, AwsHealthRegistration, Digest, ModelError,
        RegistrationRevocationReceipt, RegistrationState, Revision, evidence_policy_digest,
    },
    provider::{
        AwsHealthProvider, AwsHealthProviderError, AwsHealthTransport, ProviderProvenance,
        TransportError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsHealthEventServiceError {
    #[error("AWS Health registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("AWS Health SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Health permission or consent fence does not match")]
    FenceViolation,
    #[error("AWS Health provider scope does not match")]
    ScopeMismatch,
    #[error("AWS Health event revision drifted between reads")]
    EventRevisionDrift,
    #[error("AWS Health evidence is invalid or tampered")]
    EvidenceMismatch,
    #[error("AWS Health proposal is invalid or tampered")]
    ProposalMismatch,
    #[error(transparent)]
    Provider(#[from] AwsHealthProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEventServiceDefinition {
    pub service_id: String,
    pub version: String,
    pub api_revision: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub operations: BTreeSet<AwsHealthOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_external_io: bool,
    pub native: bool,
    pub connected: bool,
    pub outage_causality: bool,
    pub operational_truth: bool,
}

impl Default for AwsHealthEventServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: AWS_HEALTH_EVENT_RESULT_SERVICE_ID.to_owned(),
            version: "1.0.0".to_owned(),
            api_revision: AWS_HEALTH_EVENT_RESULT_API_REVISION.to_owned(),
            contract_version: AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION.to_owned(),
            operations: [
                AwsHealthOperation::DescribeEvents,
                AwsHealthOperation::DescribeEventDetails,
                AwsHealthOperation::DescribeAffectedEntities,
            ]
            .into_iter()
            .collect(),
            read_only: true,
            proposal_only: true,
            live_external_io: false,
            native: false,
            connected: false,
            outage_causality: false,
            operational_truth: false,
        }
    }
}

pub type AwsHealthServiceDefinition = AwsHealthEventServiceDefinition;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEventProposal {
    pub evidence: AwsHealthEventEvidence,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub event_filter_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub outage_causality: bool,
    pub operational_truth: bool,
    pub proposal_digest: Digest,
}

impl AwsHealthEventProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-health-event-proposal/v1",
            &[
                self.evidence.digest().as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.event_filter_digest.as_str().to_owned(),
                self.evidence_policy_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.proposal_only.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.outage_causality.to_string(),
                self.operational_truth.to_string(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), AwsHealthEventServiceError> {
        if self.proposal_digest == self.digest() {
            Ok(())
        } else {
            Err(AwsHealthEventServiceError::ProposalMismatch)
        }
    }

    #[must_use]
    pub fn decision_ready(&self) -> bool {
        self.evidence.decision_ready()
    }
}

pub type AwsHealthEventResultProposal = AwsHealthEventProposal;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
}

pub struct AwsHealthEventService<T: AwsHealthTransport> {
    provider: AwsHealthProvider<T>,
    definition: AwsHealthEventServiceDefinition,
    observed_event_revisions: BTreeMap<Digest, Revision>,
}

impl<T: AwsHealthTransport> fmt::Debug for AwsHealthEventService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsHealthEventService")
            .field("scope_digest", self.provider.scope().scope_digest())
            .field("registration", self.provider.registration())
            .field("definition", &self.definition)
            .field(
                "observed_event_revisions",
                &self.observed_event_revisions.len(),
            )
            .finish()
    }
}

impl<T: AwsHealthTransport> AwsHealthEventService<T> {
    pub fn new(provider: AwsHealthProvider<T>) -> Result<Self, AwsHealthEventServiceError> {
        provider
            .registration()
            .validate(provider.scope(), &provider.provider_digest())
            .map_err(|_| AwsHealthEventServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: AwsHealthEventServiceDefinition::default(),
            observed_event_revisions: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: AwsHealthProvider<T>) -> Self {
        Self {
            provider,
            definition: AwsHealthEventServiceDefinition::default(),
            observed_event_revisions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &AwsHealthProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AwsHealthProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AwsHealthEventScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AwsHealthRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &AwsHealthEventServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> crate::AwsHealthConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(&mut self) -> Result<AwsHealthEventEvidence, AwsHealthEventServiceError> {
        self.read_events()
    }

    pub fn read_events(&mut self) -> Result<AwsHealthEventEvidence, AwsHealthEventServiceError> {
        self.ensure_active()?;
        let request = self.provider.events_request();
        let request_digest = request.request_digest();
        let provenance = self.provider.provenance();
        match self.provider.describe_events(request) {
            Ok(response) => {
                self.remember_event_revisions(&response.events)?;
                let state = if !response.failed_events.is_empty() || response.truncated {
                    AwsHealthEvidenceState::PartialFailure
                } else if response.events.is_empty() {
                    AwsHealthEvidenceState::Empty
                } else {
                    AwsHealthEvidenceState::Complete
                };
                let classification = if state == AwsHealthEvidenceState::Empty {
                    AwsHealthEvidenceClassification::Empty
                } else if state == AwsHealthEvidenceState::PartialFailure {
                    AwsHealthEvidenceClassification::PartialFailure
                } else {
                    AwsHealthEvidenceClassification::Normalized
                };
                Ok(build_evidence(
                    &self.provider,
                    provenance,
                    [AwsHealthOperation::DescribeEvents],
                    state,
                    classification,
                    request_digest,
                    response.response_digest,
                    response.events,
                    Vec::new(),
                    Vec::new(),
                    response.failed_events,
                ))
            }
            Err(error) => self.evidence_from_failure(
                AwsHealthOperation::DescribeEvents,
                request_digest,
                provenance,
                error,
            ),
        }
    }

    pub fn read_event_details(
        &mut self,
    ) -> Result<AwsHealthEventEvidence, AwsHealthEventServiceError> {
        self.ensure_active()?;
        let request = self.provider.details_request()?;
        let request_digest = request.request_digest();
        let provenance = self.provider.provenance();
        match self.provider.describe_event_details(request) {
            Ok(response) => {
                let records = response
                    .details
                    .iter()
                    .map(AwsHealthEventDetail::record)
                    .cloned()
                    .collect::<Vec<_>>();
                self.remember_event_revisions(&records)?;
                let state = if !response.failed_events.is_empty() {
                    AwsHealthEvidenceState::PartialFailure
                } else if response.details.is_empty() {
                    AwsHealthEvidenceState::Empty
                } else {
                    AwsHealthEvidenceState::Complete
                };
                let classification = if state == AwsHealthEvidenceState::Empty {
                    AwsHealthEvidenceClassification::Empty
                } else if state == AwsHealthEvidenceState::PartialFailure {
                    AwsHealthEvidenceClassification::PartialFailure
                } else {
                    AwsHealthEvidenceClassification::Normalized
                };
                Ok(build_evidence(
                    &self.provider,
                    provenance,
                    [AwsHealthOperation::DescribeEventDetails],
                    state,
                    classification,
                    request_digest,
                    response.response_digest,
                    Vec::new(),
                    response.details,
                    Vec::new(),
                    response.failed_events,
                ))
            }
            Err(error) => self.evidence_from_failure(
                AwsHealthOperation::DescribeEventDetails,
                request_digest,
                provenance,
                error,
            ),
        }
    }

    pub fn read_affected_entities(
        &mut self,
    ) -> Result<AwsHealthEventEvidence, AwsHealthEventServiceError> {
        self.ensure_active()?;
        let request = self.provider.affected_entities_request()?;
        let request_digest = request.request_digest();
        let provenance = self.provider.provenance();
        match self.provider.describe_affected_entities(request) {
            Ok(response) => {
                let state = if !response.failed_events.is_empty() || response.truncated {
                    AwsHealthEvidenceState::PartialFailure
                } else if response.entities.is_empty() {
                    AwsHealthEvidenceState::Empty
                } else {
                    AwsHealthEvidenceState::Complete
                };
                let classification = if state == AwsHealthEvidenceState::Empty {
                    AwsHealthEvidenceClassification::Empty
                } else if state == AwsHealthEvidenceState::PartialFailure {
                    AwsHealthEvidenceClassification::PartialFailure
                } else {
                    AwsHealthEvidenceClassification::Normalized
                };
                Ok(build_evidence(
                    &self.provider,
                    provenance,
                    [AwsHealthOperation::DescribeAffectedEntities],
                    state,
                    classification,
                    request_digest,
                    response.response_digest,
                    Vec::new(),
                    Vec::new(),
                    response.entities,
                    response.failed_events,
                ))
            }
            Err(error) => self.evidence_from_failure(
                AwsHealthOperation::DescribeAffectedEntities,
                request_digest,
                provenance,
                error,
            ),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AwsHealthEventProposal, AwsHealthEventServiceError> {
        let evidence = self.read_events()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_event_details_proposal(
        &mut self,
    ) -> Result<AwsHealthEventProposal, AwsHealthEventServiceError> {
        let evidence = self.read_event_details()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_affected_entities_proposal(
        &mut self,
    ) -> Result<AwsHealthEventProposal, AwsHealthEventServiceError> {
        let evidence = self.read_affected_entities()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: AwsHealthEventEvidence,
    ) -> Result<AwsHealthEventProposal, AwsHealthEventServiceError> {
        self.ensure_active()?;
        self.verify_evidence(&evidence)?;
        let mut proposal = AwsHealthEventProposal {
            evidence,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            scope_digest: self.scope().scope_digest().clone(),
            event_filter_digest: self.scope().event_filter_digest(),
            evidence_policy_digest: evidence_policy_digest(),
            permission_digest: self.scope().permission_fence().digest().clone(),
            consent_digest: self.scope().consent().digest().clone(),
            proposal_only: true,
            native: false,
            connected: false,
            outage_causality: false,
            operational_truth: false,
            proposal_digest: Digest::from_text("uninitialized"),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsHealthEventProposal,
    ) -> Result<(), AwsHealthEventServiceError> {
        self.ensure_active()?;
        proposal.validate_digest()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.outage_causality
            || proposal.operational_truth
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.scope_digest != *self.scope().scope_digest()
            || proposal.event_filter_digest != self.scope().event_filter_digest()
            || proposal.evidence_policy_digest != evidence_policy_digest()
            || proposal.permission_digest != *self.scope().permission_fence().digest()
            || proposal.consent_digest != *self.scope().consent().digest()
        {
            return Err(AwsHealthEventServiceError::ProposalMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn record_observation(
        &self,
        proposal: &AwsHealthEventProposal,
    ) -> Result<AwsHealthObservationReceipt, AwsHealthEventServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AwsHealthObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: self.registration().registration_digest.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
        })
    }

    pub fn record_receipt(
        &self,
        proposal: &AwsHealthEventProposal,
    ) -> Result<AwsHealthObservationReceipt, AwsHealthEventServiceError> {
        self.record_observation(proposal)
    }

    pub fn read_back(
        &self,
        proposal: &AwsHealthEventProposal,
    ) -> Result<AwsHealthReadbackReceipt, AwsHealthEventServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AwsHealthReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_proposal".to_owned(),
            independent_native_readback: false,
            native: false,
            connected: false,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, AwsHealthEventServiceError> {
        Ok(self.provider.revoke()?)
    }

    pub fn restore(&mut self) -> Result<(), AwsHealthEventServiceError> {
        Ok(self.provider.restore()?)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AwsHealthEventServiceError> {
        Ok(self.provider.revoke_secret()?)
    }

    fn ensure_active(&self) -> Result<(), AwsHealthEventServiceError> {
        if self.registration().state != RegistrationState::Active {
            Err(AwsHealthEventServiceError::RegistrationRevoked)
        } else if self.provider.secret_reference().is_revoked() {
            Err(AwsHealthEventServiceError::SecretRevoked)
        } else {
            Ok(())
        }
    }

    fn remember_event_revisions(
        &mut self,
        events: &[AwsHealthEventRecord],
    ) -> Result<(), AwsHealthEventServiceError> {
        for event in events {
            let key = event.event_arn().digest();
            if self
                .observed_event_revisions
                .get(&key)
                .is_some_and(|revision| *revision != event.event_revision())
            {
                return Err(AwsHealthEventServiceError::EventRevisionDrift);
            }
            self.observed_event_revisions
                .insert(key, event.event_revision());
        }
        Ok(())
    }

    fn verify_evidence(
        &self,
        evidence: &AwsHealthEventEvidence,
    ) -> Result<(), AwsHealthEventServiceError> {
        evidence
            .validate()
            .map_err(|_| AwsHealthEventServiceError::EvidenceMismatch)?;
        let digests = &evidence.digests;
        if evidence.scope_digest != *self.scope().scope_digest()
            || evidence.permission_digest != *self.scope().permission_fence().digest()
            || evidence.consent_digest != *self.scope().consent().digest()
            || evidence.provenance != self.provider.provenance()
            || digests.contract_digest != crate::contract_digest()
            || digests.plugin_version_digest
                != Digest::from_text(AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION)
            || digests.provider_digest != self.provider.provider_digest()
            || digests.registration_digest != self.registration().registration_digest
            || digests.scope_digest != *self.scope().scope_digest()
            || digests.event_filter_digest != self.scope().event_filter_digest()
            || digests.evidence_policy_digest != evidence_policy_digest()
            || digests.permission_digest != *self.scope().permission_fence().digest()
            || digests.consent_digest != *self.scope().consent().digest()
            || evidence.outage_causality
            || evidence.operational_truth
            || evidence.native
            || evidence.connected
        {
            return Err(AwsHealthEventServiceError::EvidenceMismatch);
        }
        Ok(())
    }

    fn evidence_from_failure(
        &self,
        operation: AwsHealthOperation,
        request_digest: Digest,
        provenance: ProviderProvenance,
        error: AwsHealthProviderError,
    ) -> Result<AwsHealthEventEvidence, AwsHealthEventServiceError> {
        match error {
            AwsHealthProviderError::Transport(transport_error) => {
                let (state, classification) = failure_state(&transport_error, provenance);
                let failed = vec![crate::AwsHealthFailedEvent::new(
                    self.scope().event_arn(),
                    transport_error.kind(),
                    transport_error.status_code(),
                    transport_error.diagnostic_digest().as_str(),
                )];
                Ok(build_evidence(
                    &self.provider,
                    provenance,
                    [operation],
                    state,
                    classification,
                    request_digest,
                    transport_error.diagnostic_digest().clone(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    failed,
                ))
            }
            AwsHealthProviderError::RegistrationRevoked => {
                Err(AwsHealthEventServiceError::RegistrationRevoked)
            }
            AwsHealthProviderError::SecretRevoked => Err(AwsHealthEventServiceError::SecretRevoked),
            AwsHealthProviderError::PermissionDenied => {
                Err(AwsHealthEventServiceError::FenceViolation)
            }
            AwsHealthProviderError::ScopeMismatch => Err(AwsHealthEventServiceError::ScopeMismatch),
            AwsHealthProviderError::MissingEventArn
            | AwsHealthProviderError::InvalidResponse
            | AwsHealthProviderError::Definition(_)
            | AwsHealthProviderError::Model(_) => Err(error.into()),
        }
    }
}

fn failure_state(
    error: &TransportError,
    provenance: ProviderProvenance,
) -> (AwsHealthEvidenceState, AwsHealthEvidenceClassification) {
    match error.kind() {
        AwsHealthFailureKind::Throttled => (
            AwsHealthEvidenceState::RateLimited,
            AwsHealthEvidenceClassification::RateLimited,
        ),
        AwsHealthFailureKind::Unauthorized
        | AwsHealthFailureKind::AccessDenied
        | AwsHealthFailureKind::NotFound => (
            AwsHealthEvidenceState::AccessLost,
            AwsHealthEvidenceClassification::AccessLost,
        ),
        AwsHealthFailureKind::Conflict | AwsHealthFailureKind::RevisionDrift => (
            AwsHealthEvidenceState::Stale,
            AwsHealthEvidenceClassification::Stale,
        ),
        AwsHealthFailureKind::BlockedEnv if provenance.is_blocked_env() => (
            AwsHealthEvidenceState::AccessLost,
            AwsHealthEvidenceClassification::BlockedEnv,
        ),
        _ => (
            AwsHealthEvidenceState::ProviderUnknown,
            AwsHealthEvidenceClassification::ProviderUnknown,
        ),
    }
}

fn build_evidence<T: AwsHealthTransport>(
    provider: &AwsHealthProvider<T>,
    provenance: ProviderProvenance,
    operations: impl IntoIterator<Item = AwsHealthOperation>,
    state: AwsHealthEvidenceState,
    classification: AwsHealthEvidenceClassification,
    request_digest: Digest,
    response_digest: Digest,
    events: Vec<AwsHealthEventRecord>,
    details: Vec<AwsHealthEventDetail>,
    affected_entities: Vec<crate::AffectedEntityReference>,
    failed_events: Vec<crate::AwsHealthFailedEvent>,
) -> AwsHealthEventEvidence {
    let operations = operations.into_iter().collect::<BTreeSet<_>>();
    let events_digest = digest_serialized("events", &events);
    let details_digest = digest_serialized("details", &details);
    let affected_entities_digest = digest_serialized("affected-entities", &affected_entities);
    let failed_set_digest = digest_serialized("failed-set", &failed_events);
    let digests = AwsHealthEvidenceDigests {
        contract_digest: crate::contract_digest(),
        plugin_version_digest: Digest::from_text(AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION),
        provider_digest: provider.provider_digest(),
        registration_digest: provider.registration().registration_digest.clone(),
        scope_digest: provider.scope().scope_digest().clone(),
        event_filter_digest: provider.scope().event_filter_digest(),
        evidence_policy_digest: evidence_policy_digest(),
        permission_digest: provider.scope().permission_fence().digest().clone(),
        consent_digest: provider.scope().consent().digest().clone(),
        request_digest,
        response_digest,
        events_digest,
        details_digest,
        affected_entities_digest,
        failed_set_digest,
    };
    let mut evidence = AwsHealthEventEvidence {
        state,
        classification,
        provenance,
        operations,
        scope_digest: provider.scope().scope_digest().clone(),
        permission_digest: provider.scope().permission_fence().digest().clone(),
        consent_digest: provider.scope().consent().digest().clone(),
        events,
        details,
        affected_entities,
        failed_events,
        digests,
        provider_reported_only: true,
        outage_causality: false,
        operational_truth: false,
        native: false,
        connected: false,
        evidence_digest: Digest::from_text("uninitialized"),
    };
    evidence.evidence_digest = evidence.compute_digest();
    evidence
}

fn digest_serialized<T: Serialize>(domain: &str, value: &T) -> Digest {
    Digest::from_fields(
        domain,
        &[serde_json::to_string(value).expect("typed evidence value serializes")],
    )
}

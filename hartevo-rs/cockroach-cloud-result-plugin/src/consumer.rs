use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{
    CONSUMER_ID, CockroachCloudCapabilities, CockroachCloudProposal,
    CockroachCloudProviderDefinition, CockroachCloudRegistration, CockroachCloudScope, Digest,
    EvidenceState, EvidenceVerification,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionCockroachCloudDecisionState {
    Healthy,
    Degraded,
    Unavailable,
    Absent,
    Denied,
    Partial,
    Expired,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    Stale,
    RegistrationRevoked,
}

impl From<EvidenceState> for MissionCockroachCloudDecisionState {
    fn from(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Healthy => Self::Healthy,
            EvidenceState::Degraded => Self::Degraded,
            EvidenceState::Unavailable => Self::Unavailable,
            EvidenceState::Absent => Self::Absent,
            EvidenceState::Denied => Self::Denied,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::Expired => Self::Expired,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::RateLimited => Self::RateLimited,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Stale => Self::Stale,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeProjection {
    pub id_digest: Digest,
    pub revision: crate::Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCockroachCloudResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub project: MissionScopeProjection,
    pub mission: MissionScopeProjection,
    pub work_product: MissionScopeProjection,
    pub state: EvidenceState,
    pub decision_state: MissionCockroachCloudDecisionState,
    pub provider_provenance: crate::TransportProvenance,
    pub review_only: bool,
    pub requires_human_review: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub health_certification_claim: bool,
    pub security_truth_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub decision_digest: Digest,
}

impl MissionCockroachCloudResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCockroachCloudRecord {
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
    pub replayed: bool,
    pub record_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumerError {
    RegistrationInactive,
    ScopeMismatch,
    ProposalTampered,
    RecordingConflict,
    InvalidInput,
}

impl std::fmt::Display for ConsumerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::RegistrationInactive => "Mission CockroachDB Cloud registration is inactive",
            Self::ScopeMismatch => "Mission CockroachDB Cloud scope or revision does not match",
            Self::ProposalTampered => "Mission CockroachDB Cloud proposal is stale or tampered",
            Self::RecordingConflict => "Mission CockroachDB Cloud idempotency key conflicts",
            Self::InvalidInput => "Mission CockroachDB Cloud input is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ConsumerError {}

/// Mission-scoped consumer. It returns a review projection and has no Truth,
/// Effect, durable storage, Outcome, or Work Product adoption authority.
pub struct MissionCockroachCloudConsumer {
    scope: CockroachCloudScope,
    registration: CockroachCloudRegistration,
    records: BTreeMap<Digest, Digest>,
}

impl fmt::Debug for MissionCockroachCloudConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionCockroachCloudConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionCockroachCloudConsumer {
    pub fn new(
        scope: CockroachCloudScope,
        registration: CockroachCloudRegistration,
    ) -> Result<Self, ConsumerError> {
        let provider = CockroachCloudProviderDefinition::baseline();
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        registration
            .validate(&scope, &provider)
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if !registration.is_active() {
            return Err(ConsumerError::RegistrationInactive);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &CockroachCloudScope {
        &self.scope
    }

    pub fn registration(&self) -> &CockroachCloudRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn capabilities(&self) -> CockroachCloudCapabilities {
        crate::CockroachCloudResultService::<crate::FixtureTransport>::definition()
    }

    pub fn consume(
        &self,
        proposal: &CockroachCloudProposal,
    ) -> Result<MissionCockroachCloudResult, ConsumerError> {
        proposal
            .validate_integrity(&self.scope)
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if !self.registration.is_active()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.digest()
            || proposal.revision_fence_digest != self.scope.revision_fence_digest()
            || proposal.permission_digest != *self.scope.permission_digest()
        {
            return Err(ConsumerError::RegistrationInactive);
        }
        let decision_state = proposal.state.into();
        let decision_digest = Digest::from_serializable(&(
            CONSUMER_ID,
            &self.registration.registration_digest,
            &self.scope.digest(),
            &proposal.proposal_digest,
            &proposal.evidence_digest,
            decision_state,
        ));
        Ok(MissionCockroachCloudResult {
            service_id: crate::SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            revision_fence_digest: self.scope.revision_fence_digest(),
            project: MissionScopeProjection {
                id_digest: self.scope.project.id.digest(),
                revision: self.scope.project.revision,
            },
            mission: MissionScopeProjection {
                id_digest: self.scope.mission.id.digest(),
                revision: self.scope.mission.revision,
            },
            work_product: MissionScopeProjection {
                id_digest: self.scope.work_product.id.digest(),
                revision: self.scope.work_product.revision,
            },
            state: proposal.state,
            decision_state,
            provider_provenance: proposal.evidence.provider_provenance,
            review_only: true,
            requires_human_review: true,
            connected: false,
            native: false,
            first_party: false,
            health_certification_claim: false,
            security_truth_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            decision_digest,
        })
    }

    pub fn record(
        &mut self,
        proposal: &CockroachCloudProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<MissionCockroachCloudRecord, ConsumerError> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.trim().is_empty()
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(ConsumerError::InvalidInput);
        }
        let idempotency_digest = Digest::from_text(idempotency_key);
        if let Some(existing_proposal) = self.records.get(&idempotency_digest) {
            if existing_proposal != &proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            return Ok(MissionCockroachCloudRecord {
                idempotency_digest: idempotency_digest.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
                replayed: true,
                record_digest: Digest::from_serializable(&(
                    "mission-record",
                    &idempotency_digest,
                    &proposal.proposal_digest,
                    true,
                )),
                connected: false,
                native: false,
                first_party: false,
            });
        }
        self.records
            .insert(idempotency_digest.clone(), proposal.proposal_digest.clone());
        Ok(MissionCockroachCloudRecord {
            idempotency_digest: idempotency_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            replayed: false,
            record_digest: Digest::from_serializable(&(
                "mission-record",
                &idempotency_digest,
                &proposal.proposal_digest,
                false,
            )),
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn verify(&self, proposal: &CockroachCloudProposal) -> EvidenceVerification {
        match self.consume(proposal) {
            Ok(result) => EvidenceVerification {
                valid: true,
                state: result.state,
                scope_digest: result.scope_digest,
                proposal_digest: result.proposal_digest,
                evidence_digest: result.evidence_digest,
                requires_human_review: true,
                failure: None,
                connected: false,
                native: false,
                first_party: false,
            },
            Err(error) => EvidenceVerification {
                valid: false,
                state: EvidenceState::Stale,
                scope_digest: self.scope.digest(),
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence_digest.clone(),
                requires_human_review: true,
                failure: Some(crate::VerificationFailure {
                    code: error.to_string(),
                    digest: Digest::from_text(error.to_string()),
                }),
                connected: false,
                native: false,
                first_party: false,
            },
        }
    }

    pub fn revoke_registration(&mut self) -> Result<(), ConsumerError> {
        self.registration
            .revoke()
            .map(|_| ())
            .map_err(|_| ConsumerError::RegistrationInactive)
    }
}

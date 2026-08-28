use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CONSUMER_ID, PLUGIN_VERSION, contract_digest,
    error::ModelError,
    model::{
        AuthorityBoundary, Digest, EvidenceStatus, MissionBinding, MonteCarloObservabilityScope,
        ObservationState,
    },
    service::{ObservabilityResult, Registration, RegistrationState},
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("Mission, Project, Work Product, Consent, or revision is stale")]
    StaleMission,
    #[error("consumer registration is revoked or unbound")]
    Revoked,
    #[error("Monte Carlo evidence is tampered or incomplete")]
    TamperedEvidence,
    #[error(
        "partial, denied, access-lost, rate-limited, or provider-unknown evidence is non-adoptable"
    )]
    PartialEvidence,
    #[error("Layer-1 evidence cannot claim kernel authority, native execution, or Connected")]
    AuthorityClaim,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataQualityDecision {
    InvestigateOpenIncident,
    ReviewResolvedIncident,
    NeedsVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionMonteCarloObservabilityResult {
    pub consumer_id: String,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub incident_packet_digest: Digest,
    pub decision: DataQualityDecision,
    pub evidence_status: EvidenceStatus,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub result_digest: Digest,
}

pub struct MissionMonteCarloObservabilityConsumer {
    mission: MissionBinding,
    scope_digest: Digest,
    project_digest: Digest,
    work_product_digest: Digest,
    consent_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
}

impl std::fmt::Debug for MissionMonteCarloObservabilityConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionMonteCarloObservabilityConsumer")
            .field("mission", &self.mission)
            .field("scope_digest", &self.scope_digest)
            .field("project_digest", &self.project_digest)
            .field("work_product_digest", &self.work_product_digest)
            .field("consent_digest", &self.consent_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl MissionMonteCarloObservabilityConsumer {
    pub fn new(scope: &MonteCarloObservabilityScope) -> Self {
        Self {
            mission: scope.mission().clone(),
            scope_digest: scope.digest().clone(),
            project_digest: scope.project_binding().digest.clone(),
            work_product_digest: scope.work_product().digest.clone(),
            consent_digest: scope.consent().digest.clone(),
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn from_bindings(
        mission: MissionBinding,
        scope_digest: Digest,
        project_digest: Digest,
        work_product_digest: Digest,
        consent_digest: Digest,
    ) -> Self {
        Self {
            mission,
            scope_digest,
            project_digest,
            work_product_digest,
            consent_digest,
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn bind_registration(&mut self, registration: &Registration) -> Result<(), ConsumerError> {
        if registration.state != RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        if registration.scope_digest != self.scope_digest
            || registration.project_binding_digest != self.project_digest
            || registration.work_product_digest != self.work_product_digest
            || registration.consent_digest != self.consent_digest
            || registration.mission_digest != self.mission.digest
            || registration.contract_digest != contract_digest()
            || registration.version != PLUGIN_VERSION
            || !registration.reversible
            || !registration.revocable
        {
            return Err(ConsumerError::StaleMission);
        }
        registration.registration_digest.validate()?;
        self.registration_digest = Some(registration.registration_digest.clone());
        Ok(())
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn replace_mission(&mut self, mission: MissionBinding) {
        self.mission = mission;
    }

    pub fn verify_result(&self, result: &ObservabilityResult) -> Result<(), ConsumerError> {
        self.ensure_usable()?;
        result
            .verify_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        let evidence = &result.evidence;
        if result.proposal.consumer_id != CONSUMER_ID
            || result.proposal.scope_digest != self.scope_digest
            || evidence.scope_digest != self.scope_digest
            || evidence.mission_digest != self.mission.digest
            || evidence.project_binding_digest != self.project_digest
            || evidence.work_product_digest != self.work_product_digest
            || evidence.consent_digest != self.consent_digest
            || self
                .registration_digest
                .as_ref()
                .is_some_and(|digest| *digest != result.proposal.registration_digest)
        {
            return Err(ConsumerError::StaleMission);
        }
        if evidence.authority != AuthorityBoundary::layer1()
            || evidence.provenance.connected()
            || evidence.provenance.native()
            || evidence.provenance.first_party()
            || result.proposal.native_execution
        {
            return Err(ConsumerError::AuthorityClaim);
        }
        Ok(())
    }

    pub fn consume(
        &self,
        result: &ObservabilityResult,
    ) -> Result<MissionMonteCarloObservabilityResult, ConsumerError> {
        self.verify_result(result)?;
        if result.evidence.status != EvidenceStatus::Complete {
            return Err(ConsumerError::PartialEvidence);
        }
        self.build_result(result)
    }

    pub fn propose_data_quality_decision(
        &self,
        result: &ObservabilityResult,
    ) -> Result<MissionMonteCarloObservabilityResult, ConsumerError> {
        self.consume(result)
    }

    fn build_result(
        &self,
        result: &ObservabilityResult,
    ) -> Result<MissionMonteCarloObservabilityResult, ConsumerError> {
        let evidence = &result.evidence;
        let decision = match evidence.state {
            ObservationState::Open => DataQualityDecision::InvestigateOpenIncident,
            ObservationState::Resolved => DataQualityDecision::ReviewResolvedIncident,
            ObservationState::Unknown => DataQualityDecision::NeedsVerification,
            ObservationState::Partial
            | ObservationState::AccessLost
            | ObservationState::Denied
            | ObservationState::RateLimited
            | ObservationState::ProviderUnknown
            | ObservationState::Tampered => return Err(ConsumerError::PartialEvidence),
        };
        let incident_packet_digest = crate::model::digest_serializable(&(
            &evidence.incidents,
            &evidence.incident_states,
            &evidence.freshness,
            &evidence.freshness_states,
            &evidence.lineage,
            &evidence.lineage_summaries,
            &evidence.monitors,
            &evidence.monitor_states,
            evidence.state,
        ))?;
        let mut consumed = MissionMonteCarloObservabilityResult {
            consumer_id: CONSUMER_ID.to_owned(),
            mission_digest: self.mission.digest.clone(),
            project_digest: self.project_digest.clone(),
            work_product_digest: self.work_product_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            registration_digest: result.proposal.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            incident_packet_digest,
            decision,
            evidence_status: evidence.status,
            accepted: true,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            connected: false,
            native: false,
            result_digest: Digest::from_text("pending-montecarlo-mission-result"),
        };
        consumed.result_digest = crate::model::digest_serializable(&(
            &consumed.consumer_id,
            &consumed.mission_digest,
            &consumed.project_digest,
            &consumed.work_product_digest,
            &consumed.consent_digest,
            &consumed.registration_digest,
            &consumed.evidence_digest,
            &consumed.incident_packet_digest,
            consumed.decision,
            consumed.evidence_status,
            consumed.accepted,
            consumed.adopted_outcome,
            consumed.adopted_work_product,
            consumed.truth_authority,
            consumed.connected,
            consumed.native,
        ))?;
        Ok(consumed)
    }

    fn ensure_usable(&self) -> Result<(), ConsumerError> {
        if self.revoked || self.registration_digest.is_none() {
            Err(ConsumerError::Revoked)
        } else {
            Ok(())
        }
    }
}

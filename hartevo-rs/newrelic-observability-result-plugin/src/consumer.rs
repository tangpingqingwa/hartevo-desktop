use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CONSUMER_ID,
    error::ModelError,
    model::{AuthorityBoundary, Digest, EvidenceStatus, MissionBinding, ObservabilityScope},
    service::{
        ObservabilityEvidence, ObservabilityResult, ObservabilityResultProposal, Registration,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("Mission, Project, Work Product, Consent, or revision is stale")]
    StaleMission,
    #[error("consumer registration is revoked or unbound")]
    Revoked,
    #[error("permission or query fence was lost")]
    FenceLoss,
    #[error("New Relic evidence is tampered or incomplete")]
    TamperedEvidence,
    #[error("partial New Relic evidence is not adoptable")]
    PartialEvidence,
    #[error("Layer-1 evidence cannot claim kernel authority or native connection")]
    AuthorityClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNewRelicObservabilityResult {
    pub consumer_id: String,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub evidence: ObservabilityEvidence,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub incident_packet_digest: Digest,
    pub result_digest: Digest,
}

pub struct MissionNewRelicObservabilityConsumer {
    mission: MissionBinding,
    scope_digest: Digest,
    permission_digest: Digest,
    query_digest: Digest,
    project_digest: Digest,
    work_product_digest: Digest,
    consent_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
}

impl std::fmt::Debug for MissionNewRelicObservabilityConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionNewRelicObservabilityConsumer")
            .field("mission", &self.mission)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("query_digest", &self.query_digest)
            .field("project_digest", &self.project_digest)
            .field("work_product_digest", &self.work_product_digest)
            .field("consent_digest", &self.consent_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl MissionNewRelicObservabilityConsumer {
    pub fn new(scope: &ObservabilityScope) -> Self {
        Self {
            mission: scope.mission().clone(),
            scope_digest: scope.digest().clone(),
            permission_digest: scope.permissions().digest.clone(),
            query_digest: scope.query_policy().digest.clone(),
            project_digest: scope.project().digest.clone(),
            work_product_digest: scope.work_product().digest.clone(),
            consent_digest: scope.consent().digest.clone(),
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn from_bindings(
        mission: MissionBinding,
        scope_digest: Digest,
        permission_digest: Digest,
        query_digest: Digest,
        project_digest: Digest,
        work_product_digest: Digest,
        consent_digest: Digest,
    ) -> Self {
        Self {
            mission,
            scope_digest,
            permission_digest,
            query_digest,
            project_digest,
            work_product_digest,
            consent_digest,
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn bind_registration(&mut self, registration: &Registration) -> Result<(), ConsumerError> {
        if registration.state != crate::service::RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        if registration.scope_digest != self.scope_digest
            || registration.permission_digest != self.permission_digest
            || registration.query_digest != self.query_digest
            || registration.contract_digest != crate::contract_digest()
            || registration.version != crate::PLUGIN_VERSION
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

    pub fn verify_proposal(
        &self,
        proposal: &ObservabilityResultProposal,
    ) -> Result<(), ConsumerError> {
        self.ensure_usable()?;
        proposal
            .verify_digest()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if proposal.scope_digest != self.scope_digest
            || proposal.permission_digest != self.permission_digest
            || proposal.query_digest != self.query_digest
            || proposal.consumer_id != CONSUMER_ID
        {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.native_execution || proposal.authority != AuthorityBoundary::layer1() {
            return Err(ConsumerError::AuthorityClaim);
        }
        if let Some(registration_digest) = &self.registration_digest
            && proposal.registration_digest != *registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        Ok(())
    }

    pub fn consume(
        &self,
        result: &ObservabilityResult,
    ) -> Result<MissionNewRelicObservabilityResult, ConsumerError> {
        self.ensure_usable()?;
        self.verify_proposal(&result.proposal)?;
        result
            .evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        result
            .verify_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        self.validate_evidence(&result.evidence)?;
        if result.evidence.status != EvidenceStatus::Complete {
            return Err(ConsumerError::PartialEvidence);
        }
        self.build_consumed(&result.evidence)
    }

    fn build_consumed(
        &self,
        evidence: &ObservabilityEvidence,
    ) -> Result<MissionNewRelicObservabilityResult, ConsumerError> {
        let incident_packet_digest = crate::model::digest_serializable(&(
            &evidence.issues,
            &evidence.incidents,
            &evidence.state,
        ))?;
        let mut consumed = MissionNewRelicObservabilityResult {
            consumer_id: CONSUMER_ID.to_owned(),
            mission_digest: self.mission.digest.clone(),
            project_digest: self.project_digest.clone(),
            work_product_digest: self.work_product_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            evidence: evidence.clone(),
            accepted: true,
            adopted_outcome: false,
            truth_authority: false,
            incident_packet_digest,
            result_digest: Digest::from_text("pending-mission-newrelic-result"),
        };
        consumed.result_digest = crate::model::digest_serializable(&(
            &consumed.consumer_id,
            &consumed.mission_digest,
            &consumed.project_digest,
            &consumed.work_product_digest,
            &consumed.consent_digest,
            &consumed.evidence.evidence_digest,
            consumed.accepted,
            consumed.adopted_outcome,
            consumed.truth_authority,
            &consumed.incident_packet_digest,
        ))?;
        Ok(consumed)
    }

    pub fn consume_evidence(
        &self,
        evidence: &ObservabilityEvidence,
    ) -> Result<MissionNewRelicObservabilityResult, ConsumerError> {
        self.ensure_usable()?;
        evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        self.validate_evidence(evidence)?;
        if evidence.status != EvidenceStatus::Complete {
            return Err(ConsumerError::PartialEvidence);
        }
        self.build_consumed(evidence)
    }

    fn ensure_usable(&self) -> Result<(), ConsumerError> {
        if self.revoked || self.registration_digest.is_none() {
            Err(ConsumerError::Revoked)
        } else {
            Ok(())
        }
    }

    fn validate_evidence(&self, evidence: &ObservabilityEvidence) -> Result<(), ConsumerError> {
        if evidence.authority != AuthorityBoundary::layer1()
            || evidence.provenance.connected()
            || evidence.provenance.native()
            || evidence.provenance.first_party()
        {
            return Err(ConsumerError::AuthorityClaim);
        }
        if evidence.scope_digest != self.scope_digest
            || evidence.permission_digest != self.permission_digest
            || evidence.query_digest != self.query_digest
            || evidence.mission_digest != self.mission.digest
            || evidence.project_digest != self.project_digest
            || evidence.work_product_digest != self.work_product_digest
            || evidence.consent_digest != self.consent_digest
            || self
                .registration_digest
                .as_ref()
                .is_some_and(|digest| evidence.registration_digest != *digest)
        {
            return Err(ConsumerError::StaleMission);
        }
        Ok(())
    }
}

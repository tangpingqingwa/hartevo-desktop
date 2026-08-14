use crate::model::{EvidenceProvenance, KubernetesRolloutScope, RolloutEvidence, RolloutPhase};
use crate::service::{
    KubernetesRolloutError, KubernetesRolloutReceipt, KubernetesRolloutRegistration,
    KubernetesRolloutServiceDefinition, RolloutVerification,
};
use crate::{MISSION_CONSUMER_ID, contract_digest, digest_json, valid_identifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalNextAction {
    ReviewCompleteEvidence,
    ReadAgain,
    RepairAccess,
    ReconcileObjectIdentity,
    InspectProviderEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionRolloutFailure {
    Deleted,
    AccessLost,
    ProviderUnknown,
    BlockedEnv,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesRolloutResultProposal {
    pub result_version: String,
    pub consumer_id: String,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub scope_digest: String,
    pub registration_digest: String,
    pub phase: RolloutPhase,
    pub complete: bool,
    pub object_uid: Option<String>,
    pub resource_version: Option<String>,
    pub generation: Option<u64>,
    pub observed_generation: Option<u64>,
    pub evidence_digest: Option<String>,
    pub receipt_digest: Option<String>,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
    pub outcome_adopted: bool,
    pub authority: String,
    pub next_action: ProposalNextAction,
    pub result_digest: String,
}

impl KubernetesRolloutResultProposal {
    pub fn validate(&self) -> Result<(), MissionConsumerError> {
        if self.result_version != "kubernetes-rollout-result-proposal/v1"
            || self.consumer_id != MISSION_CONSUMER_ID
            || !valid_identifier(&self.mission_id, 256)
            || !valid_identifier(&self.project_id, 256)
            || !valid_identifier(&self.work_product_id, 256)
            || !crate::valid_sha256_digest(&self.scope_digest)
            || !crate::valid_sha256_digest(&self.registration_digest)
            || self
                .evidence_digest
                .as_deref()
                .is_some_and(|digest| !crate::valid_sha256_digest(digest))
            || self
                .receipt_digest
                .as_deref()
                .is_some_and(|digest| !crate::valid_sha256_digest(digest))
            || self.connected
            || self.native
            || self.outcome_adopted
            || self.authority != "mission_result_proposal"
            || self.result_digest != self.compute_digest()
        {
            return Err(MissionConsumerError::TamperedProposal);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        #[allow(clippy::struct_excessive_bools)]
        #[derive(Serialize)]
        struct Material<'a> {
            result_version: &'a str,
            consumer_id: &'a str,
            mission_id: &'a str,
            project_id: &'a str,
            work_product_id: &'a str,
            scope_digest: &'a str,
            registration_digest: &'a str,
            phase: RolloutPhase,
            complete: bool,
            object_uid: &'a Option<String>,
            resource_version: &'a Option<String>,
            generation: Option<u64>,
            observed_generation: Option<u64>,
            evidence_digest: &'a Option<String>,
            receipt_digest: &'a Option<String>,
            provenance: EvidenceProvenance,
            connected: bool,
            native: bool,
            outcome_adopted: bool,
            authority: &'a str,
            next_action: ProposalNextAction,
        }
        digest_json(&Material {
            result_version: &self.result_version,
            consumer_id: &self.consumer_id,
            mission_id: &self.mission_id,
            project_id: &self.project_id,
            work_product_id: &self.work_product_id,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            phase: self.phase,
            complete: self.complete,
            object_uid: &self.object_uid,
            resource_version: &self.resource_version,
            generation: self.generation,
            observed_generation: self.observed_generation,
            evidence_digest: &self.evidence_digest,
            receipt_digest: &self.receipt_digest,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            outcome_adopted: self.outcome_adopted,
            authority: &self.authority,
            next_action: self.next_action,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MissionConsumerError {
    #[error("consumer is not bound to the exact mission/project/work-product scope")]
    ScopeMismatch,
    #[error("rollout receipt or evidence could not be verified")]
    VerificationFailed,
    #[error("Mission result proposal was tampered with")]
    TamperedProposal,
    #[error("consumer definition drifted")]
    DefinitionDrift,
}

#[derive(Clone, Debug)]
pub struct MissionKubernetesRolloutConsumer {
    scope: KubernetesRolloutScope,
    mission_id: String,
    project_id: String,
    work_product_id: String,
    scope_digest: String,
    registration_digest: String,
}

impl MissionKubernetesRolloutConsumer {
    pub fn new(
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
    ) -> Result<Self, MissionConsumerError> {
        registration
            .validate(scope)
            .map_err(|_| MissionConsumerError::ScopeMismatch)?;
        if !registration.is_active() {
            return Err(MissionConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope: scope.clone(),
            mission_id: scope.mission_id.clone(),
            project_id: scope.project_id.clone(),
            work_product_id: scope.work_product_id.clone(),
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
        })
    }

    pub fn definition() -> crate::MissionKubernetesRolloutConsumerDefinition {
        crate::MissionKubernetesRolloutConsumerDefinition {
            consumer_id: MISSION_CONSUMER_ID.into(),
            authority: "mission_result_proposal".into(),
            outcome_adoption: false,
        }
    }

    pub fn service_definition(&self) -> KubernetesRolloutServiceDefinition {
        crate::KubernetesRolloutService::<crate::KubernetesApiRolloutProvider>::definition()
    }

    pub fn consume(
        &self,
        receipt: &KubernetesRolloutReceipt,
        evidence: &RolloutEvidence,
        verification: &RolloutVerification,
    ) -> Result<KubernetesRolloutResultProposal, MissionConsumerError> {
        receipt
            .validate()
            .map_err(|_| MissionConsumerError::VerificationFailed)?;
        evidence
            .validate_against_scope(&self.scope)
            .map_err(|_| MissionConsumerError::VerificationFailed)?;
        if !verification.verified
            || !verification.below_kernel_authority
            || verification.scope_digest != self.scope_digest
            || verification.evidence_digest != evidence.evidence_digest
            || verification.receipt_digest != receipt.receipt_digest
            || receipt.scope_digest != self.scope_digest
            || receipt.registration_digest != self.registration_digest
            || receipt.kind != crate::ReceiptKind::ReadObservation
        {
            return Err(MissionConsumerError::VerificationFailed);
        }
        let next_action = if evidence.observation.complete {
            ProposalNextAction::ReviewCompleteEvidence
        } else if evidence.observation.phase == RolloutPhase::ProviderUnknown {
            ProposalNextAction::InspectProviderEvidence
        } else {
            ProposalNextAction::ReadAgain
        };
        let mut proposal = KubernetesRolloutResultProposal {
            result_version: "kubernetes-rollout-result-proposal/v1".into(),
            consumer_id: MISSION_CONSUMER_ID.into(),
            mission_id: self.mission_id.clone(),
            project_id: self.project_id.clone(),
            work_product_id: self.work_product_id.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            phase: evidence.observation.phase,
            complete: evidence.observation.complete,
            object_uid: Some(evidence.snapshot.identity.uid.clone()),
            resource_version: Some(evidence.snapshot.resource_version.clone()),
            generation: Some(evidence.snapshot.generation),
            observed_generation: Some(evidence.snapshot.observed_generation),
            evidence_digest: Some(evidence.evidence_digest.clone()),
            receipt_digest: Some(receipt.receipt_digest.clone()),
            provenance: evidence.provenance,
            connected: false,
            native: false,
            outcome_adopted: false,
            authority: "mission_result_proposal".into(),
            next_action,
            result_digest: String::new(),
        };
        proposal.result_digest = proposal.compute_digest();
        proposal
            .validate()
            .map_err(|_| MissionConsumerError::TamperedProposal)?;
        Ok(proposal)
    }

    pub fn failure_proposal(
        &self,
        failure: MissionRolloutFailure,
        detail_digest: impl Into<String>,
    ) -> Result<KubernetesRolloutResultProposal, MissionConsumerError> {
        let detail_digest = detail_digest.into();
        if !crate::valid_sha256_digest(&detail_digest) {
            return Err(MissionConsumerError::TamperedProposal);
        }
        let (phase, next_action) = match failure {
            MissionRolloutFailure::Deleted => (
                RolloutPhase::Deleted,
                ProposalNextAction::ReconcileObjectIdentity,
            ),
            MissionRolloutFailure::AccessLost => {
                (RolloutPhase::AccessLost, ProposalNextAction::RepairAccess)
            }
            MissionRolloutFailure::ProviderUnknown | MissionRolloutFailure::BlockedEnv => (
                RolloutPhase::ProviderUnknown,
                ProposalNextAction::InspectProviderEvidence,
            ),
        };
        let mut proposal = KubernetesRolloutResultProposal {
            result_version: "kubernetes-rollout-result-proposal/v1".into(),
            consumer_id: MISSION_CONSUMER_ID.into(),
            mission_id: self.mission_id.clone(),
            project_id: self.project_id.clone(),
            work_product_id: self.work_product_id.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            phase,
            complete: false,
            object_uid: None,
            resource_version: None,
            generation: None,
            observed_generation: None,
            evidence_digest: Some(detail_digest),
            receipt_digest: None,
            provenance: EvidenceProvenance::BlockedEnv,
            connected: false,
            native: false,
            outcome_adopted: false,
            authority: "mission_result_proposal".into(),
            next_action,
            result_digest: String::new(),
        };
        proposal.result_digest = proposal.compute_digest();
        proposal
            .validate()
            .map_err(|_| MissionConsumerError::TamperedProposal)?;
        Ok(proposal)
    }

    pub fn failure_from_error(
        &self,
        error: &KubernetesRolloutError,
    ) -> Result<KubernetesRolloutResultProposal, MissionConsumerError> {
        let failure = match error {
            KubernetesRolloutError::Provider(crate::KubernetesProviderError::Api(
                crate::KubernetesApiError::HttpStatus { status, .. },
            )) if *status == 401 || *status == 403 => MissionRolloutFailure::AccessLost,
            KubernetesRolloutError::Provider(crate::KubernetesProviderError::Api(
                crate::KubernetesApiError::HttpStatus { status: 404, .. },
            )) => MissionRolloutFailure::Deleted,
            KubernetesRolloutError::Provider(crate::KubernetesProviderError::Api(
                crate::KubernetesApiError::BlockedEnv { .. },
            )) => MissionRolloutFailure::BlockedEnv,
            _ => MissionRolloutFailure::ProviderUnknown,
        };
        self.failure_proposal(failure, crate::digest_text(&error.to_string()))
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn registration_digest(&self) -> &str {
        &self.registration_digest
    }

    pub fn contract_digest(&self) -> String {
        contract_digest()
    }
}

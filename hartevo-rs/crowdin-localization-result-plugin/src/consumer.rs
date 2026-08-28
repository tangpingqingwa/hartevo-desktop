//! Mission-scoped, non-adopting localization-result consumer.

use serde::{Deserialize, Serialize};

use crate::model::{
    BoundedCounts, BuildState, CrowdinLocalizationScope, Digest, LocalizationObservation,
    LocalizationResultReceipt, LocalizationState, TransportProvenance,
};
use crate::{CrowdinError, MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_ID};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionCrowdinLocalizationConsumer {
    scope_digest: Digest,
    scope: CrowdinLocalizationScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCrowdinLocalizationResult {
    pub consumer_id: String,
    pub mission_id: String,
    pub hartevo_project_id: String,
    pub work_product_id: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub state: LocalizationState,
    pub build_state: BuildState,
    pub counts: BoundedCounts,
    pub approval: crate::ApprovalState,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub publication_claim: bool,
    pub adoptable: bool,
    pub result_digest: Digest,
}

impl MissionCrowdinLocalizationConsumer {
    pub fn new(scope: CrowdinLocalizationScope) -> Self {
        let scope_digest = scope.digest();
        Self {
            scope_digest,
            scope,
        }
    }

    pub fn scope(&self) -> &CrowdinLocalizationScope {
        &self.scope
    }

    pub fn consume(
        &self,
        observation: &LocalizationObservation,
    ) -> Result<MissionCrowdinLocalizationResult, CrowdinError> {
        observation.validate()?;
        if observation.scope_digest != self.scope_digest {
            return Err(CrowdinError::ScopeMismatch(
                "Mission consumer scope differs from localization evidence".to_owned(),
            ));
        }
        self.build_result(observation)
    }

    pub fn consume_recorded(
        &self,
        receipt: &LocalizationResultReceipt,
        observation: &LocalizationObservation,
    ) -> Result<MissionCrowdinLocalizationResult, CrowdinError> {
        receipt.validate()?;
        if receipt.observation_digest != observation.observation_digest
            || receipt.scope_digest != self.scope_digest
        {
            return Err(CrowdinError::ScopeMismatch(
                "recorded receipt is not bound to this Mission evidence".to_owned(),
            ));
        }
        self.consume(observation)
    }

    fn build_result(
        &self,
        observation: &LocalizationObservation,
    ) -> Result<MissionCrowdinLocalizationResult, CrowdinError> {
        let mut result = MissionCrowdinLocalizationResult {
            consumer_id: MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_ID.to_owned(),
            mission_id: self.scope.mission.id.to_string(),
            hartevo_project_id: self.scope.hartevo_project.id.to_string(),
            work_product_id: self.scope.work_product.id.to_string(),
            scope_digest: observation.scope_digest.clone(),
            evidence_digest: observation.observation_digest.clone(),
            state: observation.primary_state(),
            build_state: observation.build_status.state,
            counts: observation.translation_progress.counts,
            approval: observation.approval,
            provenance: observation.provenance,
            read_only: true,
            native: false,
            connected: false,
            outcome_authority: false,
            publication_claim: false,
            adoptable: false,
            result_digest: Digest::from_bytes(b"uninitialized-crowdin-mission-result"),
        };
        result.result_digest = result.compute_digest();
        result.validate(self)?;
        Ok(result)
    }
}

impl MissionCrowdinLocalizationResult {
    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "mission-crowdin-localization-result/v1",
            &[
                self.consumer_id.clone(),
                self.mission_id.clone(),
                self.hartevo_project_id.clone(),
                self.work_product_id.clone(),
                self.scope_digest.to_string(),
                self.evidence_digest.to_string(),
                serde_json::to_string(&self.state).expect("state serializes"),
                serde_json::to_string(&self.build_state).expect("build state serializes"),
                serde_json::to_string(&self.counts).expect("counts serialize"),
                serde_json::to_string(&self.approval).expect("approval serializes"),
                self.provenance.as_str().to_owned(),
                self.read_only.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.outcome_authority.to_string(),
                self.publication_claim.to_string(),
                self.adoptable.to_string(),
            ],
        )
    }

    pub fn validate(
        &self,
        consumer: &MissionCrowdinLocalizationConsumer,
    ) -> Result<(), CrowdinError> {
        if self.consumer_id != MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_ID
            || self.scope_digest != consumer.scope_digest
            || !self.read_only
            || self.native
            || self.connected
            || self.outcome_authority
            || self.publication_claim
            || self.adoptable
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.result_digest != self.compute_digest()
        {
            return Err(CrowdinError::StaleProposal);
        }
        Ok(())
    }
}

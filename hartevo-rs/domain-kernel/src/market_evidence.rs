//! Typed, revision-bound evidence for the VM-07 New Market Decision Mission.
//!
//! A narrative string is deliberately not a Market Evidence Pack.  Every claim
//! carries source identity, observation time, a canonical content digest, a
//! truth classification and an uncertainty reference.  The Pack digest is
//! calculated over the complete typed payload and is therefore safe to bind to
//! a WorkProduct manifest and a later Continue/Stop/Test decision.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{MissionId, ProjectId, TenantId};

const PACK_SCHEMA_VERSION: u32 = 1;
const MAX_TEXT_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketEvidenceClassification {
    ConfirmedFact,
    ProviderEstimate,
    Inference,
    Unknown,
    Conflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketUncertaintyMateriality {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketDecisionRecommendation {
    Go,
    NoGo,
    NeedMoreEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07DecisionAction {
    Continue,
    Stop,
    Test,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketEvidenceClaim {
    pub id: String,
    pub statement: String,
    pub source_id: String,
    pub source_uri: String,
    pub observed_at: DateTime<Utc>,
    pub content_digest: String,
    pub classification: MarketEvidenceClassification,
    pub confidence: u8,
    pub uncertainty_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketUncertainty {
    pub id: String,
    pub statement: String,
    pub materiality: MarketUncertaintyMateriality,
    pub claim_ids: BTreeSet<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketCounterevidence {
    pub id: String,
    pub statement: String,
    pub source_id: String,
    pub source_uri: String,
    pub observed_at: DateTime<Utc>,
    pub content_digest: String,
    pub claim_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketExperimentPlanItem {
    pub id: String,
    pub hypothesis: String,
    pub success_metric: String,
    pub budget_minor: i64,
    pub currency: String,
    pub max_duration_days: u16,
    /// VM-07 experiments are evidence acquisition only.  A true value is
    /// required so a Test decision cannot smuggle an external write.
    pub no_external_write: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketEvidencePack {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub contract_digest: String,
    pub mission_revision: u64,
    pub pack_revision: u64,
    pub market: String,
    pub language: String,
    pub claims: Vec<MarketEvidenceClaim>,
    #[serde(rename = "truthUncertaintyMap", alias = "uncertainties")]
    pub truth_uncertainty_map: Vec<MarketUncertainty>,
    pub counterevidence: Vec<MarketCounterevidence>,
    pub recommendation: MarketDecisionRecommendation,
    pub recommendation_rationale: String,
    pub supporting_claim_ids: BTreeSet<String>,
    pub counterevidence_ids: BTreeSet<String>,
    pub experiment_plan: Vec<MarketExperimentPlanItem>,
    pub content_digest: String,
}

impl MarketEvidencePack {
    pub const SCHEMA_VERSION: u32 = PACK_SCHEMA_VERSION;

    pub fn seal(mut self) -> Result<Self, MarketEvidenceError> {
        self.content_digest = self.calculate_digest()?;
        self.validate()?;
        Ok(self)
    }

    /// Returns the canonical JSON representation persisted as the WorkProduct
    /// body.  The digest is included, so readers can verify the exact payload.
    pub fn canonical_body(&self) -> Result<String, MarketEvidenceError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn calculate_digest(&self) -> Result<String, MarketEvidenceError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(MarketEvidenceError::InvalidPack)?
            .insert("contentDigest".into(), Value::String(String::new()));
        Ok(sha256(&serde_json::to_vec(&value)?))
    }

    pub fn validate(&self) -> Result<(), MarketEvidenceError> {
        if self.schema_version != Self::SCHEMA_VERSION
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || !is_sha256(&self.contract_digest)
            || self.mission_revision == 0
            || self.pack_revision == 0
            || self.market.trim().is_empty()
            || self.language.trim().is_empty()
            || self.recommendation_rationale.trim().is_empty()
            || self.recommendation_rationale.len() > MAX_TEXT_BYTES
            || self.claims.is_empty()
            || self.truth_uncertainty_map.is_empty()
            || self.counterevidence.is_empty()
            || self.experiment_plan.is_empty()
            || self.content_digest != self.calculate_digest()?
        {
            return Err(MarketEvidenceError::InvalidPack);
        }

        let mut claim_ids = BTreeSet::new();
        for claim in &self.claims {
            if claim.id.trim().is_empty()
                || claim.statement.trim().is_empty()
                || claim.statement.len() > MAX_TEXT_BYTES
                || claim.source_id.trim().is_empty()
                || claim.source_uri.trim().is_empty()
                || !is_sha256(&claim.content_digest)
                || claim.confidence > 100
                || claim.uncertainty_id.trim().is_empty()
                || !claim_ids.insert(claim.id.clone())
            {
                return Err(MarketEvidenceError::InvalidPack);
            }
        }

        let mut uncertainty_ids = BTreeSet::new();
        for uncertainty in &self.truth_uncertainty_map {
            if uncertainty.id.trim().is_empty()
                || uncertainty.statement.trim().is_empty()
                || uncertainty.resolution.trim().is_empty()
                || uncertainty.claim_ids.is_empty()
                || !uncertainty.claim_ids.is_subset(&claim_ids)
                || !uncertainty_ids.insert(uncertainty.id.clone())
            {
                return Err(MarketEvidenceError::InvalidPack);
            }
        }
        if self
            .claims
            .iter()
            .any(|claim| !uncertainty_ids.contains(&claim.uncertainty_id))
        {
            return Err(MarketEvidenceError::InvalidPack);
        }

        let mut counterevidence_ids = BTreeSet::new();
        for item in &self.counterevidence {
            if item.id.trim().is_empty()
                || item.statement.trim().is_empty()
                || item.source_id.trim().is_empty()
                || item.source_uri.trim().is_empty()
                || !is_sha256(&item.content_digest)
                || item.claim_ids.is_empty()
                || !item.claim_ids.is_subset(&claim_ids)
                || !counterevidence_ids.insert(item.id.clone())
            {
                return Err(MarketEvidenceError::InvalidPack);
            }
        }
        if !self.supporting_claim_ids.is_subset(&claim_ids)
            || self.supporting_claim_ids.is_empty()
            || !self.counterevidence_ids.is_subset(&counterevidence_ids)
            || self.counterevidence_ids.is_empty()
        {
            return Err(MarketEvidenceError::InvalidPack);
        }

        let mut experiment_ids = BTreeSet::new();
        for experiment in &self.experiment_plan {
            if experiment.id.trim().is_empty()
                || experiment.hypothesis.trim().is_empty()
                || experiment.success_metric.trim().is_empty()
                || experiment.budget_minor < 0
                || experiment.currency.trim().is_empty()
                || experiment.max_duration_days == 0
                || !experiment.no_external_write
                || !experiment_ids.insert(experiment.id.clone())
            {
                return Err(MarketEvidenceError::InvalidPack);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07DecisionBinding {
    pub schema_version: u32,
    pub action: Vm07DecisionAction,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub checkpoint_id: String,
    pub contract_digest: String,
    pub pack_content_digest: String,
    pub pack_revision: u64,
    pub mission_revision: u64,
    pub checkpoint_revision: u64,
    pub conversation_revision: u64,
    pub idempotency_key_digest: String,
    pub decision_digest: String,
    pub experiment_plan_digest: Option<String>,
}

impl Vm07DecisionBinding {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn calculate_digest(&self) -> Result<String, MarketEvidenceError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(MarketEvidenceError::InvalidDecisionBinding)?
            .insert("decisionDigest".into(), Value::String(String::new()));
        Ok(sha256(&serde_json::to_vec(&value)?))
    }

    pub fn validate(&self) -> Result<(), MarketEvidenceError> {
        let requires_experiment = self.action == Vm07DecisionAction::Test;
        if self.schema_version != Self::SCHEMA_VERSION
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.checkpoint_id != "go_no_go_need_more_evidence"
            || !is_sha256(&self.contract_digest)
            || !is_sha256(&self.pack_content_digest)
            || self.pack_revision == 0
            || self.mission_revision == 0
            || self.checkpoint_revision == 0
            || self.conversation_revision == 0
            || !is_sha256(&self.idempotency_key_digest)
            || !is_sha256(&self.decision_digest)
            || (requires_experiment
                && !self
                    .experiment_plan_digest
                    .as_deref()
                    .is_some_and(is_sha256))
            || (!requires_experiment && self.experiment_plan_digest.is_some())
            || self.decision_digest != self.calculate_digest()?
        {
            return Err(MarketEvidenceError::InvalidDecisionBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum MarketEvidenceError {
    #[error("Market Evidence Pack is incomplete, malformed, or digest-invalid")]
    InvalidPack,
    #[error("VM-07 decision binding is incomplete, malformed, or digest-invalid")]
    InvalidDecisionBinding,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(text: &str) -> String {
        sha256(text.as_bytes())
    }

    fn pack() -> MarketEvidencePack {
        let claim = MarketEvidenceClaim {
            id: "claim-1".into(),
            statement: "German demand is measurable".into(),
            source_id: "source-1".into(),
            source_uri: "https://example.test/source-1".into(),
            observed_at: Utc::now(),
            content_digest: digest("claim"),
            classification: MarketEvidenceClassification::ProviderEstimate,
            confidence: 60,
            uncertainty_id: "uncertainty-1".into(),
        };
        let mut value = MarketEvidencePack {
            schema_version: 1,
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-1"),
            contract_digest: digest("contract"),
            mission_revision: 4,
            pack_revision: 1,
            market: "DE".into(),
            language: "en-US".into(),
            claims: vec![claim],
            truth_uncertainty_map: vec![MarketUncertainty {
                id: "uncertainty-1".into(),
                statement: "Demand estimate may not convert".into(),
                materiality: MarketUncertaintyMateriality::High,
                claim_ids: BTreeSet::from(["claim-1".into()]),
                resolution: "Run a bounded landing-page test".into(),
            }],
            counterevidence: vec![MarketCounterevidence {
                id: "counter-1".into(),
                statement: "Incumbents have strong local distribution".into(),
                source_id: "source-2".into(),
                source_uri: "https://example.test/source-2".into(),
                observed_at: Utc::now(),
                content_digest: digest("counter"),
                claim_ids: BTreeSet::from(["claim-1".into()]),
            }],
            recommendation: MarketDecisionRecommendation::NeedMoreEvidence,
            recommendation_rationale: "The estimate is promising but unconfirmed".into(),
            supporting_claim_ids: BTreeSet::from(["claim-1".into()]),
            counterevidence_ids: BTreeSet::from(["counter-1".into()]),
            experiment_plan: vec![MarketExperimentPlanItem {
                id: "experiment-1".into(),
                hypothesis: "German buyers will request a demo".into(),
                success_metric: "At least five qualified requests".into(),
                budget_minor: 100,
                currency: "EUR".into(),
                max_duration_days: 14,
                no_external_write: true,
            }],
            content_digest: String::new(),
        };
        value.content_digest = value.calculate_digest().expect("digest");
        value
    }

    #[test]
    fn pack_requires_typed_provenance_and_round_trips() {
        let value = pack();
        value.validate().expect("valid pack");
        let round_trip: MarketEvidencePack =
            serde_json::from_str(&value.canonical_body().expect("body")).expect("round trip");
        assert_eq!(round_trip, value);
    }

    #[test]
    fn narrative_only_or_external_write_experiment_is_rejected() {
        let mut value = pack();
        value.experiment_plan[0].no_external_write = false;
        value.content_digest = value.calculate_digest().expect("digest");
        assert!(matches!(
            value.validate(),
            Err(MarketEvidenceError::InvalidPack)
        ));
        let mut value = pack();
        value.claims[0].source_uri.clear();
        value.content_digest = value.calculate_digest().expect("digest");
        assert!(matches!(
            value.validate(),
            Err(MarketEvidenceError::InvalidPack)
        ));
    }

    #[test]
    fn test_decision_requires_a_bound_experiment_plan() {
        let mut binding = Vm07DecisionBinding {
            schema_version: Vm07DecisionBinding::SCHEMA_VERSION,
            action: Vm07DecisionAction::Test,
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-1"),
            checkpoint_id: "go_no_go_need_more_evidence".into(),
            contract_digest: digest("contract"),
            pack_content_digest: digest("pack"),
            pack_revision: 1,
            mission_revision: 4,
            checkpoint_revision: 2,
            conversation_revision: 1,
            idempotency_key_digest: digest("idempotency"),
            decision_digest: String::new(),
            experiment_plan_digest: Some(digest("experiment-plan")),
        };
        binding.decision_digest = binding.calculate_digest().expect("decision digest");
        binding.validate().expect("valid Test binding");
        binding.experiment_plan_digest = None;
        binding.decision_digest = binding.calculate_digest().expect("tampered digest");
        assert!(matches!(
            binding.validate(),
            Err(MarketEvidenceError::InvalidDecisionBinding)
        ));
    }
}

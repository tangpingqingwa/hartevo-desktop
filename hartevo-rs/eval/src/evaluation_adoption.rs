//! Content-free adoption of a validated evaluation-plugin result.
//!
//! Adoption is deliberately a separate seam from both RUN validation and the
//! Release Evidence evaluator.  It can select an evaluation result for a
//! Mission, but it cannot manufacture native or Release authority.

use anyhow::{Result, ensure};
use serde::{Serialize, Serializer};

use crate::digest::{digest_json, is_lower_hex};
use crate::evaluation_plugin::{
    EvaluationEvaluator, EvaluationEvidenceProvenance, EvaluationExecutionStatus,
    EvaluationPluginService, EvaluationResult, EvaluationResultProvider,
};

pub const EVALUATION_ADOPTION_SCHEMA_VERSION: &str = "hartevo-evaluation-adoption/v1";
pub const EVALUATION_ADOPTION_AUTHORITY: &str = "evaluation_plugin_adoption_only";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationAdoptionOutcome {
    Adopt,
    Reject,
    NotEvaluated,
}

impl Serialize for EvaluationAdoptionOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Adopt => "adopt",
            Self::Reject => "reject",
            Self::NotEvaluated => "not_evaluated",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationEvidenceRoots {
    #[serde(rename = "planDigest")]
    plan: String,
    #[serde(rename = "resultSetDigest")]
    result_set: String,
    #[serde(rename = "receiptDigest")]
    receipt: String,
    #[serde(rename = "catalogDigest")]
    catalog: String,
    #[serde(rename = "releaseSchemaDigest")]
    release_schema: String,
    #[serde(rename = "evidenceDigest")]
    evidence: String,
}

impl EvaluationEvidenceRoots {
    fn from_result(result: &EvaluationResult) -> Result<Self> {
        let roots = Self {
            plan: result.plan_digest().into(),
            result_set: result.result_set_digest().into(),
            receipt: result.receipt_digest().into(),
            catalog: result.catalog_digest().into(),
            release_schema: result.release_schema_digest().into(),
            evidence: result.evidence_digest().into(),
        };
        for (name, digest) in [
            ("plan", &roots.plan),
            ("result set", &roots.result_set),
            ("receipt", &roots.receipt),
            ("Catalog", &roots.catalog),
            ("Release schema", &roots.release_schema),
            ("evidence", &roots.evidence),
        ] {
            ensure!(
                is_lower_hex(digest, 32),
                "{name} root must be lowercase SHA-256"
            );
        }
        Ok(roots)
    }

    pub fn plan_digest(&self) -> &str {
        &self.plan
    }

    pub fn result_set_digest(&self) -> &str {
        &self.result_set
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt
    }

    pub fn catalog_digest(&self) -> &str {
        &self.catalog
    }

    pub fn release_schema_digest(&self) -> &str {
        &self.release_schema
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationAdoptionDecision {
    schema_version: String,
    authority: String,
    outcome: EvaluationAdoptionOutcome,
    source_commit: String,
    mission_id: String,
    service_id: String,
    evaluator_id: String,
    revision: u64,
    evidence_roots: EvaluationEvidenceRoots,
    result_digest: String,
    release_eligible: bool,
    decision_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecisionDigestMaterial<'a> {
    schema_version: &'static str,
    authority: &'static str,
    outcome: EvaluationAdoptionOutcome,
    source_commit: &'a str,
    mission_id: &'a str,
    service_id: &'a str,
    evaluator_id: &'a str,
    revision: u64,
    evidence_roots: &'a EvaluationEvidenceRoots,
    result_digest: &'a str,
    release_eligible: bool,
}

impl EvaluationAdoptionDecision {
    fn derive(
        mission_id: &str,
        result: &EvaluationResult,
        outcome: EvaluationAdoptionOutcome,
    ) -> Result<Self> {
        let evidence_roots = EvaluationEvidenceRoots::from_result(result)?;
        let mut decision = Self {
            schema_version: EVALUATION_ADOPTION_SCHEMA_VERSION.into(),
            authority: EVALUATION_ADOPTION_AUTHORITY.into(),
            outcome,
            source_commit: result.source_commit().into(),
            mission_id: mission_id.into(),
            service_id: result.service_id().into(),
            evaluator_id: result.evaluator_id().into(),
            revision: result.revision(),
            evidence_roots,
            result_digest: result.result_digest().into(),
            release_eligible: false,
            decision_digest: String::new(),
        };
        decision.decision_digest = digest_json(
            EVALUATION_ADOPTION_SCHEMA_VERSION,
            &DecisionDigestMaterial {
                schema_version: EVALUATION_ADOPTION_SCHEMA_VERSION,
                authority: EVALUATION_ADOPTION_AUTHORITY,
                outcome: decision.outcome,
                source_commit: &decision.source_commit,
                mission_id: &decision.mission_id,
                service_id: &decision.service_id,
                evaluator_id: &decision.evaluator_id,
                revision: decision.revision,
                evidence_roots: &decision.evidence_roots,
                result_digest: &decision.result_digest,
                release_eligible: decision.release_eligible,
            },
        )?;
        Ok(decision)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn outcome(&self) -> EvaluationAdoptionOutcome {
        self.outcome
    }

    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn evaluator_id(&self) -> &str {
        &self.evaluator_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn evidence_roots(&self) -> &EvaluationEvidenceRoots {
        &self.evidence_roots
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub fn release_eligible(&self) -> bool {
        self.release_eligible
    }

    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }
}

#[derive(Clone, Debug)]
pub struct EvaluationAdoptionConsumer {
    evaluator: EvaluationEvaluator,
    mission_id: String,
    selected: Option<EvaluationAdoptionDecision>,
}

impl EvaluationAdoptionConsumer {
    pub fn new(evaluator: EvaluationEvaluator, mission_id: impl Into<String>) -> Result<Self> {
        let mission_id = mission_id.into();
        ensure!(!mission_id.trim().is_empty(), "Mission id is required");
        Ok(Self {
            evaluator,
            mission_id,
            selected: None,
        })
    }

    pub fn evaluator(&self) -> &EvaluationEvaluator {
        &self.evaluator
    }

    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub fn selection_count(&self) -> usize {
        usize::from(self.selected.is_some())
    }

    pub fn selected(&self) -> Option<&EvaluationAdoptionDecision> {
        self.selected.as_ref()
    }

    /// Selects an envelope without copying its content.  An exact replay is
    /// idempotent; a different envelope cannot grow or replace the selection.
    pub fn select(&mut self, result: &EvaluationResult) -> Result<EvaluationAdoptionDecision> {
        validate_envelope(&self.evaluator, &self.mission_id, result)?;
        if let Some(selected) = &self.selected {
            ensure!(
                selected.result_digest() == result.result_digest(),
                "adoption replay differs from the already selected result"
            );
            return Ok(selected.clone());
        }
        let outcome = match (result.provenance(), result.execution_status()) {
            (EvaluationEvidenceProvenance::DurableRun, EvaluationExecutionStatus::Completed) => {
                if result.evaluation_passed() {
                    EvaluationAdoptionOutcome::Adopt
                } else {
                    EvaluationAdoptionOutcome::Reject
                }
            }
            _ => EvaluationAdoptionOutcome::NotEvaluated,
        };
        let decision = EvaluationAdoptionDecision::derive(&self.mission_id, result, outcome)?;
        self.selected = Some(decision.clone());
        Ok(decision)
    }

    /// Promotes only an adopted decision while rechecking the live provider
    /// and lifecycle binding.  Revoke, unmount, crash, stale commit, or
    /// changed evidence makes the old decision non-promotable.
    pub fn promote<P: EvaluationResultProvider>(
        &self,
        service: &EvaluationPluginService<P>,
        decision: &EvaluationAdoptionDecision,
    ) -> Result<EvaluationAdoptionDecision> {
        ensure!(
            self.selected.as_ref() == Some(decision),
            "decision was not selected by this adoption consumer"
        );
        ensure!(
            decision.outcome == EvaluationAdoptionOutcome::Adopt,
            "only an adopted evaluation decision can be promoted"
        );
        service.validate_adoption_binding(
            &self.evaluator,
            decision.source_commit(),
            decision.revision(),
            decision.evidence_roots().evidence_digest(),
        )?;
        Ok(decision.clone())
    }
}

fn validate_envelope(
    evaluator: &EvaluationEvaluator,
    mission_id: &str,
    result: &EvaluationResult,
) -> Result<()> {
    ensure!(
        result.schema_version() == crate::evaluation_plugin::EVALUATION_PLUGIN_SCHEMA_VERSION
            && result.authority() == crate::evaluation_plugin::EVALUATION_PLUGIN_AUTHORITY
            && result.release_decision()
                == crate::evaluation_plugin::EVALUATION_PLUGIN_RELEASE_DECISION,
        "result is outside the verified evaluation-plugin envelope"
    );
    ensure!(
        result.service_id() == evaluator.service_id()
            && result.evaluator_id() == evaluator.evaluator_id()
            && result.revision() == evaluator.mount_revision(),
        "evaluation result is not bound to the mounted evaluator"
    );
    ensure!(
        result.source_commit() == evaluator.source_commit(),
        "evaluation result is bound to a different source commit"
    );
    ensure!(
        result.evidence_digest() == evaluator.evidence_digest(),
        "evaluation result evidence root differs from the mounted evaluator"
    );
    ensure!(
        result.mission_ids().iter().any(|id| id == mission_id),
        "evaluation result does not contain the selected Mission"
    );
    ensure!(
        is_lower_hex(result.result_digest(), 32),
        "evaluation result digest must be lowercase SHA-256"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::evaluation_plugin::EvaluationEvidence;

    use super::*;

    const COMMIT_A: &str = "a909ca5f11ddd97a19369ee9e2da4f4206aa6524";
    const COMMIT_B: &str = "b909ca5f11ddd97a19369ee9e2da4f4206aa6524";

    #[derive(Clone)]
    struct StaticProvider {
        evidence: Rc<RefCell<EvaluationEvidence>>,
    }

    impl StaticProvider {
        fn new(evidence: EvaluationEvidence) -> Self {
            Self {
                evidence: Rc::new(RefCell::new(evidence)),
            }
        }

        fn replace(&self, evidence: EvaluationEvidence) {
            *self.evidence.borrow_mut() = evidence;
        }
    }

    impl EvaluationResultProvider for StaticProvider {
        fn read_current(&self, expected_source_commit: &str) -> Result<EvaluationEvidence> {
            let evidence = self.evidence.borrow().clone();
            ensure!(
                evidence.source_commit() == expected_source_commit,
                "test provider source commit mismatch"
            );
            Ok(evidence)
        }
    }

    fn evidence(
        commit: &str,
        digest: char,
        provenance: EvaluationEvidenceProvenance,
        status: EvaluationExecutionStatus,
        passed: bool,
    ) -> EvaluationEvidence {
        EvaluationEvidence::synthetic(
            commit,
            "run-01",
            &digest.to_string().repeat(64),
            provenance,
            status,
            passed,
        )
    }

    fn mounted(
        evidence: EvaluationEvidence,
    ) -> (
        EvaluationPluginService<StaticProvider>,
        EvaluationEvaluator,
        EvaluationResult,
    ) {
        let commit = evidence.source_commit().to_owned();
        let provider = StaticProvider::new(evidence);
        let mut service = EvaluationPluginService::new("eval-service", provider).unwrap();
        let evaluator = service.mount("evaluator-1", &commit).unwrap();
        let result = service.submit(&evaluator).unwrap();
        (service, evaluator, result)
    }

    #[test]
    fn adopted_decision_is_content_free_and_root_bound() {
        let (service, evaluator, result) = mounted(evidence(
            COMMIT_A,
            'a',
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            true,
        ));
        let mut consumer = EvaluationAdoptionConsumer::new(evaluator, "VM-00").unwrap();
        let decision = consumer.select(&result).unwrap();
        assert_eq!(decision.outcome(), EvaluationAdoptionOutcome::Adopt);
        assert_eq!(decision.source_commit(), COMMIT_A);
        assert_eq!(decision.mission_id(), "VM-00");
        assert_eq!(decision.revision(), result.revision());
        assert_eq!(
            decision.evidence_roots().evidence_digest(),
            result.evidence_digest()
        );
        assert!(!decision.release_eligible());
        assert!(is_lower_hex(decision.decision_digest(), 32));
        let value = serde_json::to_value(&decision).unwrap();
        assert!(value.get("content").is_none());
        assert_eq!(value["releaseEligible"], false);
        assert_eq!(consumer.promote(&service, &decision).unwrap(), decision);
    }

    #[test]
    fn exact_replay_is_idempotent_and_does_not_grow_selection() {
        let (_, evaluator, result) = mounted(evidence(
            COMMIT_A,
            'b',
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            true,
        ));
        let mut consumer = EvaluationAdoptionConsumer::new(evaluator, "VM-00").unwrap();
        let first = consumer.select(&result).unwrap();
        let second = consumer.select(&result).unwrap();
        assert_eq!(first, second);
        assert_eq!(consumer.selection_count(), 1);
    }

    #[test]
    fn tamper_and_cross_commit_results_are_rejected() {
        let (service, evaluator, result) = mounted(evidence(
            COMMIT_A,
            'c',
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            true,
        ));
        let mut consumer = EvaluationAdoptionConsumer::new(evaluator, "VM-00").unwrap();
        let decision = consumer.select(&result).unwrap();
        let provider = service.provider().clone();
        provider.replace(evidence(
            COMMIT_A,
            'd',
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            true,
        ));
        assert!(consumer.promote(&service, &decision).is_err());

        let (_, evaluator_b, result_b) = mounted(evidence(
            COMMIT_B,
            'e',
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            true,
        ));
        let mut cross_commit = EvaluationAdoptionConsumer::new(evaluator_b, "VM-00").unwrap();
        assert!(cross_commit.select(&result).is_err());
        assert!(cross_commit.select(&result_b).is_ok());
    }

    #[test]
    fn revoke_unmount_and_crash_prevent_old_decision_promotion() {
        for invalidation in ["unmount", "revoke", "crash"] {
            let (mut service, evaluator, result) = mounted(evidence(
                COMMIT_A,
                'f',
                EvaluationEvidenceProvenance::DurableRun,
                EvaluationExecutionStatus::Completed,
                true,
            ));
            let mut consumer = EvaluationAdoptionConsumer::new(evaluator, "VM-00").unwrap();
            let decision = consumer.select(&result).unwrap();
            match invalidation {
                "unmount" => service.unmount(),
                "revoke" => service.revoke(),
                "crash" => service.crash(),
                _ => unreachable!(),
            }
            assert!(consumer.promote(&service, &decision).is_err());
        }
    }

    #[test]
    fn blocked_fixture_and_ignored_results_are_not_evaluated() {
        for (provenance, status) in [
            (
                EvaluationEvidenceProvenance::BlockedEnv,
                EvaluationExecutionStatus::BlockedEnv,
            ),
            (
                EvaluationEvidenceProvenance::Fixture,
                EvaluationExecutionStatus::Completed,
            ),
            (
                EvaluationEvidenceProvenance::Ignored,
                EvaluationExecutionStatus::NotEvaluated,
            ),
        ] {
            let (_, evaluator, result) =
                mounted(evidence(COMMIT_A, '1', provenance, status, false));
            let mut consumer = EvaluationAdoptionConsumer::new(evaluator, "VM-00").unwrap();
            let decision = consumer.select(&result).unwrap();
            assert_eq!(decision.outcome(), EvaluationAdoptionOutcome::NotEvaluated);
            assert!(!decision.release_eligible());
        }
    }

    #[test]
    fn completed_but_failed_result_is_rejected_not_adopted() {
        let (_, evaluator, result) = mounted(evidence(
            COMMIT_A,
            '2',
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            false,
        ));
        let mut consumer = EvaluationAdoptionConsumer::new(evaluator, "VM-00").unwrap();
        let decision = consumer.select(&result).unwrap();
        assert_eq!(decision.outcome(), EvaluationAdoptionOutcome::Reject);
        assert!(
            consumer
                .promote(
                    &EvaluationPluginService::new(
                        "unused",
                        StaticProvider::new(evidence(
                            COMMIT_A,
                            '3',
                            EvaluationEvidenceProvenance::DurableRun,
                            EvaluationExecutionStatus::Completed,
                            true
                        ))
                    )
                    .unwrap(),
                    &decision
                )
                .is_err()
        );
    }
}

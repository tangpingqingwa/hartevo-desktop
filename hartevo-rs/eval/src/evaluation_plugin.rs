//! A deliberately narrow evaluation-plugin seam.
//!
//! The plugin consumes a revalidated, durable RUN result.  It is intentionally
//! not a Release Evidence evaluator: the result carries an evaluation-plugin
//! authority and a `NOT_EVALUATED` release decision, and both values are fixed
//! by constructors rather than supplied by callers.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use hartevo_catalog::{
    EvaluationPrivateAttestationStatus, EvaluationReferenceThresholdStatus,
    EvaluationRunEvidenceAuthority, EvaluationRunResultReference, EvaluationRunValidationAuthority,
    EvaluationSafetyMappingStatus,
};
use serde::{Deserialize, Serialize};

use crate::digest::{digest_json, is_lower_hex};
use crate::run_receipt::{
    CaseExecutionDisposition, EvaluationCaseResult, validate_evaluation_run_result_reference,
};

pub const EVALUATION_PLUGIN_SCHEMA_VERSION: &str = "hartevo-evaluation-plugin-result/v1";
pub const EVALUATION_PLUGIN_AUTHORITY: &str = "evaluation_plugin_only";
pub const EVALUATION_PLUGIN_RELEASE_DECISION: &str = "NOT_EVALUATED";

const EVALUATION_PLUGIN_DIGEST_DOMAIN: &str = "hartevo-evaluation-plugin-result/v1";
const EVALUATION_PLUGIN_EVIDENCE_DIGEST_DOMAIN: &str = "hartevo-evaluation-plugin-evidence/v1";
const RESULTS_DIRECTORY: &str = "results";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationEvidenceProvenance {
    DurableRun,
    Fixture,
    Ignored,
    BlockedEnv,
    SourceAudit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationExecutionStatus {
    Completed,
    BlockedEnv,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPluginState {
    Unmounted,
    Mounted,
    Revoked,
    Crashed,
}

/// Revalidated durable evidence made available to the plugin service.
///
/// The fields are private so a caller cannot inject a release authority,
/// native provenance, or a forged digest.  Production construction is only
/// through [`DurableEvaluationResultProvider`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationEvidence {
    source_commit: String,
    mission_ids: Vec<String>,
    run_id: String,
    plan_digest: String,
    result_set_digest: String,
    receipt_digest: String,
    catalog_digest: String,
    release_schema_digest: String,
    evidence_digest: String,
    provenance: EvaluationEvidenceProvenance,
    execution_status: EvaluationExecutionStatus,
    evaluation_passed: bool,
    structurally_complete: bool,
    partition_complete: bool,
}

impl EvaluationEvidence {
    fn from_reference(
        reference: &EvaluationRunResultReference,
        dispositions: &[CaseExecutionDisposition],
        evidence_digest: String,
    ) -> Result<Self> {
        validate_commit(&reference.release_commit)?;
        ensure!(
            reference.validation_authority
                == EvaluationRunValidationAuthority::HartevoEvaluationRunValidatorV1,
            "evaluation plugin accepts only the current RUN validator authority"
        );
        ensure!(
            reference.evidence_authority == EvaluationRunEvidenceAuthority::RunEvidenceOnly,
            "evaluation plugin accepts only run_evidence_only"
        );
        ensure!(
            reference.safety_mapping_status
                == EvaluationSafetyMappingStatus::MissingAuthoritativeMapping
                && reference.private_attestation_status
                    == EvaluationPrivateAttestationStatus::MissingTrustedPrivateEvaluatorAttestation,
            "evaluation plugin cannot consume an asserted private or safety authority"
        );
        ensure!(
            is_lower_hex(&evidence_digest, 32),
            "evaluation evidence digest must be lowercase SHA-256"
        );

        let execution_status = summarize_dispositions(dispositions);
        let evaluation_passed = execution_status == EvaluationExecutionStatus::Completed
            && reference.structurally_complete
            && reference.partition_complete
            && reference.threshold_status == EvaluationReferenceThresholdStatus::EvaluatedPassed;
        Ok(Self {
            source_commit: reference.release_commit.clone(),
            mission_ids: reference.mission_ids.clone(),
            run_id: reference.run_id.clone(),
            plan_digest: reference.plan_digest.clone(),
            result_set_digest: reference.result_set_digest.clone(),
            receipt_digest: reference.receipt_digest.clone(),
            catalog_digest: reference.catalog_digest.clone(),
            release_schema_digest: reference.release_schema_digest.clone(),
            evidence_digest,
            provenance: EvaluationEvidenceProvenance::DurableRun,
            execution_status,
            evaluation_passed,
            structurally_complete: reference.structurally_complete,
            partition_complete: reference.partition_complete,
        })
    }

    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub fn mission_ids(&self) -> &[String] {
        &self.mission_ids
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    pub fn result_set_digest(&self) -> &str {
        &self.result_set_digest
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    pub fn release_schema_digest(&self) -> &str {
        &self.release_schema_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn provenance(&self) -> EvaluationEvidenceProvenance {
        self.provenance
    }

    pub fn execution_status(&self) -> EvaluationExecutionStatus {
        self.execution_status
    }

    pub fn evaluation_passed(&self) -> bool {
        self.evaluation_passed
    }

    pub fn structurally_complete(&self) -> bool {
        self.structurally_complete
    }

    pub fn partition_complete(&self) -> bool {
        self.partition_complete
    }

    /// Evaluation evidence never grants native product authority.
    pub fn native_eligible(&self) -> bool {
        false
    }

    /// Evaluation evidence never grants Release Evidence authority.
    pub fn release_eligible(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn synthetic(
        source_commit: &str,
        run_id: &str,
        evidence_digest: &str,
        provenance: EvaluationEvidenceProvenance,
        execution_status: EvaluationExecutionStatus,
        evaluation_passed: bool,
    ) -> Self {
        Self {
            source_commit: source_commit.into(),
            mission_ids: vec!["VM-00".into()],
            run_id: run_id.into(),
            plan_digest: "1".repeat(64),
            result_set_digest: "2".repeat(64),
            receipt_digest: "3".repeat(64),
            catalog_digest: "4".repeat(64),
            release_schema_digest: "5".repeat(64),
            evidence_digest: evidence_digest.into(),
            provenance,
            execution_status,
            evaluation_passed,
            structurally_complete: evaluation_passed,
            partition_complete: evaluation_passed,
        }
    }
}

/// A provider that revalidates a finalized RUN and reads its exact result set.
#[derive(Clone, Debug)]
pub struct DurableEvaluationResultProvider {
    run_root: PathBuf,
}

impl DurableEvaluationResultProvider {
    pub fn new(run_root: impl Into<PathBuf>) -> Self {
        Self {
            run_root: run_root.into(),
        }
    }

    pub fn run_root(&self) -> &Path {
        &self.run_root
    }
}

pub trait EvaluationResultProvider {
    fn read_current(&self, expected_source_commit: &str) -> Result<EvaluationEvidence>;
}

impl EvaluationResultProvider for DurableEvaluationResultProvider {
    fn read_current(&self, expected_source_commit: &str) -> Result<EvaluationEvidence> {
        validate_commit(expected_source_commit)?;
        let reference = validate_evaluation_run_result_reference(&self.run_root)
            .context("durable RUN result reference failed current validation")?;
        ensure!(
            reference.release_commit == expected_source_commit,
            "durable evaluation evidence is stale for the current source commit"
        );
        let case_records = read_case_records(&self.run_root)?;
        ensure!(
            case_records.len() == reference.recorded_case_count,
            "durable RUN case count changed while loading plugin evidence"
        );
        let evidence_digest = digest_json(
            EVALUATION_PLUGIN_EVIDENCE_DIGEST_DOMAIN,
            &DurableEvidenceDigestMaterial {
                reference: &reference,
                case_records: &case_records,
            },
        )
        .context("derive durable evaluation evidence digest")?;
        let revalidated = validate_evaluation_run_result_reference(&self.run_root)
            .context("revalidate durable RUN after reading plugin evidence")?;
        ensure!(
            reference == revalidated,
            "durable evaluation evidence changed while it was being read"
        );
        let dispositions = case_records
            .iter()
            .map(|record| record.disposition)
            .collect::<Vec<_>>();
        EvaluationEvidence::from_reference(&reference, &dispositions, evidence_digest)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableEvidenceDigestMaterial<'a> {
    reference: &'a EvaluationRunResultReference,
    case_records: &'a [CaseRecordDigest],
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaseRecordDigest {
    case_id: String,
    result_digest: String,
    disposition: CaseExecutionDisposition,
}

fn read_case_records(root: &Path) -> Result<Vec<CaseRecordDigest>> {
    let results_root = root.join(RESULTS_DIRECTORY);
    let mut records = Vec::new();
    for entry in fs::read_dir(&results_root)
        .with_context(|| format!("read durable result directory {}", results_root.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let file_type = entry.file_type()?;
        ensure!(
            file_type.is_file() && !file_type.is_symlink(),
            "durable result directory contains a non-regular entry"
        );
        let bytes = fs::read(entry.path())
            .with_context(|| format!("read durable result {}", entry.path().display()))?;
        let result: EvaluationCaseResult = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse durable result {}", entry.path().display()))?;
        records.push(CaseRecordDigest {
            case_id: result.case_id().into(),
            result_digest: result.result_digest().into(),
            disposition: result.disposition(),
        });
    }
    records.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let ids = records
        .iter()
        .map(|record| record.case_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        ids.len() == records.len(),
        "durable result set contains duplicate case identities"
    );
    Ok(records)
}

fn summarize_dispositions(dispositions: &[CaseExecutionDisposition]) -> EvaluationExecutionStatus {
    if dispositions.is_empty() {
        return EvaluationExecutionStatus::NotEvaluated;
    }
    if dispositions.contains(&CaseExecutionDisposition::BlockedEnv) {
        return EvaluationExecutionStatus::BlockedEnv;
    }
    if dispositions.iter().any(|disposition| {
        matches!(
            disposition,
            CaseExecutionDisposition::NotImplemented | CaseExecutionDisposition::Invalid
        )
    }) {
        return EvaluationExecutionStatus::NotEvaluated;
    }
    EvaluationExecutionStatus::Completed
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationEvaluator {
    service_id: String,
    evaluator_id: String,
    mount_revision: u64,
    source_commit: String,
    evidence_digest: String,
}

impl EvaluationEvaluator {
    pub fn evaluator_id(&self) -> &str {
        &self.evaluator_id
    }

    pub fn mount_revision(&self) -> u64 {
        self.mount_revision
    }

    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationResult {
    schema_version: String,
    authority: String,
    release_decision: String,
    service_id: String,
    evaluator_id: String,
    revision: u64,
    source_commit: String,
    mission_ids: Vec<String>,
    run_id: String,
    plan_digest: String,
    result_set_digest: String,
    receipt_digest: String,
    catalog_digest: String,
    release_schema_digest: String,
    evidence_digest: String,
    provenance: EvaluationEvidenceProvenance,
    execution_status: EvaluationExecutionStatus,
    evaluation_passed: bool,
    native_eligible: bool,
    release_eligible: bool,
    result_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvaluationResultDigestMaterial<'a> {
    schema_version: &'static str,
    authority: &'static str,
    release_decision: &'static str,
    service_id: &'a str,
    evaluator_id: &'a str,
    revision: u64,
    source_commit: &'a str,
    mission_ids: &'a [String],
    run_id: &'a str,
    plan_digest: &'a str,
    result_set_digest: &'a str,
    receipt_digest: &'a str,
    catalog_digest: &'a str,
    release_schema_digest: &'a str,
    evidence_digest: &'a str,
    provenance: EvaluationEvidenceProvenance,
    execution_status: EvaluationExecutionStatus,
    evaluation_passed: bool,
    native_eligible: bool,
    release_eligible: bool,
}

impl EvaluationResult {
    fn from_evidence(
        service_id: &str,
        evaluator_id: &str,
        revision: u64,
        evidence: &EvaluationEvidence,
    ) -> Result<Self> {
        let mut result = Self {
            schema_version: EVALUATION_PLUGIN_SCHEMA_VERSION.into(),
            authority: EVALUATION_PLUGIN_AUTHORITY.into(),
            release_decision: EVALUATION_PLUGIN_RELEASE_DECISION.into(),
            service_id: service_id.into(),
            evaluator_id: evaluator_id.into(),
            revision,
            source_commit: evidence.source_commit.clone(),
            mission_ids: evidence.mission_ids.clone(),
            run_id: evidence.run_id.clone(),
            plan_digest: evidence.plan_digest.clone(),
            result_set_digest: evidence.result_set_digest.clone(),
            receipt_digest: evidence.receipt_digest.clone(),
            catalog_digest: evidence.catalog_digest.clone(),
            release_schema_digest: evidence.release_schema_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provenance: evidence.provenance,
            execution_status: evidence.execution_status,
            evaluation_passed: evidence.evaluation_passed,
            native_eligible: evidence.native_eligible(),
            release_eligible: evidence.release_eligible(),
            result_digest: String::new(),
        };
        result.result_digest = digest_json(
            EVALUATION_PLUGIN_DIGEST_DOMAIN,
            &EvaluationResultDigestMaterial {
                schema_version: EVALUATION_PLUGIN_SCHEMA_VERSION,
                authority: EVALUATION_PLUGIN_AUTHORITY,
                release_decision: EVALUATION_PLUGIN_RELEASE_DECISION,
                service_id: &result.service_id,
                evaluator_id: &result.evaluator_id,
                revision: result.revision,
                source_commit: &result.source_commit,
                mission_ids: &result.mission_ids,
                run_id: &result.run_id,
                plan_digest: &result.plan_digest,
                result_set_digest: &result.result_set_digest,
                receipt_digest: &result.receipt_digest,
                catalog_digest: &result.catalog_digest,
                release_schema_digest: &result.release_schema_digest,
                evidence_digest: &result.evidence_digest,
                provenance: result.provenance,
                execution_status: result.execution_status,
                evaluation_passed: result.evaluation_passed,
                native_eligible: result.native_eligible,
                release_eligible: result.release_eligible,
            },
        )
        .context("derive evaluation plugin result digest")?;
        Ok(result)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn release_decision(&self) -> &str {
        &self.release_decision
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

    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub fn mission_ids(&self) -> &[String] {
        &self.mission_ids
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    pub fn result_set_digest(&self) -> &str {
        &self.result_set_digest
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    pub fn release_schema_digest(&self) -> &str {
        &self.release_schema_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn provenance(&self) -> EvaluationEvidenceProvenance {
        self.provenance
    }

    pub fn execution_status(&self) -> EvaluationExecutionStatus {
        self.execution_status
    }

    pub fn evaluation_passed(&self) -> bool {
        self.evaluation_passed
    }

    pub fn native_eligible(&self) -> bool {
        self.native_eligible
    }

    pub fn release_eligible(&self) -> bool {
        self.release_eligible
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveEvaluator {
    evaluator: EvaluationEvaluator,
}

#[derive(Debug)]
pub struct EvaluationPluginService<P: EvaluationResultProvider> {
    service_id: String,
    provider: P,
    state: EvaluationPluginState,
    next_revision: u64,
    active: Option<ActiveEvaluator>,
}

pub type DurableEvaluationService = EvaluationPluginService<DurableEvaluationResultProvider>;

impl<P: EvaluationResultProvider> EvaluationPluginService<P> {
    pub fn new(service_id: impl Into<String>, provider: P) -> Result<Self> {
        let service_id = service_id.into();
        ensure!(
            !service_id.trim().is_empty(),
            "evaluation service id is required"
        );
        Ok(Self {
            service_id,
            provider,
            state: EvaluationPluginState::Unmounted,
            next_revision: 0,
            active: None,
        })
    }

    pub fn state(&self) -> EvaluationPluginState {
        self.state
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn mount(
        &mut self,
        evaluator_id: impl Into<String>,
        expected_source_commit: &str,
    ) -> Result<EvaluationEvaluator> {
        let evaluator_id = evaluator_id.into();
        ensure!(!evaluator_id.trim().is_empty(), "evaluator id is required");
        validate_commit(expected_source_commit)?;
        let evidence = self.provider.read_current(expected_source_commit)?;
        ensure!(
            evidence.source_commit() == expected_source_commit,
            "provider evidence is not bound to the requested source commit"
        );
        let mount_revision = self.next_revision();
        let evaluator = EvaluationEvaluator {
            service_id: self.service_id.clone(),
            evaluator_id,
            mount_revision,
            source_commit: expected_source_commit.into(),
            evidence_digest: evidence.evidence_digest().into(),
        };
        self.active = Some(ActiveEvaluator {
            evaluator: evaluator.clone(),
        });
        self.state = EvaluationPluginState::Mounted;
        Ok(evaluator)
    }

    pub fn unmount(&mut self) {
        self.invalidate(EvaluationPluginState::Unmounted);
    }

    pub fn revoke(&mut self) {
        self.invalidate(EvaluationPluginState::Revoked);
    }

    pub fn crash(&mut self) {
        self.invalidate(EvaluationPluginState::Crashed);
    }

    pub fn submit(&self, evaluator: &EvaluationEvaluator) -> Result<EvaluationResult> {
        ensure!(
            self.state == EvaluationPluginState::Mounted,
            "evaluation evaluator cannot submit while plugin is {:?}",
            self.state
        );
        let active = self
            .active
            .as_ref()
            .context("evaluation plugin has no active evaluator")?;
        ensure!(
            active.evaluator == *evaluator && evaluator.service_id == self.service_id,
            "evaluation evaluator mount is stale or belongs to another service"
        );
        let evidence = self.provider.read_current(evaluator.source_commit())?;
        ensure!(
            evidence.evidence_digest() == evaluator.evidence_digest(),
            "evaluation evidence changed after evaluator mount; remount is required"
        );
        EvaluationResult::from_evidence(
            &self.service_id,
            evaluator.evaluator_id(),
            evaluator.mount_revision(),
            &evidence,
        )
    }

    fn next_revision(&mut self) -> u64 {
        self.next_revision = self.next_revision.saturating_add(1);
        self.next_revision
    }

    fn invalidate(&mut self, state: EvaluationPluginState) {
        self.next_revision();
        self.active = None;
        self.state = state;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationMissionView {
    mission_id: String,
    evaluation_result_digest: String,
    execution_status: EvaluationExecutionStatus,
    evaluation_passed: bool,
    native_eligible: bool,
    release_eligible: bool,
}

impl EvaluationMissionView {
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub fn evaluation_result_digest(&self) -> &str {
        &self.evaluation_result_digest
    }

    pub fn execution_status(&self) -> EvaluationExecutionStatus {
        self.execution_status
    }

    pub fn evaluation_passed(&self) -> bool {
        self.evaluation_passed
    }

    pub fn native_eligible(&self) -> bool {
        self.native_eligible
    }

    pub fn release_eligible(&self) -> bool {
        self.release_eligible
    }
}

#[derive(Clone, Debug, Default)]
pub struct EvaluationMissionConsumer {
    mission_id: String,
}

impl EvaluationMissionConsumer {
    pub fn new(mission_id: impl Into<String>) -> Result<Self> {
        let mission_id = mission_id.into();
        ensure!(!mission_id.trim().is_empty(), "Mission id is required");
        Ok(Self { mission_id })
    }

    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub fn consume(&self, result: &EvaluationResult) -> Result<EvaluationMissionView> {
        ensure!(
            result.schema_version == EVALUATION_PLUGIN_SCHEMA_VERSION
                && result.authority == EVALUATION_PLUGIN_AUTHORITY
                && result.release_decision == EVALUATION_PLUGIN_RELEASE_DECISION,
            "Mission consumer received a result outside the evaluation-plugin contract"
        );
        ensure!(
            result.mission_ids.iter().any(|id| id == &self.mission_id),
            "evaluation result does not contain the requested Mission"
        );
        ensure!(
            !result.native_eligible && !result.release_eligible,
            "evaluation plugin result cannot carry native or Release authority"
        );
        Ok(EvaluationMissionView {
            mission_id: self.mission_id.clone(),
            evaluation_result_digest: result.result_digest.clone(),
            execution_status: result.execution_status,
            evaluation_passed: result.evaluation_passed,
            native_eligible: false,
            release_eligible: false,
        })
    }
}

fn validate_commit(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "source commit must be a lowercase 40-hex Git commit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

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

    fn completed_evidence(commit: &str, digest: &str) -> EvaluationEvidence {
        EvaluationEvidence::synthetic(
            commit,
            "run-01",
            digest,
            EvaluationEvidenceProvenance::DurableRun,
            EvaluationExecutionStatus::Completed,
            true,
        )
    }

    #[test]
    fn plugin_result_is_revision_and_digest_bound_without_release_authority() {
        let provider = StaticProvider::new(completed_evidence(COMMIT_A, &"a".repeat(64)));
        let mut service = EvaluationPluginService::new("eval-service", provider).unwrap();
        let evaluator = service.mount("evaluator-1", COMMIT_A).unwrap();
        let result = service.submit(&evaluator).unwrap();
        assert_eq!(result.schema_version(), EVALUATION_PLUGIN_SCHEMA_VERSION);
        assert_eq!(result.authority(), EVALUATION_PLUGIN_AUTHORITY);
        assert_eq!(
            result.release_decision(),
            EVALUATION_PLUGIN_RELEASE_DECISION
        );
        assert_eq!(result.revision(), evaluator.mount_revision());
        assert_eq!(result.evidence_digest(), evaluator.evidence_digest());
        assert!(!result.native_eligible());
        assert!(!result.release_eligible());
        assert!(is_lower_hex(result.result_digest(), 32));

        let consumer = EvaluationMissionConsumer::new("VM-00").unwrap();
        let view = consumer.consume(&result).unwrap();
        assert_eq!(view.evaluation_result_digest(), result.result_digest());
        assert!(!view.native_eligible());
        assert!(!view.release_eligible());
    }

    #[test]
    fn stale_handles_cannot_submit_after_unmount_revoke_or_crash() {
        let provider = StaticProvider::new(completed_evidence(COMMIT_A, &"b".repeat(64)));
        let mut service = EvaluationPluginService::new("eval-service", provider).unwrap();

        let evaluator = service.mount("evaluator-unmount", COMMIT_A).unwrap();
        service.unmount();
        assert!(service.submit(&evaluator).is_err());

        let evaluator = service.mount("evaluator-revoke", COMMIT_A).unwrap();
        service.revoke();
        assert!(service.submit(&evaluator).is_err());

        let evaluator = service.mount("evaluator-crash", COMMIT_A).unwrap();
        service.crash();
        assert!(service.submit(&evaluator).is_err());
    }

    #[test]
    fn evidence_tamper_and_replay_require_a_new_mount() {
        let provider = StaticProvider::new(completed_evidence(COMMIT_A, &"c".repeat(64)));
        let mut service = EvaluationPluginService::new("eval-service", provider.clone()).unwrap();
        let evaluator = service.mount("evaluator-1", COMMIT_A).unwrap();
        provider.replace(completed_evidence(COMMIT_A, &"d".repeat(64)));
        let error = service
            .submit(&evaluator)
            .expect_err("changed evidence must invalidate the old evaluator");
        assert!(error.to_string().contains("evidence changed"));

        let replayed = service.mount("evaluator-2", COMMIT_A).unwrap();
        let result = service.submit(&replayed).unwrap();
        assert_ne!(result.result_digest(), evaluator.evidence_digest());
    }

    #[test]
    fn current_commit_binding_rejects_stale_mount_and_provider() {
        let provider = StaticProvider::new(completed_evidence(COMMIT_A, &"e".repeat(64)));
        let mut service = EvaluationPluginService::new("eval-service", provider).unwrap();
        assert!(service.mount("evaluator", COMMIT_B).is_err());
        let evaluator = service.mount("evaluator", COMMIT_A).unwrap();
        assert!(service.submit(&evaluator).is_ok());
    }

    #[test]
    fn fixture_ignored_and_blocked_evidence_never_upgrade_native_or_release() {
        for (provenance, status) in [
            (
                EvaluationEvidenceProvenance::Fixture,
                EvaluationExecutionStatus::Completed,
            ),
            (
                EvaluationEvidenceProvenance::Ignored,
                EvaluationExecutionStatus::NotEvaluated,
            ),
            (
                EvaluationEvidenceProvenance::BlockedEnv,
                EvaluationExecutionStatus::BlockedEnv,
            ),
        ] {
            let evidence = EvaluationEvidence::synthetic(
                COMMIT_A,
                "run-01",
                &"f".repeat(64),
                provenance,
                status,
                false,
            );
            assert!(!evidence.native_eligible());
            assert!(!evidence.release_eligible());
        }
    }

    #[test]
    fn durable_provider_fails_closed_for_missing_or_non_run_evidence() {
        let root = tempfile::tempdir().unwrap();
        let provider = DurableEvaluationResultProvider::new(root.path());
        assert!(provider.read_current(COMMIT_A).is_err());
    }

    #[test]
    fn invalid_commit_shapes_are_rejected_before_provider_access() {
        let provider = StaticProvider::new(completed_evidence(COMMIT_A, &"1".repeat(64)));
        let mut service = EvaluationPluginService::new("eval-service", provider).unwrap();
        assert!(service.mount("evaluator", "not-a-commit").is_err());
    }
}

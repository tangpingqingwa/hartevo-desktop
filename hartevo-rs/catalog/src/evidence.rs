use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::CatalogSnapshot;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EvidenceLevel {
    E0,
    E1,
    E2,
    E3,
    E4,
    E5,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionEvidenceStatus {
    NotImplemented,
    BlockedEnv,
    Fail,
    Partial,
    ExpectedRefusal,
    Pass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStage {
    EngineeringFoundation,
    InternalAlpha,
    ControlledBeta,
    GeneralAvailability,
    MatureE5,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionEvidenceRecord {
    pub mission_id: String,
    pub evidence_level: EvidenceLevel,
    pub status: MissionEvidenceStatus,
    pub configured_v0_cases: usize,
    pub configured_v1_cases: usize,
    pub configured_v2_cases: usize,
    pub executed_v0_cases: usize,
    pub passed_v0_cases: usize,
    pub executed_v1_cases: usize,
    pub passed_v1_cases: usize,
    pub executed_v2_cases: usize,
    pub passed_v2_cases: usize,
    pub configured_cross_cutting_cases: usize,
    pub passed_cross_cutting_cases: usize,
    pub provider_canary_scenarios: usize,
    pub tenant_project_evidence: usize,
    pub observation_days: usize,
    pub failures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseEvidence {
    pub schema_version: String,
    pub passed: bool,
    pub release_commit: String,
    pub environment: String,
    pub requested_stage: ReleaseStage,
    pub mission_catalog_version: String,
    pub application_handler_registry_version: String,
    pub application_route_count: usize,
    pub implemented_application_handler_count: usize,
    pub not_implemented_application_route_count: usize,
    pub capability_catalog_version: String,
    pub provider_catalog_version: String,
    pub dataset_partition_revision: String,
    pub catalog_digest: String,
    pub contamination_audit_digest: Option<String>,
    pub traceability_complete: bool,
    pub mission_results: BTreeMap<String, MissionEvidenceRecord>,
    pub quality: QualityEvidence,
    pub safety_invariants: BTreeMap<String, bool>,
    pub not_implemented: Vec<String>,
    pub blocked_env: Vec<String>,
    pub failures: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityEvidence {
    pub mgcr: Option<f64>,
    pub vbor: Option<f64>,
    pub lcr: Option<f64>,
    pub work_product_adoption: Option<f64>,
    pub judge_calibrated_samples: usize,
    pub longitudinal_tenants: usize,
    pub longitudinal_verticals: usize,
    pub longitudinal_markets: usize,
    pub longitudinal_days: usize,
}

impl ReleaseEvidence {
    /// Produces an honest Wave 0 baseline. It is deliberately impossible for
    /// this record to pass a release gate: contract metadata is E1 evidence,
    /// not an implemented Mission, real Provider canary or longitudinal proof.
    pub fn wave_zero_baseline(
        snapshot: &CatalogSnapshot,
        release_commit: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let mut mission_results = BTreeMap::new();
        for mission_id in (0..12).map(|index| format!("VM-{index:02}")) {
            mission_results.insert(
                mission_id.clone(),
                MissionEvidenceRecord {
                    mission_id,
                    evidence_level: EvidenceLevel::E1,
                    status: MissionEvidenceStatus::NotImplemented,
                    configured_v0_cases: 20,
                    configured_v1_cases: 10,
                    configured_v2_cases: 5,
                    executed_v0_cases: 0,
                    passed_v0_cases: 0,
                    executed_v1_cases: 0,
                    passed_v1_cases: 0,
                    executed_v2_cases: 0,
                    passed_v2_cases: 0,
                    configured_cross_cutting_cases: 15,
                    passed_cross_cutting_cases: 0,
                    provider_canary_scenarios: 0,
                    tenant_project_evidence: 0,
                    observation_days: 0,
                    failures: vec!["E3 Mission journey has not been demonstrated".into()],
                },
            );
        }
        let not_implemented = mission_results.keys().cloned().collect();
        Self {
            schema_version: "2.2.0".into(),
            passed: false,
            release_commit: release_commit.into(),
            environment: "wave-zero-contract-baseline".into(),
            requested_stage: ReleaseStage::EngineeringFoundation,
            mission_catalog_version: snapshot.mission_catalog_version.clone(),
            application_handler_registry_version: snapshot
                .application_handler_registry_version
                .clone(),
            application_route_count: snapshot.summary.application_route_count,
            implemented_application_handler_count: snapshot
                .summary
                .implemented_application_handler_count,
            not_implemented_application_route_count: snapshot
                .summary
                .not_implemented_application_route_count,
            capability_catalog_version: snapshot.capability_catalog_version.clone(),
            provider_catalog_version: snapshot.provider_catalog_version.clone(),
            dataset_partition_revision: snapshot.dataset_registry_version.clone(),
            catalog_digest: snapshot.digest.clone(),
            contamination_audit_digest: None,
            traceability_complete: true,
            mission_results,
            quality: QualityEvidence {
                mgcr: None,
                vbor: None,
                lcr: None,
                work_product_adoption: None,
                judge_calibrated_samples: 0,
                longitudinal_tenants: 0,
                longitudinal_verticals: 0,
                longitudinal_markets: 0,
                longitudinal_days: 0,
            },
            safety_invariants: BTreeMap::from([
                ("approval_bypass".into(), false),
                ("cross_tenant_leak".into(), false),
                ("duplicate_external_effect".into(), false),
                ("human_handoff_violation".into(), false),
                ("private_dataset_leak".into(), false),
                ("secret_or_pii_leak".into(), false),
                ("uncertain_auto_replay".into(), false),
                ("wrong_money_consent_or_attribution".into(), false),
            ]),
            not_implemented,
            blocked_env: vec![
                "private V1 evaluator content is not mounted".into(),
                "fresh V2 content must be created after candidate freeze".into(),
                "real Provider credentials and approvals are not configured".into(),
                "local PostgreSQL L2 URL is not configured; the isolated CI Cell replay is a separate gate"
                    .into(),
                "platform signing and notarization credentials are not configured".into(),
                "the frozen twelve-tenant E5 cohort has not started".into(),
            ],
            failures: vec![
                "Engineering Foundation requires VM-00, VM-07, VM-11 and a writing Mission at E3"
                    .into(),
                format!(
                    "{} of {} Application routes have no registered production handler",
                    snapshot.summary.not_implemented_application_route_count,
                    snapshot.summary.application_route_count
                ),
                "no V0, V1 or V2 Mission case has executed against the target product".into(),
                "zero-tolerance suites are configured but have not executed".into(),
                "real Provider E4 canaries are absent".into(),
                "E5 longitudinal evidence is absent".into(),
            ],
            started_at: observed_at,
            completed_at: observed_at,
        }
    }

    pub fn validate_fail_closed(&self) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();
        if self.mission_results.len() != 12 {
            violations.push("release evidence must include all twelve Missions".into());
        }
        if self.application_handler_registry_version.trim().is_empty()
            || self.application_route_count
                != self.implemented_application_handler_count
                    + self.not_implemented_application_route_count
        {
            violations.push(
                "release evidence Application handler coverage is missing or inconsistent".into(),
            );
        }
        if self.passed
            && (!self.failures.is_empty()
                || !self.not_implemented.is_empty()
                || self.not_implemented_application_route_count > 0
                || self
                    .safety_invariants
                    .values()
                    .any(|invariant_passed| !invariant_passed))
        {
            violations.push(
                "passed=true is forbidden while failures, NOT_IMPLEMENTED or unproven safety invariants remain"
                    .into(),
            );
        }
        for (mission_id, mission) in &self.mission_results {
            if mission.mission_id != *mission_id {
                violations.push(format!("Mission evidence key mismatch for {mission_id}"));
            }
            if mission.configured_v0_cases != 20
                || mission.configured_v1_cases != 10
                || mission.configured_v2_cases != 5
                || mission.configured_cross_cutting_cases < 15
            {
                violations.push(format!(
                    "{mission_id} does not preserve the 20/10/5 + 15 contract"
                ));
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::Catalog;

    #[test]
    fn wave_zero_baseline_is_honest_and_fail_closed() {
        let snapshot = Catalog::load()
            .expect("catalog")
            .snapshot()
            .expect("snapshot");
        let observed_at = Utc
            .with_ymd_and_hms(2026, 8, 10, 16, 0, 0)
            .single()
            .expect("valid time");
        let evidence = ReleaseEvidence::wave_zero_baseline(
            &snapshot,
            "0e1e69e2793aa4df3b746a3779a466f683834915",
            observed_at,
        );
        assert!(!evidence.passed);
        assert_eq!(evidence.not_implemented.len(), 12);
        assert_eq!(
            (
                evidence.application_route_count,
                evidence.implemented_application_handler_count,
                evidence.not_implemented_application_route_count,
            ),
            (52, 3, 49)
        );
        let schema: serde_json::Value =
            serde_json::from_str(crate::RELEASE_EVIDENCE_SCHEMA_JSON).expect("release schema");
        let serialized = serde_json::to_value(&evidence).expect("release evidence JSON");
        for required in schema
            .get("required")
            .and_then(serde_json::Value::as_array)
            .expect("root required fields")
        {
            let field = required.as_str().expect("required field name");
            assert!(
                serialized.get(field).is_some(),
                "ReleaseEvidence is missing schema-required field {field}"
            );
        }
        assert_eq!(
            schema
                .pointer("/properties/schemaVersion/const")
                .and_then(serde_json::Value::as_str),
            Some(evidence.schema_version.as_str())
        );
        assert!(evidence.validate_fail_closed().is_ok());
    }

    #[test]
    fn a_false_positive_release_is_rejected() {
        let snapshot = Catalog::load()
            .expect("catalog")
            .snapshot()
            .expect("snapshot");
        let observed_at = Utc
            .with_ymd_and_hms(2026, 8, 10, 16, 0, 0)
            .single()
            .expect("valid time");
        let mut evidence = ReleaseEvidence::wave_zero_baseline(
            &snapshot,
            "0e1e69e2793aa4df3b746a3779a466f683834915",
            observed_at,
        );
        evidence.passed = true;
        assert!(evidence.validate_fail_closed().is_err());
    }
}

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{DataSubjectExportId, ProjectId, TenantId};

/// Durable data classes used by local retention and export policy.
///
/// Secret material is never an export payload. It is included here so a
/// policy can explicitly document that boundary rather than silently treating
/// a missing secret as ordinary business data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Restricted,
    Secret,
    Audit,
    Operations,
    EvalPrivate,
}

impl DataClassification {
    pub const fn all() -> [Self; 6] {
        [
            Self::Public,
            Self::Restricted,
            Self::Secret,
            Self::Audit,
            Self::Operations,
            Self::EvalPrivate,
        ]
    }

    pub const fn is_exportable(self) -> bool {
        !matches!(self, Self::Secret)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionAction {
    Delete,
    EraseContentRetainAudit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionRule {
    pub max_age_seconds: u64,
    pub action: RetentionAction,
    pub legal_hold_allowed: bool,
}

impl RetentionRule {
    pub fn validate(&self) -> Result<(), PrivacyError> {
        if self.max_age_seconds == 0 && !matches!(self.action, RetentionAction::Delete) {
            return Err(PrivacyError::InvalidRetentionPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicy {
    pub id: String,
    pub version: u64,
    pub effective_at: DateTime<Utc>,
    pub rules: BTreeMap<DataClassification, RetentionRule>,
    pub policy_digest: String,
}

impl RetentionPolicy {
    pub fn create(
        id: impl Into<String>,
        version: u64,
        effective_at: DateTime<Utc>,
        rules: BTreeMap<DataClassification, RetentionRule>,
    ) -> Result<Self, PrivacyError> {
        let mut policy = Self {
            id: id.into().trim().to_owned(),
            version,
            effective_at,
            rules,
            policy_digest: String::new(),
        };
        policy.policy_digest = policy.compute_digest()?;
        policy.validate(effective_at)?;
        Ok(policy)
    }

    /// The initial local policy mirrors the retention boundary in the threat
    /// model: operations are short-lived, audit evidence is retained, and
    /// restricted content is erased on request or at its explicit age.
    pub fn local_default(effective_at: DateTime<Utc>) -> Result<Self, PrivacyError> {
        let rules = BTreeMap::from([
            (
                DataClassification::Public,
                RetentionRule {
                    max_age_seconds: 365 * 24 * 60 * 60,
                    action: RetentionAction::Delete,
                    legal_hold_allowed: false,
                },
            ),
            (
                DataClassification::Restricted,
                RetentionRule {
                    max_age_seconds: 365 * 24 * 60 * 60,
                    action: RetentionAction::Delete,
                    legal_hold_allowed: true,
                },
            ),
            (
                DataClassification::Secret,
                RetentionRule {
                    max_age_seconds: 0,
                    action: RetentionAction::Delete,
                    legal_hold_allowed: false,
                },
            ),
            (
                DataClassification::Audit,
                RetentionRule {
                    max_age_seconds: 90 * 24 * 60 * 60,
                    action: RetentionAction::EraseContentRetainAudit,
                    legal_hold_allowed: true,
                },
            ),
            (
                DataClassification::Operations,
                RetentionRule {
                    max_age_seconds: 7 * 24 * 60 * 60,
                    action: RetentionAction::Delete,
                    legal_hold_allowed: false,
                },
            ),
            (
                DataClassification::EvalPrivate,
                RetentionRule {
                    max_age_seconds: 30 * 24 * 60 * 60,
                    action: RetentionAction::Delete,
                    legal_hold_allowed: false,
                },
            ),
        ]);
        Self::create("local-default", 1, effective_at, rules)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), PrivacyError> {
        if self.id.is_empty()
            || self.version == 0
            || self.effective_at > now
            || self.rules.len() != DataClassification::all().len()
            || DataClassification::all()
                .iter()
                .any(|classification| !self.rules.contains_key(classification))
            || self.policy_digest != self.compute_digest()?
        {
            return Err(PrivacyError::InvalidRetentionPolicy);
        }
        for rule in self.rules.values() {
            rule.validate()?;
        }
        Ok(())
    }

    pub fn decide(
        &self,
        classification: DataClassification,
        recorded_at: DateTime<Utc>,
        now: DateTime<Utc>,
        legal_hold: bool,
    ) -> Result<RetentionDecision, PrivacyError> {
        self.validate(now)?;
        let rule = self
            .rules
            .get(&classification)
            .ok_or(PrivacyError::InvalidRetentionPolicy)?;
        if legal_hold && !rule.legal_hold_allowed {
            return Err(PrivacyError::LegalHoldNotAllowed);
        }
        let due_at = recorded_at
            .checked_add_signed(Duration::seconds(
                i64::try_from(rule.max_age_seconds)
                    .map_err(|_| PrivacyError::RetentionIntervalOverflow)?,
            ))
            .ok_or(PrivacyError::RetentionIntervalOverflow)?;
        Ok(RetentionDecision {
            classification,
            action: if legal_hold {
                RetentionAction::EraseContentRetainAudit
            } else {
                rule.action
            },
            due_at,
            legal_hold,
            policy_digest: self.policy_digest.clone(),
        })
    }

    fn compute_digest(&self) -> Result<String, PrivacyError> {
        let bytes = serde_json::to_vec(&(&self.id, self.version, self.effective_at, &self.rules))
            .map_err(|_| PrivacyError::Serialization)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionDecision {
    pub classification: DataClassification,
    pub action: RetentionAction,
    pub due_at: DateTime<Utc>,
    pub legal_hold: bool,
    pub policy_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSubjectExportStatus {
    Requested,
    Ready,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSubjectExportRedaction {
    MetadataOnly,
    ContentErased,
    SecretWithheld,
}

/// One source summary in a DSR export. It deliberately contains no source
/// identifier, subject identifier, title, body, path, or credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSubjectExportArtifact {
    pub source_kind: String,
    pub classification: DataClassification,
    pub object_count: u64,
    pub metadata_digest: String,
    pub provenance_digest: String,
    pub redaction: DataSubjectExportRedaction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSubjectExport {
    pub id: DataSubjectExportId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub subject_digest: String,
    pub authorized_by: String,
    pub authorization_evidence_digest: String,
    pub status: DataSubjectExportStatus,
    pub redaction_profile: String,
    pub artifacts: Vec<DataSubjectExportArtifact>,
    pub generated_at: DateTime<Utc>,
    pub export_digest: String,
    pub revision: u64,
}

impl DataSubjectExport {
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds every export scope, authorization, redaction, and provenance field before persistence"
    )]
    pub fn create(
        id: DataSubjectExportId,
        tenant_id: TenantId,
        project_id: ProjectId,
        subject_digest: impl Into<String>,
        authorized_by: impl Into<String>,
        authorization_evidence_digest: impl Into<String>,
        redaction_profile: impl Into<String>,
        artifacts: Vec<DataSubjectExportArtifact>,
        generated_at: DateTime<Utc>,
    ) -> Result<Self, PrivacyError> {
        let mut export = Self {
            id,
            tenant_id,
            project_id,
            subject_digest: subject_digest.into(),
            authorized_by: authorized_by.into(),
            authorization_evidence_digest: authorization_evidence_digest.into(),
            status: DataSubjectExportStatus::Ready,
            redaction_profile: redaction_profile.into(),
            artifacts,
            generated_at,
            export_digest: String::new(),
            revision: 1,
        };
        export.export_digest = export.compute_digest()?;
        export.validate(generated_at)?;
        Ok(export)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), PrivacyError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !is_sha256(&self.subject_digest)
            || self.authorized_by.trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || self.redaction_profile.trim().is_empty()
            || self.generated_at > now
            || self.revision != 1
            || self.export_digest != self.compute_digest()?
            || self.artifacts.iter().any(|artifact| {
                artifact.source_kind.trim().is_empty()
                    || !is_sha256(&artifact.metadata_digest)
                    || !is_sha256(&artifact.provenance_digest)
                    || (matches!(artifact.classification, DataClassification::Secret)
                        && artifact.redaction != DataSubjectExportRedaction::SecretWithheld)
                    || (!artifact.classification.is_exportable()
                        && artifact.redaction != DataSubjectExportRedaction::SecretWithheld)
            })
        {
            return Err(PrivacyError::InvalidDataSubjectExport);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, PrivacyError> {
        let bytes = serde_json::to_vec(&(
            &self.id,
            &self.tenant_id,
            &self.project_id,
            &self.subject_digest,
            &self.authorized_by,
            &self.authorization_evidence_digest,
            self.status,
            &self.redaction_profile,
            &self.artifacts,
            self.generated_at,
            self.revision,
        ))
        .map_err(|_| PrivacyError::Serialization)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PrivacyError {
    #[error("retention policy is incomplete, stale, or tampered")]
    InvalidRetentionPolicy,
    #[error("retention policy interval cannot be represented")]
    RetentionIntervalOverflow,
    #[error("the requested legal hold is not allowed for this classification")]
    LegalHoldNotAllowed,
    #[error("data-subject export metadata is malformed or contains unredacted material")]
    InvalidDataSubjectExport,
    #[error("privacy digest could not be serialized")]
    Serialization,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 15, 0, 0)
            .single()
            .expect("valid time")
    }

    #[test]
    fn local_policy_has_explicit_classification_and_due_dates() {
        let policy = RetentionPolicy::local_default(now()).expect("policy");
        let decision = policy
            .decide(
                DataClassification::Operations,
                now() - Duration::days(8),
                now(),
                false,
            )
            .expect("decision");
        assert_eq!(decision.action, RetentionAction::Delete);
        assert!(decision.due_at < now());
        assert_eq!(policy.rules.len(), 6);
    }

    #[test]
    fn export_rejects_secret_artifact_without_explicit_withholding() {
        let artifact = DataSubjectExportArtifact {
            source_kind: "secret_store".into(),
            classification: DataClassification::Secret,
            object_count: 1,
            metadata_digest: "1".repeat(64),
            provenance_digest: "2".repeat(64),
            redaction: DataSubjectExportRedaction::MetadataOnly,
        };
        assert_eq!(
            DataSubjectExport::create(
                DataSubjectExportId::from("export-1"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                "3".repeat(64),
                "actor-1",
                "4".repeat(64),
                "metadata-v1",
                vec![artifact],
                now(),
            ),
            Err(PrivacyError::InvalidDataSubjectExport)
        );
    }
}

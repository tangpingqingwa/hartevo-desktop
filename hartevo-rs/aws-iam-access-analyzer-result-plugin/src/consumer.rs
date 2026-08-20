//! Mission-facing review candidates. These values remain below kernel Truth,
//! Consent, Effect, Verification, and Outcome authority.

use std::fmt;

use serde::Serialize;

use crate::error::{AwsIamAccessAnalyzerError, Result};
use crate::model::{
    AccessExposure, AnalysisState, AwsIamAccessAnalyzerScope, CapabilityClaim, Digest,
    FindingSummaryV2, MissionIdentity, ProjectIdentity, ProviderErrorKind, ValidatePolicyFinding,
};
use crate::service::{
    AwsIamAccessAnalyzerRegistration, FindingsEvidence, PolicyValidationEvidence,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionReviewState {
    PendingReview,
    Partial,
    ProviderUnknown,
    BlockedEnv,
}

impl MissionReviewState {
    fn from_analysis(state: &AnalysisState) -> Self {
        match state {
            AnalysisState::Complete | AnalysisState::EmptyNotProof => Self::PendingReview,
            AnalysisState::Partial(_) => Self::Partial,
            AnalysisState::ProviderUnknown(_) => Self::ProviderUnknown,
            AnalysisState::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposureCounts {
    pub public: usize,
    pub cross_account: usize,
    pub internal: usize,
    pub unused: usize,
}

impl ExposureCounts {
    fn from_findings(findings: &[FindingSummaryV2]) -> Self {
        let mut counts = Self {
            public: 0,
            cross_account: 0,
            internal: 0,
            unused: 0,
        };
        for finding in findings {
            match finding.exposure {
                AccessExposure::Public => counts.public += 1,
                AccessExposure::CrossAccount => counts.cross_account += 1,
                AccessExposure::Internal => counts.internal += 1,
                AccessExposure::Unused => counts.unused += 1,
            }
        }
        counts
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyFindingCounts {
    pub errors: usize,
    pub security_warnings: usize,
    pub warnings: usize,
    pub suggestions: usize,
}

impl PolicyFindingCounts {
    fn from_findings(findings: &[ValidatePolicyFinding]) -> Self {
        let mut counts = Self {
            errors: 0,
            security_warnings: 0,
            warnings: 0,
            suggestions: 0,
        };
        for finding in findings {
            match finding.finding_type {
                crate::PolicyFindingType::Error => counts.errors += 1,
                crate::PolicyFindingType::SecurityWarning => counts.security_warnings += 1,
                crate::PolicyFindingType::Warning => counts.warnings += 1,
                crate::PolicyFindingType::Suggestion => counts.suggestions += 1,
            }
        }
        counts
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIamAccessAnalyzerReview {
    pub state: MissionReviewState,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub consent_id: crate::ConsentId,
    pub consent_revision: crate::Revision,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub finding_count: usize,
    pub exposure_counts: ExposureCounts,
    pub policy_finding_counts: PolicyFindingCounts,
    pub policy_digest: Option<Digest>,
    pub policy_bytes: Option<usize>,
    pub provider_error: Option<ProviderErrorKind>,
    pub review_required: bool,
    pub absence_is_not_proof: bool,
    pub can_be_adopted: bool,
    pub least_privilege_certified: bool,
    pub authority: CapabilityClaim,
}

impl MissionIamAccessAnalyzerReview {
    pub const fn is_review_only(&self) -> bool {
        !self.can_be_adopted
    }
}

pub type MissionIamAccessAnalyzerResult = MissionIamAccessAnalyzerReview;
pub type MissionIamAccessAnalyzerReviewCandidate = MissionIamAccessAnalyzerReview;

#[derive(Clone)]
pub struct MissionIamAccessAnalyzerConsumer {
    scope: AwsIamAccessAnalyzerScope,
    registration_digest: Digest,
    active: bool,
}

impl fmt::Debug for MissionIamAccessAnalyzerConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIamAccessAnalyzerConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionIamAccessAnalyzerConsumer {
    /// Construct a consumer before a registration is attached. Use
    /// `from_registration` when the registration binding is available.
    pub fn new(scope: AwsIamAccessAnalyzerScope) -> Self {
        Self {
            registration_digest: Digest::from_text("unbound-registration"),
            scope,
            active: true,
        }
    }

    pub fn from_registration(registration: &AwsIamAccessAnalyzerRegistration) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            scope: registration.scope().clone(),
            registration_digest: registration.binding_digest().clone(),
            active: registration.is_active(),
        })
    }

    pub fn bind_registration(
        &mut self,
        registration: &AwsIamAccessAnalyzerRegistration,
    ) -> Result<()> {
        registration.validate()?;
        if registration.scope() != &self.scope {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        self.registration_digest = registration.binding_digest().clone();
        self.active = registration.is_active();
        Ok(())
    }

    pub fn scope(&self) -> &AwsIamAccessAnalyzerScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.active {
            self.active = false;
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::ConsumerRevoked)
        }
    }

    pub fn consume_findings(
        &self,
        evidence: &FindingsEvidence,
    ) -> Result<MissionIamAccessAnalyzerReview> {
        self.consume_findings_at_revision(evidence, self.scope.mission.revision)
    }

    pub fn consume_findings_at_revision(
        &self,
        evidence: &FindingsEvidence,
        mission_revision: crate::Revision,
    ) -> Result<MissionIamAccessAnalyzerReview> {
        self.ensure_revision(mission_revision)?;
        evidence.validate_integrity()?;
        self.ensure_evidence_binding(&evidence.scope_digest, &evidence.registration_digest)?;
        Ok(MissionIamAccessAnalyzerReview {
            state: MissionReviewState::from_analysis(&evidence.state),
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            consent_id: self.scope.consent.id.clone(),
            consent_revision: self.scope.consent.revision,
            consent_digest: self.scope.consent.digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            finding_count: evidence.finding_count,
            exposure_counts: ExposureCounts::from_findings(&evidence.findings),
            policy_finding_counts: PolicyFindingCounts {
                errors: 0,
                security_warnings: 0,
                warnings: 0,
                suggestions: 0,
            },
            policy_digest: None,
            policy_bytes: None,
            provider_error: evidence.provider_error,
            review_required: true,
            absence_is_not_proof: true,
            can_be_adopted: false,
            least_privilege_certified: false,
            authority: CapabilityClaim::layer_one(),
        })
    }

    pub fn consume_policy_validation(
        &self,
        evidence: &PolicyValidationEvidence,
    ) -> Result<MissionIamAccessAnalyzerReview> {
        self.consume_policy_validation_at_revision(evidence, self.scope.mission.revision)
    }

    pub fn consume_policy_validation_at_revision(
        &self,
        evidence: &PolicyValidationEvidence,
        mission_revision: crate::Revision,
    ) -> Result<MissionIamAccessAnalyzerReview> {
        self.ensure_revision(mission_revision)?;
        evidence.validate_integrity()?;
        self.ensure_evidence_binding(&evidence.scope_digest, &evidence.registration_digest)?;
        Ok(MissionIamAccessAnalyzerReview {
            state: MissionReviewState::from_analysis(&evidence.state),
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            consent_id: self.scope.consent.id.clone(),
            consent_revision: self.scope.consent.revision,
            consent_digest: self.scope.consent.digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            finding_count: evidence.finding_count,
            exposure_counts: ExposureCounts {
                public: 0,
                cross_account: 0,
                internal: 0,
                unused: 0,
            },
            policy_finding_counts: PolicyFindingCounts::from_findings(&evidence.findings),
            policy_digest: Some(evidence.policy_digest.clone()),
            policy_bytes: Some(evidence.policy_bytes),
            provider_error: evidence.provider_error,
            review_required: true,
            absence_is_not_proof: true,
            can_be_adopted: false,
            least_privilege_certified: false,
            authority: CapabilityClaim::layer_one(),
        })
    }

    pub fn review_findings(
        &self,
        evidence: &FindingsEvidence,
    ) -> Result<MissionIamAccessAnalyzerReview> {
        self.consume_findings(evidence)
    }

    pub fn review_policy(
        &self,
        evidence: &PolicyValidationEvidence,
    ) -> Result<MissionIamAccessAnalyzerReview> {
        self.consume_policy_validation(evidence)
    }

    fn ensure_revision(&self, mission_revision: crate::Revision) -> Result<()> {
        if !self.active {
            return Err(AwsIamAccessAnalyzerError::ConsumerRevoked);
        }
        if mission_revision != self.scope.mission.revision {
            return Err(AwsIamAccessAnalyzerError::StaleMissionRevision);
        }
        Ok(())
    }

    fn ensure_evidence_binding(
        &self,
        scope_digest: &Digest,
        registration_digest: &Digest,
    ) -> Result<()> {
        if *scope_digest != self.scope.digest() {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        if self.registration_digest.as_str() != "unbound-registration"
            && *registration_digest != self.registration_digest
        {
            return Err(AwsIamAccessAnalyzerError::RegistrationMismatch);
        }
        Ok(())
    }
}

pub type MissionIamAccessAnalyzerResultConsumer = MissionIamAccessAnalyzerConsumer;

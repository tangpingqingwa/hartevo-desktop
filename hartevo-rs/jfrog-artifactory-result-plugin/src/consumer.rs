//! Mission-scoped digest-fenced release decision proposal and recording seam.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    ArtifactStatus, Digest, JfrogScope, MissionId, ProjectId, ProjectionCompleteness,
    RegistrationId, TransportProvenance, WorkProductId,
};
use crate::provider::JfrogArtifactProjection;
use crate::service::JfrogRegistration;
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, JfrogArtifactoryResultError, Result, SERVICE_ID, validate_text,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecision {
    RecommendRelease,
    DoNotRelease,
    NeedsReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    RecommendRelease,
    DoNotRelease,
    ReviewOnly,
    Truncated,
}

/// A below-kernel release decision proposal. It contains digests and bounded
/// state only; it is not a Receipt, Verification, Outcome, or provider write.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JfrogArtifactReleaseProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub registration_id: RegistrationId,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub status: ArtifactStatus,
    pub release_decision: ReleaseDecision,
    pub disposition: ProposalDisposition,
    pub artifact_metadata_digest: Option<Digest>,
    pub checksum_digest: Option<Digest>,
    pub build_info_digest: Option<Digest>,
    pub promotion_digest: Option<Digest>,
    pub projection_digest: Digest,
    pub provenance_digest: Digest,
    pub completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl JfrogArtifactReleaseProposal {
    fn from_projection(
        registration: &JfrogRegistration,
        scope: &JfrogScope,
        projection: &JfrogArtifactProjection,
        idempotency_key: &str,
    ) -> Self {
        let complete = projection.is_complete();
        let release_decision = match projection.status {
            ArtifactStatus::Promoted if complete && projection.artifact_metadata.is_some() => {
                ReleaseDecision::RecommendRelease
            }
            ArtifactStatus::Rejected if complete => ReleaseDecision::DoNotRelease,
            _ => ReleaseDecision::NeedsReview,
        };
        let disposition = match release_decision {
            ReleaseDecision::RecommendRelease => ProposalDisposition::RecommendRelease,
            ReleaseDecision::DoNotRelease => ProposalDisposition::DoNotRelease,
            ReleaseDecision::NeedsReview if !complete => ProposalDisposition::Truncated,
            ReleaseDecision::NeedsReview => ProposalDisposition::ReviewOnly,
        };
        let mut proposal = Self {
            proposal_version: format!("{CONTRACT_VERSION}/release-decision-proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_id: registration.id().clone(),
            registration_revision: registration.registration_revision(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            mission_id: scope.mission.id.clone(),
            mission_revision: scope.mission.revision,
            project_id: scope.project.id.clone(),
            project_revision: scope.project.revision,
            work_product_id: scope.work_product.id.clone(),
            work_product_revision: scope.work_product.revision,
            status: projection.status,
            release_decision,
            disposition,
            artifact_metadata_digest: projection.artifact_metadata_digest().cloned(),
            checksum_digest: projection.checksum_digest(),
            build_info_digest: projection.build_info_digest().cloned(),
            promotion_digest: projection
                .promotion
                .as_ref()
                .map(|promotion| promotion.promotion_digest.clone()),
            projection_digest: projection.projection_digest.clone(),
            provenance_digest: projection.provenance_digest.clone(),
            completeness: projection.completeness,
            provenance: projection.provenance,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            proposal_digest: Digest::from_text("unsealed-jfrog-release-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        for digest in [
            self.artifact_metadata_digest.as_ref(),
            self.checksum_digest.as_ref(),
            self.build_info_digest.as_ref(),
            self.promotion_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        self.projection_digest.validate()?;
        self.provenance_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        if self.proposal_version != format!("{CONTRACT_VERSION}/release-decision-proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.registration_revision == 0
            || self.mission_revision == 0
            || self.project_revision == 0
            || self.work_product_revision == 0
            || self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.provenance.is_native()
            || self.provenance.claims_connected()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "jfrog-artifactory-release-decision-proposal/v1",
            &[
                ("proposal_version", self.proposal_version.clone()),
                ("service_id", self.service_id.clone()),
                ("consumer_id", self.consumer_id.clone()),
                ("registration_id", self.registration_id.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                (
                    "registration_digest",
                    self.registration_digest.as_str().to_owned(),
                ),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                ("mission_id", self.mission_id.as_str().to_owned()),
                ("mission_revision", self.mission_revision.to_string()),
                ("project_id", self.project_id.as_str().to_owned()),
                ("project_revision", self.project_revision.to_string()),
                ("work_product_id", self.work_product_id.as_str().to_owned()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                ("status", format!("{:?}", self.status)),
                ("release_decision", format!("{:?}", self.release_decision)),
                ("disposition", format!("{:?}", self.disposition)),
                (
                    "artifact_metadata_digest",
                    optional_digest(self.artifact_metadata_digest.as_ref()),
                ),
                (
                    "checksum_digest",
                    optional_digest(self.checksum_digest.as_ref()),
                ),
                (
                    "build_info_digest",
                    optional_digest(self.build_info_digest.as_ref()),
                ),
                (
                    "promotion_digest",
                    optional_digest(self.promotion_digest.as_ref()),
                ),
                (
                    "projection_digest",
                    self.projection_digest.as_str().to_owned(),
                ),
                (
                    "provenance_digest",
                    self.provenance_digest.as_str().to_owned(),
                ),
                ("completeness", format!("{:?}", self.completeness)),
                ("provenance", format!("{:?}", self.provenance)),
                (
                    "idempotency_key_digest",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

pub type ReleaseDecisionProposal = JfrogArtifactReleaseProposal;
pub type JfrogReleaseDecisionProposal = JfrogArtifactReleaseProposal;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedJfrogArtifactResult {
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub release_decision: ReleaseDecision,
    pub disposition: ProposalDisposition,
    pub completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedJfrogArtifactResult {
    fn from_proposal(proposal: &JfrogArtifactReleaseProposal, replayed: bool) -> Self {
        let mut result = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            release_decision: proposal.release_decision,
            disposition: proposal.disposition,
            completeness: proposal.completeness,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-jfrog-recording"),
        };
        result.recording_digest = Digest::from_serialized(&(
            &result.proposal_digest,
            &result.scope_digest,
            &result.registration_digest,
            result.release_decision,
            result.disposition,
            result.completeness,
            result.provenance,
        ));
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        if self.connected || self.native || self.provider_receipt || self.outcome_adopted {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        let expected = Digest::from_serialized(&(
            &self.proposal_digest,
            &self.scope_digest,
            &self.registration_digest,
            self.release_decision,
            self.disposition,
            self.completeness,
            self.provenance,
        ));
        if self.recording_digest != expected {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct JfrogArtifactRecordingLog {
    records: BTreeMap<Digest, RecordedJfrogArtifactResult>,
}

impl JfrogArtifactRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedJfrogArtifactResult> {
        self.records.get(idempotency_key_digest)
    }

    fn record(
        &mut self,
        proposal: &JfrogArtifactReleaseProposal,
    ) -> Result<RecordedJfrogArtifactResult> {
        proposal.validate_integrity()?;
        if let Some(existing) = self.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(JfrogArtifactoryResultError::ReplayConflict);
            }
            let replay = RecordedJfrogArtifactResult::from_proposal(proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedJfrogArtifactResult::from_proposal(proposal, false);
        result.validate_integrity()?;
        self.records
            .insert(proposal.idempotency_key_digest.clone(), result.clone());
        Ok(result)
    }
}

/// A Mission consumer bound to one exact JFrog and Hartevo scope. It emits a
/// digest-fenced release decision proposal and safe recording only.
#[derive(Clone, Debug)]
pub struct MissionJfrogArtifactConsumer {
    scope: JfrogScope,
}

impl MissionJfrogArtifactConsumer {
    pub fn new(scope: JfrogScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &JfrogScope {
        &self.scope
    }

    pub fn compile_release_decision_proposal(
        &self,
        registration: &JfrogRegistration,
        projection: &JfrogArtifactProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<JfrogArtifactReleaseProposal> {
        self.scope.validate()?;
        registration.validate()?;
        projection.validate_integrity()?;
        if registration.scope() != &self.scope || projection.scope != self.scope {
            return Err(JfrogArtifactoryResultError::ScopeMismatch);
        }
        let idempotency_key = idempotency_key.into();
        validate_text(&idempotency_key, "idempotencyKey", 256, false)?;
        Ok(JfrogArtifactReleaseProposal::from_projection(
            registration,
            &self.scope,
            projection,
            &idempotency_key,
        ))
    }

    pub fn compile_proposal(
        &self,
        registration: &JfrogRegistration,
        projection: &JfrogArtifactProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<JfrogArtifactReleaseProposal> {
        self.compile_release_decision_proposal(registration, projection, idempotency_key)
    }

    pub fn record_release_decision(
        &self,
        log: &mut JfrogArtifactRecordingLog,
        proposal: &JfrogArtifactReleaseProposal,
    ) -> Result<RecordedJfrogArtifactResult> {
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != self.scope.mission.id
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.project_id != self.scope.project.id
            || proposal.project_revision != self.scope.project.revision
            || proposal.work_product_id != self.scope.work_product.id
            || proposal.work_product_revision != self.scope.work_product.revision
        {
            return Err(JfrogArtifactoryResultError::ScopeMismatch);
        }
        log.record(proposal)
    }

    pub fn record(
        &self,
        log: &mut JfrogArtifactRecordingLog,
        proposal: &JfrogArtifactReleaseProposal,
    ) -> Result<RecordedJfrogArtifactResult> {
        self.record_release_decision(log, proposal)
    }
}

fn optional_digest(value: Option<&Digest>) -> String {
    value.map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned())
}

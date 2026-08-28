use std::fmt;

use serde::Serialize;

use crate::error::{CloudinaryAssetResultError, Result};
use crate::model::{CloudinaryEvidenceState, CloudinaryScope, Digest, TransportProvenance};
use crate::service::{
    CloudinaryAssetResultProposal, CloudinaryAssetResultRegistration, RegistrationStatus,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    RecordedForReview,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCloudinaryAssetResult {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub state: CloudinaryEvidenceState,
    pub provenance: TransportProvenance,
    pub disposition: ProposalDisposition,
    pub review_only: bool,
    pub can_be_adopted: bool,
    pub result_digest: Digest,
}

pub type RecordedCloudinaryAssetResult = MissionCloudinaryAssetResult;
pub type MissionCloudinaryResult = MissionCloudinaryAssetResult;

impl MissionCloudinaryAssetResult {
    fn from_proposal(proposal: &CloudinaryAssetResultProposal) -> Self {
        let result_digest = Digest::from_parts(
            "cloudinary-mission-result/v1",
            &[
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                (
                    "evidence",
                    proposal.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("scope", proposal.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", proposal.state)),
                ("provenance", proposal.provenance.as_str().to_owned()),
                ("disposition", "recorded_for_review".to_owned()),
            ],
        );
        Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            provenance: proposal.provenance,
            disposition: ProposalDisposition::RecordedForReview,
            review_only: true,
            can_be_adopted: false,
            result_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.disposition != ProposalDisposition::RecordedForReview
            || !self.review_only
            || self.can_be_adopted
            || self.result_digest
                != Digest::from_parts(
                    "cloudinary-mission-result/v1",
                    &[
                        ("proposal", self.proposal_digest.as_str().to_owned()),
                        ("evidence", self.evidence_digest.as_str().to_owned()),
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("state", format!("{:?}", self.state)),
                        ("provenance", self.provenance.as_str().to_owned()),
                        ("disposition", "recorded_for_review".to_owned()),
                    ],
                )
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        self.proposal_digest.validate()?;
        self.evidence_digest.validate()?;
        self.scope_digest.validate()
    }
}

pub struct MissionCloudinaryAssetConsumer {
    scope: CloudinaryScope,
    registration: CloudinaryAssetResultRegistration,
    records: Vec<MissionCloudinaryAssetResult>,
}

impl fmt::Debug for MissionCloudinaryAssetConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionCloudinaryAssetConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionCloudinaryAssetConsumer {
    pub fn new(
        scope: CloudinaryScope,
        registration: CloudinaryAssetResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest() {
            return Err(CloudinaryAssetResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: Vec::new(),
        })
    }

    pub fn scope(&self) -> &CloudinaryScope {
        &self.scope
    }

    pub fn registration(&self) -> &CloudinaryAssetResultRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn records(&self) -> &[MissionCloudinaryAssetResult] {
        &self.records
    }

    pub fn consume(
        &mut self,
        proposal: &CloudinaryAssetResultProposal,
    ) -> Result<MissionCloudinaryAssetResult> {
        self.ensure_active()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
        {
            return Err(CloudinaryAssetResultError::ReplayConflict);
        }
        proposal.validate_integrity()?;
        if self
            .records
            .iter()
            .any(|record| record.proposal_digest == proposal.proposal_digest)
        {
            return Err(CloudinaryAssetResultError::DuplicateEvidence);
        }
        let result = MissionCloudinaryAssetResult::from_proposal(proposal);
        result.validate()?;
        self.records.push(result.clone());
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &CloudinaryAssetResultProposal,
    ) -> Result<MissionCloudinaryAssetResult> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<()> {
        self.registration.restore()?;
        Ok(())
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration.validate()?;
        if !matches!(self.registration.status(), RegistrationStatus::Active) {
            return Err(CloudinaryAssetResultError::RegistrationInactive);
        }
        Ok(())
    }
}

pub type MissionCloudinaryResultConsumer = MissionCloudinaryAssetConsumer;

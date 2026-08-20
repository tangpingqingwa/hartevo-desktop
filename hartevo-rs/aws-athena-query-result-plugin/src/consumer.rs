use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::CONSUMER_ID;
use crate::error::Result;
use crate::model::{AthenaQueryResultStatus, AwsAthenaQueryResultScope, Digest};
use crate::service::{
    AwsAthenaQueryResultProposal, AwsAthenaQueryResultRegistration, RegistrationStatus,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    AvailableReview,
    QueuedReview,
    RunningReview,
    FailedReview,
    CancelledReview,
    Partial,
    Expired,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Revoked,
    Stale,
}

impl ProposalDisposition {
    const fn from_status(status: AthenaQueryResultStatus) -> Self {
        match status {
            AthenaQueryResultStatus::Queued => Self::QueuedReview,
            AthenaQueryResultStatus::Running => Self::RunningReview,
            AthenaQueryResultStatus::Succeeded => Self::AvailableReview,
            AthenaQueryResultStatus::Failed => Self::FailedReview,
            AthenaQueryResultStatus::Cancelled => Self::CancelledReview,
            AthenaQueryResultStatus::Partial => Self::Partial,
            AthenaQueryResultStatus::Expired => Self::Expired,
            AthenaQueryResultStatus::AccessLost => Self::AccessLoss,
            AthenaQueryResultStatus::ProviderUnknown => Self::ProviderUnknown,
            AthenaQueryResultStatus::Tampered => Self::Tampered,
            AthenaQueryResultStatus::Revoked => Self::Revoked,
            AthenaQueryResultStatus::Stale => Self::Stale,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Athena consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Athena consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Athena consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS Athena consumer idempotency key conflicts with a prior result")]
    ReplayConflict,
    #[error("Mission AWS Athena consumer operation failed: {0}")]
    Service(#[from] crate::error::AwsAthenaQueryResultError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsAthenaResult {
    pub consumer_id: &'static str,
    pub disposition: ProposalDisposition,
    pub observed_state: AthenaQueryResultStatus,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub mission_id_digest: Digest,
    pub mission_revision: crate::model::Revision,
    pub project_id_digest: Digest,
    pub work_product_id_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub result_digest: Digest,
}

impl MissionAwsAthenaResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        let expected = Digest::from_parts(
            "aws-athena-mission-result/v1",
            &[
                ("consumer", self.consumer_id.to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("mission", self.mission_id_digest.as_str().to_owned()),
                ("mission_revision", self.mission_revision.get().to_string()),
                ("project", self.project_id_digest.as_str().to_owned()),
                (
                    "work_product",
                    self.work_product_id_digest.as_str().to_owned(),
                ),
                ("state", self.observed_state.as_str().to_owned()),
                ("review", self.requires_human_review.to_string()),
                ("safe", self.safe_to_promote.to_string()),
            ],
        );
        if self.outcome_adopted || self.work_product_adopted || expected != self.result_digest {
            Err(crate::error::AwsAthenaQueryResultError::EvidenceTampered)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsAthenaResult {
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub replayed: bool,
    pub receipt_digest: Digest,
}

impl RecordedAwsAthenaResult {
    pub fn validate_integrity(&self) -> Result<()> {
        let expected = Digest::from_parts(
            "aws-athena-recorded-result/v1",
            &[
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        );
        if expected == self.receipt_digest {
            Ok(())
        } else {
            Err(crate::error::AwsAthenaQueryResultError::EvidenceTampered)
        }
    }
}

pub struct MissionAwsAthenaConsumer {
    scope: AwsAthenaQueryResultScope,
    registration: AwsAthenaQueryResultRegistration,
    records: BTreeMap<Digest, Digest>,
    revoked: bool,
}

impl fmt::Debug for MissionAwsAthenaConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsAthenaConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl MissionAwsAthenaConsumer {
    pub fn new(
        scope: AwsAthenaQueryResultScope,
        registration: AwsAthenaQueryResultRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        registration.validate()?;
        if registration.scope_digest() != scope.scope_digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
            revoked: false,
        })
    }

    pub fn registration(&self) -> &AwsAthenaQueryResultRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsAthenaQueryResultScope {
        &self.scope
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub const fn is_active(&self) -> bool {
        !self.revoked
    }

    pub fn revoke(&mut self) -> std::result::Result<(), ConsumerError> {
        if self.revoked {
            Err(ConsumerError::RegistrationRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: &AwsAthenaQueryResultProposal,
    ) -> std::result::Result<MissionAwsAthenaResult, ConsumerError> {
        self.validate_proposal(proposal)?;
        let requires_human_review = true;
        let safe_to_promote = false;
        let result_digest = Digest::from_parts(
            "aws-athena-mission-result/v1",
            &[
                ("consumer", CONSUMER_ID.to_owned()),
                ("scope", proposal.scope_digest.as_str().to_owned()),
                (
                    "registration",
                    proposal.registration_digest.as_str().to_owned(),
                ),
                (
                    "evidence",
                    proposal.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                ("mission", proposal.mission.id_digest.as_str().to_owned()),
                (
                    "mission_revision",
                    proposal.mission.revision.get().to_string(),
                ),
                ("project", proposal.project.id_digest.as_str().to_owned()),
                (
                    "work_product",
                    proposal.work_product.id_digest.as_str().to_owned(),
                ),
                ("state", proposal.state.as_str().to_owned()),
                ("review", requires_human_review.to_string()),
                ("safe", safe_to_promote.to_string()),
            ],
        );
        Ok(MissionAwsAthenaResult {
            consumer_id: CONSUMER_ID,
            disposition: ProposalDisposition::from_status(proposal.state),
            observed_state: proposal.state,
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            mission_id_digest: proposal.mission.id_digest.clone(),
            mission_revision: proposal.mission.revision,
            project_id_digest: proposal.project.id_digest.clone(),
            work_product_id_digest: proposal.work_product.id_digest.clone(),
            requires_human_review,
            safe_to_promote,
            outcome_adopted: false,
            work_product_adopted: false,
            result_digest,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsAthenaQueryResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedAwsAthenaResult, ConsumerError> {
        self.validate_proposal(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::Service(
                crate::error::AwsAthenaQueryResultError::InvalidRequest,
            ));
        }
        let idempotency_digest =
            Digest::from_parts("aws-athena-idempotency-key/v1", &[("key", key.to_owned())]);
        if let Some(previous) = self.records.get(&idempotency_digest) {
            if previous != &proposal.proposal_digest {
                return Err(ConsumerError::ReplayConflict);
            }
            let receipt_digest = Digest::from_parts(
                "aws-athena-recorded-result/v1",
                &[
                    ("idempotency", idempotency_digest.as_str().to_owned()),
                    ("proposal", proposal.proposal_digest.as_str().to_owned()),
                    (
                        "evidence",
                        proposal.evidence.evidence_digest.as_str().to_owned(),
                    ),
                    ("replayed", "true".to_owned()),
                ],
            );
            return Ok(RecordedAwsAthenaResult {
                idempotency_digest,
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence.evidence_digest.clone(),
                replayed: true,
                receipt_digest,
            });
        }
        self.records
            .insert(idempotency_digest.clone(), proposal.proposal_digest.clone());
        let receipt_digest = Digest::from_parts(
            "aws-athena-recorded-result/v1",
            &[
                ("idempotency", idempotency_digest.as_str().to_owned()),
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                (
                    "evidence",
                    proposal.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("replayed", "false".to_owned()),
            ],
        );
        Ok(RecordedAwsAthenaResult {
            idempotency_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            replayed: false,
            receipt_digest,
        })
    }

    fn validate_proposal(
        &self,
        proposal: &AwsAthenaQueryResultProposal,
    ) -> std::result::Result<(), ConsumerError> {
        if self.revoked
            || !self.registration.is_active()
            || self.registration.status() == RegistrationStatus::Revoked
        {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.scope.scope_digest()
            || proposal.mission.revision != self.scope.mission_revision()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

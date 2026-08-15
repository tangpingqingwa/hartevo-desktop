use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::CONSUMER_ID;
use crate::error::Result;
use crate::model::{AppSyncEvidenceState, AwsAppSyncApiScope, Digest};
use crate::service::{
    AwsAppSyncApiResultProposal, AwsAppSyncApiResultRegistration, RegistrationStatus,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    AvailableReview,
    DisabledReview,
    DegradedReview,
    StaleReview,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl ProposalDisposition {
    const fn from_state(state: AppSyncEvidenceState) -> Self {
        match state {
            AppSyncEvidenceState::Available => Self::AvailableReview,
            AppSyncEvidenceState::Disabled => Self::DisabledReview,
            AppSyncEvidenceState::Degraded => Self::DegradedReview,
            AppSyncEvidenceState::Stale => Self::StaleReview,
            AppSyncEvidenceState::Partial => Self::Partial,
            AppSyncEvidenceState::AccessLost => Self::AccessLoss,
            AppSyncEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AppSyncEvidenceState::Tampered => Self::Tampered,
            AppSyncEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS AppSync consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS AppSync consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS AppSync consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS AppSync consumer idempotency key conflicts with a prior result")]
    ReplayConflict,
    #[error("Mission AWS AppSync consumer operation failed: {0}")]
    Service(#[from] crate::error::AwsAppSyncApiResultError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsAppSyncResult {
    pub consumer_id: &'static str,
    pub disposition: ProposalDisposition,
    pub observed_state: AppSyncEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub mission_id_digest: Digest,
    pub project_id_digest: Digest,
    pub work_product_id_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub availability_claim: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

impl MissionAwsAppSyncResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.consumer_id != CONSUMER_ID
            || !self.requires_human_review
            || self.safe_to_promote
            || self.connected
            || self.native
            || self.first_party
            || self.availability_claim
            || self.adopted_outcome
            || self.adopted_work_product
            || self.truth_authority
        {
            return Err(crate::error::AwsAppSyncApiResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsAppSyncResult {
    pub idempotency_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub disposition: ProposalDisposition,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub record_digest: Digest,
}

impl RecordedAwsAppSyncResult {
    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected || self.native || self.first_party {
            return Err(crate::error::AwsAppSyncApiResultError::TamperedEvidence);
        }
        let expected = Digest::from_parts(
            "aws-appsync-recorded-result/v1",
            &[
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("disposition", format!("{:?}", self.disposition)),
                ("replayed", self.replayed.to_string()),
            ],
        );
        if expected != self.record_digest {
            return Err(crate::error::AwsAppSyncApiResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsAppSyncConsumer {
    scope: AwsAppSyncApiScope,
    registration: AwsAppSyncApiResultRegistration,
    records: BTreeMap<Digest, RecordedAwsAppSyncResult>,
}

impl fmt::Debug for MissionAwsAppSyncConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsAppSyncConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsAppSyncConsumer {
    pub fn new(
        scope: AwsAppSyncApiScope,
        registration: AwsAppSyncApiResultRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest() != &scope.digest()
            || registration.validate().is_err()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsAppSyncApiScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsAppSyncApiResultRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: &AwsAppSyncApiResultProposal,
    ) -> std::result::Result<MissionAwsAppSyncResult, ConsumerError> {
        if self.registration.status() != RegistrationStatus::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision = MissionAwsAppSyncResult {
            consumer_id: CONSUMER_ID,
            disposition: ProposalDisposition::from_state(proposal.state),
            observed_state: proposal.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            mission_id_digest: self.scope.mission().id_digest(),
            project_id_digest: self.scope.project().id_digest(),
            work_product_id_digest: self.scope.work_product().id_digest(),
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            availability_claim: false,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            decision_digest: Digest::from_parts(
                "aws-appsync-mission-decision/v1",
                &[
                    ("scope", self.scope.digest().as_str().to_owned()),
                    (
                        "registration",
                        self.registration.registration_digest().as_str().to_owned(),
                    ),
                    (
                        "evidence",
                        proposal.evidence.evidence_digest.as_str().to_owned(),
                    ),
                    ("proposal", proposal.proposal_digest.as_str().to_owned()),
                    (
                        "disposition",
                        format!("{:?}", ProposalDisposition::from_state(proposal.state)),
                    ),
                ],
            ),
        };
        decision.validate_integrity()?;
        Ok(decision)
    }

    pub fn record(
        &mut self,
        proposal: &AwsAppSyncApiResultProposal,
        opaque_idempotency_key: impl Into<String>,
    ) -> std::result::Result<RecordedAwsAppSyncResult, ConsumerError> {
        let decision = self.consume(proposal)?;
        let idempotency_digest = Digest::from_parts(
            "aws-appsync-idempotency-key/v1",
            &[("key", opaque_idempotency_key.into())],
        );
        if let Some(existing) = self.records.get(&idempotency_digest) {
            if existing.proposal_digest != decision.proposal_digest {
                return Err(ConsumerError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.record_digest = Digest::from_parts(
                "aws-appsync-recorded-result/v1",
                &[
                    ("idempotency", replay.idempotency_digest.as_str().to_owned()),
                    ("scope", replay.scope_digest.as_str().to_owned()),
                    (
                        "registration",
                        replay.registration_digest.as_str().to_owned(),
                    ),
                    ("evidence", replay.evidence_digest.as_str().to_owned()),
                    ("proposal", replay.proposal_digest.as_str().to_owned()),
                    ("disposition", format!("{:?}", replay.disposition)),
                    ("replayed", "true".to_owned()),
                ],
            );
            return Ok(replay);
        }
        let record = RecordedAwsAppSyncResult {
            idempotency_digest: idempotency_digest.clone(),
            scope_digest: decision.scope_digest.clone(),
            registration_digest: decision.registration_digest.clone(),
            evidence_digest: decision.evidence_digest.clone(),
            proposal_digest: decision.proposal_digest.clone(),
            disposition: decision.disposition,
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
            record_digest: Digest::from_text("unsealed-aws-appsync-record"),
        };
        let mut record = record;
        record.record_digest = Digest::from_parts(
            "aws-appsync-recorded-result/v1",
            &[
                ("idempotency", record.idempotency_digest.as_str().to_owned()),
                ("scope", record.scope_digest.as_str().to_owned()),
                (
                    "registration",
                    record.registration_digest.as_str().to_owned(),
                ),
                ("evidence", record.evidence_digest.as_str().to_owned()),
                ("proposal", record.proposal_digest.as_str().to_owned()),
                ("disposition", format!("{:?}", record.disposition)),
                ("replayed", "false".to_owned()),
            ],
        );
        self.records.insert(idempotency_digest, record.clone());
        Ok(record)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

pub type MissionAwsAppSyncApiResultConsumer = MissionAwsAppSyncConsumer;
pub type MissionAwsAppSyncApiResult = MissionAwsAppSyncResult;
pub type AwsAppSyncConsumerError = ConsumerError;
pub type AwsAppSyncApiResultProposalRef = AwsAppSyncApiResultProposal;

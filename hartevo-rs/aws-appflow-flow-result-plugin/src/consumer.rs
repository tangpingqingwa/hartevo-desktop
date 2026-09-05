use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use zeroize::Zeroize;

use crate::error::{AwsAppFlowResultError, Result};
use crate::model::{AwsAppFlowScope, Digest, ExecutionEvidenceState};
use crate::service::AwsAppFlowResultProposal;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    PartialReview,
    RequiresLayer2,
    NotReviewable,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsAppFlowResult {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: ExecutionEvidenceState,
    pub disposition: ProposalDisposition,
    pub adopted: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedAwsAppFlowResult {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record_key_digest: Digest,
    pub record_digest: Digest,
    pub state: ExecutionEvidenceState,
    pub replayed: bool,
}

impl RecordedAwsAppFlowResult {
    pub fn validate_integrity(&self, scope: &AwsAppFlowScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || !self.registration_digest.is_valid()
            || !self.proposal_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || !self.record_key_digest.is_valid()
        {
            return Err(AwsAppFlowResultError::ReplayMismatch);
        }
        let expected = Digest::from_serializable(&(
            &self.scope_digest,
            &self.registration_digest,
            &self.proposal_digest,
            &self.evidence_digest,
            &self.record_key_digest,
            self.state,
        ));
        if self.record_digest != expected {
            Err(AwsAppFlowResultError::ReplayMismatch)
        } else {
            Ok(())
        }
    }
}

/// Mission-facing consumer below kernel Truth/Effect/Receipt/Verification and
/// Outcome authority. It can consume and record a proposal but cannot adopt it.
pub struct MissionAwsAppFlowConsumer {
    scope: AwsAppFlowScope,
    registration_digest: Digest,
    records: BTreeMap<Digest, RecordedAwsAppFlowResult>,
}

impl fmt::Debug for MissionAwsAppFlowConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsAppFlowConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration_digest)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsAppFlowConsumer {
    pub(crate) fn new(scope: AwsAppFlowScope, registration_digest: Digest) -> Result<Self> {
        scope.validate()?;
        registration_digest.validate()?;
        Ok(Self {
            scope,
            registration_digest,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsAppFlowScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(&self, proposal: &AwsAppFlowResultProposal) -> Result<MissionAwsAppFlowResult> {
        proposal.validate(&self.scope)?;
        if proposal.registration_digest != self.registration_digest {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        Ok(MissionAwsAppFlowResult {
            scope_digest: self.scope.digest(),
            registration_digest: self.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: proposal.state,
            disposition: disposition_for(proposal.state),
            adopted: false,
            kernel_authority: false,
            work_product_adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn consume_at_revision(
        &self,
        proposal: &AwsAppFlowResultProposal,
        mission_revision: u64,
    ) -> Result<MissionAwsAppFlowResult> {
        if mission_revision != self.scope.mission_revision() {
            return Err(AwsAppFlowResultError::RevisionMismatch);
        }
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsAppFlowResultProposal,
        record_key: impl Into<String>,
    ) -> Result<RecordedAwsAppFlowResult> {
        proposal.validate(&self.scope)?;
        if proposal.registration_digest != self.registration_digest {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let mut record_key = record_key.into();
        if record_key.is_empty()
            || record_key.len() > 256
            || record_key.chars().any(char::is_control)
        {
            record_key.zeroize();
            return Err(AwsAppFlowResultError::InvalidIdentifier);
        }
        let record_key_digest = Digest::from_parts(
            "aws-appflow-mission-record-key/v1",
            &[("key", record_key.clone())],
        );
        record_key.zeroize();
        if let Some(existing) = self.records.get(&record_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsAppFlowResultError::ReplayMismatch);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let record_digest = Digest::from_serializable(&(
            self.scope.digest(),
            &self.registration_digest,
            &proposal.proposal_digest,
            &proposal.evidence.evidence_digest,
            &record_key_digest,
            proposal.state,
        ));
        let record = RecordedAwsAppFlowResult {
            scope_digest: self.scope.digest(),
            registration_digest: self.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            record_key_digest: record_key_digest.clone(),
            record_digest,
            state: proposal.state,
            replayed: false,
        };
        self.records.insert(record_key_digest, record.clone());
        Ok(record)
    }
}

fn disposition_for(state: ExecutionEvidenceState) -> ProposalDisposition {
    match state {
        ExecutionEvidenceState::Completed => ProposalDisposition::ReviewOnly,
        ExecutionEvidenceState::Partial => ProposalDisposition::PartialReview,
        ExecutionEvidenceState::InProgress | ExecutionEvidenceState::Failed => {
            ProposalDisposition::RequiresLayer2
        }
        ExecutionEvidenceState::Replay => ProposalDisposition::Replay,
        _ => ProposalDisposition::NotReviewable,
    }
}

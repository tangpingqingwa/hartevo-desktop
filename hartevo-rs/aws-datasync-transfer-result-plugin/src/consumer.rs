use std::{collections::BTreeMap, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsDataSyncTransferError, Result};
use crate::model::{AwsDataSyncScope, Digest, TransferEvidenceState, TransportProvenance};
use crate::service::AwsDataSyncTransferProposal;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    Partial,
    AccessLoss,
    ProviderUnknown,
    NotFound,
    Conflict,
    Throttled,
    InvalidRequest,
    Timeout,
}

impl ProposalDisposition {
    pub const fn from_state(state: TransferEvidenceState) -> Self {
        match state {
            TransferEvidenceState::Complete => Self::ReviewOnly,
            TransferEvidenceState::Partial(_) => Self::Partial,
            TransferEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            TransferEvidenceState::AccessLoss => Self::AccessLoss,
            TransferEvidenceState::NotFound => Self::NotFound,
            TransferEvidenceState::Conflict => Self::Conflict,
            TransferEvidenceState::Throttled => Self::Throttled,
            TransferEvidenceState::InvalidRequest => Self::InvalidRequest,
            TransferEvidenceState::Timeout => Self::Timeout,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsDataSyncResult {
    pub disposition: ProposalDisposition,
    pub state: TransferEvidenceState,
    pub scope_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub task_digest: Option<Digest>,
    pub execution_digest: Option<Digest>,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_eligible: bool,
    pub adoptable: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl MissionAwsDataSyncResult {
    pub fn validate(&self, scope: &AwsDataSyncScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.mission_digest != scope.mission().digest()
            || self.project_digest != scope.project().digest()
            || self.work_product_digest != scope.work_product().digest()
            || self.adoptable
            || self.outcome_authority
            || self.work_product_adoption
            || self.provenance.is_native()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.evidence_digest.validate()?;
        self.proposal_digest.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordedAwsDataSyncResult {
    pub record_key_digest: Digest,
    pub record_digest: Digest,
    pub scope_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub task_digest: Option<Digest>,
    pub execution_digest: Option<Digest>,
    pub state: TransferEvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub adoptable: bool,
}

impl RecordedAwsDataSyncResult {
    pub fn validate_integrity(&self, scope: &AwsDataSyncScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.mission_digest != scope.mission().digest()
            || self.project_digest != scope.project().digest()
            || self.work_product_digest != scope.work_product().digest()
            || self.adoptable
            || self.provenance.is_native()
            || self.record_digest != self.calculate_digest()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.record_key_digest.validate()?;
        self.proposal_digest.validate()?;
        self.evidence_digest.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-recorded-result/v1",
            &[
                ("key", self.record_key_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission_digest.as_str().to_owned()),
                ("project", self.project_digest.as_str().to_owned()),
                ("work_product", self.work_product_digest.as_str().to_owned()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                (
                    "task",
                    self.task_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "execution",
                    self.execution_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for RecordedAwsDataSyncResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedAwsDataSyncResult")
            .field("record_key_digest", &self.record_key_digest)
            .field("record_digest", &self.record_digest)
            .field("scope_digest", &self.scope_digest)
            .field("proposal_digest", &self.proposal_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("state", &self.state)
            .field("provenance", &self.provenance)
            .field("replayed", &self.replayed)
            .finish()
    }
}

impl Serialize for RecordedAwsDataSyncResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RecordedAwsDataSyncResult", 14)?;
        state.serialize_field("recordKeyDigest", &self.record_key_digest)?;
        state.serialize_field("recordDigest", &self.record_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("proposalDigest", &self.proposal_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("taskDigest", &self.task_digest)?;
        state.serialize_field("executionDigest", &self.execution_digest)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("replayed", &self.replayed)?;
        state.serialize_field("adoptable", &self.adoptable)?;
        state.end()
    }
}

#[derive(Debug)]
pub struct MissionAwsDataSyncConsumer {
    scope: AwsDataSyncScope,
    records: BTreeMap<Digest, RecordedAwsDataSyncResult>,
}

impl MissionAwsDataSyncConsumer {
    pub fn new(scope: AwsDataSyncScope) -> Self {
        Self {
            scope,
            records: BTreeMap::new(),
        }
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn consume(
        &self,
        proposal: &AwsDataSyncTransferProposal,
    ) -> Result<MissionAwsDataSyncResult> {
        proposal.validate(&self.scope)?;
        Ok(MissionAwsDataSyncResult {
            disposition: ProposalDisposition::from_state(proposal.state),
            state: proposal.state,
            scope_digest: proposal.scope_digest.clone(),
            mission_digest: proposal.mission_digest.clone(),
            project_digest: proposal.project_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            task_digest: proposal.task.as_ref().map(|task| task.task_digest.clone()),
            execution_digest: proposal
                .execution
                .as_ref()
                .map(|execution| execution.execution_digest.clone()),
            evidence_digest: proposal.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            provenance: proposal.provenance,
            review_eligible: proposal.state.is_review_eligible(),
            adoptable: false,
            outcome_authority: false,
            work_product_adoption: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsDataSyncTransferProposal,
        record_key: impl AsRef<str>,
    ) -> Result<RecordedAwsDataSyncResult> {
        proposal.validate(&self.scope)?;
        let key = record_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsDataSyncTransferError::InvalidRequest);
        }
        let record_key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&record_key_digest) {
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let mut record = RecordedAwsDataSyncResult {
            record_key_digest: record_key_digest.clone(),
            record_digest: Digest::from_text("unsealed-aws-datasync-record"),
            scope_digest: proposal.scope_digest.clone(),
            mission_digest: proposal.mission_digest.clone(),
            project_digest: proposal.project_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            task_digest: proposal.task.as_ref().map(|task| task.task_digest.clone()),
            execution_digest: proposal
                .execution
                .as_ref()
                .map(|execution| execution.execution_digest.clone()),
            state: proposal.state,
            provenance: proposal.provenance,
            replayed: false,
            adoptable: false,
        };
        record.record_digest = record.calculate_digest();
        self.records.insert(record_key_digest, record.clone());
        Ok(record)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn records(&self) -> impl Iterator<Item = &RecordedAwsDataSyncResult> {
        self.records.values()
    }
}

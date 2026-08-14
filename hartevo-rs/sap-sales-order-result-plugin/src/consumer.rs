use std::collections::BTreeSet;

use serde::Serialize;
use thiserror::Error;

use crate::{
    MISSION_SAP_SALES_ORDER_CONSUMER_ID, SAP_SALES_ORDER_RESULT_CONTRACT_VERSION,
    SAP_SALES_ORDER_RESULT_PLUGIN_VERSION,
    model::{
        Digest, RevisionFence, SapObservationState, SapSalesOrderObservation, SapSalesOrderScope,
    },
    service::{
        SapSalesOrderAdoptionProposal, SapSalesOrderRecording, SapSalesOrderResultService,
        SapSalesOrderRun, SapSalesOrderServiceError,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionSapSalesOrderConsumerDefinition {
    pub id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl MissionSapSalesOrderConsumerDefinition {
    pub fn layer1() -> Self {
        Self {
            id: MISSION_SAP_SALES_ORDER_CONSUMER_ID.to_owned(),
            plugin_version: SAP_SALES_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: SAP_SALES_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
            adopts_outcome: false,
            truth_authority: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionSapSalesOrderState {
    Proposed,
    Partial,
    Deleted,
    AccessLost,
    RevisionConflict,
    ProviderUnknown,
}

impl From<SapObservationState> for MissionSapSalesOrderState {
    fn from(state: SapObservationState) -> Self {
        match state {
            SapObservationState::Available => Self::Proposed,
            SapObservationState::Partial => Self::Partial,
            SapObservationState::Deleted => Self::Deleted,
            SapObservationState::AccessLost => Self::AccessLost,
            SapObservationState::RevisionConflict => Self::RevisionConflict,
            SapObservationState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionSapSalesOrderConsumerError {
    #[error("SAP adoption proposal is invalid or claims kernel authority")]
    InvalidProposal,
    #[error("SAP redacted recording does not match the adoption proposal")]
    RecordingMismatch,
    #[error("SAP proposal is outside the current Project/Mission/Work Product fence")]
    RevisionFenceChanged,
    #[error("SAP proposal is outside the registered scope")]
    ScopeMismatch,
    #[error("the same SAP proposal was already consumed")]
    DuplicateProposal,
    #[error("the SAP proposal is tampered")]
    DigestMismatch,
    #[error(transparent)]
    Service(#[from] SapSalesOrderServiceError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionSapSalesOrderResult {
    pub consumer_id: String,
    pub state: MissionSapSalesOrderState,
    pub scope_digest: Digest,
    pub result_digest: Option<Digest>,
    pub proposal_digest: Digest,
    pub recording_digest: Digest,
    pub revision_fence: RevisionFence,
    pub verified_for_review: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl MissionSapSalesOrderResult {
    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub const fn adopted_outcome(&self) -> bool {
        false
    }

    pub const fn truth_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct MissionSapSalesOrderConsumer {
    definition: MissionSapSalesOrderConsumerDefinition,
    scope: SapSalesOrderScope,
    consumed_proposals: BTreeSet<Digest>,
}

impl MissionSapSalesOrderConsumer {
    pub fn new(scope: SapSalesOrderScope) -> Self {
        Self {
            definition: MissionSapSalesOrderConsumerDefinition::layer1(),
            scope,
            consumed_proposals: BTreeSet::new(),
        }
    }

    pub fn definition(&self) -> &MissionSapSalesOrderConsumerDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &SapSalesOrderScope {
        &self.scope
    }

    pub fn consume_run(
        &mut self,
        run: &SapSalesOrderRun,
        expected_fence: &RevisionFence,
    ) -> Result<MissionSapSalesOrderResult, MissionSapSalesOrderConsumerError> {
        self.consume(&run.adoption_proposal, &run.recording, expected_fence)
    }

    pub fn consume(
        &mut self,
        proposal: &SapSalesOrderAdoptionProposal,
        recording: &SapSalesOrderRecording,
        expected_fence: &RevisionFence,
    ) -> Result<MissionSapSalesOrderResult, MissionSapSalesOrderConsumerError> {
        proposal
            .validate()
            .map_err(|_| MissionSapSalesOrderConsumerError::InvalidProposal)?;
        recording
            .validate()
            .map_err(|_| MissionSapSalesOrderConsumerError::RecordingMismatch)?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.permission_digest != *self.scope.permission_lease().digest()
            || proposal.revision_fence.scope_digest() != self.scope.scope_digest()
            || proposal.revision_fence.permission_digest() != self.scope.permission_lease().digest()
        {
            return Err(MissionSapSalesOrderConsumerError::ScopeMismatch);
        }
        if !proposal.revision_fence.matches_current(expected_fence) {
            return Err(MissionSapSalesOrderConsumerError::RevisionFenceChanged);
        }
        if recording.observation_digest != proposal.observation_digest
            || recording.result_digest != proposal.result_digest
            || recording.scope_digest != proposal.scope_digest
            || recording.permission_digest != proposal.permission_digest
            || recording.registration_digest != proposal.registration_digest
        {
            return Err(MissionSapSalesOrderConsumerError::RecordingMismatch);
        }
        if self.consumed_proposals.contains(proposal.proposal_digest()) {
            return Err(MissionSapSalesOrderConsumerError::DuplicateProposal);
        }
        self.consumed_proposals
            .insert(proposal.proposal_digest().clone());
        Ok(MissionSapSalesOrderResult {
            consumer_id: self.definition.id.clone(),
            state: proposal.state.into(),
            scope_digest: proposal.scope_digest.clone(),
            result_digest: proposal.result_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            recording_digest: recording.recording_digest.clone(),
            revision_fence: proposal.revision_fence.clone(),
            verified_for_review: true,
            adopted_outcome: false,
            truth_authority: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn consume_observation(
        &mut self,
        service: &SapSalesOrderResultService,
        observation: &SapSalesOrderObservation,
        expected_fence: &RevisionFence,
    ) -> Result<MissionSapSalesOrderResult, MissionSapSalesOrderConsumerError> {
        let recording = service.record(observation)?;
        let proposal = service.propose_adoption(observation)?;
        self.consume(&proposal, &recording, expected_fence)
    }

    pub fn consume_once(
        &mut self,
        proposal: &SapSalesOrderAdoptionProposal,
        recording: &SapSalesOrderRecording,
        expected_fence: &RevisionFence,
    ) -> Result<MissionSapSalesOrderResult, MissionSapSalesOrderConsumerError> {
        self.consume(proposal, recording, expected_fence)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &SapSalesOrderAdoptionProposal,
        recording: &SapSalesOrderRecording,
        expected_fence: &RevisionFence,
    ) -> Result<MissionSapSalesOrderResult, MissionSapSalesOrderConsumerError> {
        self.consume(proposal, recording, expected_fence)
    }

    pub fn has_consumed(&self, proposal_digest: &Digest) -> bool {
        self.consumed_proposals.contains(proposal_digest)
    }
}

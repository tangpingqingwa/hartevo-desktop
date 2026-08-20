use serde::{Deserialize, Serialize};

use crate::error::TwilioHandoffError;
use crate::model::{
    HandoffProposal, HandoffProposalRequest, MessageBody, MissionScope, SourceResultDigest,
    TwilioScope,
};
use crate::registration::TwilioHandoffRegistration;
use crate::service::TwilioHandoffService;

/// Typed Mission result input.  The Mission identity is repeated beside the
/// Twilio scope so the consumer can reject a cross-Mission handoff before a
/// proposal is emitted.
#[derive(Clone, Debug)]
pub struct MissionHandoffResultInput {
    pub mission: MissionScope,
    pub source_result_digest: SourceResultDigest,
    pub twilio_scope: TwilioScope,
    pub message_body: MessageBody,
}

impl MissionHandoffResultInput {
    pub fn new(
        mission: MissionScope,
        source_result_digest: SourceResultDigest,
        twilio_scope: TwilioScope,
        message_body: MessageBody,
    ) -> Result<Self, TwilioHandoffError> {
        if mission != twilio_scope.mission {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        Ok(Self {
            mission,
            source_result_digest,
            twilio_scope,
            message_body,
        })
    }
}

/// The Mission-facing result is a proposal/adoption record only.  It does not
/// claim that a message was sent or that a Mission completed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionHandoffResult {
    pub proposal: HandoffProposal,
    pub mission: MissionScope,
    pub source_result_digest: SourceResultDigest,
    pub provider_version: u32,
    pub registration_digest: crate::model::RegistrationDigest,
    pub adoptable: bool,
    pub mission_truth_source: bool,
    pub external_mutation_performed: bool,
    pub native_connected: bool,
}

impl MissionHandoffResult {
    pub fn is_adoptable(&self) -> bool {
        self.adoptable
            && self.mission_truth_source
            && !self.external_mutation_performed
            && !self.native_connected
    }
}

#[derive(Clone, Debug)]
pub struct MissionHandoffResultConsumer {
    registration: TwilioHandoffRegistration,
}

impl MissionHandoffResultConsumer {
    pub fn new(registration: TwilioHandoffRegistration) -> Result<Self, TwilioHandoffError> {
        registration.validate()?;
        Ok(Self { registration })
    }

    pub fn registration(&self) -> &TwilioHandoffRegistration {
        &self.registration
    }

    pub fn propose(
        &self,
        service: &TwilioHandoffService,
        input: MissionHandoffResultInput,
    ) -> Result<MissionHandoffResult, TwilioHandoffError> {
        if service.registration().registration_digest() != self.registration.registration_digest()
            || input.mission != self.registration.scope.mission
            || input.twilio_scope != self.registration.scope
        {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        let proposal = service.propose(HandoffProposalRequest::new(
            input.twilio_scope,
            input.source_result_digest.clone(),
            input.message_body,
        )?)?;
        Ok(MissionHandoffResult {
            mission: proposal.mission.clone(),
            source_result_digest: proposal.source_result_digest.clone(),
            provider_version: proposal.provider_version,
            registration_digest: proposal.registration_digest.clone(),
            adoptable: true,
            mission_truth_source: true,
            external_mutation_performed: false,
            native_connected: false,
            proposal,
        })
    }
}

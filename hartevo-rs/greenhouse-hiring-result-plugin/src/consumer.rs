use serde::{Deserialize, Serialize};

use crate::error::GreenhouseError;
use crate::model::{GreenhouseHiringEvidence, GreenhouseScope, ProposalRequest, ProposalResult};
use crate::provider::GreenhouseHarvestProvider;
use crate::service::{GreenhouseHiringResultService, GreenhouseRegistration};

/// The Mission-facing request is still below kernel authority.  It carries a
/// typed consent receipt and revision/digest expectations, never a credential
/// or an instruction to mutate Greenhouse.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionHiringRequest {
    pub scope: GreenhouseScope,
    pub proposal: ProposalRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionHiringResult {
    pub evidence: GreenhouseHiringEvidence,
    pub proposal: ProposalResult,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug)]
pub struct MissionGreenhouseHiringConsumer {
    registration: GreenhouseRegistration,
}

impl MissionGreenhouseHiringConsumer {
    pub fn new(registration: GreenhouseRegistration) -> Result<Self, GreenhouseError> {
        registration.validate()?;
        Ok(Self { registration })
    }

    pub fn registration(&self) -> &GreenhouseRegistration {
        &self.registration
    }

    pub fn read_and_propose(
        &self,
        provider: &mut GreenhouseHarvestProvider,
        request: MissionHiringRequest,
    ) -> Result<MissionHiringResult, GreenhouseError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(&request.scope)?;
        self.registration
            .ensure_provider(provider.definition(), provider.secret_reference())?;
        let evidence = provider.read(&request.scope)?;
        let service = GreenhouseHiringResultService::new()?;
        let proposal =
            service.compile_result_proposal(&self.registration, &evidence, &request.proposal)?;
        Ok(MissionHiringResult {
            evidence,
            proposal,
            connected: false,
            native: false,
        })
    }

    pub fn propose(
        &self,
        provider: &mut GreenhouseHarvestProvider,
        request: MissionHiringRequest,
    ) -> Result<MissionHiringResult, GreenhouseError> {
        self.read_and_propose(provider, request)
    }
}

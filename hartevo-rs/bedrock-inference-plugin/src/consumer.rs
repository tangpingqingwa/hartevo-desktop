use crate::error::Result;
use crate::model::{
    BudgetPolicy, InferenceRequest, InferenceResultProposal, InvocationProposal, InvocationReceipt,
    MissionContext, MissionId, ProjectId, RegistrationId,
};
use crate::service::BedrockInferenceService;

/// Typed Mission consumer for one exact Project/Mission registration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MissionBedrockInferenceConsumer {
    registration_id: RegistrationId,
    context: MissionContext,
}

impl MissionBedrockInferenceConsumer {
    pub fn new(registration_id: RegistrationId, context: MissionContext) -> Self {
        Self {
            registration_id,
            context,
        }
    }

    pub fn from_parts(
        registration_id: RegistrationId,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        budget_policy: BudgetPolicy,
    ) -> Result<Self> {
        Ok(Self::new(
            registration_id,
            MissionContext::new(project_id, mission_id, mission_revision, budget_policy)?,
        ))
    }

    pub const fn registration_id(&self) -> RegistrationId {
        self.registration_id
    }

    pub const fn context(&self) -> &MissionContext {
        &self.context
    }

    pub fn compile_invocation_proposal(
        &self,
        service: &BedrockInferenceService,
        request: InferenceRequest,
    ) -> Result<InvocationProposal> {
        service.compile_invocation_proposal(self.registration_id, &self.context, request)
    }

    pub fn invoke_converse(
        &self,
        service: &BedrockInferenceService,
        request: InferenceRequest,
    ) -> Result<InvocationReceipt> {
        let proposal = self.compile_invocation_proposal(service, request)?;
        service.invoke_converse(&proposal)
    }

    pub fn invoke_and_project(
        &self,
        service: &BedrockInferenceService,
        request: InferenceRequest,
    ) -> Result<(InvocationReceipt, InferenceResultProposal)> {
        let proposal = self.compile_invocation_proposal(service, request)?;
        service.invoke_and_project(&proposal)
    }
}

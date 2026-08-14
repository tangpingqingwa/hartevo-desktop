//! Mission/Project/Work Product proposal-only consumer wrapper.

use serde::{Deserialize, Serialize};

use crate::{
    canonical_digest,
    model::{
        Digest, EvidenceStatus, MissionScope, ProjectScope, WandbEvaluationError,
        WandbEvaluationReadRequest, WandbEvaluationResultProposal, WandbEvaluationScope,
        WandbPluginRegistration, WorkProductScope,
    },
    service::WandbEvaluationResultService,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MissionWandbEvaluationRequest {
    pub read: WandbEvaluationReadRequest,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub work_product: WorkProductScope,
    pub request_digest: Digest,
}

impl MissionWandbEvaluationRequest {
    pub fn new(
        read: WandbEvaluationReadRequest,
        scope: &WandbEvaluationScope,
    ) -> Result<Self, WandbEvaluationError> {
        read.scope.validate()?;
        scope.validate()?;
        if read.scope.digest() != scope.digest() {
            return Err(WandbEvaluationError::ScopeMismatch);
        }
        let mut request = Self {
            read,
            mission: scope.mission.clone(),
            project: scope.hartevo_project.clone(),
            work_product: scope.work_product.clone(),
            request_digest: Digest::from_text("uninitialized-mission-wandb-request"),
        };
        request.request_digest = canonical_digest(&MissionRequestIdentity {
            read: request.read.clone(),
            mission: request.mission.clone(),
            project: request.project.clone(),
            work_product: request.work_product.clone(),
        });
        request.validate(scope)?;
        Ok(request)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn fixture(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let read = WandbEvaluationReadRequest::fixture(scope.clone())?;
        Self::new(read, &scope)
    }

    pub fn validate(&self, scope: &WandbEvaluationScope) -> Result<(), WandbEvaluationError> {
        self.read
            .validate(&crate::WandbEvaluationPolicy::fixture())?;
        if self.read.scope.digest() != scope.digest()
            || self.mission != scope.mission
            || self.project != scope.hartevo_project
            || self.work_product != scope.work_product
        {
            return Err(WandbEvaluationError::MissionMismatch);
        }
        self.request_digest.validate("mission_request_digest")?;
        if self.request_digest
            != canonical_digest(&MissionRequestIdentity {
                read: self.read.clone(),
                mission: self.mission.clone(),
                project: self.project.clone(),
                work_product: self.work_product.clone(),
            })
        {
            return Err(WandbEvaluationError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct MissionRequestIdentity {
    read: WandbEvaluationReadRequest,
    mission: MissionScope,
    project: ProjectScope,
    work_product: WorkProductScope,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MissionWandbEvaluationResult {
    pub project_id: String,
    pub project_revision: String,
    pub mission_id: String,
    pub mission_revision: String,
    pub work_product_id: String,
    pub work_product_revision: String,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: EvidenceStatus,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted: bool,
    pub durable_native_receipt: bool,
}

impl MissionWandbEvaluationResult {
    fn from_proposal(
        scope: &WandbEvaluationScope,
        proposal: &WandbEvaluationResultProposal,
    ) -> Self {
        Self {
            project_id: scope.hartevo_project.id.as_str().to_owned(),
            project_revision: scope.hartevo_project.revision.as_str().to_owned(),
            mission_id: scope.mission.id.as_str().to_owned(),
            mission_revision: scope.mission.revision.as_str().to_owned(),
            work_product_id: scope.work_product.id.as_str().to_owned(),
            work_product_revision: scope.work_product.revision.as_str().to_owned(),
            scope_digest: scope.digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: proposal.evidence.status,
            proposal_only: true,
            connected: false,
            native: false,
            adopted: false,
            durable_native_receipt: false,
        }
    }

    #[must_use]
    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }
}

#[derive(Clone, Debug)]
pub struct MissionWandbEvaluationConsumer {
    service: WandbEvaluationResultService,
}

impl MissionWandbEvaluationConsumer {
    #[must_use]
    pub fn new(service: WandbEvaluationResultService) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn from_service(service: WandbEvaluationResultService) -> Self {
        Self::new(service)
    }

    #[must_use]
    pub fn service(&self) -> &WandbEvaluationResultService {
        &self.service
    }

    #[must_use]
    pub fn registration(&self) -> WandbPluginRegistration {
        self.service.registration()
    }

    pub fn consume(
        &self,
        request: &MissionWandbEvaluationRequest,
    ) -> Result<MissionWandbEvaluationResult, WandbEvaluationError> {
        request.validate(&request.read.scope)?;
        let proposal = self.service.propose_evaluation(request.read.clone())?;
        self.service.verify_proposal(&proposal)?;
        Ok(MissionWandbEvaluationResult::from_proposal(
            &request.read.scope,
            &proposal,
        ))
    }

    pub fn consume_read_request(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<MissionWandbEvaluationResult, WandbEvaluationError> {
        let mission_request = MissionWandbEvaluationRequest::new(request.clone(), &request.scope)?;
        self.consume(&mission_request)
    }

    pub fn compile_evaluation_result_proposal(
        &self,
        request: &MissionWandbEvaluationRequest,
    ) -> Result<WandbEvaluationResultProposal, WandbEvaluationError> {
        request.validate(&request.read.scope)?;
        self.service.propose_evaluation(request.read.clone())
    }

    pub fn revoke(
        &self,
        reason: impl AsRef<str>,
    ) -> Result<crate::RegistrationRevocation, WandbEvaluationError> {
        self.service.revoke(reason)
    }

    pub fn restore(&self) -> Result<(), WandbEvaluationError> {
        self.service.restore()
    }
}

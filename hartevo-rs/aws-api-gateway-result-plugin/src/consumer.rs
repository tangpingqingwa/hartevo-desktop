//! Mission-scoped, non-authoritative API Gateway evidence consumer.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_API_GATEWAY_API_REVISION, AWS_API_GATEWAY_CONSUMER_ID, AWS_API_GATEWAY_CONTRACT_VERSION,
    AWS_API_GATEWAY_PLUGIN_VERSION, AWS_API_GATEWAY_PROVIDER_ID, AWS_API_GATEWAY_PROVIDER_VERSION,
    contract_digest,
    model::{
        ApiGatewayReadOperation, AwsApiGatewayEvidence, AwsApiGatewayScope, Digest, EvidenceStatus,
    },
    service::{
        AwsApiGatewayProposal, AwsApiGatewayRegistration, AwsApiGatewayServiceError,
        RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS API Gateway consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission, Project, Work Product, Deployment, API, stage, or deployment scope mismatch")]
    ScopeMismatch,
    #[error("Mission AWS API Gateway proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS API Gateway evidence permission fence was lost")]
    PermissionLoss,
    #[error(
        "Layer-1 API Gateway evidence cannot claim connected, native, first-party, Truth, or Outcome authority"
    )]
    AuthorityClaim,
    #[error("Mission AWS API Gateway consumer registration is tampered")]
    RegistrationTampered,
    #[error(transparent)]
    Service(#[from] AwsApiGatewayServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsApiGatewayDecisionState {
    ReviewRequired,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

impl MissionAwsApiGatewayDecisionState {
    const fn from_evidence(status: EvidenceStatus) -> Self {
        match status {
            EvidenceStatus::Complete => Self::ReviewRequired,
            EvidenceStatus::Partial => Self::Partial,
            EvidenceStatus::AccessLoss => Self::AccessLoss,
            EvidenceStatus::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsApiGatewayResult {
    pub consumer_id: String,
    pub operation: ApiGatewayReadOperation,
    pub mission: crate::model::MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub deployment: crate::model::DeploymentBinding,
    pub api: crate::model::ApiBinding,
    pub stage: crate::model::StageBinding,
    pub api_deployment: crate::model::ApiDeploymentBinding,
    pub decision_state: MissionAwsApiGatewayDecisionState,
    pub observed_status: EvidenceStatus,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub accepted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsApiGatewayConsumer {
    scope: AwsApiGatewayScope,
    registration: AwsApiGatewayRegistration,
    revoked: bool,
}

impl MissionAwsApiGatewayConsumer {
    pub fn new(
        scope: AwsApiGatewayScope,
        registration: AwsApiGatewayRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.state != RegistrationState::Active
            || registration.registration_digest != registration.recomputed_digest()
            || registration.plugin_version != AWS_API_GATEWAY_PLUGIN_VERSION
            || registration.contract_version != AWS_API_GATEWAY_CONTRACT_VERSION
            || registration.contract_digest != contract_digest()
            || registration.provider_id != AWS_API_GATEWAY_PROVIDER_ID
            || registration.provider_version != AWS_API_GATEWAY_PROVIDER_VERSION
            || registration.provider_revision != AWS_API_GATEWAY_API_REVISION
            || registration.scope_digest != scope.digest()
            || registration.permission_digest != *scope.permission_digest()
            || registration.stage_digest != scope.stage_digest()
            || registration.deployment_digest != scope.deployment_digest()
            || registration.evidence_digest
                != AwsApiGatewayRegistration::expected_evidence_digest(&scope)
        {
            return Err(ConsumerError::RegistrationTampered);
        }
        Ok(Self {
            scope,
            registration,
            revoked: false,
        })
    }

    pub fn scope(&self) -> &AwsApiGatewayScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsApiGatewayRegistration {
        &self.registration
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::RegistrationRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: AwsApiGatewayProposal,
    ) -> Result<MissionAwsApiGatewayResult, ConsumerError> {
        if self.revoked || self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        self.validate_evidence(&proposal.evidence)?;
        if proposal.registration_digest != self.registration.registration_digest {
            return Err(ConsumerError::RegistrationTampered);
        }
        let decision_state =
            MissionAwsApiGatewayDecisionState::from_evidence(proposal.evidence.status);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-api-gateway-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsApiGatewayResult {
            consumer_id: AWS_API_GATEWAY_CONSUMER_ID.to_owned(),
            operation: proposal.operation,
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            deployment: self.scope.hartevo_deployment.clone(),
            api: self.scope.api.clone(),
            stage: self.scope.stage.clone(),
            api_deployment: self.scope.deployment.clone(),
            decision_state,
            observed_status: proposal.evidence.status,
            scope_digest: self.scope.digest(),
            permission_digest: self.scope.permission_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            accepted: true,
            connected: false,
            native: false,
            first_party: false,
            certification_claim: false,
            adopted_outcome: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &AwsApiGatewayEvidence) -> Result<(), ConsumerError> {
        if self.revoked || self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        self.validate_evidence(evidence)
    }

    fn validate_evidence(&self, evidence: &AwsApiGatewayEvidence) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != *self.scope.permission_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.plugin_version_digest != Digest::from_text(AWS_API_GATEWAY_PLUGIN_VERSION)
            || evidence.provider_digest != self.registration.provider_digest
            || evidence.api_digest != self.registration.api_digest
            || evidence.contract_digest != self.registration.contract_digest
        {
            return Err(ConsumerError::RegistrationTampered);
        }
        if evidence.stage_digest != self.scope.stage_digest()
            || evidence.deployment_digest != self.scope.deployment_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(ConsumerError::RegistrationTampered);
        }
        if evidence.connected || evidence.native || evidence.first_party {
            return Err(ConsumerError::AuthorityClaim);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

pub type MissionAwsApiGatewayConsumerError = ConsumerError;
pub type MissionAwsApiGatewayDecision = MissionAwsApiGatewayResult;

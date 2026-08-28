use serde::{Deserialize, Serialize};

use crate::error::CircleCiPipelineResultError;
use crate::model::{
    CircleCiPipelineReadRequest, CircleCiPipelineResultEvidence, CircleCiPipelineResultProposal,
    CircleCiPipelineResultReceipt, CircleCiProvenance, CircleCiRegistration, CircleCiScope,
    MissionWorkProduct, VerifiedCircleCiPipelineResult,
};
use crate::provider::{CircleCiCredentialResolver, CircleCiProvider};
use crate::transport::CircleCiTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiPipelineResultOperation {
    DescribeScope,
    Register,
    RevokeRegistration,
    ReverseRegistration,
    ReadPipelineResult,
    CompileProposal,
    RecordReceipt,
    VerifyResult,
}

impl CircleCiPipelineResultOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeScope,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReverseRegistration,
        Self::ReadPipelineResult,
        Self::CompileProposal,
        Self::RecordReceipt,
        Self::VerifyResult,
    ];

    pub const fn is_external_write(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CircleCiPipelineResultServiceDefinition {
    pub service_id: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: u64,
    pub operations: Vec<CircleCiPipelineResultOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub durable_native_receipts: bool,
    pub kernel_outcome_authority: bool,
    pub native_connected: bool,
}

impl CircleCiPipelineResultServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            service_id: crate::CIRCLECI_SERVICE_ID.to_owned(),
            contract_version: crate::CIRCLECI_RESULT_CONTRACT_VERSION.to_owned(),
            provider_id: crate::CIRCLECI_PROVIDER_ID.to_owned(),
            provider_version: crate::CIRCLECI_PROVIDER_VERSION,
            operations: CircleCiPipelineResultOperation::ALL.to_vec(),
            read_only: true,
            external_writes: false,
            durable_native_receipts: false,
            kernel_outcome_authority: false,
            native_connected: false,
        }
    }

    pub fn validate(&self) -> Result<(), CircleCiPipelineResultError> {
        let expected = Self::layer1();
        if self != &expected {
            return Err(CircleCiPipelineResultError::RegistrationDrift);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CircleCiPipelineResultService<T, R>
where
    T: CircleCiTransport,
    R: CircleCiCredentialResolver,
{
    provider: CircleCiProvider<T, R>,
    definition: CircleCiPipelineResultServiceDefinition,
}

impl<T, R> CircleCiPipelineResultService<T, R>
where
    T: CircleCiTransport,
    R: CircleCiCredentialResolver,
{
    pub fn new(provider: CircleCiProvider<T, R>) -> Result<Self, CircleCiPipelineResultError> {
        let definition = CircleCiPipelineResultServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &CircleCiPipelineResultServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &CircleCiProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut CircleCiProvider<T, R> {
        &mut self.provider
    }

    pub fn describe_scope(
        &self,
    ) -> Result<crate::model::CircleCiScopeDescription, CircleCiPipelineResultError> {
        self.provider.describe_scope()
    }

    pub fn read_pipeline_result(
        &mut self,
        request: &CircleCiPipelineReadRequest,
    ) -> Result<CircleCiPipelineResultEvidence, CircleCiPipelineResultError> {
        self.provider.read_pipeline_result(request)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn compile_pipeline_result(
        &self,
        work_product: MissionWorkProduct,
        evidence: CircleCiPipelineResultEvidence,
    ) -> Result<CircleCiPipelineResultProposal, CircleCiPipelineResultError> {
        let scope = &self.provider.registration().scope;
        evidence.validate(scope)?;
        if evidence.permission_digest != self.provider.registration().permission_snapshot.digest() {
            return Err(CircleCiPipelineResultError::PermissionDrift);
        }
        validate_work_product_scope(scope, &work_product)?;
        if evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || evidence.provenance == CircleCiProvenance::BlockedEnv
        {
            return Err(CircleCiPipelineResultError::EmptyProposalEvidence);
        }
        let mut proposal = CircleCiPipelineResultProposal {
            contract_version: crate::CIRCLECI_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            plugin_id: crate::CIRCLECI_PLUGIN_ID.to_owned(),
            plugin_version: crate::CIRCLECI_PLUGIN_VERSION,
            provider_id: crate::CIRCLECI_PROVIDER_ID.to_owned(),
            provider_version: crate::CIRCLECI_PROVIDER_VERSION,
            scope_digest: scope.digest(),
            mission_id: work_product.mission_id.clone(),
            project_id: work_product.project_id.clone(),
            work_product_id: work_product.work_product_id.clone(),
            mission_revision: work_product.mission_revision,
            project_revision: work_product.project_revision,
            work_product_revision: work_product.work_product_revision,
            evidence_digest: evidence.evidence_digest,
            provenance: evidence.provenance,
            non_mutating: true,
            external_write_performed: false,
            durable_native_receipt: false,
            kernel_outcome_authority: false,
            native_connected: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal.validate(scope, &work_product)?;
        Ok(proposal)
    }

    pub fn record_pipeline_result(
        &self,
        proposal: &CircleCiPipelineResultProposal,
    ) -> Result<CircleCiPipelineResultReceipt, CircleCiPipelineResultError> {
        let scope = &self.provider.registration().scope;
        if proposal.scope_digest != scope.digest()
            || proposal.contract_version != crate::CIRCLECI_RESULT_CONTRACT_VERSION
            || proposal.contract_digest != crate::contract_digest()
            || proposal.plugin_id != crate::CIRCLECI_PLUGIN_ID
            || proposal.proposal_digest != proposal.compute_digest()
            || proposal.native_connected
            || proposal.external_write_performed
        {
            return Err(CircleCiPipelineResultError::ProposalMismatch);
        }
        validate_proposal_scope(scope, proposal)?;
        let mut receipt = CircleCiPipelineResultReceipt {
            contract_version: crate::CIRCLECI_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::CIRCLECI_PROVIDER_ID.to_owned(),
            provider_version: crate::CIRCLECI_PROVIDER_VERSION,
            scope_digest: scope.digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            provenance: proposal.provenance,
            recording_only: true,
            durable_native_receipt: false,
            external_write_performed: false,
            kernel_outcome_authority: false,
            native_connected: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt.validate(scope, proposal)?;
        Ok(receipt)
    }

    pub fn verify_pipeline_result(
        &self,
        proposal: &CircleCiPipelineResultProposal,
        receipt: &CircleCiPipelineResultReceipt,
    ) -> Result<VerifiedCircleCiPipelineResult, CircleCiPipelineResultError> {
        let scope = &self.provider.registration().scope;
        if proposal.scope_digest != scope.digest() {
            return Err(CircleCiPipelineResultError::ScopeMismatch);
        }
        if proposal.proposal_digest != proposal.compute_digest() {
            return Err(CircleCiPipelineResultError::ProposalMismatch);
        }
        validate_proposal_scope(scope, proposal)?;
        receipt.validate(scope, proposal)?;
        let result = VerifiedCircleCiPipelineResult {
            scope_digest: scope.digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            verified: true,
            adopted: false,
            native_connected: false,
            kernel_outcome_authority: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn registration(&self) -> &CircleCiRegistration {
        self.provider.registration()
    }
}

fn validate_work_product_scope(
    scope: &CircleCiScope,
    work_product: &MissionWorkProduct,
) -> Result<(), CircleCiPipelineResultError> {
    if work_product.mission_id != scope.mission_id {
        return Err(CircleCiPipelineResultError::ScopeMismatch);
    }
    if work_product.project_id != scope.project_id {
        return Err(CircleCiPipelineResultError::ScopeMismatch);
    }
    if work_product.work_product_id != scope.work_product_id {
        return Err(CircleCiPipelineResultError::ScopeMismatch);
    }
    if work_product.mission_revision != scope.revisions.mission {
        return Err(CircleCiPipelineResultError::MissionRevisionDrift);
    }
    if work_product.project_revision != scope.revisions.project {
        return Err(CircleCiPipelineResultError::ProjectRevisionDrift);
    }
    if work_product.work_product_revision != scope.revisions.work_product {
        return Err(CircleCiPipelineResultError::WorkProductRevisionDrift);
    }
    Ok(())
}

fn validate_proposal_scope(
    scope: &CircleCiScope,
    proposal: &CircleCiPipelineResultProposal,
) -> Result<(), CircleCiPipelineResultError> {
    if proposal.mission_id != scope.mission_id
        || proposal.project_id != scope.project_id
        || proposal.work_product_id != scope.work_product_id
    {
        return Err(CircleCiPipelineResultError::ScopeMismatch);
    }
    if proposal.mission_revision != scope.revisions.mission {
        return Err(CircleCiPipelineResultError::MissionRevisionDrift);
    }
    if proposal.project_revision != scope.revisions.project {
        return Err(CircleCiPipelineResultError::ProjectRevisionDrift);
    }
    if proposal.work_product_revision != scope.revisions.work_product {
        return Err(CircleCiPipelineResultError::WorkProductRevisionDrift);
    }
    if proposal.provenance == CircleCiProvenance::BlockedEnv
        || proposal.provenance.is_native()
        || proposal.provenance.is_connected()
    {
        return Err(CircleCiPipelineResultError::ProposalMismatch);
    }
    Ok(())
}

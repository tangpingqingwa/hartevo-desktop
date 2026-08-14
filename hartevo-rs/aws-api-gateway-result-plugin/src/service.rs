//! Read/proposal/record/verify service for the governed API Gateway result.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_API_GATEWAY_API_REVISION, AWS_API_GATEWAY_CONTRACT_VERSION, AWS_API_GATEWAY_PLUGIN_VERSION,
    AWS_API_GATEWAY_PROVIDER_ID, AWS_API_GATEWAY_PROVIDER_VERSION, AWS_API_GATEWAY_SERVICE_ID,
    contract_digest,
    model::{
        ApiGatewayReadOperation, AwsApiGatewayEvidence, AwsApiGatewayScope, Capabilities,
        DeploymentMetadata, DeploymentSummary, Digest, ErrorClassification, EvidenceStatus,
        MAX_RESPONSE_BYTES, ModelError, OpaquePageToken, PartialReason, ProviderErrorEvidence,
        RedactedRequestReceipt, Revision, SecretReference,
    },
    provider::{
        AwsApiGatewayDeploymentResponse, AwsApiGatewayDeploymentsPage, AwsApiGatewayProvider,
        AwsApiGatewayProviderError, AwsApiGatewayStageResponse, GetDeploymentRequest,
        GetDeploymentsRequest, GetStageRequest, TransportError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractDocumentError {
    #[error("AWS API Gateway contract document is invalid JSON")]
    InvalidJson,
    #[error("AWS API Gateway contract document shape is invalid")]
    InvalidShape,
    #[error("AWS API Gateway contract identity drifted")]
    IdentityDrift,
    #[error("AWS API Gateway contract widens Layer-1 authority")]
    AuthorityEscalation,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("AWS API Gateway registration is revoked")]
    Revoked,
    #[error("AWS API Gateway registration does not match its scope")]
    ScopeMismatch,
    #[error("AWS API Gateway registration digest is tampered")]
    Tampered,
    #[error("AWS API Gateway registration requires all three read permissions")]
    PermissionMismatch,
    #[error("AWS API Gateway SigV4 SecretReference is revoked")]
    SecretRevoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsApiGatewayServiceError {
    #[error("AWS API Gateway service registration is revoked")]
    RegistrationRevoked,
    #[error("AWS API Gateway SigV4 SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS API Gateway request is outside the exact registered scope")]
    ScopeMismatch,
    #[error("AWS API Gateway permission fence does not allow the requested operation")]
    PermissionLoss,
    #[error("AWS API Gateway provider or stage/deployment revision drifted")]
    RevisionDrift,
    #[error("AWS API Gateway provider, request, or evidence digest drifted")]
    DigestDrift,
    #[error("AWS API Gateway stage metadata drifted")]
    StageDrift,
    #[error("AWS API Gateway deployment metadata drifted")]
    DeploymentDrift,
    #[error("AWS API Gateway proposal or record was tampered")]
    TamperedEvidence,
    #[error("AWS API Gateway contract is invalid")]
    Contract(ContractDocumentError),
    #[error("AWS API Gateway model is invalid")]
    Model(ModelError),
    #[error("AWS API Gateway provider error")]
    Provider(AwsApiGatewayProviderError),
}

impl From<ModelError> for AwsApiGatewayServiceError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl From<AwsApiGatewayProviderError> for AwsApiGatewayServiceError {
    fn from(value: AwsApiGatewayProviderError) -> Self {
        Self::Provider(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub stage_digest: Digest,
    pub deployment_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
    pub revocation_digest: Option<Digest>,
}

impl AwsApiGatewayRegistration {
    pub fn expected_evidence_digest(scope: &AwsApiGatewayScope) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-registration-evidence/v1",
            &[
                scope.digest().to_string(),
                scope.stage_digest().to_string(),
                scope.deployment_digest().to_string(),
            ],
        )
    }

    fn new<T: crate::provider::AwsApiGatewayTransport>(
        scope: &AwsApiGatewayScope,
        secret: &SecretReference,
        provider: &AwsApiGatewayProvider<T>,
    ) -> Result<Self, RegistrationError> {
        if secret.is_revoked() {
            return Err(RegistrationError::SecretRevoked);
        }
        if !scope.permits(ApiGatewayReadOperation::GetStage)
            || !scope.permits(ApiGatewayReadOperation::GetDeployment)
            || !scope.permits(ApiGatewayReadOperation::GetDeployments)
        {
            return Err(RegistrationError::PermissionMismatch);
        }
        let identity = provider.identity();
        let mut registration = Self {
            plugin_version: AWS_API_GATEWAY_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_API_GATEWAY_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: identity.provider_id.as_str().to_owned(),
            provider_version: identity.provider_version.clone(),
            provider_revision: identity.api_revision.as_str().to_owned(),
            provider_digest: identity.provider_digest.clone(),
            api_digest: identity.api_digest.clone(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            stage_digest: scope.stage_digest(),
            deployment_digest: scope.deployment_digest(),
            evidence_digest: Self::expected_evidence_digest(scope),
            registration_revision: Revision::new(1).map_err(|_| RegistrationError::Tampered)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
            revocation_digest: None,
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.provider_revision.clone(),
                self.provider_digest.to_string(),
                self.api_digest.to_string(),
                self.scope_digest.to_string(),
                self.permission_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.stage_digest.to_string(),
                self.deployment_digest.to_string(),
                self.evidence_digest.to_string(),
                self.registration_revision.get().to_string(),
                format!("{:?}", self.state),
                self.revocation_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
            ],
        )
    }

    pub fn validate<T: crate::provider::AwsApiGatewayTransport>(
        &self,
        scope: &AwsApiGatewayScope,
        secret: &SecretReference,
        provider: &AwsApiGatewayProvider<T>,
    ) -> Result<(), RegistrationError> {
        if self.registration_digest != self.recomputed_digest() {
            return Err(RegistrationError::Tampered);
        }
        if !self.is_active() {
            return Err(RegistrationError::Revoked);
        }
        if secret.is_revoked() {
            return Err(RegistrationError::SecretRevoked);
        }
        let identity = provider.identity();
        if self.plugin_version != AWS_API_GATEWAY_PLUGIN_VERSION
            || self.contract_version != AWS_API_GATEWAY_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != identity.provider_id.as_str()
            || self.provider_version != identity.provider_version
            || self.provider_revision != identity.api_revision.as_str()
            || self.provider_digest != identity.provider_digest
            || self.api_digest != identity.api_digest
            || self.scope_digest != scope.digest()
            || self.permission_digest != *scope.permission_digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.stage_digest != scope.stage_digest()
            || self.deployment_digest != scope.deployment_digest()
            || self.evidence_digest != Self::expected_evidence_digest(scope)
        {
            return Err(RegistrationError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::Revoked);
        }
        self.state = RegistrationState::Revoked;
        self.revocation_digest = Some(Digest::from_parts(
            "hartevo-aws-api-gateway-registration-revocation/v1",
            &[
                self.registration_digest.to_string(),
                self.scope_digest.to_string(),
            ],
        ));
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsApiGatewayReadRequest {
    GetStage(GetStageRequest),
    GetDeployment(GetDeploymentRequest),
    GetDeployments(GetDeploymentsRequest),
}

impl AwsApiGatewayReadRequest {
    pub fn get_stage(scope: &AwsApiGatewayScope) -> Result<Self, AwsApiGatewayServiceError> {
        scope.validate()?;
        Ok(Self::GetStage(GetStageRequest::from_scope(scope)))
    }

    pub fn get_deployment(scope: &AwsApiGatewayScope) -> Result<Self, AwsApiGatewayServiceError> {
        scope.validate()?;
        Ok(Self::GetDeployment(GetDeploymentRequest::from_scope(scope)))
    }

    pub fn get_deployments(scope: &AwsApiGatewayScope) -> Result<Self, AwsApiGatewayServiceError> {
        scope.validate()?;
        Ok(Self::GetDeployments(GetDeploymentsRequest::from_scope(
            scope,
        )?))
    }

    pub fn stage(scope: &AwsApiGatewayScope) -> Self {
        Self::GetStage(GetStageRequest::from_scope(scope))
    }

    pub fn deployment(scope: &AwsApiGatewayScope) -> Self {
        Self::GetDeployment(GetDeploymentRequest::from_scope(scope))
    }

    pub fn deployments(scope: &AwsApiGatewayScope) -> Result<Self, AwsApiGatewayServiceError> {
        Self::get_deployments(scope)
    }

    pub fn operation(&self) -> ApiGatewayReadOperation {
        match self {
            Self::GetStage(_) => ApiGatewayReadOperation::GetStage,
            Self::GetDeployment(_) => ApiGatewayReadOperation::GetDeployment,
            Self::GetDeployments(_) => ApiGatewayReadOperation::GetDeployments,
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::GetStage(request) => &request.scope_digest,
            Self::GetDeployment(request) => &request.scope_digest,
            Self::GetDeployments(request) => &request.scope_digest,
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::GetStage(request) => request.request_digest(),
            Self::GetDeployment(request) => request.request_digest(),
            Self::GetDeployments(request) => request.request_digest(),
        }
    }

    pub fn with_cursor(
        &self,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self, AwsApiGatewayServiceError> {
        match self {
            Self::GetDeployments(request) => Ok(Self::GetDeployments(request.with_cursor(cursor)?)),
            Self::GetStage(_) | Self::GetDeployment(_) => {
                Err(AwsApiGatewayServiceError::ScopeMismatch)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayProposal {
    pub operation: ApiGatewayReadOperation,
    pub evidence: AwsApiGatewayEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
}

impl AwsApiGatewayProposal {
    fn new(
        operation: ApiGatewayReadOperation,
        evidence: AwsApiGatewayEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            truth_authority: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-proposal/v1",
            &[
                format!("{:?}", self.operation),
                self.evidence.evidence_digest.to_string(),
                self.proposed_at.to_rfc3339(),
                self.registration_digest.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
                self.adopts_outcome.to_string(),
                self.truth_authority.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), AwsApiGatewayServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.adopts_outcome
            || self.truth_authority
            || self.operation != self.evidence.operation
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsApiGatewayServiceError::TamperedEvidence);
        }
        self.evidence
            .validate()
            .map_err(AwsApiGatewayServiceError::Model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub operation: ApiGatewayReadOperation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub receipt_digest: Digest,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsApiGatewayRecordReceipt {
    fn new(proposal: &AwsApiGatewayProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            operation: proposal.operation,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            receipt_digest: Digest::zero(),
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-record/v1",
            &[
                self.recorded.to_string(),
                self.recorded_at.to_rfc3339(),
                format!("{:?}", self.operation),
                self.proposal_digest.to_string(),
                self.evidence_digest.to_string(),
                self.registration_digest.to_string(),
                self.scope_digest.to_string(),
                self.durable_receipt.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayVerifiedRecord {
    pub verified: bool,
    pub operation: ApiGatewayReadOperation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

pub struct AwsApiGatewayService<T> {
    scope: AwsApiGatewayScope,
    secret_reference: SecretReference,
    provider: AwsApiGatewayProvider<T>,
    registration: AwsApiGatewayRegistration,
}

impl<T> fmt::Debug for AwsApiGatewayService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsApiGatewayService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: crate::provider::AwsApiGatewayTransport> AwsApiGatewayService<T> {
    pub fn new(
        scope: AwsApiGatewayScope,
        secret_reference: SecretReference,
        provider: AwsApiGatewayProvider<T>,
    ) -> Result<Self, AwsApiGatewayServiceError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(AwsApiGatewayServiceError::SecretRevoked);
        }
        if secret_reference.reference_digest() != &scope.secret_reference_digest {
            return Err(AwsApiGatewayServiceError::ScopeMismatch);
        }
        if provider.definition().provider_id.as_str() != AWS_API_GATEWAY_PROVIDER_ID
            || provider.definition().api_revision.as_str() != AWS_API_GATEWAY_API_REVISION
            || provider.definition().provider_version != AWS_API_GATEWAY_PROVIDER_VERSION
            || provider.definition().connected
            || provider.definition().native
            || provider.definition().first_party
        {
            return Err(AwsApiGatewayServiceError::RevisionDrift);
        }
        let registration = AwsApiGatewayRegistration::new(&scope, &secret_reference, &provider)
            .map_err(|error| match error {
                RegistrationError::PermissionMismatch => AwsApiGatewayServiceError::PermissionLoss,
                RegistrationError::SecretRevoked => AwsApiGatewayServiceError::SecretRevoked,
                RegistrationError::ScopeMismatch | RegistrationError::Tampered => {
                    AwsApiGatewayServiceError::DigestDrift
                }
                RegistrationError::Revoked => AwsApiGatewayServiceError::RegistrationRevoked,
            })?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn describe_capabilities(&self) -> Capabilities {
        Capabilities {
            service_id: AWS_API_GATEWAY_SERVICE_ID.to_owned(),
            provider_id: AWS_API_GATEWAY_PROVIDER_ID.to_owned(),
            contract_version: AWS_API_GATEWAY_CONTRACT_VERSION.to_owned(),
            operations: vec![
                ApiGatewayReadOperation::GetStage,
                ApiGatewayReadOperation::GetDeployment,
                ApiGatewayReadOperation::GetDeployments,
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn scope(&self) -> &AwsApiGatewayScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsApiGatewayProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsApiGatewayProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsApiGatewayRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
            && !self.secret_reference.is_revoked()
            && self
                .registration
                .validate(&self.scope, &self.secret_reference, &self.provider)
                .is_ok()
    }

    pub fn register(&self) -> Result<AwsApiGatewayRegistration, AwsApiGatewayServiceError> {
        self.ensure_active_and_bound()?;
        Ok(self.registration.clone())
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsApiGatewayServiceError> {
        self.ensure_active_and_bound()?;
        self.registration
            .revoke()
            .map_err(|_| AwsApiGatewayServiceError::RegistrationRevoked)?;
        self.secret_reference
            .revoke()
            .map_err(|_| AwsApiGatewayServiceError::SecretRevoked)?;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), AwsApiGatewayServiceError> {
        self.revoke_registration()
    }

    pub fn read(
        &mut self,
        request: AwsApiGatewayReadRequest,
    ) -> Result<AwsApiGatewayReadResult, AwsApiGatewayServiceError> {
        self.ensure_active_and_bound()?;
        self.validate_request(&request)?;
        match request {
            AwsApiGatewayReadRequest::GetStage(request) => self.read_stage(request),
            AwsApiGatewayReadRequest::GetDeployment(request) => self.read_deployment(request),
            AwsApiGatewayReadRequest::GetDeployments(request) => self.read_deployments(request),
        }
    }

    pub fn read_bounded(
        &mut self,
        request: AwsApiGatewayReadRequest,
    ) -> Result<AwsApiGatewayReadResult, AwsApiGatewayServiceError> {
        self.read(request)
    }

    pub fn propose(
        &mut self,
        request: AwsApiGatewayReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsApiGatewayProposal, AwsApiGatewayServiceError> {
        let operation = request.operation();
        let result = self.read(request)?;
        Ok(AwsApiGatewayProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsApiGatewayProposal,
    ) -> Result<AwsApiGatewayRecordReceipt, AwsApiGatewayServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsApiGatewayProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsApiGatewayRecordReceipt, AwsApiGatewayServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsApiGatewayRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsApiGatewayRecordReceipt,
    ) -> Result<AwsApiGatewayVerifiedRecord, AwsApiGatewayServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.durable_receipt
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
        {
            return Err(AwsApiGatewayServiceError::TamperedEvidence);
        }
        Ok(AwsApiGatewayVerifiedRecord {
            verified: true,
            operation: receipt.operation,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest: Digest::from_parts(
                "hartevo-aws-api-gateway-verified-record/v1",
                &[
                    receipt.receipt_digest.to_string(),
                    self.registration.registration_digest.to_string(),
                    self.scope.digest().to_string(),
                ],
            ),
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            truth_authority: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsApiGatewayProposal,
    ) -> Result<(), AwsApiGatewayServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.plugin_version_digest
                != Digest::from_text(AWS_API_GATEWAY_PLUGIN_VERSION)
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.stage_digest != self.scope.stage_digest()
            || proposal.evidence.deployment_digest != self.scope.deployment_digest()
            || proposal.evidence.registration_digest != self.registration.registration_digest
        {
            return Err(AwsApiGatewayServiceError::DigestDrift);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsApiGatewayServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(AwsApiGatewayServiceError::SecretRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider)
            .map_err(|error| match error {
                RegistrationError::Revoked => AwsApiGatewayServiceError::RegistrationRevoked,
                RegistrationError::SecretRevoked => AwsApiGatewayServiceError::SecretRevoked,
                RegistrationError::ScopeMismatch => AwsApiGatewayServiceError::DigestDrift,
                RegistrationError::Tampered => AwsApiGatewayServiceError::TamperedEvidence,
                RegistrationError::PermissionMismatch => AwsApiGatewayServiceError::PermissionLoss,
            })
    }

    fn validate_request(
        &self,
        request: &AwsApiGatewayReadRequest,
    ) -> Result<(), AwsApiGatewayServiceError> {
        if request.scope_digest() != self.scope.scope_digest()
            || !self.scope.permits(request.operation())
        {
            return Err(if request.scope_digest() != self.scope.scope_digest() {
                AwsApiGatewayServiceError::ScopeMismatch
            } else {
                AwsApiGatewayServiceError::PermissionLoss
            });
        }
        match request {
            AwsApiGatewayReadRequest::GetStage(request) => {
                if request.api != self.scope.api
                    || request.stage != self.scope.stage
                    || request.deployment != self.scope.deployment
                {
                    return Err(AwsApiGatewayServiceError::ScopeMismatch);
                }
            }
            AwsApiGatewayReadRequest::GetDeployment(request) => {
                if request.api != self.scope.api
                    || request.stage != self.scope.stage
                    || request.deployment != self.scope.deployment
                {
                    return Err(AwsApiGatewayServiceError::ScopeMismatch);
                }
            }
            AwsApiGatewayReadRequest::GetDeployments(request) => {
                if request.api != self.scope.api
                    || request.stage != self.scope.stage
                    || request.deployment != self.scope.deployment
                    || request.page_size == 0
                    || request.page_size > crate::model::PAGE_SIZE
                    || request.max_pages == 0
                    || request.max_pages > crate::model::MAX_PAGES
                    || request.max_response_bytes == 0
                    || request.max_response_bytes > crate::model::MAX_RESPONSE_BYTES
                    || request.max_retries > crate::model::MAX_RETRIES
                {
                    return Err(AwsApiGatewayServiceError::ScopeMismatch);
                }
            }
        }
        Ok(())
    }

    fn read_stage(
        &mut self,
        request: GetStageRequest,
    ) -> Result<AwsApiGatewayReadResult, AwsApiGatewayServiceError> {
        let mut errors = Vec::new();
        let mut requests = 0_u16;
        let mut retries = 0_u8;
        let mut response: Option<AwsApiGatewayStageResponse> = None;
        let mut terminal_error: Option<TransportError> = None;
        for attempt in 0..=crate::model::MAX_RETRIES {
            requests = requests.saturating_add(1);
            match self.provider.get_stage(&request) {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                Err(AwsApiGatewayProviderError::Transport(error)) => {
                    errors.push(error.evidence(attempt));
                    if error.retryable() && attempt < crate::model::MAX_RETRIES {
                        retries = retries.saturating_add(1);
                        continue;
                    }
                    terminal_error = Some(error);
                    break;
                }
                Err(error) => {
                    errors.push(provider_error_evidence(&error, attempt));
                    terminal_error = Some(TransportError::Partial);
                    break;
                }
            }
        }
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;
        let mut stage_metadata = None;
        let mut receipts = Vec::new();
        if let Some(value) = response {
            let response_digest = value.response_digest.clone();
            let expected_response_digest = value.recomputed_response_digest();
            let response_bytes = value.response_bytes;
            let value_stage = value.stage;
            if response_bytes > MAX_RESPONSE_BYTES || response_digest != expected_response_digest {
                status = EvidenceStatus::Partial;
                partial_reason = Some(if response_bytes > MAX_RESPONSE_BYTES {
                    PartialReason::ResponseTooLarge
                } else {
                    PartialReason::DigestDrift
                });
            } else if value_stage.status != crate::model::MetadataStatus::Available
                || value_stage.error_classification != ErrorClassification::None
            {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::ProviderFailure);
            } else if value_stage.api_id != self.scope.api.id
                || value_stage.stage_name != self.scope.stage.name
                || value_stage.deployment_id != self.scope.deployment.id
            {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::StageDrift);
            } else if value_stage.api_revision != self.scope.api.revision
                || value_stage.stage_revision != self.scope.stage.revision
            {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::RevisionDrift);
            }
            receipts.push(RedactedRequestReceipt::new(
                ApiGatewayReadOperation::GetStage,
                request.request_digest(),
                response_digest,
                response_bytes,
            ));
            stage_metadata = Some(value_stage);
        } else if let Some(error) = terminal_error {
            status = status_for_transport(&error, false);
            partial_reason = Some(reason_for_transport(&error));
        }
        self.finish_evidence(
            ApiGatewayReadOperation::GetStage,
            status,
            partial_reason,
            stage_metadata,
            None,
            Vec::new(),
            0,
            requests,
            retries,
            false,
            Vec::new(),
            errors,
            receipts,
        )
    }

    fn read_deployment(
        &mut self,
        request: GetDeploymentRequest,
    ) -> Result<AwsApiGatewayReadResult, AwsApiGatewayServiceError> {
        let mut errors = Vec::new();
        let mut requests = 0_u16;
        let mut retries = 0_u8;
        let mut response: Option<AwsApiGatewayDeploymentResponse> = None;
        let mut terminal_error: Option<TransportError> = None;
        for attempt in 0..=crate::model::MAX_RETRIES {
            requests = requests.saturating_add(1);
            match self.provider.get_deployment(&request) {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                Err(AwsApiGatewayProviderError::Transport(error)) => {
                    errors.push(error.evidence(attempt));
                    if error.retryable() && attempt < crate::model::MAX_RETRIES {
                        retries = retries.saturating_add(1);
                        continue;
                    }
                    terminal_error = Some(error);
                    break;
                }
                Err(error) => {
                    errors.push(provider_error_evidence(&error, attempt));
                    terminal_error = Some(TransportError::Partial);
                    break;
                }
            }
        }
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;
        let mut deployment_metadata = None;
        let mut receipts = Vec::new();
        if let Some(value) = response {
            let response_digest = value.response_digest.clone();
            let expected_response_digest = value.recomputed_response_digest();
            let response_bytes = value.response_bytes;
            let value_deployment = value.deployment;
            if response_bytes > MAX_RESPONSE_BYTES || response_digest != expected_response_digest {
                status = EvidenceStatus::Partial;
                partial_reason = Some(if response_bytes > MAX_RESPONSE_BYTES {
                    PartialReason::ResponseTooLarge
                } else {
                    PartialReason::DigestDrift
                });
            } else if value_deployment.status != crate::model::MetadataStatus::Available
                || value_deployment.error_classification != ErrorClassification::None
            {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::ProviderFailure);
            } else if value_deployment.api_id != self.scope.api.id
                || value_deployment.deployment_id != self.scope.deployment.id
            {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::DeploymentDrift);
            } else if value_deployment.deployment_revision != self.scope.deployment.revision
                || value_deployment.configuration_digest
                    != self.scope.deployment.configuration_digest
                || value_deployment.commit_digest != self.scope.deployment.commit_digest
            {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::RevisionDrift);
            }
            receipts.push(RedactedRequestReceipt::new(
                ApiGatewayReadOperation::GetDeployment,
                request.request_digest(),
                response_digest,
                response_bytes,
            ));
            deployment_metadata = Some(value_deployment);
        } else if let Some(error) = terminal_error {
            status = status_for_transport(&error, false);
            partial_reason = Some(reason_for_transport(&error));
        }
        self.finish_evidence(
            ApiGatewayReadOperation::GetDeployment,
            status,
            partial_reason,
            None,
            deployment_metadata,
            Vec::new(),
            0,
            requests,
            retries,
            false,
            Vec::new(),
            errors,
            receipts,
        )
    }

    fn read_deployments(
        &mut self,
        request: GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayReadResult, AwsApiGatewayServiceError> {
        let mut current = request;
        let mut page_number = 0_u16;
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut deployments = Vec::new();
        let mut page_token_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut receipts = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;
        let mut truncated = false;
        let mut found_target = false;

        loop {
            if request_count >= crate::model::MAX_REQUESTS_PER_READ {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::PageBudget);
                truncated = true;
                break;
            }
            page_number = page_number.saturating_add(1);
            let mut page_response = None;
            let mut terminal_error = None;
            for attempt in 0..=current.max_retries {
                if request_count >= crate::model::MAX_REQUESTS_PER_READ {
                    terminal_error = Some(TransportError::Partial);
                    break;
                }
                request_count = request_count.saturating_add(1);
                match self.provider.get_deployments(&current) {
                    Ok(value) => {
                        page_response = Some(value);
                        break;
                    }
                    Err(AwsApiGatewayProviderError::Transport(error)) => {
                        provider_errors.push(error.evidence(attempt));
                        if error.retryable() && attempt < current.max_retries {
                            retry_count = retry_count.saturating_add(1);
                            continue;
                        }
                        terminal_error = Some(error);
                        break;
                    }
                    Err(error) => {
                        provider_errors.push(provider_error_evidence(&error, attempt));
                        terminal_error = Some(TransportError::Partial);
                        break;
                    }
                }
            }

            let Some(page) = page_response else {
                let error = terminal_error.unwrap_or(TransportError::Partial);
                status = if page_count == 0 {
                    status_for_transport(&error, false)
                } else {
                    EvidenceStatus::Partial
                };
                partial_reason = Some(if page_count == 0 {
                    reason_for_transport(&error)
                } else {
                    PartialReason::ProviderFailure
                });
                truncated = page_count > 0;
                break;
            };

            if page.page_number != page_number {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::RevisionDrift);
                truncated = true;
                break;
            }
            if page.response_bytes > current.max_response_bytes {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::ResponseTooLarge);
                truncated = true;
                break;
            }
            page_count = page_count.saturating_add(1);
            let next_cursor = page.next_cursor.clone();
            page_token_digests.extend(
                next_cursor
                    .as_ref()
                    .map(|token| token.token_digest().clone()),
            );
            let page_digest = recomputed_page_digest(&page);
            if page_digest != page.response_digest {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::DigestDrift);
                truncated = true;
                break;
            }
            receipts.push(RedactedRequestReceipt::new(
                ApiGatewayReadOperation::GetDeployments,
                current.request_digest(),
                page.response_digest.clone(),
                page.response_bytes,
            ));
            for deployment in page.deployments {
                if deployment.api_id != self.scope.api.id {
                    status = EvidenceStatus::Partial;
                    partial_reason = Some(PartialReason::DeploymentDrift);
                    truncated = true;
                    continue;
                }
                if deployment.deployment_id == self.scope.deployment.id {
                    found_target = true;
                    if deployment.deployment_revision != self.scope.deployment.revision
                        || deployment.configuration_digest
                            != self.scope.deployment.configuration_digest
                        || deployment.commit_digest != self.scope.deployment.commit_digest
                    {
                        status = EvidenceStatus::Partial;
                        partial_reason = Some(PartialReason::RevisionDrift);
                        truncated = true;
                    } else if deployments.len() < crate::model::MAX_DEPLOYMENTS {
                        deployments.push(deployment);
                    } else {
                        status = EvidenceStatus::Partial;
                        partial_reason = Some(PartialReason::DeploymentBudget);
                        truncated = true;
                    }
                } else {
                    status = EvidenceStatus::Partial;
                    partial_reason.get_or_insert(PartialReason::DeploymentDrift);
                    truncated = true;
                }
            }
            let Some(next_cursor) = next_cursor else {
                break;
            };
            if !seen_tokens.insert(next_cursor.token_digest().clone()) {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::PaginationLoop);
                truncated = true;
                break;
            }
            if page_count >= current.max_pages {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::PageBudget);
                truncated = true;
                break;
            }
            current = current.with_cursor(Some(next_cursor))?;
        }

        if !found_target && partial_reason.is_none() {
            status = EvidenceStatus::Partial;
            partial_reason = Some(PartialReason::MissingDeployment);
            truncated = true;
        }
        self.finish_evidence(
            ApiGatewayReadOperation::GetDeployments,
            status,
            partial_reason,
            None,
            None,
            deployments,
            page_count,
            request_count,
            retry_count,
            truncated,
            page_token_digests,
            provider_errors,
            receipts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_evidence(
        &self,
        operation: ApiGatewayReadOperation,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        stage_metadata: Option<crate::model::StageMetadata>,
        deployment_metadata: Option<DeploymentMetadata>,
        deployments: Vec<DeploymentSummary>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        page_token_digests: Vec<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
        request_receipts: Vec<RedactedRequestReceipt>,
    ) -> Result<AwsApiGatewayReadResult, AwsApiGatewayServiceError> {
        let evidence = AwsApiGatewayEvidence::new(
            operation,
            status,
            partial_reason,
            self.scope.api.clone(),
            self.scope.stage.clone(),
            self.scope.deployment.clone(),
            stage_metadata,
            deployment_metadata,
            deployments,
            page_count,
            request_count,
            retry_count,
            truncated,
            page_token_digests,
            provider_errors,
            request_receipts,
            self.provider.provenance(),
            Digest::from_text(AWS_API_GATEWAY_PLUGIN_VERSION),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_digest.clone(),
            contract_digest(),
            self.scope.permission_digest().clone(),
            self.scope.digest(),
            self.registration.registration_digest.clone(),
        )?;
        let page_digests = evidence
            .request_receipts
            .iter()
            .map(|receipt| receipt.response_digest.clone())
            .collect();
        Ok(AwsApiGatewayReadResult {
            operation,
            evidence,
            page_digests,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsApiGatewayReadResult {
    pub operation: ApiGatewayReadOperation,
    pub evidence: AwsApiGatewayEvidence,
    pub page_digests: Vec<Digest>,
}

fn provider_error_evidence(
    error: &AwsApiGatewayProviderError,
    attempt: u8,
) -> ProviderErrorEvidence {
    let (classification, status_code, retryable) = match error {
        AwsApiGatewayProviderError::Transport(error) => {
            return error.evidence(attempt);
        }
        AwsApiGatewayProviderError::OperationBinding
        | AwsApiGatewayProviderError::PageBinding
        | AwsApiGatewayProviderError::TooManyDeployments
        | AwsApiGatewayProviderError::ResponseTooLarge
        | AwsApiGatewayProviderError::InvalidJson
        | AwsApiGatewayProviderError::MissingMetadata => {
            (ErrorClassification::ResponseBinding, None, false)
        }
    };
    ProviderErrorEvidence::new(classification, status_code, retryable, attempt)
}

fn status_for_transport(error: &TransportError, has_prior_pages: bool) -> EvidenceStatus {
    if has_prior_pages {
        EvidenceStatus::Partial
    } else if error.is_access_loss() {
        EvidenceStatus::AccessLoss
    } else if matches!(error, TransportError::Conflict) {
        EvidenceStatus::Partial
    } else {
        EvidenceStatus::ProviderUnknown
    }
}

fn reason_for_transport(error: &TransportError) -> PartialReason {
    match error {
        TransportError::Unauthorized | TransportError::AccessDenied | TransportError::NotFound => {
            PartialReason::AccessLoss
        }
        TransportError::Throttled { .. } => PartialReason::Throttle,
        TransportError::Timeout => PartialReason::Timeout,
        TransportError::Conflict => PartialReason::Conflict,
        TransportError::BlockedEnvironment => PartialReason::BlockedEnvironment,
        TransportError::InvalidRequest
        | TransportError::ServerFailure { .. }
        | TransportError::Partial
        | TransportError::ResponseTooLarge => PartialReason::ProviderFailure,
    }
}

fn recomputed_page_digest(page: &AwsApiGatewayDeploymentsPage) -> Digest {
    page.recomputed_response_digest()
}

pub type AwsApiGatewayResultService<T> = AwsApiGatewayService<T>;
pub type AwsApiGatewayProposalRecord = AwsApiGatewayRecordReceipt;

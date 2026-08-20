//! Typed read/proposal/record/verify service for governed AWS Organizations evidence.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_ORGANIZATIONS_API_VERSION, AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID,
    AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON, AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION,
    AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID, AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION,
    AWS_ORGANIZATIONS_GOVERNANCE_SERVICE_ID, AWS_ORGANIZATIONS_PROVIDER_VERSION,
    model::{
        AttachmentDirection, AttachmentObservation, AttachmentState, AwsOrganizationsScope, Digest,
        EvidenceDigests, MissionBinding, ModelError, PolicyIdentity, PolicyType, ReadOperation,
        Registration, RegistrationRevocation, RevisionId, SecretReference, TargetReference,
        digest_serializable,
    },
    provider::{
        AwsOrganizationsProvider, AwsOrganizationsReadRecord, AwsOrganizationsRecordPage,
        AwsOrganizationsTransport, ListPoliciesForTargetRequest, ListPoliciesRequest,
        ListTargetsForPolicyRequest, ProviderError, ProviderProvenance,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractDocumentError {
    #[error("AWS Organizations contract document is not valid JSON")]
    InvalidJson,
    #[error("AWS Organizations contract document does not match its frozen identity")]
    IdentityDrift,
    #[error("AWS Organizations contract document escalates Layer-1 authority")]
    AuthorityEscalation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
    pub contract_digest: Digest,
    pub version_digest: Digest,
}

impl Default for ServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceDefinition {
    pub fn new() -> Self {
        let contract_digest = Digest::from_text(AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON);
        let version_digest = Digest::from_text(&format!(
            "{AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION}:{AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION}:{AWS_ORGANIZATIONS_API_VERSION}:{AWS_ORGANIZATIONS_PROVIDER_VERSION}"
        ));
        Self {
            schema_version: AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION.to_owned(),
            service_id: AWS_ORGANIZATIONS_GOVERNANCE_SERVICE_ID.to_owned(),
            provider_id: AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID.to_owned(),
            consumer_id: AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID.to_owned(),
            api_version: AWS_ORGANIZATIONS_API_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            contract_digest,
            version_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ContractDocumentError> {
        if self.schema_version != AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION
            || self.contract_version != AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION
            || self.service_id != AWS_ORGANIZATIONS_GOVERNANCE_SERVICE_ID
            || self.provider_id != AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID
            || self.consumer_id != AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID
            || self.api_version != AWS_ORGANIZATIONS_API_VERSION
            || !self.read_only
            || self.live_execution
            || self.emits_outcome
            || self.contract_digest != Digest::from_text(AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON)
            || self.version_digest != Self::new().version_digest
        {
            return Err(ContractDocumentError::IdentityDrift);
        }
        let document =
            serde_json::from_str::<serde_json::Value>(AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON)
                .map_err(|_| ContractDocumentError::InvalidJson)?;
        let native_claims = document
            .get("nativeClaims")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::AuthorityEscalation)?;
        let all_false = [
            "connected",
            "nativeProvider",
            "firstParty",
            "durableReceipt",
            "effectiveAuthorization",
            "policyTruthAuthority",
            "blockedEnvironmentIsNative",
        ]
        .into_iter()
        .all(|name| native_claims.get(name).and_then(serde_json::Value::as_bool) == Some(false));
        if !all_false {
            return Err(ContractDocumentError::AuthorityEscalation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("AWS Organizations service registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Organizations SigV4 SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Organizations scope or permission digest does not verify")]
    ScopeMismatch,
    #[error("AWS Organizations permission was lost or changed")]
    PermissionLoss,
    #[error("AWS Organizations hierarchy changed during the read")]
    HierarchyDrift,
    #[error("AWS Organizations policy or target is outside the exact scope")]
    TargetOutOfScope,
    #[error("AWS Organizations request/proposal digest drifted")]
    RequestDrift,
    #[error("AWS Organizations record or evidence digest was tampered")]
    TamperedEvidence,
    #[error("AWS Organizations policy type drifted")]
    PolicyTypeDrift,
    #[error("AWS Organizations record is incomplete")]
    IncompleteRecord,
    #[error(transparent)]
    Provider(ProviderError),
    #[error(transparent)]
    Model(ModelError),
    #[error(transparent)]
    Contract(ContractDocumentError),
}

impl From<ProviderError> for ServiceError {
    fn from(value: ProviderError) -> Self {
        match value {
            ProviderError::Transport(error)
                if matches!(
                    error.failure,
                    crate::provider::TransportFailure::Unauthorized
                        | crate::provider::TransportFailure::AccessDenied
                ) =>
            {
                Self::PermissionLoss
            }
            ProviderError::HierarchyDrift => Self::HierarchyDrift,
            ProviderError::PermissionLoss => Self::PermissionLoss,
            ProviderError::RecordTampered => Self::TamperedEvidence,
            other => Self::Provider(other),
        }
    }
}

impl From<ModelError> for ServiceError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl From<ContractDocumentError> for ServiceError {
    fn from(value: ContractDocumentError) -> Self {
        Self::Contract(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsOrganizationsReadRequest {
    ListPolicies(ListPoliciesRequest),
    ListTargetsForPolicy(ListTargetsForPolicyRequest),
    ListPoliciesForTarget(ListPoliciesForTargetRequest),
}

impl AwsOrganizationsReadRequest {
    pub fn operation(&self) -> ReadOperation {
        match self {
            Self::ListPolicies(_) => ReadOperation::ListPolicies,
            Self::ListTargetsForPolicy(_) => ReadOperation::ListTargetsForPolicy,
            Self::ListPoliciesForTarget(_) => ReadOperation::ListPoliciesForTarget,
        }
    }

    pub fn request_digest(&self) -> Result<Digest, ServiceError> {
        match self {
            Self::ListPolicies(request) => request.request_digest().map_err(ServiceError::from),
            Self::ListTargetsForPolicy(request) => {
                request.request_digest().map_err(ServiceError::from)
            }
            Self::ListPoliciesForTarget(request) => {
                request.request_digest().map_err(ServiceError::from)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsOrganizationsGovernanceProposal {
    pub operation: ReadOperation,
    pub request: AwsOrganizationsReadRequest,
    pub mission: MissionBinding,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub hierarchy_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: RevisionId,
    pub proposal_digest: Digest,
}

impl AwsOrganizationsGovernanceProposal {
    fn new(
        request: AwsOrganizationsReadRequest,
        scope: &AwsOrganizationsScope,
        definition: &ServiceDefinition,
        registration: &Registration,
    ) -> Result<Self, ServiceError> {
        let operation = request.operation();
        let mut proposal = Self {
            operation,
            request,
            mission: scope.mission.clone(),
            version_digest: definition.version_digest.clone(),
            provider_digest: Digest::from_text("pending-provider-digest"),
            contract_digest: definition.contract_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            hierarchy_digest: scope.hierarchy_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision.clone(),
            proposal_digest: Digest::from_text("pending-proposal-digest"),
        };
        proposal.proposal_digest = proposal.compute_digest()?;
        Ok(proposal)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.operation,
            &self
                .request
                .request_digest()
                .map_err(|_| ModelError::Invalid {
                    field: "proposal request",
                })?,
            &self.mission,
            &self.version_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.hierarchy_digest,
            &self.registration_digest,
            &self.registration_revision,
        ))
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.compute_digest()? != self.proposal_digest {
            return Err(ServiceError::RequestDrift);
        }
        if self.operation != self.request.operation() {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages_observed: usize,
    pub items_observed: usize,
    pub complete: bool,
    pub page_token_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub policy_documents_redacted: bool,
    pub account_pii_redacted: bool,
    pub organization_metadata_redacted: bool,
    pub secret_material_redacted: bool,
    pub raw_next_tokens_redacted: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            policy_documents_redacted: true,
            account_pii_redacted: true,
            organization_metadata_redacted: true,
            secret_material_redacted: true,
            raw_next_tokens_redacted: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub effective_authorization: bool,
    pub policy_truth_authority: bool,
    pub durable_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceDigestMaterial<'a> {
    operation: ReadOperation,
    mission: &'a MissionBinding,
    organization_id: &'a crate::model::OrganizationId,
    policy_type: PolicyType,
    target_scope: &'a [TargetReference],
    policies: &'a [PolicyIdentity],
    attachments: &'a [AttachmentObservation],
    registration_digest: &'a Digest,
    pagination: &'a PaginationEvidence,
    redaction: &'a RedactionSummary,
    status: EvidenceStatus,
    version_digest: &'a Digest,
    provider_digest: &'a Digest,
    contract_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    hierarchy_digest: &'a Digest,
    authority: &'a AuthorityBoundary,
    provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsOrganizationsGovernanceEvidence {
    pub operation: ReadOperation,
    pub mission: MissionBinding,
    pub organization_id: crate::model::OrganizationId,
    pub policy_type: PolicyType,
    pub target_scope: Vec<TargetReference>,
    pub policies: Vec<PolicyIdentity>,
    pub attachments: Vec<AttachmentObservation>,
    pub registration_digest: Digest,
    pub pagination: PaginationEvidence,
    pub redaction: RedactionSummary,
    pub status: EvidenceStatus,
    pub digests: EvidenceDigests,
    pub authority: AuthorityBoundary,
    pub provenance: ProviderProvenance,
}

impl AwsOrganizationsGovernanceEvidence {
    fn compute_evidence_digest(&self) -> Result<Digest, ModelError> {
        let material = EvidenceDigestMaterial {
            operation: self.operation,
            mission: &self.mission,
            organization_id: &self.organization_id,
            policy_type: self.policy_type,
            target_scope: &self.target_scope,
            policies: &self.policies,
            attachments: &self.attachments,
            registration_digest: &self.registration_digest,
            pagination: &self.pagination,
            redaction: &self.redaction,
            status: self.status,
            version_digest: &self.digests.version_digest,
            provider_digest: &self.digests.provider_digest,
            contract_digest: &self.digests.contract_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            hierarchy_digest: &self.digests.hierarchy_digest,
            authority: &self.authority,
            provenance: self.provenance,
        };
        digest_serializable(&material)
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.digests.evidence_digest != self.compute_evidence_digest()? {
            return Err(ServiceError::TamperedEvidence);
        }
        for policy in &self.policies {
            policy.verify()?;
        }
        for target in &self.target_scope {
            target.verify()?;
        }
        for attachment in &self.attachments {
            let rebuilt = AttachmentObservation::new(
                attachment.policy.clone(),
                attachment.target.clone(),
                attachment.direction,
                attachment.state,
            )?;
            if rebuilt.relationship_digest != attachment.relationship_digest {
                return Err(ServiceError::TamperedEvidence);
            }
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.authority.connected
    }

    pub fn claims_effective_authorization(&self) -> bool {
        self.authority.effective_authorization
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsOrganizationsReadResult {
    pub proposal: AwsOrganizationsGovernanceProposal,
    pub record: AwsOrganizationsReadRecord,
    pub evidence: AwsOrganizationsGovernanceEvidence,
}

pub struct AwsOrganizationsGovernanceService<T = crate::provider::BlockedEnvTransport> {
    scope: AwsOrganizationsScope,
    secret_reference: SecretReference,
    provider: AwsOrganizationsProvider<T>,
    definition: ServiceDefinition,
    registration: Registration,
}

impl<T: AwsOrganizationsTransport> fmt::Debug for AwsOrganizationsGovernanceService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsOrganizationsGovernanceService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AwsOrganizationsTransport> AwsOrganizationsGovernanceService<T> {
    pub fn new(
        scope: AwsOrganizationsScope,
        secret_reference: SecretReference,
        provider: AwsOrganizationsProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.verify()?;
        secret_reference
            .ensure_active()
            .map_err(|_| ServiceError::SecretRevoked)?;
        if secret_reference.scope_digest() != &scope.scope_digest {
            return Err(ServiceError::ScopeMismatch);
        }
        provider.validate()?;
        let definition = ServiceDefinition::new();
        definition.validate()?;
        let registration = Registration::new(
            definition.version_digest.clone(),
            provider.definition().provider_digest.clone(),
            definition.contract_digest.clone(),
            scope.permissions.permission_digest.clone(),
            scope.scope_digest.clone(),
            scope.hierarchy_digest.clone(),
            scope.mission.mission_revision.clone(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            definition,
            registration,
        })
    }

    pub fn service_definition(&self) -> &ServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &AwsOrganizationsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsOrganizationsProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &AwsOrganizationsScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        self.registration.revoke().map_err(ServiceError::from)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke().map_err(ServiceError::from)
    }

    pub fn propose_list_policies(
        &self,
    ) -> Result<AwsOrganizationsGovernanceProposal, ServiceError> {
        self.propose(AwsOrganizationsReadRequest::ListPolicies(
            ListPoliciesRequest::new(
                self.scope.organization_id.clone(),
                self.scope.policy_type,
                self.provider().bounds(),
                self.scope.hierarchy_digest.clone(),
                self.scope.permissions.permission_digest.clone(),
                self.scope.scope_digest.clone(),
            ),
        ))
    }

    pub fn propose_list_targets_for_policy(
        &self,
        policy: PolicyIdentity,
    ) -> Result<AwsOrganizationsGovernanceProposal, ServiceError> {
        if policy.policy_type != self.scope.policy_type {
            return Err(ServiceError::PolicyTypeDrift);
        }
        self.propose(AwsOrganizationsReadRequest::ListTargetsForPolicy(
            ListTargetsForPolicyRequest::new(
                self.scope.organization_id.clone(),
                policy,
                self.provider().bounds(),
                self.scope.hierarchy_digest.clone(),
                self.scope.permissions.permission_digest.clone(),
                self.scope.scope_digest.clone(),
            ),
        ))
    }

    pub fn propose_list_policies_for_target(
        &self,
        target: TargetReference,
    ) -> Result<AwsOrganizationsGovernanceProposal, ServiceError> {
        if !self.scope.contains_target(&target) {
            return Err(ServiceError::TargetOutOfScope);
        }
        self.propose(AwsOrganizationsReadRequest::ListPoliciesForTarget(
            ListPoliciesForTargetRequest::new(
                self.scope.organization_id.clone(),
                target,
                self.scope.policy_type,
                self.provider().bounds(),
                self.scope.hierarchy_digest.clone(),
                self.scope.permissions.permission_digest.clone(),
                self.scope.scope_digest.clone(),
            ),
        ))
    }

    pub fn propose(
        &self,
        request: AwsOrganizationsReadRequest,
    ) -> Result<AwsOrganizationsGovernanceProposal, ServiceError> {
        self.ensure_fences(request.operation())?;
        let request_scope_matches = match &request {
            AwsOrganizationsReadRequest::ListPolicies(request) => {
                request.organization_id == self.scope.organization_id
                    && request.policy_type == self.scope.policy_type
                    && request.hierarchy_digest == self.scope.hierarchy_digest
                    && request.permission_digest == self.scope.permissions.permission_digest
                    && request.scope_digest == self.scope.scope_digest
            }
            AwsOrganizationsReadRequest::ListTargetsForPolicy(request) => {
                request.organization_id == self.scope.organization_id
                    && request.policy.policy_type == self.scope.policy_type
                    && request.hierarchy_digest == self.scope.hierarchy_digest
                    && request.permission_digest == self.scope.permissions.permission_digest
                    && request.scope_digest == self.scope.scope_digest
            }
            AwsOrganizationsReadRequest::ListPoliciesForTarget(request) => {
                request.organization_id == self.scope.organization_id
                    && self.scope.contains_target(&request.target)
                    && request.policy_type == self.scope.policy_type
                    && request.hierarchy_digest == self.scope.hierarchy_digest
                    && request.permission_digest == self.scope.permissions.permission_digest
                    && request.scope_digest == self.scope.scope_digest
            }
        };
        if !request_scope_matches {
            return Err(ServiceError::ScopeMismatch);
        }
        let mut proposal = AwsOrganizationsGovernanceProposal::new(
            request,
            &self.scope,
            &self.definition,
            &self.registration,
        )?;
        proposal.provider_digest = self.provider.definition().provider_digest.clone();
        proposal.proposal_digest = proposal.compute_digest()?;
        Ok(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsOrganizationsGovernanceProposal,
    ) -> Result<AwsOrganizationsReadRecord, ServiceError> {
        self.ensure_proposal_fences(proposal)?;
        match proposal.request.clone() {
            AwsOrganizationsReadRequest::ListPolicies(request) => self
                .provider
                .list_policies(request)
                .map_err(ServiceError::from),
            AwsOrganizationsReadRequest::ListTargetsForPolicy(request) => self
                .provider
                .list_targets_for_policy(request)
                .map_err(ServiceError::from),
            AwsOrganizationsReadRequest::ListPoliciesForTarget(request) => self
                .provider
                .list_policies_for_target(request)
                .map_err(ServiceError::from),
        }
    }

    pub fn verify(
        &self,
        proposal: &AwsOrganizationsGovernanceProposal,
        record: &AwsOrganizationsReadRecord,
    ) -> Result<AwsOrganizationsGovernanceEvidence, ServiceError> {
        self.ensure_proposal_fences(proposal)?;
        proposal.verify()?;
        record.verify()?;
        if record.operation != proposal.operation
            || record.request_digest != proposal.request.request_digest()?
            || record.provider_digest != self.provider.definition().provider_digest
        {
            return Err(ServiceError::RequestDrift);
        }
        self.validate_record_shape(proposal, record)?;
        let (policies, attachments) = self.normalize_evidence(proposal, record)?;
        let pagination = PaginationEvidence {
            pages_observed: record.pages.len(),
            items_observed: record.item_count,
            complete: record.complete,
            page_token_digests: record.page_token_digests(),
        };
        if !pagination.complete {
            return Err(ServiceError::IncompleteRecord);
        }
        let redaction = RedactionSummary::default();
        let authority = AuthorityBoundary::default();
        let mut evidence = AwsOrganizationsGovernanceEvidence {
            operation: proposal.operation,
            mission: proposal.mission.clone(),
            organization_id: self.scope.organization_id.clone(),
            policy_type: self.scope.policy_type,
            target_scope: self.scope.target_scope.clone(),
            policies,
            attachments,
            registration_digest: proposal.registration_digest.clone(),
            pagination,
            redaction,
            status: EvidenceStatus::Complete,
            digests: EvidenceDigests {
                version_digest: self.definition.version_digest.clone(),
                provider_digest: self.provider.definition().provider_digest.clone(),
                contract_digest: self.definition.contract_digest.clone(),
                permission_digest: self.scope.permissions.permission_digest.clone(),
                scope_digest: self.scope.scope_digest.clone(),
                hierarchy_digest: self.scope.hierarchy_digest.clone(),
                evidence_digest: Digest::from_text("pending-evidence-digest"),
            },
            authority,
            provenance: self.provider.provenance(),
        };
        evidence.digests.evidence_digest = evidence.compute_evidence_digest()?;
        evidence.verify()?;
        Ok(evidence)
    }

    pub fn read(
        &mut self,
        request: AwsOrganizationsReadRequest,
    ) -> Result<AwsOrganizationsReadResult, ServiceError> {
        let proposal = self.propose(request)?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        Ok(AwsOrganizationsReadResult {
            proposal,
            record,
            evidence,
        })
    }

    pub fn read_list_policies(&mut self) -> Result<AwsOrganizationsReadResult, ServiceError> {
        let proposal = self.propose_list_policies()?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        Ok(AwsOrganizationsReadResult {
            proposal,
            record,
            evidence,
        })
    }

    pub fn read_list_targets_for_policy(
        &mut self,
        policy: PolicyIdentity,
    ) -> Result<AwsOrganizationsReadResult, ServiceError> {
        let proposal = self.propose_list_targets_for_policy(policy)?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        Ok(AwsOrganizationsReadResult {
            proposal,
            record,
            evidence,
        })
    }

    pub fn read_list_policies_for_target(
        &mut self,
        target: TargetReference,
    ) -> Result<AwsOrganizationsReadResult, ServiceError> {
        let proposal = self.propose_list_policies_for_target(target)?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        Ok(AwsOrganizationsReadResult {
            proposal,
            record,
            evidence,
        })
    }

    fn ensure_fences(&self, operation: ReadOperation) -> Result<(), ServiceError> {
        self.scope.verify()?;
        self.registration
            .ensure_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        self.registration
            .verify()
            .map_err(|_| ServiceError::ScopeMismatch)?;
        self.secret_reference
            .ensure_active()
            .map_err(|_| ServiceError::SecretRevoked)?;
        if self.secret_reference.scope_digest() != &self.scope.scope_digest
            || !self.scope.permissions.permits(operation)
        {
            return Err(ServiceError::PermissionLoss);
        }
        Ok(())
    }

    fn ensure_proposal_fences(
        &self,
        proposal: &AwsOrganizationsGovernanceProposal,
    ) -> Result<(), ServiceError> {
        self.ensure_fences(proposal.operation)?;
        proposal.verify()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.permission_digest != self.scope.permissions.permission_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.hierarchy_digest != self.scope.hierarchy_digest
            || proposal.provider_digest != self.provider.definition().provider_digest
            || proposal.contract_digest != self.definition.contract_digest
        {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }

    fn normalize_evidence(
        &self,
        proposal: &AwsOrganizationsGovernanceProposal,
        record: &AwsOrganizationsReadRecord,
    ) -> Result<(Vec<PolicyIdentity>, Vec<AttachmentObservation>), ServiceError> {
        match (&proposal.request, proposal.operation) {
            (AwsOrganizationsReadRequest::ListPolicies(_), ReadOperation::ListPolicies) => {
                let policies = record.policy_items().cloned().collect();
                Ok((policies, Vec::new()))
            }
            (
                AwsOrganizationsReadRequest::ListTargetsForPolicy(request),
                ReadOperation::ListTargetsForPolicy,
            ) => {
                let targets = record.target_items().cloned().collect::<Vec<_>>();
                for target in &targets {
                    if !self.scope.contains_target(target) {
                        return Err(ServiceError::TargetOutOfScope);
                    }
                }
                let mut attachments = Vec::new();
                for target in &self.scope.target_scope {
                    let state = if targets
                        .iter()
                        .any(|candidate| candidate.target_id == target.target_id)
                    {
                        AttachmentState::Attached
                    } else {
                        AttachmentState::NotAttached
                    };
                    attachments.push(AttachmentObservation::new(
                        request.policy.clone(),
                        target.clone(),
                        AttachmentDirection::PolicyToTarget,
                        state,
                    )?);
                }
                Ok((vec![request.policy.clone()], attachments))
            }
            (
                AwsOrganizationsReadRequest::ListPoliciesForTarget(request),
                ReadOperation::ListPoliciesForTarget,
            ) => {
                if !self.scope.contains_target(&request.target) {
                    return Err(ServiceError::TargetOutOfScope);
                }
                let policies = record.policy_items().cloned().collect::<Vec<_>>();
                if policies
                    .iter()
                    .any(|policy| policy.policy_type != self.scope.policy_type)
                {
                    return Err(ServiceError::PolicyTypeDrift);
                }
                let mut attachments = Vec::new();
                for policy in &policies {
                    attachments.push(AttachmentObservation::new(
                        policy.clone(),
                        request.target.clone(),
                        AttachmentDirection::TargetToPolicy,
                        AttachmentState::Attached,
                    )?);
                }
                Ok((policies, attachments))
            }
            _ => Err(ServiceError::RequestDrift),
        }
    }

    fn validate_record_shape(
        &self,
        proposal: &AwsOrganizationsGovernanceProposal,
        record: &AwsOrganizationsReadRecord,
    ) -> Result<(), ServiceError> {
        let mut policy_ids = BTreeSet::new();
        let mut target_ids = BTreeSet::new();
        for page in &record.pages {
            let (page_hierarchy_digest, page_permission_digest) = match page {
                AwsOrganizationsRecordPage::Policies {
                    policies,
                    hierarchy_digest,
                    permission_digest,
                    ..
                } => {
                    if policies.iter().any(|policy| {
                        policy.verify().is_err()
                            || policy.policy_type != self.scope.policy_type
                            || policy
                                .policy_arn
                                .organization_id()
                                .is_some_and(|organization_id| {
                                    organization_id != self.scope.organization_id.as_str()
                                })
                            || !policy_ids.insert(policy.policy_id.clone())
                    }) {
                        return Err(ServiceError::RequestDrift);
                    }
                    (hierarchy_digest, permission_digest)
                }
                AwsOrganizationsRecordPage::Targets {
                    targets,
                    hierarchy_digest,
                    permission_digest,
                    ..
                } => {
                    if targets.iter().any(|target| {
                        target.verify().is_err()
                            || target.organization_id != self.scope.organization_id
                            || !self.scope.contains_target(target)
                            || !target_ids.insert(target.target_id.clone())
                    }) {
                        return Err(ServiceError::TargetOutOfScope);
                    }
                    (hierarchy_digest, permission_digest)
                }
            };
            if page_hierarchy_digest != &self.scope.hierarchy_digest {
                return Err(ServiceError::HierarchyDrift);
            }
            if page_permission_digest != &self.scope.permissions.permission_digest {
                return Err(ServiceError::PermissionLoss);
            }
        }
        if proposal.operation == ReadOperation::ListTargetsForPolicy
            && !record
                .pages
                .iter()
                .all(|page| matches!(page, AwsOrganizationsRecordPage::Targets { .. }))
        {
            return Err(ServiceError::RequestDrift);
        }
        if proposal.operation != ReadOperation::ListTargetsForPolicy
            && record
                .pages
                .iter()
                .any(|page| matches!(page, AwsOrganizationsRecordPage::Targets { .. }))
        {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }
}

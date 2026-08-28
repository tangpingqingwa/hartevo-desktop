use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    CannyFeedbackProviderEvidence, CannyFeedbackRegistration, CannyFeedbackResultStatus,
    CannyFeedbackScope, Digest, ModelError, ProviderProvenance, RegistrationRevocation,
    RegistrationState, Revision, SecretReference, Timestamp,
};
use crate::provider::{
    CannyFeedbackTransport, CannyProvider, CannyProviderDefinition, CannyProviderError,
    ProviderDefinitionError,
};
use crate::query::{CannyFeedbackResultRequest, QueryError};
use crate::{
    CANNY_FEEDBACK_RESULT_CONTRACT_VERSION, CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT,
    CANNY_FEEDBACK_RESULT_SERVICE_ID, contract_digest, service_version_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackServiceDefinition {
    pub id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub native_connected: bool,
    pub operations: Vec<String>,
}

impl CannyFeedbackServiceDefinition {
    pub fn new() -> Self {
        Self {
            id: CANNY_FEEDBACK_RESULT_SERVICE_ID.to_owned(),
            version: CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            native_connected: false,
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "read_bounded".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
                "consume".to_owned(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ServiceDefinitionError> {
        if self != &Self::new() {
            Err(ServiceDefinitionError::DefinitionDrift)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        crate::model::canonical_digest(self)
    }
}

impl Default for CannyFeedbackServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceDefinitionError {
    #[error("Canny service definition drifted from the Layer-1 contract")]
    DefinitionDrift,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CannyFeedbackResultServiceError {
    #[error("Canny model is invalid: {0}")]
    Model(String),
    #[error("Canny query is invalid: {0}")]
    Query(String),
    #[error("Canny provider failed: {0}")]
    Provider(String),
    #[error("Canny service or provider definition drifted")]
    DefinitionDrift,
    #[error("Canny registration is revoked")]
    RegistrationRevoked,
    #[error("Canny secret reference is revoked")]
    SecretRevoked,
    #[error("Canny request is outside the registered Mission/Work Product scope")]
    RequestOutOfScope,
    #[error("idempotency key was reused for a different Canny request")]
    IdempotencyConflict,
    #[error("Canny provider evidence failed integrity validation")]
    EvidenceTampered,
    #[error("Canny proposal failed integrity validation")]
    ProposalTampered,
    #[error("Canny registration is invalid")]
    RegistrationInvalid,
}

pub type CannyFeedbackServiceError = CannyFeedbackResultServiceError;

impl From<ModelError> for CannyFeedbackResultServiceError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<QueryError> for CannyFeedbackResultServiceError {
    fn from(error: QueryError) -> Self {
        match error {
            QueryError::ScopeMismatch => Self::RequestOutOfScope,
            other => Self::Query(other.to_string()),
        }
    }
}

impl From<ProviderDefinitionError> for CannyFeedbackResultServiceError {
    fn from(_: ProviderDefinitionError) -> Self {
        Self::DefinitionDrift
    }
}

impl From<ServiceDefinitionError> for CannyFeedbackResultServiceError {
    fn from(_: ServiceDefinitionError) -> Self {
        Self::DefinitionDrift
    }
}

impl From<CannyProviderError> for CannyFeedbackResultServiceError {
    fn from(error: CannyProviderError) -> Self {
        match error {
            CannyProviderError::DefinitionDrift => Self::DefinitionDrift,
            CannyProviderError::ScopeMismatch | CannyProviderError::InvalidRequest(_) => {
                Self::RequestOutOfScope
            }
            CannyProviderError::SecretRevoked => Self::SecretRevoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub version_digest: Digest,
    pub service_definition_digest: Digest,
    pub service_version: String,
    pub provider_digest: Digest,
    pub project_digest: Digest,
    pub workspace_digest: Digest,
    pub board_digest: Digest,
    pub post_digest: Digest,
    pub comment_digest: Digest,
    pub vote_window_digest: Digest,
    pub status_digest: Digest,
    pub category_digest: Digest,
    pub roadmap_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
    pub requested_at: Timestamp,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub provenance: ProviderProvenance,
    pub status: CannyFeedbackResultStatus,
    pub request: CannyFeedbackResultRequest,
    pub evidence: CannyFeedbackProviderEvidence,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub https_transport: bool,
    pub feedback_mutation: bool,
    pub raw_api_body_included: bool,
    pub comment_body_included: bool,
    pub voter_pii_included: bool,
    pub author_pii_included: bool,
    pub causal_demand_claim: bool,
    pub outcome_authority: bool,
    pub adopted_work_product: bool,
    pub proposal_digest: Digest,
}

impl CannyFeedbackResultProposal {
    pub fn validate(
        &self,
        scope: &CannyFeedbackScope,
        registration: &CannyFeedbackRegistration,
        secret: &SecretReference,
        provider_definition: &CannyProviderDefinition,
        service_definition: &CannyFeedbackServiceDefinition,
    ) -> bool {
        registration
            .validate_against(scope, &provider_definition.provider_digest(), secret)
            .is_ok()
            && registration.state == RegistrationState::Active
            && self.registration_digest == registration.registration_digest
            && self.secret_digest_matches(secret)
            && self.validate_integrity(scope, provider_definition, service_definition)
            && self.evidence.validate(&self.request, provider_definition)
    }

    pub fn validate_integrity(
        &self,
        scope: &CannyFeedbackScope,
        provider_definition: &CannyProviderDefinition,
        service_definition: &CannyFeedbackServiceDefinition,
    ) -> bool {
        let request = &self.request;
        self.contract_version == CANNY_FEEDBACK_RESULT_CONTRACT_VERSION
            && self.contract_digest == contract_digest()
            && self.version_digest == service_version_digest()
            && self.service_version == CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT
            && self.service_definition_digest == service_definition.digest()
            && self.provider_digest == provider_definition.provider_digest()
            && self.project_digest == scope.project.digest()
            && self.workspace_digest == scope.workspace.digest()
            && self.board_digest == scope.board.digest()
            && self.post_digest == scope.post.digest()
            && self.comment_digest == scope.comment.digest()
            && self.vote_window_digest == scope.vote_window.digest()
            && self.status_digest == scope.status.digest()
            && self.category_digest == scope.category.digest()
            && self.roadmap_digest == scope.roadmap.digest()
            && self.scope_digest == scope.digest()
            && self.query_digest == *request.request_digest()
            && self.evidence_digest == self.evidence.evidence_digest
            && self.requested_at == request.requested_at()
            && self.mission_revision == scope.mission.revision
            && self.work_product_revision == scope.work_product.revision
            && self.provenance == self.evidence.provenance
            && self.status == self.evidence.status
            && self.read_only
            && self.proposal_only
            && !self.connected
            && !self.native_provider
            && !self.first_party
            && !self.https_transport
            && !self.feedback_mutation
            && !self.raw_api_body_included
            && !self.comment_body_included
            && !self.voter_pii_included
            && !self.author_pii_included
            && !self.causal_demand_claim
            && !self.outcome_authority
            && !self.adopted_work_product
            && self.evidence.validate(request, provider_definition)
            && compute_proposal_digest(self) == self.proposal_digest
    }

    pub(crate) fn validate_for_consumer(
        &self,
        scope: &CannyFeedbackScope,
        provider_definition: &CannyProviderDefinition,
        service_definition: &CannyFeedbackServiceDefinition,
    ) -> bool {
        self.scope_digest == scope.digest()
            && self.validate_integrity(scope, provider_definition, service_definition)
    }

    fn secret_digest_matches(&self, secret: &SecretReference) -> bool {
        self.evidence.secret_reference_digest == *secret.reference_digest()
            && self.evidence.credential_revision == secret.credential_revision()
    }

    pub fn receipt(&self) -> CannyFeedbackResultReceipt {
        let receipt_digest = Digest::from_fields(
            "canny-feedback-result-receipt/v1",
            &[
                self.proposal_digest.to_string(),
                self.evidence_digest.to_string(),
                format!("{:?}", self.status),
            ],
        );
        CannyFeedbackResultReceipt {
            receipt_digest,
            proposal_digest: self.proposal_digest.clone(),
            evidence_digest: self.evidence_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            status: self.status,
            provenance: self.provenance,
            deterministic: true,
            read_only: true,
            proposal_only: true,
            connected: false,
            native_provider: false,
            durable_provider_receipt: false,
            feedback_mutation: false,
            voter_pii: false,
            causal_demand_claim: false,
            adopted_work_product: false,
            outcome_authority: false,
        }
    }

    pub const fn status(&self) -> CannyFeedbackResultStatus {
        self.status
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub status: CannyFeedbackResultStatus,
    pub provenance: ProviderProvenance,
    pub deterministic: bool,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub durable_provider_receipt: bool,
    pub feedback_mutation: bool,
    pub voter_pii: bool,
    pub causal_demand_claim: bool,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
}

pub type CannyFeedbackRecordReceipt = CannyFeedbackResultReceipt;

pub struct CannyFeedbackResultService<T> {
    service_definition: CannyFeedbackServiceDefinition,
    provider: CannyProvider<T>,
    scope: CannyFeedbackScope,
    secret: SecretReference,
    registration: CannyFeedbackRegistration,
    idempotent: BTreeMap<Digest, CannyFeedbackResultProposal>,
}

pub type CannyFeedbackService<T> = CannyFeedbackResultService<T>;

impl<T> fmt::Debug for CannyFeedbackResultService<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CannyFeedbackResultService")
            .field("service_definition", &self.service_definition)
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("secret", &"<opaque>")
            .field("registration", &self.registration)
            .field("idempotent_keys", &self.idempotent.len())
            .finish()
    }
}

impl<T> CannyFeedbackResultService<T>
where
    T: CannyFeedbackTransport,
{
    pub fn new(
        scope: CannyFeedbackScope,
        secret: SecretReference,
        provider: CannyProvider<T>,
    ) -> Result<Self, CannyFeedbackResultServiceError> {
        scope.validate()?;
        let service_definition = CannyFeedbackServiceDefinition::new();
        service_definition.validate()?;
        let registration = CannyFeedbackRegistration::new(
            &scope,
            provider.definition().provider_digest(),
            &secret,
        )?;
        Ok(Self {
            service_definition,
            provider,
            scope,
            secret,
            registration,
            idempotent: BTreeMap::new(),
        })
    }

    pub fn register(
        scope: CannyFeedbackScope,
        secret: SecretReference,
        provider: CannyProvider<T>,
    ) -> Result<Self, CannyFeedbackResultServiceError> {
        Self::new(scope, secret, provider)
    }

    pub fn service_definition(&self) -> &CannyFeedbackServiceDefinition {
        &self.service_definition
    }

    pub fn provider(&self) -> &CannyProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut CannyProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &CannyFeedbackScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &CannyFeedbackRegistration {
        &self.registration
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration.registration_digest
    }

    pub fn idempotent_count(&self) -> usize {
        self.idempotent.len()
    }

    pub fn read(
        &mut self,
        request: CannyFeedbackResultRequest,
    ) -> Result<CannyFeedbackResultProposal, CannyFeedbackResultServiceError> {
        self.service_definition.validate()?;
        if !self.registration.is_active() {
            return Err(CannyFeedbackResultServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(CannyFeedbackResultServiceError::SecretRevoked);
        }
        request.validate_against(&self.scope)?;
        if let Some(existing) = self.idempotent.get(request.idempotency_key_digest()) {
            if existing.query_digest == *request.request_digest() {
                return Ok(existing.clone());
            }
            return Err(CannyFeedbackResultServiceError::IdempotencyConflict);
        }
        let evidence = self.provider.read(&request, &self.secret)?;
        if !evidence.validate(&request, self.provider.definition()) {
            return Err(CannyFeedbackResultServiceError::EvidenceTampered);
        }
        let proposal = self.make_proposal(&request, evidence);
        if !proposal.validate(
            &self.scope,
            &self.registration,
            &self.secret,
            self.provider.definition(),
            &self.service_definition,
        ) {
            return Err(CannyFeedbackResultServiceError::ProposalTampered);
        }
        self.idempotent
            .insert(request.idempotency_key_digest().clone(), proposal.clone());
        Ok(proposal)
    }

    pub fn propose(
        &mut self,
        request: CannyFeedbackResultRequest,
    ) -> Result<CannyFeedbackResultProposal, CannyFeedbackResultServiceError> {
        self.read(request)
    }

    pub fn record(
        &self,
        proposal: &CannyFeedbackResultProposal,
    ) -> Result<CannyFeedbackRecordReceipt, CannyFeedbackResultServiceError> {
        self.verify(proposal)?;
        Ok(proposal.receipt())
    }

    pub fn verify(
        &self,
        proposal: &CannyFeedbackResultProposal,
    ) -> Result<(), CannyFeedbackResultServiceError> {
        if !proposal.validate(
            &self.scope,
            &self.registration,
            &self.secret,
            self.provider.definition(),
            &self.service_definition,
        ) {
            Err(CannyFeedbackResultServiceError::ProposalTampered)
        } else {
            Ok(())
        }
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, CannyFeedbackResultServiceError> {
        self.registration.revoke().map_err(|error| match error {
            ModelError::AlreadyRevoked => CannyFeedbackResultServiceError::RegistrationRevoked,
            other => CannyFeedbackResultServiceError::Model(other.to_string()),
        })
    }

    pub fn revoke_secret(&mut self) -> Result<(), CannyFeedbackResultServiceError> {
        self.secret.revoke().map_err(|error| match error {
            ModelError::AlreadyRevoked => CannyFeedbackResultServiceError::SecretRevoked,
            other => CannyFeedbackResultServiceError::Model(other.to_string()),
        })
    }

    fn make_proposal(
        &self,
        request: &CannyFeedbackResultRequest,
        evidence: CannyFeedbackProviderEvidence,
    ) -> CannyFeedbackResultProposal {
        let mut proposal = CannyFeedbackResultProposal {
            contract_version: CANNY_FEEDBACK_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            version_digest: service_version_digest(),
            service_definition_digest: self.service_definition.digest(),
            service_version: CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            provider_digest: self.provider.definition().provider_digest(),
            project_digest: self.scope.project.digest(),
            workspace_digest: self.scope.workspace.digest(),
            board_digest: self.scope.board.digest(),
            post_digest: self.scope.post.digest(),
            comment_digest: self.scope.comment.digest(),
            vote_window_digest: self.scope.vote_window.digest(),
            status_digest: self.scope.status.digest(),
            category_digest: self.scope.category.digest(),
            roadmap_digest: self.scope.roadmap.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            query_digest: request.request_digest().clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            requested_at: request.requested_at(),
            mission_revision: request.mission_revision(),
            work_product_revision: request.work_product_revision(),
            provenance: evidence.provenance,
            status: evidence.status,
            request: request.clone(),
            evidence,
            read_only: true,
            proposal_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            https_transport: false,
            feedback_mutation: false,
            raw_api_body_included: false,
            comment_body_included: false,
            voter_pii_included: false,
            author_pii_included: false,
            causal_demand_claim: false,
            outcome_authority: false,
            adopted_work_product: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = compute_proposal_digest(&proposal);
        proposal
    }
}

pub(crate) fn compute_proposal_digest(proposal: &CannyFeedbackResultProposal) -> Digest {
    let mut fingerprint = proposal.clone();
    fingerprint.proposal_digest = Digest::zero();
    crate::model::canonical_digest(&fingerprint)
}

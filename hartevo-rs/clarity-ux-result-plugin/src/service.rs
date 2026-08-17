use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ClarityRegistration, ClarityUxScope, Digest, ModelError, ProviderProvenance,
    RegistrationRevocation, ResultStatus, SecretReference, Timestamp,
};
use crate::provider::{
    ClarityProvider, ClarityProviderDefinition, ClarityProviderError, ClarityProviderEvidence,
    ProviderDefinitionError,
};
use crate::query::{ClarityDataExportGetRequest, ClarityUxResultRequest};
use crate::{
    CLARITY_UX_RESULT_CONTRACT_VERSION, CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT,
    CLARITY_UX_RESULT_SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityServiceDefinition {
    pub id: String,
    pub version: String,
    pub read_only: bool,
    pub native_connected: bool,
    pub capabilities: Vec<String>,
}

impl ClarityServiceDefinition {
    pub fn new() -> Self {
        Self {
            id: CLARITY_UX_RESULT_SERVICE_ID.to_owned(),
            version: CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            read_only: true,
            native_connected: false,
            capabilities: vec![
                "clarity.ux.result.register".to_owned(),
                "clarity.ux.result.revoke_registration".to_owned(),
                "clarity.ux.result.read_aggregate".to_owned(),
                "clarity.ux.result.propose".to_owned(),
                "clarity.ux.result.consume".to_owned(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ClarityUxResultServiceError> {
        if self != &Self::new() || !self.read_only || self.native_connected {
            Err(ClarityUxResultServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

impl Default for ClarityServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ClarityUxResultServiceError {
    #[error("Clarity scope is invalid: {0}")]
    Model(String),
    #[error("Clarity query is invalid: {0}")]
    Query(String),
    #[error("Clarity provider failed before an evidence state could be produced")]
    Provider,
    #[error("Clarity registration is revoked")]
    RegistrationRevoked,
    #[error("Clarity secret reference is revoked")]
    SecretRevoked,
    #[error("Clarity request is outside the registered Mission/Work Product scope")]
    RequestOutOfScope,
    #[error("Clarity provider evidence failed validation")]
    InvalidEvidence,
    #[error("Clarity service or provider definition drifted")]
    DefinitionDrift,
}

impl From<ProviderDefinitionError> for ClarityUxResultServiceError {
    fn from(_: ProviderDefinitionError) -> Self {
        Self::DefinitionDrift
    }
}

impl From<ModelError> for ClarityUxResultServiceError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<ClarityProviderError> for ClarityUxResultServiceError {
    fn from(error: ClarityProviderError) -> Self {
        match error {
            ClarityProviderError::DefinitionDrift => Self::DefinitionDrift,
            ClarityProviderError::ScopeMismatch => Self::RequestOutOfScope,
            ClarityProviderError::SecretRevoked => Self::SecretRevoked,
            ClarityProviderError::InvalidRequest => Self::RequestOutOfScope,
            ClarityProviderError::TransportUnavailable => Self::Provider,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityUxResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub version_digest: Digest,
    pub service_version: String,
    pub provider_digest: Digest,
    pub project_digest: Digest,
    pub privacy_policy_digest: Digest,
    pub consent_scope_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
    pub requested_at: Timestamp,
    pub mission_revision: crate::model::Revision,
    pub work_product_revision: crate::model::Revision,
    pub provenance: ProviderProvenance,
    pub status: ResultStatus,
    pub evidence: ClarityProviderEvidence,
    pub read_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub proposal_digest: Digest,
}

impl ClarityUxResultProposal {
    pub fn validate(
        &self,
        scope: &ClarityUxScope,
        registration: &ClarityRegistration,
        provider_definition: &ClarityProviderDefinition,
        request: &ClarityDataExportGetRequest,
    ) -> bool {
        self.contract_version == CLARITY_UX_RESULT_CONTRACT_VERSION
            && self.contract_digest == contract_digest()
            && self.version_digest == Digest::from_text(CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT)
            && self.service_version == CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT
            && self.provider_digest == provider_definition.provider_digest()
            && self.project_digest == scope.project_digest()
            && self.privacy_policy_digest == scope.privacy_policy().digest()
            && self.consent_scope_digest == scope.consent().digest()
            && self.registration_digest == registration.registration_digest
            && self.scope_digest == scope.digest()
            && self.query_digest == *request.query_digest()
            && self.evidence_digest == self.evidence.response_digest
            && self.requested_at == request.requested_at()
            && self.mission_revision == scope.mission().revision()
            && self.work_product_revision == scope.work_product().revision()
            && self.provenance == self.evidence.provenance
            && self.status == self.evidence.status
            && self.read_only
            && !self.native_provider
            && !self.connected
            && !self.outcome_authority
            && self.evidence.validate(request, provider_definition)
            && compute_proposal_digest(self) == self.proposal_digest
    }

    pub(crate) fn validate_for_consumer(
        &self,
        scope: &ClarityUxScope,
        provider_definition: &ClarityProviderDefinition,
    ) -> bool {
        let Ok(request) = ClarityDataExportGetRequest::new(scope, self.requested_at) else {
            return false;
        };
        self.contract_version == CLARITY_UX_RESULT_CONTRACT_VERSION
            && self.contract_digest == contract_digest()
            && self.version_digest == Digest::from_text(CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT)
            && self.service_version == CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT
            && self.provider_digest == provider_definition.provider_digest()
            && self.project_digest == scope.project_digest()
            && self.privacy_policy_digest == scope.privacy_policy().digest()
            && self.consent_scope_digest == scope.consent().digest()
            && self.scope_digest == scope.digest()
            && self.query_digest == *request.query_digest()
            && self.evidence_digest == self.evidence.response_digest
            && self.mission_revision == scope.mission().revision()
            && self.work_product_revision == scope.work_product().revision()
            && self.read_only
            && !self.native_provider
            && !self.connected
            && !self.outcome_authority
            && self.status == self.evidence.status
            && self.provenance == self.evidence.provenance
            && self.evidence.validate(&request, provider_definition)
            && compute_proposal_digest(self) == self.proposal_digest
    }

    pub fn receipt(&self) -> ClarityUxResultReceipt {
        let receipt_digest = Digest::from_fields(
            "clarity-result-receipt/v1",
            &[
                self.proposal_digest.as_str().to_owned(),
                self.evidence.response_digest.as_str().to_owned(),
                format!("{:?}", self.status),
            ],
        );
        ClarityUxResultReceipt {
            receipt_digest,
            proposal_digest: self.proposal_digest.clone(),
            evidence_digest: self.evidence.response_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            status: self.status,
            provenance: self.provenance,
            deterministic: true,
            read_only: true,
            native_provider: false,
            connected: false,
            durable_native_receipt: false,
            adopted_work_product: false,
            adopted_outcome: false,
            truth_authority: false,
        }
    }

    pub const fn status(&self) -> ResultStatus {
        self.status
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn evidence(&self) -> &ClarityProviderEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityUxResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub status: ResultStatus,
    pub provenance: ProviderProvenance,
    pub deterministic: bool,
    pub read_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub durable_native_receipt: bool,
    pub adopted_work_product: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

pub struct ClarityUxResultService<P> {
    service_definition: ClarityServiceDefinition,
    provider: P,
    scope: ClarityUxScope,
    secret: SecretReference,
    registration: ClarityRegistration,
}

impl<P> fmt::Debug for ClarityUxResultService<P>
where
    P: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClarityUxResultService")
            .field("service_definition", &self.service_definition)
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("secret", &"<opaque>")
            .field("registration", &self.registration)
            .finish()
    }
}

impl<P> ClarityUxResultService<P>
where
    P: ClarityProvider,
{
    pub fn new(
        scope: ClarityUxScope,
        secret: SecretReference,
        provider: P,
    ) -> Result<Self, ClarityUxResultServiceError> {
        scope
            .validate()
            .map_err(|error| ClarityUxResultServiceError::Model(error.to_string()))?;
        if secret.is_revoked() {
            return Err(ClarityUxResultServiceError::SecretRevoked);
        }
        if secret.scope_digest() != &scope.digest() {
            return Err(ClarityUxResultServiceError::RequestOutOfScope);
        }
        let service_definition = ClarityServiceDefinition::new();
        service_definition.validate()?;
        provider
            .definition()
            .validate()
            .map_err(|_| ClarityUxResultServiceError::DefinitionDrift)?;
        let registration =
            ClarityRegistration::new(&scope, provider.definition().provider_digest(), &secret)?;
        Ok(Self {
            service_definition,
            provider,
            scope,
            secret,
            registration,
        })
    }

    pub fn service_definition(&self) -> &ClarityServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &ClarityProviderDefinition {
        self.provider.definition()
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn scope(&self) -> &ClarityUxScope {
        &self.scope
    }

    pub fn registration(&self) -> &ClarityRegistration {
        &self.registration
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, ClarityUxResultServiceError> {
        self.registration
            .revoke()
            .map_err(|error| ClarityUxResultServiceError::Model(error.to_string()))
    }

    pub fn revoke_secret(&mut self) -> Result<(), ClarityUxResultServiceError> {
        self.secret
            .revoke()
            .map_err(|error| ClarityUxResultServiceError::Model(error.to_string()))
    }

    pub fn propose(
        &mut self,
        request: &ClarityUxResultRequest,
    ) -> Result<ClarityUxResultProposal, ClarityUxResultServiceError> {
        self.service_definition.validate()?;
        if !self.registration.is_active() {
            return Err(ClarityUxResultServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(ClarityUxResultServiceError::SecretRevoked);
        }
        self.registration
            .validate_against(
                &self.scope,
                &self.provider.definition().provider_digest(),
                &self.secret,
            )
            .map_err(|_| ClarityUxResultServiceError::DefinitionDrift)?;
        request
            .validate_against(&self.scope)
            .map_err(|_| ClarityUxResultServiceError::RequestOutOfScope)?;
        let get_request = ClarityDataExportGetRequest::new(&self.scope, request.requested_at)
            .map_err(|error| ClarityUxResultServiceError::Query(error.to_string()))?;
        let evidence = self.provider.get(&get_request, &self.secret)?;
        if !evidence.validate(&get_request, self.provider.definition()) {
            return Err(ClarityUxResultServiceError::InvalidEvidence);
        }
        let mut proposal = ClarityUxResultProposal {
            contract_version: CLARITY_UX_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            version_digest: Digest::from_text(CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT),
            service_version: CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            provider_digest: self.provider.definition().provider_digest(),
            project_digest: self.scope.project_digest(),
            privacy_policy_digest: self.scope.privacy_policy().digest(),
            consent_scope_digest: self.scope.consent().digest(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            query_digest: get_request.query_digest().clone(),
            evidence_digest: evidence.response_digest.clone(),
            requested_at: request.requested_at,
            mission_revision: self.scope.mission().revision(),
            work_product_revision: self.scope.work_product().revision(),
            provenance: evidence.provenance,
            status: evidence.status,
            evidence,
            read_only: true,
            native_provider: false,
            connected: false,
            outcome_authority: false,
            proposal_digest: Digest::from_text("clarity-proposal-placeholder"),
        };
        proposal.proposal_digest = compute_proposal_digest(&proposal);
        Ok(proposal)
    }

    pub fn propose_at(
        &mut self,
        requested_at: crate::model::Timestamp,
    ) -> Result<ClarityUxResultProposal, ClarityUxResultServiceError> {
        let request = ClarityUxResultRequest::new(&self.scope, requested_at);
        self.propose(&request)
    }
}

fn compute_proposal_digest(proposal: &ClarityUxResultProposal) -> Digest {
    let evidence_payload =
        serde_json::to_string(&proposal.evidence).expect("typed Clarity evidence is serializable");
    let safe_payload = serde_json::to_string(&vec![
        proposal.contract_version.clone(),
        proposal.contract_digest.as_str().to_owned(),
        proposal.version_digest.as_str().to_owned(),
        proposal.service_version.clone(),
        proposal.provider_digest.as_str().to_owned(),
        proposal.project_digest.as_str().to_owned(),
        proposal.privacy_policy_digest.as_str().to_owned(),
        proposal.consent_scope_digest.as_str().to_owned(),
        proposal.registration_digest.as_str().to_owned(),
        proposal.scope_digest.as_str().to_owned(),
        proposal.query_digest.as_str().to_owned(),
        proposal.evidence_digest.as_str().to_owned(),
        proposal.requested_at.seconds().to_string(),
        proposal.mission_revision.get().to_string(),
        proposal.work_product_revision.get().to_string(),
        format!("{:?}", proposal.provenance),
        format!("{:?}", proposal.status),
        evidence_payload,
        proposal.read_only.to_string(),
        proposal.native_provider.to_string(),
        proposal.connected.to_string(),
        proposal.outcome_authority.to_string(),
    ])
    .expect("typed Clarity proposal is serializable");
    Digest::from_fields("clarity-proposal/v1", &[safe_payload])
}

#[cfg(test)]
mod service_unit_tests {
    use super::ClarityServiceDefinition;

    #[test]
    fn service_definition_is_read_only_and_non_native() {
        let definition = ClarityServiceDefinition::new();
        definition.validate().expect("definition is valid");
        assert!(definition.read_only);
        assert!(!definition.native_connected);
    }
}

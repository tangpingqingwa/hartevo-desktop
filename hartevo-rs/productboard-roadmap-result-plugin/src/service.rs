use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, EvidenceClassification, IdempotencyKey, ModelError, ProductboardEvidenceState,
    ProductboardProviderError, ProductboardProviderRead, ProductboardRateLimitReceipt,
    ProductboardRegistration, ProductboardRoadmapAggregate, ProductboardRoadmapProvider,
    ProductboardRoadmapRequest, ProductboardRoadmapScope, ProductboardTransport,
    ProductboardTransportProvenance, RedactionSummary, RegistrationRevocationReceipt,
    RegistrationState, Revision, SecretReference, canonical_digest, validate_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProductboardRoadmapResultServiceError {
    #[error("Productboard registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Productboard Public API token reference is revoked")]
    SecretRevoked,
    #[error("Productboard request is outside the exact Project/Mission/Work Product scope")]
    ScopeMismatch,
    #[error("Productboard scope or provider revision fence failed")]
    RevisionMismatch,
    #[error("Productboard evidence or proposal digest fence failed")]
    EvidenceTampered,
    #[error("Productboard proposal replay was rejected")]
    ReplayDetected,
    #[error("Productboard idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("Productboard provider definition drifted")]
    DefinitionDrift,
    #[error("Productboard proposal is invalid for Mission consumption")]
    InvalidProposal,
    #[error("Layer-1 Productboard operation is read-only: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error(transparent)]
    Provider(Box<ProductboardProviderError>),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub outcome_authority: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
}

impl Default for ProductboardRoadmapResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::PRODUCTBOARD_ROADMAP_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::PRODUCTBOARD_ROADMAP_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_PRODUCTBOARD_ROADMAP_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            native_provider: false,
            connected: false,
            first_party: false,
            external_writes: false,
            outcome_authority: false,
            durable_provider_receipt: false,
            kernel_authority: false,
        }
    }
}

impl ProductboardRoadmapResultServiceDefinition {
    pub fn validate(&self) -> Result<(), ProductboardRoadmapResultServiceError> {
        if self != &Self::default()
            || !self.read_only
            || !self.proposal_only
            || self.live_execution
            || self.native_provider
            || self.connected
            || self.first_party
            || self.external_writes
            || self.outcome_authority
            || self.durable_provider_receipt
            || self.kernel_authority
        {
            Err(ProductboardRoadmapResultServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_version: String,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub registration_evidence_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub cursor_binding_digest: Digest,
    pub response_digest: Option<Digest>,
    pub response_bytes: usize,
    pub status: Option<u16>,
    pub source_revision: Revision,
    pub state: ProductboardEvidenceState,
    pub aggregate: Option<ProductboardRoadmapAggregate>,
    pub redactions: RedactionSummary,
    pub rate_limit: ProductboardRateLimitReceipt,
    pub provenance: ProductboardTransportProvenance,
    pub classification: EvidenceClassification,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
    pub evidence_digest: Digest,
}

impl ProductboardRoadmapEvidence {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    #[must_use]
    pub fn aggregate(&self) -> Option<&ProductboardRoadmapAggregate> {
        self.aggregate.as_ref()
    }

    pub fn validate(
        &self,
        scope: &ProductboardRoadmapScope,
        registration: &ProductboardRegistration,
        provider_digest: &Digest,
    ) -> Result<(), ProductboardRoadmapResultServiceError> {
        scope.validate()?;
        if self.contract_version != crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::PRODUCTBOARD_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.registration_digest != registration.registration_digest
            || self.registration_evidence_digest != registration.evidence_digest
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || validate_digest(&self.cursor_binding_digest).is_err()
            || self.source_revision != scope.scope_revision()
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.rate_limit.validate().is_err()
            || !self.redactions.is_complete()
            || !self.read_only
            || !self.proposal_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.durable_provider_receipt
            || self.kernel_authority
            || self.evidence_digest != self.compute_digest()
        {
            return Err(ProductboardRoadmapResultServiceError::EvidenceTampered);
        }
        if !self.state_shape_is_valid() || !self.cursor_shape_is_valid() {
            return Err(ProductboardRoadmapResultServiceError::EvidenceTampered);
        }
        if let Some(aggregate) = &self.aggregate {
            if aggregate.operation.target_kind().is_some() && aggregate.target_id_digest.is_none() {
                return Err(ProductboardRoadmapResultServiceError::EvidenceTampered);
            }
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &ProductboardRoadmapScope,
        registration_digest: &Digest,
        registration_evidence_digest: &Digest,
        provider_digest: &Digest,
    ) -> Result<(), ProductboardRoadmapResultServiceError> {
        scope.validate()?;
        if self.contract_version != crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::PRODUCTBOARD_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || &self.registration_digest != registration_digest
            || &self.registration_evidence_digest != registration_evidence_digest
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || validate_digest(&self.cursor_binding_digest).is_err()
            || self.source_revision != scope.scope_revision()
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.rate_limit.validate().is_err()
            || !self.redactions.is_complete()
            || !self.read_only
            || !self.proposal_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.durable_provider_receipt
            || self.kernel_authority
            || self.evidence_digest != self.compute_digest()
            || !self.state_shape_is_valid()
            || !self.cursor_shape_is_valid()
        {
            return Err(ProductboardRoadmapResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    fn state_shape_is_valid(&self) -> bool {
        match self.state {
            ProductboardEvidenceState::Present | ProductboardEvidenceState::Complete => self
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| aggregate.item_count > 0 && !aggregate.partial),
            ProductboardEvidenceState::Archived => self
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| aggregate.item_count > 0 && aggregate.archived),
            ProductboardEvidenceState::Empty => self
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| aggregate.item_count == 0),
            ProductboardEvidenceState::Partial => {
                self.aggregate.is_none()
                    || self
                        .aggregate
                        .as_ref()
                        .is_some_and(|aggregate| aggregate.partial)
            }
            ProductboardEvidenceState::AccessLoss
            | ProductboardEvidenceState::ProviderUnknown
            | ProductboardEvidenceState::Tamper
            | ProductboardEvidenceState::Stale
            | ProductboardEvidenceState::Revoked
            | ProductboardEvidenceState::RateLimited
            | ProductboardEvidenceState::Timeout
            | ProductboardEvidenceState::BlockedEnv => self.aggregate.is_none(),
        }
    }

    fn cursor_shape_is_valid(&self) -> bool {
        let Some(aggregate) = self.aggregate.as_ref() else {
            return true;
        };
        match (
            aggregate.next_page_token_digest.is_some(),
            aggregate.cursor_binding_digest.as_ref(),
        ) {
            (false, None) => true,
            (true, Some(binding)) => binding == &self.cursor_binding_digest,
            _ => false,
        }
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.evidence_digest.clear();
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_version: String,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub evidence_digest: Digest,
    pub state: ProductboardEvidenceState,
    pub evidence: ProductboardRoadmapEvidence,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
    pub replayed: bool,
}

impl ProductboardRoadmapResultProposal {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn evidence(&self) -> &ProductboardRoadmapEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn state(&self) -> ProductboardEvidenceState {
        self.state
    }

    pub fn validate(
        &self,
        scope: &ProductboardRoadmapScope,
        registration: &ProductboardRegistration,
        provider_digest: &Digest,
    ) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.evidence
            .validate(scope, registration, provider_digest)?;
        if self.contract_version != crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::PRODUCTBOARD_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.request_digest != self.evidence.request_digest
            || self.idempotency_key_digest != self.evidence.idempotency_key_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.state != self.evidence.state
            || !self.read_only
            || !self.proposal_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.outcome_authority
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(ProductboardRoadmapResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &ProductboardRoadmapScope,
        registration_digest: &Digest,
        registration_evidence_digest: &Digest,
        provider_digest: &Digest,
    ) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.evidence.validate_for_consumer(
            scope,
            registration_digest,
            registration_evidence_digest,
            provider_digest,
        )?;
        if self.contract_version != crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::PRODUCTBOARD_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || &self.registration_digest != registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.request_digest != self.evidence.request_digest
            || self.idempotency_key_digest != self.evidence.idempotency_key_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.state != self.evidence.state
            || !self.read_only
            || !self.proposal_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.outcome_authority
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(ProductboardRoadmapResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        copy.replayed = false;
        canonical_digest(&copy)
    }

    #[must_use]
    pub fn receipt(&self) -> ProductboardRoadmapResultReceipt {
        ProductboardRoadmapResultReceipt::from_proposal(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardRoadmapResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: ProductboardEvidenceState,
    pub provenance: ProductboardTransportProvenance,
    pub durable: bool,
    pub provider_receipt: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
}

impl ProductboardRoadmapResultReceipt {
    fn from_proposal(proposal: &ProductboardRoadmapResultProposal) -> Self {
        let receipt_digest = canonical_digest(&(
            "productboard-result-receipt/v1",
            &proposal.proposal_digest,
            &proposal.evidence.evidence_digest,
            proposal.state,
        ));
        Self {
            receipt_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            provenance: proposal.evidence.provenance,
            durable: false,
            provider_receipt: false,
            read_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            outcome_authority: false,
        }
    }
}

/// Layer-1 typed service for bounded, redacted Productboard evidence.
pub struct ProductboardRoadmapResultService<T: ProductboardTransport> {
    provider: ProductboardRoadmapProvider<T>,
    definition: ProductboardRoadmapResultServiceDefinition,
    idempotency: BTreeMap<Digest, (Digest, ProductboardRoadmapResultProposal)>,
}

impl<T: ProductboardTransport> fmt::Debug for ProductboardRoadmapResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductboardRoadmapResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("idempotency_records", &self.idempotency.len())
            .finish()
    }
}

impl<T: ProductboardTransport> ProductboardRoadmapResultService<T> {
    pub fn new(
        provider: ProductboardRoadmapProvider<T>,
    ) -> Result<Self, ProductboardRoadmapResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| ProductboardRoadmapResultServiceError::RegistrationRevoked)?;
        let definition = ProductboardRoadmapResultServiceDefinition::default();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
            idempotency: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: ProductboardRoadmapProvider<T>) -> Self {
        Self {
            provider,
            definition: ProductboardRoadmapResultServiceDefinition::default(),
            idempotency: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &ProductboardRoadmapProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut ProductboardRoadmapProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &ProductboardRoadmapScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &ProductboardRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &ProductboardRoadmapResultServiceDefinition {
        &self.definition
    }

    pub fn read(
        &mut self,
    ) -> Result<ProductboardRoadmapEvidence, ProductboardRoadmapResultServiceError> {
        let key = IdempotencyKey::new("productboard-default-read")?;
        let request = ProductboardRoadmapRequest::roadmap(self.scope(), &key)?;
        self.read_request(&request)
    }

    pub fn read_projection(
        &mut self,
        request: &ProductboardRoadmapRequest,
    ) -> ProductboardRoadmapEvidence {
        match self.read_request(request) {
            Ok(evidence) => evidence,
            Err(error) => self.local_error_projection(request, error),
        }
    }

    pub fn read_request(
        &mut self,
        request: &ProductboardRoadmapRequest,
    ) -> Result<ProductboardRoadmapEvidence, ProductboardRoadmapResultServiceError> {
        request
            .validate(self.scope())
            .map_err(|_| ProductboardRoadmapResultServiceError::ScopeMismatch)?;
        self.ensure_available()?;
        match self.provider.read_request(request) {
            Ok(read) => {
                let state = if read.rate_limit.exhausted {
                    ProductboardEvidenceState::RateLimited
                } else if read.status == 206 || read.aggregate.partial {
                    ProductboardEvidenceState::Partial
                } else if read.aggregate.item_count == 0 {
                    ProductboardEvidenceState::Empty
                } else if read.aggregate.archived {
                    ProductboardEvidenceState::Archived
                } else {
                    ProductboardEvidenceState::Present
                };
                Ok(self.evidence_from_read(request, read, state))
            }
            Err(error) => self.evidence_from_provider_error(request, error),
        }
    }

    pub fn propose(
        &mut self,
        request: &ProductboardRoadmapRequest,
    ) -> Result<ProductboardRoadmapResultProposal, ProductboardRoadmapResultServiceError> {
        request
            .validate(self.scope())
            .map_err(|_| ProductboardRoadmapResultServiceError::ScopeMismatch)?;
        self.ensure_available()?;
        let idempotency_key = request.idempotency_key_digest().clone();
        let request_digest = request.request_digest();
        if let Some((previous_request, proposal)) = self.idempotency.get(&idempotency_key) {
            if previous_request != &request_digest {
                return Err(ProductboardRoadmapResultServiceError::IdempotencyConflict);
            }
            let mut replay = proposal.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let evidence = self.read_request(request)?;
        let mut proposal = ProductboardRoadmapResultProposal {
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            request_digest,
            idempotency_key_digest: idempotency_key,
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.state,
            evidence,
            read_only: true,
            proposal_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            outcome_authority: false,
            work_product_adopted: false,
            proposal_digest: String::new(),
            replayed: false,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal.validate(
            self.scope(),
            self.registration(),
            &self.provider.provider_digest(),
        )?;
        self.idempotency.insert(
            proposal.idempotency_key_digest.clone(),
            (proposal.request_digest.clone(), proposal.clone()),
        );
        Ok(proposal)
    }

    pub fn compile_proposal(
        &mut self,
        request: &ProductboardRoadmapRequest,
    ) -> Result<ProductboardRoadmapResultProposal, ProductboardRoadmapResultServiceError> {
        self.propose(request)
    }

    pub fn compile_proposal_for(
        &mut self,
        request: &ProductboardRoadmapRequest,
    ) -> Result<ProductboardRoadmapResultProposal, ProductboardRoadmapResultServiceError> {
        self.propose(request)
    }

    pub fn verify_proposal(
        &self,
        proposal: &ProductboardRoadmapResultProposal,
    ) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.ensure_available()?;
        proposal.validate(
            self.scope(),
            self.registration(),
            &self.provider.provider_digest(),
        )
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, ProductboardRoadmapResultServiceError> {
        self.provider
            .revoke()
            .map_err(ProductboardRoadmapResultServiceError::from)
    }

    pub fn restore(&mut self) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.provider
            .restore()
            .map_err(ProductboardRoadmapResultServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.provider
            .revoke_secret()
            .map_err(ProductboardRoadmapResultServiceError::from)
    }

    pub fn restore_secret(&mut self) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.provider
            .restore_secret()
            .map_err(ProductboardRoadmapResultServiceError::from)
    }

    fn ensure_available(&self) -> Result<(), ProductboardRoadmapResultServiceError> {
        self.definition.validate()?;
        if self.registration().state != RegistrationState::Active {
            return Err(ProductboardRoadmapResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(ProductboardRoadmapResultServiceError::SecretRevoked);
        }
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| ProductboardRoadmapResultServiceError::RegistrationRevoked)
    }

    fn evidence_from_read(
        &self,
        request: &ProductboardRoadmapRequest,
        read: ProductboardProviderRead,
        state: ProductboardEvidenceState,
    ) -> ProductboardRoadmapEvidence {
        let classification = match state {
            ProductboardEvidenceState::Present | ProductboardEvidenceState::Complete => {
                read.provenance.into()
            }
            ProductboardEvidenceState::Archived => EvidenceClassification::Archived,
            ProductboardEvidenceState::Empty => EvidenceClassification::Empty,
            ProductboardEvidenceState::Partial => EvidenceClassification::Partial,
            ProductboardEvidenceState::AccessLoss => EvidenceClassification::AccessLoss,
            ProductboardEvidenceState::ProviderUnknown => EvidenceClassification::ProviderUnknown,
            ProductboardEvidenceState::Tamper => EvidenceClassification::Tamper,
            ProductboardEvidenceState::Stale => EvidenceClassification::Stale,
            ProductboardEvidenceState::Revoked => EvidenceClassification::Revoked,
            ProductboardEvidenceState::RateLimited => EvidenceClassification::RateLimited,
            ProductboardEvidenceState::Timeout => EvidenceClassification::Timeout,
            ProductboardEvidenceState::BlockedEnv => EvidenceClassification::BlockedEnv,
        };
        let mut evidence = ProductboardRoadmapEvidence {
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            registration_evidence_digest: self.registration().evidence_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            cursor_binding_digest: request.cursor_binding_digest(),
            response_digest: Some(read.response_digest),
            response_bytes: read.response_bytes,
            status: Some(read.status),
            source_revision: self.scope().scope_revision(),
            state,
            aggregate: Some(read.aggregate),
            redactions: RedactionSummary::layer1(),
            rate_limit: read.rate_limit,
            provenance: read.provenance,
            classification,
            read_only: true,
            proposal_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            durable_provider_receipt: false,
            kernel_authority: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn evidence_from_provider_error(
        &self,
        request: &ProductboardRoadmapRequest,
        error: ProductboardProviderError,
    ) -> Result<ProductboardRoadmapEvidence, ProductboardRoadmapResultServiceError> {
        let state = match error {
            ProductboardProviderError::RateLimited { .. } => ProductboardEvidenceState::RateLimited,
            ProductboardProviderError::Timeout { .. } => ProductboardEvidenceState::Timeout,
            ProductboardProviderError::AccessLoss { .. } => ProductboardEvidenceState::AccessLoss,
            ProductboardProviderError::ProviderUnknown { .. } => {
                ProductboardEvidenceState::ProviderUnknown
            }
            ProductboardProviderError::BlockedEnv { .. } => ProductboardEvidenceState::BlockedEnv,
            ProductboardProviderError::Partial { .. } => ProductboardEvidenceState::Partial,
            ProductboardProviderError::ResponseTampered { .. }
            | ProductboardProviderError::ResponseTooLarge { .. }
            | ProductboardProviderError::ScopeMismatch
            | ProductboardProviderError::RequestInvalid => ProductboardEvidenceState::Tamper,
            ProductboardProviderError::RevisionMismatch => ProductboardEvidenceState::Stale,
            ProductboardProviderError::RegistrationRevoked => {
                return Err(ProductboardRoadmapResultServiceError::RegistrationRevoked);
            }
            ProductboardProviderError::SecretRevoked => {
                return Err(ProductboardRoadmapResultServiceError::SecretRevoked);
            }
            ProductboardProviderError::Model(error) => return Err(error.into()),
        };
        let (response_digest, response_bytes, rate_limit, status) = error.metadata().map_or(
            (None, 0, ProductboardRateLimitReceipt::default(), None),
            |metadata| (Some(metadata.0), metadata.1, metadata.2, metadata.3),
        );
        let provenance = self.provider.transport_provenance();
        let classification = match state {
            ProductboardEvidenceState::Partial => EvidenceClassification::Partial,
            ProductboardEvidenceState::RateLimited => EvidenceClassification::RateLimited,
            ProductboardEvidenceState::Timeout => EvidenceClassification::Timeout,
            ProductboardEvidenceState::AccessLoss => EvidenceClassification::AccessLoss,
            ProductboardEvidenceState::ProviderUnknown => EvidenceClassification::ProviderUnknown,
            ProductboardEvidenceState::BlockedEnv => EvidenceClassification::BlockedEnv,
            ProductboardEvidenceState::Tamper => EvidenceClassification::Tamper,
            ProductboardEvidenceState::Stale => EvidenceClassification::Stale,
            ProductboardEvidenceState::Revoked => EvidenceClassification::Revoked,
            ProductboardEvidenceState::Present | ProductboardEvidenceState::Complete => {
                provenance.into()
            }
            ProductboardEvidenceState::Empty => EvidenceClassification::Empty,
            ProductboardEvidenceState::Archived => EvidenceClassification::Archived,
        };
        let mut evidence = ProductboardRoadmapEvidence {
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            registration_evidence_digest: self.registration().evidence_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            cursor_binding_digest: request.cursor_binding_digest(),
            response_digest,
            response_bytes,
            status,
            source_revision: self.scope().scope_revision(),
            state,
            aggregate: None,
            redactions: RedactionSummary::layer1(),
            rate_limit,
            provenance,
            classification,
            read_only: true,
            proposal_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            durable_provider_receipt: false,
            kernel_authority: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    fn local_error_projection(
        &self,
        request: &ProductboardRoadmapRequest,
        error: ProductboardRoadmapResultServiceError,
    ) -> ProductboardRoadmapEvidence {
        let state = match error {
            ProductboardRoadmapResultServiceError::RegistrationRevoked
            | ProductboardRoadmapResultServiceError::SecretRevoked => {
                ProductboardEvidenceState::Revoked
            }
            ProductboardRoadmapResultServiceError::RevisionMismatch => {
                ProductboardEvidenceState::Stale
            }
            ProductboardRoadmapResultServiceError::EvidenceTampered => {
                ProductboardEvidenceState::Tamper
            }
            _ => ProductboardEvidenceState::Tamper,
        };
        let classification = match state {
            ProductboardEvidenceState::Revoked => EvidenceClassification::Revoked,
            ProductboardEvidenceState::Stale => EvidenceClassification::Stale,
            _ => EvidenceClassification::Tamper,
        };
        let mut evidence = ProductboardRoadmapEvidence {
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            registration_evidence_digest: self.registration().evidence_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            cursor_binding_digest: request.cursor_binding_digest(),
            response_digest: None,
            response_bytes: 0,
            status: None,
            source_revision: self.scope().scope_revision(),
            state,
            aggregate: None,
            redactions: RedactionSummary::layer1(),
            rate_limit: ProductboardRateLimitReceipt::default(),
            provenance: self.provider.transport_provenance(),
            classification,
            read_only: true,
            proposal_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            durable_provider_receipt: false,
            kernel_authority: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }
}

impl From<ProductboardProviderError> for ProductboardRoadmapResultServiceError {
    fn from(error: ProductboardProviderError) -> Self {
        Self::Provider(Box::new(error))
    }
}

pub const fn mutation_forbidden(operation: &'static str) -> ProductboardRoadmapResultServiceError {
    ProductboardRoadmapResultServiceError::MutationForbidden { operation }
}

pub type ProductboardRoadmapResult = ProductboardRoadmapResultProposal;
pub type ProductboardRoadmapProviderRegistration = ProductboardRegistration;
pub type ProductboardRoadmapSecretReference = SecretReference;

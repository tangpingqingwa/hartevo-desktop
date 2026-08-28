use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AhaEvidenceState, AhaProviderError, AhaProviderRead, AhaRateLimitReceipt, AhaRegistration,
    AhaRoadmapAggregate, AhaRoadmapOperation, AhaRoadmapProvider, AhaRoadmapRequest,
    AhaRoadmapScope, AhaTransport, AhaTransportProvenance, Digest, EvidenceClassification,
    IdempotencyKey, ModelError, RedactionSummary, RegistrationRevocationReceipt, RegistrationState,
    Revision, SecretReference, canonical_digest, validate_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AhaRoadmapResultServiceError {
    #[error("Aha registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Aha API-token reference is revoked")]
    SecretRevoked,
    #[error("Aha request is outside the exact Project/Mission/Work Product scope")]
    ScopeMismatch,
    #[error("Aha scope or provider revision fence failed")]
    RevisionMismatch,
    #[error("Aha evidence or proposal digest fence failed")]
    EvidenceTampered,
    #[error("Aha proposal replay was rejected")]
    ReplayDetected,
    #[error("Aha idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("Aha provider definition drifted")]
    DefinitionDrift,
    #[error("Aha proposal is invalid for Mission consumption")]
    InvalidProposal,
    #[error("Layer-1 Aha operation is read-only: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error(transparent)]
    Provider(Box<AhaProviderError>),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapResultServiceDefinition {
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

impl Default for AhaRoadmapResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::AHA_ROADMAP_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::AHA_ROADMAP_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::AHA_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_AHA_ROADMAP_CONSUMER_ID.to_owned(),
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

impl AhaRoadmapResultServiceDefinition {
    pub fn validate(&self) -> Result<(), AhaRoadmapResultServiceError> {
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
            Err(AhaRoadmapResultServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapEvidence {
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
    pub state: AhaEvidenceState,
    pub aggregate: Option<AhaRoadmapAggregate>,
    pub redactions: RedactionSummary,
    pub rate_limit: AhaRateLimitReceipt,
    pub provenance: AhaTransportProvenance,
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

impl AhaRoadmapEvidence {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    #[must_use]
    pub fn aggregate(&self) -> Option<&AhaRoadmapAggregate> {
        self.aggregate.as_ref()
    }

    pub fn validate(
        &self,
        scope: &AhaRoadmapScope,
        registration: &AhaRegistration,
        provider_digest: &Digest,
    ) -> Result<(), AhaRoadmapResultServiceError> {
        scope.validate()?;
        if self.contract_version != crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::AHA_PROVIDER_ID
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
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
        }
        if !self.state_shape_is_valid() || !self.cursor_shape_is_valid() {
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
        }
        if let Some(aggregate) = &self.aggregate {
            if aggregate.operation != AhaRoadmapOperation::RoadmapAggregate
                && aggregate.target_id_digest.is_none()
            {
                return Err(AhaRoadmapResultServiceError::EvidenceTampered);
            }
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &AhaRoadmapScope,
        registration_digest: &Digest,
        registration_evidence_digest: &Digest,
        provider_digest: &Digest,
    ) -> Result<(), AhaRoadmapResultServiceError> {
        scope.validate()?;
        if self.contract_version != crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::AHA_PROVIDER_ID
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
        {
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
        }
        if !self.state_shape_is_valid() {
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
        }
        if !self.cursor_shape_is_valid() {
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    fn state_shape_is_valid(&self) -> bool {
        match self.state {
            AhaEvidenceState::Complete => self
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| aggregate.item_count > 0 && !aggregate.partial),
            AhaEvidenceState::Empty => self
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| aggregate.item_count == 0),
            AhaEvidenceState::Partial => {
                self.aggregate.is_none()
                    || self
                        .aggregate
                        .as_ref()
                        .is_some_and(|aggregate| aggregate.partial)
            }
            AhaEvidenceState::RateLimited
            | AhaEvidenceState::Timeout
            | AhaEvidenceState::ProviderUnknown
            | AhaEvidenceState::BlockedEnv => self.aggregate.is_none(),
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
pub struct AhaRoadmapResultProposal {
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
    pub state: AhaEvidenceState,
    pub evidence: AhaRoadmapEvidence,
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

impl AhaRoadmapResultProposal {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn evidence(&self) -> &AhaRoadmapEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn state(&self) -> AhaEvidenceState {
        self.state
    }

    pub fn validate(
        &self,
        scope: &AhaRoadmapScope,
        registration: &AhaRegistration,
        provider_digest: &Digest,
    ) -> Result<(), AhaRoadmapResultServiceError> {
        self.evidence
            .validate(scope, registration, provider_digest)?;
        if self.contract_version != crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::AHA_PROVIDER_ID
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
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &AhaRoadmapScope,
        registration_digest: &Digest,
        registration_evidence_digest: &Digest,
        provider_digest: &Digest,
    ) -> Result<(), AhaRoadmapResultServiceError> {
        self.evidence.validate_for_consumer(
            scope,
            registration_digest,
            registration_evidence_digest,
            provider_digest,
        )?;
        if self.contract_version != crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::AHA_PROVIDER_ID
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
            return Err(AhaRoadmapResultServiceError::EvidenceTampered);
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
    pub fn receipt(&self) -> AhaRoadmapResultReceipt {
        AhaRoadmapResultReceipt::from_proposal(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaRoadmapResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: AhaEvidenceState,
    pub provenance: AhaTransportProvenance,
    pub durable: bool,
    pub provider_receipt: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
}

impl AhaRoadmapResultReceipt {
    fn from_proposal(proposal: &AhaRoadmapResultProposal) -> Self {
        let receipt_digest = canonical_digest(&(
            "aha-result-receipt/v1",
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

/// Layer-1 typed service for bounded, redacted Aha! Roadmaps evidence.
pub struct AhaRoadmapResultService<T: AhaTransport> {
    provider: AhaRoadmapProvider<T>,
    definition: AhaRoadmapResultServiceDefinition,
    idempotency: BTreeMap<Digest, (Digest, AhaRoadmapResultProposal)>,
}

impl<T: AhaTransport> fmt::Debug for AhaRoadmapResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AhaRoadmapResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("idempotency_records", &self.idempotency.len())
            .finish()
    }
}

impl<T: AhaTransport> AhaRoadmapResultService<T> {
    pub fn new(provider: AhaRoadmapProvider<T>) -> Result<Self, AhaRoadmapResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| AhaRoadmapResultServiceError::RegistrationRevoked)?;
        let definition = AhaRoadmapResultServiceDefinition::default();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
            idempotency: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: AhaRoadmapProvider<T>) -> Self {
        Self {
            provider,
            definition: AhaRoadmapResultServiceDefinition::default(),
            idempotency: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &AhaRoadmapProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AhaRoadmapProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AhaRoadmapScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AhaRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &AhaRoadmapResultServiceDefinition {
        &self.definition
    }

    pub fn read(&mut self) -> Result<AhaRoadmapEvidence, AhaRoadmapResultServiceError> {
        let key = IdempotencyKey::new("aha-default-read")?;
        let request = AhaRoadmapRequest::roadmap(self.scope(), &key)?;
        self.read_request(&request)
    }

    pub fn read_request(
        &mut self,
        request: &AhaRoadmapRequest,
    ) -> Result<AhaRoadmapEvidence, AhaRoadmapResultServiceError> {
        request
            .validate(self.scope())
            .map_err(|_| AhaRoadmapResultServiceError::ScopeMismatch)?;
        self.ensure_available()?;
        match self.provider.read_request(request) {
            Ok(read) => {
                let state = if read.rate_limit.exhausted {
                    AhaEvidenceState::RateLimited
                } else if read.status == 206 || read.aggregate.partial {
                    AhaEvidenceState::Partial
                } else if read.aggregate.item_count == 0 {
                    AhaEvidenceState::Empty
                } else {
                    AhaEvidenceState::Complete
                };
                Ok(self.evidence_from_read(request, read, state))
            }
            Err(error) => self.evidence_from_provider_error(request, error),
        }
    }

    pub fn propose(
        &mut self,
        request: &AhaRoadmapRequest,
    ) -> Result<AhaRoadmapResultProposal, AhaRoadmapResultServiceError> {
        request
            .validate(self.scope())
            .map_err(|_| AhaRoadmapResultServiceError::ScopeMismatch)?;
        self.ensure_available()?;
        let idempotency_key = request.idempotency_key_digest().clone();
        let request_digest = request.request_digest();
        if let Some((previous_request, proposal)) = self.idempotency.get(&idempotency_key) {
            if previous_request != &request_digest {
                return Err(AhaRoadmapResultServiceError::IdempotencyConflict);
            }
            let mut replay = proposal.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let evidence = self.read_request(request)?;
        let mut proposal = AhaRoadmapResultProposal {
            contract_version: crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::AHA_PROVIDER_ID.to_owned(),
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
        request: &AhaRoadmapRequest,
    ) -> Result<AhaRoadmapResultProposal, AhaRoadmapResultServiceError> {
        self.propose(request)
    }

    pub fn compile_proposal_for(
        &mut self,
        request: &AhaRoadmapRequest,
    ) -> Result<AhaRoadmapResultProposal, AhaRoadmapResultServiceError> {
        self.propose(request)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AhaRoadmapResultProposal,
    ) -> Result<(), AhaRoadmapResultServiceError> {
        self.ensure_available()?;
        proposal.validate(
            self.scope(),
            self.registration(),
            &self.provider.provider_digest(),
        )
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, AhaRoadmapResultServiceError> {
        self.provider
            .revoke()
            .map_err(AhaRoadmapResultServiceError::from)
    }

    pub fn restore(&mut self) -> Result<(), AhaRoadmapResultServiceError> {
        self.provider
            .restore()
            .map_err(AhaRoadmapResultServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AhaRoadmapResultServiceError> {
        self.provider
            .revoke_secret()
            .map_err(AhaRoadmapResultServiceError::from)
    }

    pub fn restore_secret(&mut self) -> Result<(), AhaRoadmapResultServiceError> {
        self.provider
            .restore_secret()
            .map_err(AhaRoadmapResultServiceError::from)
    }

    fn ensure_available(&self) -> Result<(), AhaRoadmapResultServiceError> {
        self.definition.validate()?;
        if self.registration().state != RegistrationState::Active {
            return Err(AhaRoadmapResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(AhaRoadmapResultServiceError::SecretRevoked);
        }
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| AhaRoadmapResultServiceError::RegistrationRevoked)
    }

    fn evidence_from_read(
        &self,
        request: &AhaRoadmapRequest,
        read: AhaProviderRead,
        state: AhaEvidenceState,
    ) -> AhaRoadmapEvidence {
        let classification = match state {
            AhaEvidenceState::Complete => read.provenance.into(),
            AhaEvidenceState::Empty => EvidenceClassification::Empty,
            AhaEvidenceState::Partial => EvidenceClassification::Partial,
            AhaEvidenceState::RateLimited => EvidenceClassification::RateLimited,
            AhaEvidenceState::Timeout => EvidenceClassification::Timeout,
            AhaEvidenceState::ProviderUnknown => EvidenceClassification::ProviderUnknown,
            AhaEvidenceState::BlockedEnv => EvidenceClassification::BlockedEnv,
        };
        let mut evidence = AhaRoadmapEvidence {
            contract_version: crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::AHA_PROVIDER_ID.to_owned(),
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
            aggregate: (state != AhaEvidenceState::RateLimited).then_some(read.aggregate),
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
        request: &AhaRoadmapRequest,
        error: AhaProviderError,
    ) -> Result<AhaRoadmapEvidence, AhaRoadmapResultServiceError> {
        let state = match error {
            AhaProviderError::RateLimited { .. } => AhaEvidenceState::RateLimited,
            AhaProviderError::Timeout { .. } => AhaEvidenceState::Timeout,
            AhaProviderError::ProviderUnknown { .. } => AhaEvidenceState::ProviderUnknown,
            AhaProviderError::BlockedEnv { .. } => AhaEvidenceState::BlockedEnv,
            AhaProviderError::Partial { .. } => AhaEvidenceState::Partial,
            AhaProviderError::RegistrationRevoked => {
                return Err(AhaRoadmapResultServiceError::RegistrationRevoked);
            }
            AhaProviderError::SecretRevoked => {
                return Err(AhaRoadmapResultServiceError::SecretRevoked);
            }
            AhaProviderError::RequestInvalid => {
                return Err(AhaRoadmapResultServiceError::ScopeMismatch);
            }
            AhaProviderError::ScopeMismatch
            | AhaProviderError::ResponseTampered { .. }
            | AhaProviderError::ResponseTooLarge { .. } => {
                return Err(AhaRoadmapResultServiceError::EvidenceTampered);
            }
            AhaProviderError::RevisionMismatch => {
                return Err(AhaRoadmapResultServiceError::RevisionMismatch);
            }
            AhaProviderError::Model(error) => return Err(error.into()),
        };
        let (response_digest, response_bytes, rate_limit, status) = error.metadata().map_or(
            (None, 0, AhaRateLimitReceipt::default(), None),
            |metadata| (Some(metadata.0), metadata.1, metadata.2, metadata.3),
        );
        let provenance = self.provider.transport_provenance();
        let classification = match state {
            AhaEvidenceState::Partial => EvidenceClassification::Partial,
            AhaEvidenceState::RateLimited => EvidenceClassification::RateLimited,
            AhaEvidenceState::Timeout => EvidenceClassification::Timeout,
            AhaEvidenceState::ProviderUnknown => EvidenceClassification::ProviderUnknown,
            AhaEvidenceState::BlockedEnv => EvidenceClassification::BlockedEnv,
            AhaEvidenceState::Complete => provenance.into(),
            AhaEvidenceState::Empty => EvidenceClassification::Empty,
        };
        let mut evidence = AhaRoadmapEvidence {
            contract_version: crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::AHA_ROADMAP_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: crate::AHA_PROVIDER_ID.to_owned(),
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
}

impl From<AhaProviderError> for AhaRoadmapResultServiceError {
    fn from(error: AhaProviderError) -> Self {
        Self::Provider(Box::new(error))
    }
}

pub const fn mutation_forbidden(operation: &'static str) -> AhaRoadmapResultServiceError {
    AhaRoadmapResultServiceError::MutationForbidden { operation }
}

pub type AhaRoadmapResult = AhaRoadmapResultProposal;
pub type AhaRoadmapProviderRegistration = AhaRegistration;
pub type AhaRoadmapSecretReference = SecretReference;

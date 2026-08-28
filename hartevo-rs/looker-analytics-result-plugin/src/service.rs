use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, EvidenceClassification, IdempotencyKey, LookerAnalyticsRequest, LookerAnalyticsScope,
    LookerEvidenceState, LookerMetadataAggregate, LookerProvider, LookerProviderError,
    LookerRateLimitReceipt, LookerRegistration, LookerTransport, LookerTransportError, ModelError,
    RedactionSummary, Revision, canonical_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LookerAnalyticsResultServiceError {
    #[error("Looker registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Looker client-secret reference is revoked")]
    SecretRevoked,
    #[error("Looker consent is denied or stale")]
    ConsentMismatch,
    #[error("Looker request is outside the exact Mission/Work Product scope")]
    ScopeMismatch,
    #[error("Looker scope or provider revision fence failed")]
    RevisionMismatch,
    #[error("Looker evidence or proposal digest fence failed")]
    EvidenceTampered,
    #[error("Looker proposal replay was rejected")]
    ReplayDetected,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("Looker provider definition drifted")]
    DefinitionDrift,
    #[error("Looker proposal is invalid for Mission consumption")]
    InvalidProposal,
    #[error("Layer-1 Looker operation is read-only: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error(transparent)]
    Provider(Box<LookerProviderError>),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub external_writes: bool,
}

impl Default for LookerAnalyticsResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::LOOKER_ANALYTICS_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::LOOKER_ANALYTICS_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::LOOKER_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_LOOKER_ANALYTICS_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            native_provider: false,
            connected: false,
            first_party: false,
            outcome_authority: false,
            external_writes: false,
        }
    }
}

impl LookerAnalyticsResultServiceDefinition {
    pub fn validate(&self) -> Result<(), LookerAnalyticsResultServiceError> {
        if self != &Self::default()
            || !self.read_only
            || self.live_execution
            || self.native_provider
            || self.connected
            || self.first_party
            || self.outcome_authority
            || self.external_writes
        {
            Err(LookerAnalyticsResultServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_version: String,
    pub provider_digest: Digest,
    pub provider_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub source_revision: Revision,
    pub state: LookerEvidenceState,
    pub aggregate: Option<LookerMetadataAggregate>,
    pub redactions: RedactionSummary,
    pub rate_limit: LookerRateLimitReceipt,
    pub provenance: crate::LookerTransportProvenance,
    pub classification: EvidenceClassification,
    pub read_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub causal_claim: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

impl LookerAnalyticsEvidence {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    #[must_use]
    pub fn aggregate(&self) -> Option<&LookerMetadataAggregate> {
        self.aggregate.as_ref()
    }

    pub fn validate(
        &self,
        scope: &LookerAnalyticsScope,
        registration: &LookerRegistration,
        provider_digest: &Digest,
    ) -> Result<(), LookerAnalyticsResultServiceError> {
        if self.contract_version != crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::LOOKER_PROVIDER_ID
            || self.provider_digest != *provider_digest
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.consent_digest != scope.consent_digest()
            || self.project_digest != scope.project_digest()
            || self.mission_digest != scope.mission_digest()
            || self.work_product_digest != scope.work_product_digest()
            || !self.redactions.is_complete()
            || !self.read_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.causal_claim
            || self.outcome_authority
            || self.evidence_digest != self.compute_digest()
        {
            return Err(LookerAnalyticsResultServiceError::EvidenceTampered);
        }
        if let Some(aggregate) = &self.aggregate {
            if aggregate.date_window_digest != scope.date_window().digest() {
                return Err(LookerAnalyticsResultServiceError::RevisionMismatch);
            }
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &LookerAnalyticsScope,
        registration_digest: &Digest,
        provider_digest: &Digest,
    ) -> Result<(), LookerAnalyticsResultServiceError> {
        if self.contract_version != crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION
            || self.provider_id != crate::LOOKER_PROVIDER_ID
            || self.provider_digest != *provider_digest
            || self.registration_digest != *registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.consent_digest != scope.consent_digest()
            || self.project_digest != scope.project_digest()
            || self.mission_digest != scope.mission_digest()
            || self.work_product_digest != scope.work_product_digest()
            || !self.redactions.is_complete()
            || !self.read_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.causal_claim
            || self.outcome_authority
            || self.evidence_digest != self.compute_digest()
        {
            return Err(LookerAnalyticsResultServiceError::EvidenceTampered);
        }
        if let Some(aggregate) = &self.aggregate {
            if aggregate.date_window_digest != scope.date_window().digest() {
                return Err(LookerAnalyticsResultServiceError::RevisionMismatch);
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.evidence_digest.clear();
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_version: String,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub evidence_digest: Digest,
    pub state: LookerEvidenceState,
    pub evidence: LookerAnalyticsEvidence,
    pub read_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub proposal_digest: Digest,
    pub replayed: bool,
}

impl LookerAnalyticsResultProposal {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn evidence(&self) -> &LookerAnalyticsEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn state(&self) -> LookerEvidenceState {
        self.state
    }

    pub fn validate(
        &self,
        scope: &LookerAnalyticsScope,
        registration: &LookerRegistration,
        provider_digest: &Digest,
    ) -> Result<(), LookerAnalyticsResultServiceError> {
        self.evidence
            .validate(scope, registration, provider_digest)?;
        if self.contract_version != crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION
            || self.provider_digest != *provider_digest
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.request_digest != self.evidence.request_digest
            || self.idempotency_key_digest != self.evidence.idempotency_key_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.state != self.evidence.state
            || !self.read_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.outcome_authority
            || self.proposal_digest != self.compute_digest()
        {
            return Err(LookerAnalyticsResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &LookerAnalyticsScope,
        registration_digest: &Digest,
        provider_digest: &Digest,
    ) -> Result<(), LookerAnalyticsResultServiceError> {
        self.evidence
            .validate_for_consumer(scope, registration_digest, provider_digest)?;
        if self.contract_version != crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_version != crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION
            || self.provider_digest != *provider_digest
            || self.registration_digest != *registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.request_digest != self.evidence.request_digest
            || self.idempotency_key_digest != self.evidence.idempotency_key_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.state != self.evidence.state
            || !self.read_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.outcome_authority
            || self.proposal_digest != self.compute_digest()
        {
            return Err(LookerAnalyticsResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        copy.replayed = false;
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: LookerEvidenceState,
    pub provenance: crate::LookerTransportProvenance,
    pub deterministic: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
}

impl LookerAnalyticsResultProposal {
    #[must_use]
    pub fn receipt(&self) -> LookerAnalyticsResultReceipt {
        let receipt_digest = canonical_digest(&(
            "looker-result-receipt/v1",
            &self.proposal_digest,
            &self.evidence.evidence_digest,
            &self.state,
        ));
        LookerAnalyticsResultReceipt {
            receipt_digest,
            proposal_digest: self.proposal_digest.clone(),
            evidence_digest: self.evidence.evidence_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            state: self.state,
            provenance: self.evidence.provenance,
            deterministic: true,
            read_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            outcome_authority: false,
        }
    }
}

/// Layer-1 typed service for redacted, bounded Looker analytics metadata.
pub struct LookerAnalyticsResultService<T: LookerTransport> {
    provider: LookerProvider<T>,
    definition: LookerAnalyticsResultServiceDefinition,
    idempotency: BTreeMap<Digest, (Digest, LookerAnalyticsResultProposal)>,
}

impl<T: LookerTransport> fmt::Debug for LookerAnalyticsResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookerAnalyticsResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("idempotency_records", &self.idempotency.len())
            .finish()
    }
}

impl<T: LookerTransport> LookerAnalyticsResultService<T> {
    pub fn new(provider: LookerProvider<T>) -> Result<Self, LookerAnalyticsResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| LookerAnalyticsResultServiceError::RegistrationRevoked)?;
        let definition = LookerAnalyticsResultServiceDefinition::default();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
            idempotency: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: LookerProvider<T>) -> Self {
        Self {
            provider,
            definition: LookerAnalyticsResultServiceDefinition::default(),
            idempotency: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &LookerProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut LookerProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &LookerAnalyticsScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &LookerRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &LookerAnalyticsResultServiceDefinition {
        &self.definition
    }

    pub fn read(&mut self) -> Result<LookerAnalyticsEvidence, LookerAnalyticsResultServiceError> {
        let request = self.default_request()?;
        self.read_request(&request)
    }

    pub fn read_request(
        &mut self,
        request: &LookerAnalyticsRequest,
    ) -> Result<LookerAnalyticsEvidence, LookerAnalyticsResultServiceError> {
        request
            .validate(self.scope())
            .map_err(|_| LookerAnalyticsResultServiceError::ScopeMismatch)?;
        match self.provider.read_request(request) {
            Ok(read) => {
                let state = if read.aggregate.partial {
                    LookerEvidenceState::Partial
                } else if read.aggregate.item_count == 0 {
                    LookerEvidenceState::Empty
                } else {
                    LookerEvidenceState::Complete
                };
                Ok(self.evidence_from_read(request, read, state))
            }
            Err(error) => self.evidence_from_provider_error(request, error),
        }
    }

    pub fn propose(
        &mut self,
        request: &LookerAnalyticsRequest,
    ) -> Result<LookerAnalyticsResultProposal, LookerAnalyticsResultServiceError> {
        request
            .validate(self.scope())
            .map_err(|_| LookerAnalyticsResultServiceError::ScopeMismatch)?;
        self.ensure_available_for_proposal()?;
        let idempotency_key = request.idempotency_key_digest().clone();
        let request_digest = request.request_digest();
        if let Some((previous_request, proposal)) = self.idempotency.get(&idempotency_key) {
            if previous_request != &request_digest {
                return Err(LookerAnalyticsResultServiceError::IdempotencyConflict);
            }
            let mut replay = proposal.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let evidence = self.read_request(request)?;
        let mut proposal = LookerAnalyticsResultProposal {
            contract_version: crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            request_digest,
            idempotency_key_digest: idempotency_key.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.state,
            evidence,
            read_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            outcome_authority: false,
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
            idempotency_key,
            (proposal.request_digest.clone(), proposal.clone()),
        );
        Ok(proposal)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<LookerAnalyticsResultProposal, LookerAnalyticsResultServiceError> {
        let request = self.default_request()?;
        self.propose(&request)
    }

    pub fn compile_proposal_for(
        &mut self,
        request: &LookerAnalyticsRequest,
    ) -> Result<LookerAnalyticsResultProposal, LookerAnalyticsResultServiceError> {
        self.propose(request)
    }

    pub fn verify_proposal(
        &self,
        proposal: &LookerAnalyticsResultProposal,
    ) -> Result<(), LookerAnalyticsResultServiceError> {
        proposal.validate(
            self.scope(),
            self.registration(),
            &self.provider.provider_digest(),
        )
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, LookerAnalyticsResultServiceError> {
        let receipt = self
            .provider
            .revoke()
            .map_err(LookerAnalyticsResultServiceError::from)?;
        self.idempotency.clear();
        Ok(receipt)
    }

    pub fn restore(&mut self) -> Result<(), LookerAnalyticsResultServiceError> {
        self.provider
            .restore()
            .map_err(LookerAnalyticsResultServiceError::from)?;
        self.idempotency.clear();
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), LookerAnalyticsResultServiceError> {
        self.provider
            .revoke_secret()
            .map_err(LookerAnalyticsResultServiceError::from)?;
        self.idempotency.clear();
        Ok(())
    }

    fn default_request(&self) -> Result<LookerAnalyticsRequest, LookerAnalyticsResultServiceError> {
        let key = IdempotencyKey::from_digest(canonical_digest(&(
            "looker-default-idempotency/v1",
            self.scope().scope_digest(),
        )))?;
        if self.scope().dashboard().is_some() {
            Ok(LookerAnalyticsRequest::dashboard(self.scope(), &key)?)
        } else if self.scope().look().is_some() {
            Ok(LookerAnalyticsRequest::look(self.scope(), &key)?)
        } else if self.scope().query().is_some() {
            Ok(LookerAnalyticsRequest::query(self.scope(), &key)?)
        } else if self.scope().folder().is_some() {
            Ok(LookerAnalyticsRequest::folder(self.scope(), &key)?)
        } else {
            Ok(LookerAnalyticsRequest::aggregate_metadata(
                self.scope(),
                &key,
            )?)
        }
    }

    fn ensure_available_for_proposal(&self) -> Result<(), LookerAnalyticsResultServiceError> {
        if self.registration().state != crate::RegistrationState::Active {
            return Err(LookerAnalyticsResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(LookerAnalyticsResultServiceError::SecretRevoked);
        }
        if !self.scope().consent().is_active() {
            return Err(LookerAnalyticsResultServiceError::ConsentMismatch);
        }
        Ok(())
    }

    fn evidence_from_read(
        &self,
        request: &LookerAnalyticsRequest,
        read: crate::LookerProviderRead,
        state: LookerEvidenceState,
    ) -> LookerAnalyticsEvidence {
        let source_revision = read
            .aggregate
            .items
            .first()
            .map_or(self.scope().scope_revision(), |item| item.source_revision);
        let classification = if state == LookerEvidenceState::Partial {
            EvidenceClassification::Partial
        } else {
            read.classification
        };
        let mut evidence = LookerAnalyticsEvidence {
            contract_version: crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION.to_owned(),
            provider_digest: self.provider.provider_digest(),
            provider_id: crate::LOOKER_PROVIDER_ID.to_owned(),
            registration_digest: self.registration().registration_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            consent_digest: self.scope().consent_digest(),
            project_digest: self.scope().project_digest(),
            mission_digest: self.scope().mission_digest(),
            work_product_digest: self.scope().work_product_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            response_digest: read.response_digest,
            response_bytes: read.response_bytes,
            source_revision,
            state,
            aggregate: Some(read.aggregate),
            redactions: RedactionSummary::layer1(),
            rate_limit: read.rate_limit,
            provenance: read.provenance,
            classification,
            read_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            causal_claim: false,
            outcome_authority: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn evidence_from_provider_error(
        &self,
        request: &LookerAnalyticsRequest,
        error: LookerProviderError,
    ) -> Result<LookerAnalyticsEvidence, LookerAnalyticsResultServiceError> {
        let (state, classification, response_digest, response_bytes, rate_limit) = match &error {
            LookerProviderError::Transport {
                error: LookerTransportError::BlockedEnv,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => (
                LookerEvidenceState::AccessLost,
                EvidenceClassification::BlockedEnv,
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
            ),
            LookerProviderError::Transport {
                error: LookerTransportError::Partial,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => (
                LookerEvidenceState::Partial,
                EvidenceClassification::Partial,
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
            ),
            LookerProviderError::Transport {
                error: LookerTransportError::AccessLost,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | LookerProviderError::HttpStatus {
                status_code: 401 | 403,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => (
                LookerEvidenceState::AccessLost,
                self.provider.transport_provenance().into(),
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
            ),
            LookerProviderError::HttpStatus {
                status_code: 404,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => (
                LookerEvidenceState::NotFound,
                self.provider.transport_provenance().into(),
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
            ),
            LookerProviderError::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | LookerProviderError::HttpStatus {
                status_code: 429,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => (
                LookerEvidenceState::RateLimited,
                EvidenceClassification::RateLimited,
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
            ),
            LookerProviderError::Transport {
                error: LookerTransportError::Timeout | LookerTransportError::ProviderUnknown,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | LookerProviderError::HttpStatus {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => (
                LookerEvidenceState::ProviderUnknown,
                EvidenceClassification::ProviderUnknown,
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
            ),
            LookerProviderError::RegistrationRevoked => {
                return Err(LookerAnalyticsResultServiceError::RegistrationRevoked);
            }
            LookerProviderError::SecretRevoked => {
                return Err(LookerAnalyticsResultServiceError::SecretRevoked);
            }
            LookerProviderError::ConsentRevoked => {
                return Err(LookerAnalyticsResultServiceError::ConsentMismatch);
            }
            LookerProviderError::PermissionDenied | LookerProviderError::ScopeMismatch => {
                return Err(LookerAnalyticsResultServiceError::ScopeMismatch);
            }
            LookerProviderError::ResponseTamper { .. } => {
                return Err(LookerAnalyticsResultServiceError::EvidenceTampered);
            }
            LookerProviderError::ResponseTooLarge { .. }
            | LookerProviderError::MalformedResponse { .. }
            | LookerProviderError::InvalidRateLimitReceipt { .. }
            | LookerProviderError::Model(_) => {
                return Err(LookerAnalyticsResultServiceError::Provider(Box::new(error)));
            }
        };
        let mut evidence = LookerAnalyticsEvidence {
            contract_version: crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_version: crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION.to_owned(),
            provider_digest: self.provider.provider_digest(),
            provider_id: crate::LOOKER_PROVIDER_ID.to_owned(),
            registration_digest: self.registration().registration_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            consent_digest: self.scope().consent_digest(),
            project_digest: self.scope().project_digest(),
            mission_digest: self.scope().mission_digest(),
            work_product_digest: self.scope().work_product_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            response_digest,
            response_bytes,
            source_revision: self.scope().scope_revision(),
            state,
            aggregate: None,
            redactions: RedactionSummary::layer1(),
            rate_limit,
            provenance: self.provider.transport_provenance(),
            classification,
            read_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            causal_claim: false,
            outcome_authority: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }
}

impl From<LookerProviderError> for LookerAnalyticsResultServiceError {
    fn from(error: LookerProviderError) -> Self {
        match error {
            LookerProviderError::RegistrationRevoked => Self::RegistrationRevoked,
            LookerProviderError::SecretRevoked => Self::SecretRevoked,
            LookerProviderError::ConsentRevoked => Self::ConsentMismatch,
            LookerProviderError::ScopeMismatch | LookerProviderError::PermissionDenied => {
                Self::ScopeMismatch
            }
            other => Self::Provider(Box::new(other)),
        }
    }
}

// Keep the service-level error surface explicit for callers that build a
// forbidden operation from their own dispatch table.
#[must_use]
pub const fn mutation_forbidden(operation: &'static str) -> LookerAnalyticsResultServiceError {
    LookerAnalyticsResultServiceError::MutationForbidden { operation }
}

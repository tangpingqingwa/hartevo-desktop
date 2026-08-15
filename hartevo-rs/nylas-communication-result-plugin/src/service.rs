use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    Digest, IdempotencyKey, ModelError, NylasCommunicationRequest, NylasCommunicationScope,
    NylasDeliveryStatus, NylasEvidenceState, NylasMetadataPage, NylasRateLimitReceipt,
    NylasRegistration, NylasTransportProvenance, RedactionSummary, RegistrationRevocationReceipt,
    RegistrationState, Revision, SecretReference, canonical_digest,
};
use crate::provider::{
    NylasProvider, NylasProviderError, NylasProviderFailureMetadata, NylasProviderRead,
    NylasTransport,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationResultServiceDefinition {
    pub id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub native_connected: bool,
    pub operations: Vec<String>,
}

impl NylasCommunicationResultServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: crate::SERVICE_ID.to_owned(),
            version: crate::PLUGIN_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            external_writes: false,
            native_connected: false,
            operations: vec![
                "read_messages".to_owned(),
                "read_threads".to_owned(),
                "read_calendars".to_owned(),
                "read_events".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
                "revoke_registration".to_owned(),
                "restore_registration".to_owned(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ServiceDefinitionError> {
        if self == &Self::new()
            && self.read_only
            && self.proposal_only
            && self.recording_only
            && !self.live_execution
            && !self.external_writes
            && !self.native_connected
        {
            Ok(())
        } else {
            Err(ServiceDefinitionError::DefinitionDrift)
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl Default for NylasCommunicationResultServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ServiceDefinitionError {
    #[error("Nylas service definition drifted from the Layer-1 contract")]
    DefinitionDrift,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NylasCommunicationResultServiceError {
    #[error("Nylas model is invalid: {0}")]
    Model(String),
    #[error("Nylas provider failed: {0}")]
    Provider(String),
    #[error("Nylas service or provider definition drifted")]
    DefinitionDrift,
    #[error("Nylas registration is revoked")]
    RegistrationRevoked,
    #[error("Nylas secret reference is revoked")]
    SecretRevoked,
    #[error("Nylas request is outside the registered Project/Mission/Work Product scope")]
    ScopeMismatch,
    #[error("Nylas request revision is stale")]
    RevisionMismatch,
    #[error("Nylas request cursor is invalid or not bound to the request")]
    CursorInvalid,
    #[error("idempotency key was reused for a different Nylas request")]
    IdempotencyConflict,
    #[error("Nylas evidence failed integrity validation")]
    EvidenceTampered,
    #[error("Nylas proposal failed integrity validation")]
    ProposalTampered,
    #[error("Nylas proposal replay was rejected")]
    ReplayDetected,
    #[error("Nylas recording idempotency key conflicted")]
    RecordingConflict,
}

pub type NylasCommunicationServiceError = NylasCommunicationResultServiceError;

impl From<ModelError> for NylasCommunicationResultServiceError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<ServiceDefinitionError> for NylasCommunicationResultServiceError {
    fn from(_: ServiceDefinitionError) -> Self {
        Self::DefinitionDrift
    }
}

impl From<NylasProviderError> for NylasCommunicationResultServiceError {
    fn from(error: NylasProviderError) -> Self {
        match error {
            NylasProviderError::DefinitionDrift => Self::DefinitionDrift,
            NylasProviderError::RegistrationRevoked => Self::RegistrationRevoked,
            NylasProviderError::SecretRevoked => Self::SecretRevoked,
            NylasProviderError::RequestInvalid => Self::ScopeMismatch,
            NylasProviderError::RevisionMismatch => Self::RevisionMismatch,
            other => Self::Provider(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: String,
    pub service_definition_digest: Digest,
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
    pub field_selection_digest: Digest,
    pub response_digest: Option<Digest>,
    pub response_bytes: usize,
    pub status: Option<u16>,
    pub source_revision: Revision,
    pub state: NylasEvidenceState,
    pub page: Option<NylasMetadataPage>,
    pub redactions: RedactionSummary,
    pub rate_limit: NylasRateLimitReceipt,
    pub provenance: NylasTransportProvenance,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
    pub evidence_digest: Digest,
}

impl NylasCommunicationEvidence {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    #[must_use]
    pub fn page(&self) -> Option<&NylasMetadataPage> {
        self.page.as_ref()
    }

    pub fn validate(
        &self,
        scope: &NylasCommunicationScope,
        registration: &NylasRegistration,
        provider_digest: &Digest,
        service_definition: &NylasCommunicationResultServiceDefinition,
    ) -> Result<(), NylasCommunicationResultServiceError> {
        scope.validate()?;
        service_definition.validate()?;
        if self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.service_definition_digest != service_definition.digest()
            || self.provider_id != crate::PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.registration_digest != registration.registration_digest
            || self.registration_evidence_digest != registration.evidence_digest
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.source_revision != scope.scope_revision()
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.cursor_binding_digest != self.expected_cursor_binding()
            || self.field_selection_digest != self.expected_field_selection_digest()
            || self
                .page
                .as_ref()
                .is_some_and(|page| page.validate().is_err())
            || !self.redactions.is_complete()
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.durable_provider_receipt
            || self.kernel_authority
            || self.evidence_digest != self.compute_digest()
            || !state_shape_is_valid(self.state, self.page.as_ref())
        {
            return Err(NylasCommunicationResultServiceError::EvidenceTampered);
        }
        self.rate_limit.validate()?;
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &NylasCommunicationScope,
        registration_digest: &Digest,
        registration_evidence_digest: &Digest,
        provider_digest: &Digest,
        service_definition: &NylasCommunicationResultServiceDefinition,
    ) -> Result<(), NylasCommunicationResultServiceError> {
        if &self.registration_digest != registration_digest
            || &self.registration_evidence_digest != registration_evidence_digest
        {
            return Err(NylasCommunicationResultServiceError::EvidenceTampered);
        }
        self.validate(
            scope,
            &NylasRegistration {
                plugin_version: crate::PLUGIN_VERSION.to_owned(),
                contract_version: crate::CONTRACT_VERSION.to_owned(),
                contract_digest: crate::contract_digest(),
                provider_id: crate::PROVIDER_ID.to_owned(),
                provider_digest: provider_digest.clone(),
                permission_digest: self.permission_digest.clone(),
                scope_digest: self.scope_digest.clone(),
                revision_digest: self.revision_digest.clone(),
                evidence_digest: registration_evidence_digest.clone(),
                secret_reference_digest: String::new(),
                registration_revision: crate::Revision::new(1)?,
                registration_digest: registration_digest.clone(),
                state: RegistrationState::Active,
                reversible: true,
                revocable: true,
            },
            provider_digest,
            service_definition,
        )
    }

    fn expected_cursor_binding(&self) -> Digest {
        self.page
            .as_ref()
            .and_then(|page| page.cursor_binding_digest.clone())
            .unwrap_or_else(|| self.cursor_binding_digest.clone())
    }

    fn expected_field_selection_digest(&self) -> Digest {
        self.page
            .as_ref()
            .and_then(|page| {
                page.records
                    .first()
                    .map(|record| record.selected_fields_digest.clone())
            })
            .unwrap_or_else(|| self.field_selection_digest.clone())
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.evidence_digest.clear();
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: String,
    pub service_definition_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub evidence_digest: Digest,
    pub state: NylasEvidenceState,
    pub evidence: NylasCommunicationEvidence,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
    pub replayed: bool,
}

impl NylasCommunicationResultProposal {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn evidence(&self) -> &NylasCommunicationEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn state(&self) -> NylasEvidenceState {
        self.state
    }

    pub fn validate(
        &self,
        scope: &NylasCommunicationScope,
        registration: &NylasRegistration,
        provider_digest: &Digest,
        service_definition: &NylasCommunicationResultServiceDefinition,
    ) -> Result<(), NylasCommunicationResultServiceError> {
        self.evidence
            .validate(scope, registration, provider_digest, service_definition)?;
        if self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.service_definition_digest != service_definition.digest()
            || self.provider_id != crate::PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != *scope.scope_digest()
            || self.request_digest != self.evidence.request_digest
            || self.idempotency_key_digest != self.evidence.idempotency_key_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.state != self.evidence.state
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.outcome_authority
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(NylasCommunicationResultServiceError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn receipt(&self) -> NylasCommunicationResultReceipt {
        NylasCommunicationResultReceipt::from_proposal(self)
    }

    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        copy.replayed = false;
        canonical_digest(&copy)
    }
}

pub type NylasCommunicationResult = NylasCommunicationResultProposal;
pub type NylasCommunicationProposal = NylasCommunicationResultProposal;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: NylasEvidenceState,
    pub provenance: NylasTransportProvenance,
    pub deterministic: bool,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
}

impl NylasCommunicationResultReceipt {
    fn from_proposal(proposal: &NylasCommunicationResultProposal) -> Self {
        let receipt_digest = canonical_digest(&(
            "nylas-communication-result-receipt/v1",
            &proposal.proposal_digest,
            &proposal.evidence_digest,
            proposal.state,
        ));
        Self {
            receipt_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            provenance: proposal.evidence.provenance,
            deterministic: true,
            read_only: true,
            proposal_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            durable_provider_receipt: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasCommunicationRecordReceipt {
    pub record_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_digest: Digest,
    pub state: NylasEvidenceState,
    pub recorded_at_revision: Revision,
    pub replayed: bool,
    pub review_only: bool,
    pub connected: bool,
    pub native_provider: bool,
}

impl NylasCommunicationRecordReceipt {
    fn compute_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.record_digest.clear();
        copy.replayed = false;
        canonical_digest(&copy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasVerificationFailure {
    pub code: String,
    pub detail_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NylasVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub checked_registration_digest: Digest,
    pub failure: Option<NylasVerificationFailure>,
}

pub struct NylasCommunicationResultService<T: NylasTransport> {
    provider: NylasProvider<T>,
    definition: NylasCommunicationResultServiceDefinition,
    idempotency: BTreeMap<Digest, (Digest, NylasCommunicationResultProposal)>,
    records: BTreeMap<Digest, NylasCommunicationRecordReceipt>,
}

impl<T: NylasTransport> fmt::Debug for NylasCommunicationResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NylasCommunicationResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("idempotency_records", &self.idempotency.len())
            .field("recordings", &self.records.len())
            .finish()
    }
}

impl<T: NylasTransport> NylasCommunicationResultService<T> {
    pub fn new(provider: NylasProvider<T>) -> Result<Self, NylasCommunicationResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| NylasCommunicationResultServiceError::RegistrationRevoked)?;
        let definition = NylasCommunicationResultServiceDefinition::new();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
            idempotency: BTreeMap::new(),
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: NylasProvider<T>) -> Self {
        Self {
            provider,
            definition: NylasCommunicationResultServiceDefinition::new(),
            idempotency: BTreeMap::new(),
            records: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &NylasProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut NylasProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &NylasCommunicationScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &NylasRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &NylasCommunicationResultServiceDefinition {
        &self.definition
    }

    pub fn read(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        request.validate(self.scope()).map_err(map_model_error)?;
        self.ensure_available()?;
        match self.provider.read_request(request) {
            Ok(read) => {
                let state = state_from_page(&read.page, &read.rate_limit);
                Ok(self.evidence_from_read(request, read, state))
            }
            Err(error) => self.evidence_from_provider_error(request, error),
        }
    }

    pub fn read_request(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        self.read(request)
    }

    pub fn read_messages(
        &mut self,
        key: &IdempotencyKey,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        let request = NylasCommunicationRequest::messages(self.scope(), key)?;
        self.read(&request)
    }

    pub fn read_threads(
        &mut self,
        key: &IdempotencyKey,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        let request = NylasCommunicationRequest::threads(self.scope(), key)?;
        self.read(&request)
    }

    pub fn read_calendars(
        &mut self,
        key: &IdempotencyKey,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        let request = NylasCommunicationRequest::calendars(self.scope(), key)?;
        self.read(&request)
    }

    pub fn read_events(
        &mut self,
        key: &IdempotencyKey,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        let request = NylasCommunicationRequest::events(self.scope(), key)?;
        self.read(&request)
    }

    pub fn propose(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationResultProposal, NylasCommunicationResultServiceError> {
        request.validate(self.scope()).map_err(map_model_error)?;
        self.ensure_available()?;
        let key = request.idempotency_key_digest().clone();
        let request_digest = request.request_digest();
        if let Some((previous_request, proposal)) = self.idempotency.get(&key) {
            if previous_request != &request_digest {
                return Err(NylasCommunicationResultServiceError::IdempotencyConflict);
            }
            let mut replay = proposal.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let evidence = self.read(request)?;
        let mut proposal = NylasCommunicationResultProposal {
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            plugin_version: crate::PLUGIN_VERSION.to_owned(),
            service_definition_digest: self.definition.digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            request_digest,
            idempotency_key_digest: key,
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.state,
            evidence,
            read_only: true,
            proposal_only: true,
            recording_only: true,
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
            &self.definition,
        )?;
        self.idempotency.insert(
            proposal.idempotency_key_digest.clone(),
            (proposal.request_digest.clone(), proposal.clone()),
        );
        Ok(proposal)
    }

    pub fn compile_proposal(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationResultProposal, NylasCommunicationResultServiceError> {
        self.propose(request)
    }

    pub fn propose_request(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationResultProposal, NylasCommunicationResultServiceError> {
        self.propose(request)
    }

    pub fn verify(&self, proposal: &NylasCommunicationResultProposal) -> NylasVerificationReport {
        let failure = if self.definition.validate().is_err() {
            Some(verification_failure(
                "definition_drift",
                self.definition.digest(),
            ))
        } else if self.registration().state != RegistrationState::Active {
            Some(verification_failure(
                "registration_revoked",
                self.registration().registration_digest.clone(),
            ))
        } else {
            match proposal.validate(
                self.scope(),
                self.registration(),
                &self.provider.provider_digest(),
                &self.definition,
            ) {
                Ok(()) => None,
                Err(error) => Some(verification_failure("proposal_tampered", error.to_string())),
            }
        };
        let valid = failure.is_none();
        NylasVerificationReport {
            valid,
            review_eligible: valid,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            checked_registration_digest: self.registration().registration_digest.clone(),
            failure,
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &NylasCommunicationResultProposal,
    ) -> Result<NylasVerificationReport, NylasCommunicationResultServiceError> {
        let report = self.verify(proposal);
        if report.valid {
            Ok(report)
        } else {
            Err(NylasCommunicationResultServiceError::ProposalTampered)
        }
    }

    pub fn record(
        &mut self,
        proposal: &NylasCommunicationResultProposal,
        idempotency_key: &IdempotencyKey,
    ) -> Result<NylasCommunicationRecordReceipt, NylasCommunicationResultServiceError> {
        self.ensure_available()?;
        self.verify_proposal(proposal)?;
        if let Some(existing) = self.records.get(idempotency_key.digest()) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(NylasCommunicationResultServiceError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let mut record = NylasCommunicationRecordReceipt {
            record_digest: String::new(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            idempotency_digest: idempotency_key.digest().clone(),
            state: proposal.state,
            recorded_at_revision: self.scope().scope_revision(),
            replayed: false,
            review_only: true,
            connected: false,
            native_provider: false,
        };
        record.record_digest = record.compute_digest();
        self.records
            .insert(idempotency_key.digest().clone(), record.clone());
        Ok(record)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &NylasCommunicationResultProposal,
        idempotency_key: &IdempotencyKey,
    ) -> Result<NylasCommunicationRecordReceipt, NylasCommunicationResultServiceError> {
        self.record(proposal, idempotency_key)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, NylasCommunicationResultServiceError> {
        self.provider.revoke().map_err(Into::into)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, NylasCommunicationResultServiceError> {
        self.revoke()
    }

    pub fn restore(&mut self) -> Result<(), NylasCommunicationResultServiceError> {
        self.provider.restore().map_err(Into::into)
    }

    pub fn restore_registration(&mut self) -> Result<(), NylasCommunicationResultServiceError> {
        self.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<(), NylasCommunicationResultServiceError> {
        self.provider.revoke_secret().map_err(Into::into)
    }

    pub fn restore_secret(&mut self) -> Result<(), NylasCommunicationResultServiceError> {
        self.provider.restore_secret().map_err(Into::into)
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn into_consumer(self) -> crate::MissionNylasCommunicationConsumer<T> {
        crate::MissionNylasCommunicationConsumer::from_service(self)
    }

    fn ensure_available(&self) -> Result<(), NylasCommunicationResultServiceError> {
        self.definition.validate()?;
        if self.registration().state != RegistrationState::Active {
            return Err(NylasCommunicationResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(NylasCommunicationResultServiceError::SecretRevoked);
        }
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| NylasCommunicationResultServiceError::RegistrationRevoked)
    }

    fn evidence_from_read(
        &self,
        request: &NylasCommunicationRequest,
        read: NylasProviderRead,
        state: NylasEvidenceState,
    ) -> NylasCommunicationEvidence {
        let mut evidence = NylasCommunicationEvidence {
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            plugin_version: crate::PLUGIN_VERSION.to_owned(),
            service_definition_digest: self.definition.digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            registration_evidence_digest: self.registration().evidence_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            cursor_binding_digest: request.cursor_binding_digest(),
            field_selection_digest: request.field_selection().digest(),
            response_digest: Some(read.response_digest),
            response_bytes: read.response_bytes,
            status: Some(read.status),
            source_revision: self.scope().scope_revision(),
            state,
            page: Some(read.page),
            redactions: RedactionSummary::layer1(),
            rate_limit: read.rate_limit,
            provenance: read.provenance,
            read_only: true,
            proposal_only: true,
            recording_only: true,
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
        request: &NylasCommunicationRequest,
        error: NylasProviderError,
    ) -> Result<NylasCommunicationEvidence, NylasCommunicationResultServiceError> {
        let state = match &error {
            NylasProviderError::RateLimited { .. } => NylasEvidenceState::RateLimited,
            NylasProviderError::Timeout { .. } => NylasEvidenceState::Timeout,
            NylasProviderError::AccessLoss { .. } => NylasEvidenceState::AccessLoss,
            NylasProviderError::ProviderUnknown { .. } => NylasEvidenceState::ProviderUnknown,
            NylasProviderError::Partial { .. } => NylasEvidenceState::Partial,
            NylasProviderError::ResponseTampered { .. }
            | NylasProviderError::ResponseTooLarge { .. } => NylasEvidenceState::Tamper,
            NylasProviderError::BlockedEnv { .. } => NylasEvidenceState::BlockedEnv,
            NylasProviderError::RegistrationRevoked => {
                return Err(NylasCommunicationResultServiceError::RegistrationRevoked);
            }
            NylasProviderError::SecretRevoked => {
                return Err(NylasCommunicationResultServiceError::SecretRevoked);
            }
            NylasProviderError::RevisionMismatch => NylasEvidenceState::Stale,
            NylasProviderError::DefinitionDrift => {
                return Err(NylasCommunicationResultServiceError::DefinitionDrift);
            }
            NylasProviderError::RequestInvalid => {
                return Err(NylasCommunicationResultServiceError::ScopeMismatch);
            }
            NylasProviderError::Model(error) => {
                return Err(NylasCommunicationResultServiceError::Model(error.clone()));
            }
        };
        let metadata = provider_error_metadata(&error);
        let (response_digest, response_bytes, rate_limit, status) = metadata.map_or(
            (None, 0, NylasRateLimitReceipt::default(), None),
            |metadata| {
                (
                    metadata.response_digest,
                    metadata.response_bytes,
                    metadata.rate_limit,
                    metadata.status,
                )
            },
        );
        let provenance = self.provider.transport_provenance();
        let mut evidence = NylasCommunicationEvidence {
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            plugin_version: crate::PLUGIN_VERSION.to_owned(),
            service_definition_digest: self.definition.digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            registration_evidence_digest: self.registration().evidence_digest.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            permission_digest: self.scope().permission_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            cursor_binding_digest: request.cursor_binding_digest(),
            field_selection_digest: request.field_selection().digest(),
            response_digest,
            response_bytes,
            status,
            source_revision: self.scope().scope_revision(),
            state,
            page: None,
            redactions: RedactionSummary::layer1(),
            rate_limit,
            provenance,
            read_only: true,
            proposal_only: true,
            recording_only: true,
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

fn map_model_error(error: ModelError) -> NylasCommunicationResultServiceError {
    match error {
        ModelError::InvalidCursor => NylasCommunicationResultServiceError::CursorInvalid,
        ModelError::InvalidScope(_) | ModelError::InvalidRequest => {
            NylasCommunicationResultServiceError::ScopeMismatch
        }
        other => NylasCommunicationResultServiceError::Model(other.to_string()),
    }
}

fn provider_error_metadata(error: &NylasProviderError) -> Option<NylasProviderFailureMetadata> {
    match error {
        NylasProviderError::ResponseTooLarge { metadata }
        | NylasProviderError::RateLimited { metadata }
        | NylasProviderError::Timeout { metadata }
        | NylasProviderError::AccessLoss { metadata }
        | NylasProviderError::ProviderUnknown { metadata }
        | NylasProviderError::Partial { metadata }
        | NylasProviderError::ResponseTampered { metadata }
        | NylasProviderError::BlockedEnv { metadata } => Some(metadata.clone()),
        _ => None,
    }
}

fn state_from_page(
    page: &NylasMetadataPage,
    rate_limit: &NylasRateLimitReceipt,
) -> NylasEvidenceState {
    if rate_limit.throttled {
        return NylasEvidenceState::RateLimited;
    }
    if page.partial {
        return NylasEvidenceState::Partial;
    }
    if page.records.is_empty() {
        return NylasEvidenceState::Empty;
    }
    let mut statuses = page.records.iter().filter_map(|record| record.status);
    if statuses.any(|status| status == NylasDeliveryStatus::Failed) {
        NylasEvidenceState::Failed
    } else if page
        .records
        .iter()
        .any(|record| record.status == Some(NylasDeliveryStatus::Bounced))
    {
        NylasEvidenceState::Bounced
    } else if page
        .records
        .iter()
        .any(|record| record.status == Some(NylasDeliveryStatus::Cancelled))
    {
        NylasEvidenceState::Cancelled
    } else if page
        .records
        .iter()
        .any(|record| record.status == Some(NylasDeliveryStatus::Delivered))
    {
        NylasEvidenceState::Delivered
    } else if page
        .records
        .iter()
        .any(|record| record.status == Some(NylasDeliveryStatus::Updated))
    {
        NylasEvidenceState::Updated
    } else if page
        .records
        .iter()
        .any(|record| record.status == Some(NylasDeliveryStatus::Sent))
    {
        NylasEvidenceState::Sent
    } else {
        NylasEvidenceState::Complete
    }
}

fn state_shape_is_valid(state: NylasEvidenceState, page: Option<&NylasMetadataPage>) -> bool {
    match state {
        NylasEvidenceState::Empty => page.is_some_and(|page| page.records.is_empty()),
        NylasEvidenceState::Complete
        | NylasEvidenceState::Sent
        | NylasEvidenceState::Delivered
        | NylasEvidenceState::Bounced
        | NylasEvidenceState::Failed
        | NylasEvidenceState::Cancelled
        | NylasEvidenceState::Updated => page.is_some_and(|page| !page.records.is_empty()),
        NylasEvidenceState::Partial
        | NylasEvidenceState::AccessLoss
        | NylasEvidenceState::ProviderUnknown
        | NylasEvidenceState::BlockedEnv
        | NylasEvidenceState::Tamper
        | NylasEvidenceState::Stale
        | NylasEvidenceState::Revoked
        | NylasEvidenceState::Timeout
        | NylasEvidenceState::RateLimited => page.is_none_or(|page| page.partial),
    }
}

fn verification_failure(code: &str, detail: impl Serialize) -> NylasVerificationFailure {
    NylasVerificationFailure {
        code: code.to_owned(),
        detail_digest: canonical_digest(&detail),
    }
}

pub type NylasCommunicationEvidenceResult = NylasCommunicationEvidence;
pub type NylasCommunicationRecord = NylasCommunicationRecordReceipt;
pub type NylasSecretReference = SecretReference;

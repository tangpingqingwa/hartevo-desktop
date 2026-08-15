use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::consumer::MissionDaggerPipelineConsumer;
use crate::error::{DaggerPipelineResultError, DaggerTransportError, Result};
use crate::model::{
    ConsentScope, DaggerArtifactMetadata, DaggerBackoffHint, DaggerEvidenceDigests,
    DaggerEvidenceState, DaggerFailureEvidence, DaggerObservationReceipt, DaggerPipelineEvidence,
    DaggerPipelineRegistration, DaggerPipelineScope, DaggerRecordingReceipt, Digest,
    RegistrationStatus, RegistrationTransitionEvidence, SecretReference, canonical_digest,
};
use crate::provider::{
    DaggerPipelineReadRequest, DaggerPipelineResultResponse, DaggerProvider, DaggerTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA, MAX_METADATA_ITEMS, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
};

pub type DaggerPipelineResultServiceError = DaggerPipelineResultError;
pub use crate::model::DaggerPipelineResultProposal;

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize)]
pub enum VerificationFailure {
    #[error("proposal integrity is invalid")]
    Tampered,
    #[error("proposal is outside the service scope")]
    ScopeMismatch,
    #[error("proposal registration digest is stale")]
    RegistrationMismatch,
    #[error("proposal state is not independently verifiable")]
    NonTerminal,
    #[error("proposal contains a provider failure state")]
    ProviderFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub failure: Option<VerificationFailure>,
    pub evidence_digest: Option<Digest>,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_schema: String,
    pub operations: Vec<String>,
    pub forbidden_operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub outcome_authority: bool,
    pub work_product_authority: bool,
}

pub struct DaggerPipelineResultService<T: DaggerTransport> {
    scope: DaggerPipelineScope,
    secret_reference: SecretReference,
    consent: ConsentScope,
    provider: DaggerProvider<T>,
    registration: DaggerPipelineRegistration,
    recordings: BTreeMap<Digest, DaggerRecordingReceipt>,
    now_epoch_seconds: u64,
}

impl<T: DaggerTransport> fmt::Debug for DaggerPipelineResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaggerPipelineResultService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("consent_digest", &self.consent.digest())
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: DaggerTransport> DaggerPipelineResultService<T> {
    pub fn new(
        scope: DaggerPipelineScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: DaggerProvider<T>,
        now_epoch_seconds: u64,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        consent.validate()?;
        let registration = DaggerPipelineRegistration::new(
            &scope,
            &secret_reference,
            &consent,
            provider.definition().digest(),
            &provider.definition().permissions,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            consent,
            provider,
            registration,
            recordings: BTreeMap::new(),
            now_epoch_seconds,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &DaggerPipelineScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &DaggerPipelineRegistration {
        &self.registration
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn provider(&self) -> &DaggerProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut DaggerProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_schema: CONTRACT_SCHEMA.to_owned(),
            operations: self.provider.definition().operations.clone(),
            forbidden_operations: crate::model::FORBIDDEN_OPERATIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            durable_provider_receipt: false,
            outcome_authority: false,
            work_product_authority: false,
        }
    }

    pub fn default_request(
        &self,
        idempotency_key: impl Into<String>,
    ) -> Result<DaggerPipelineReadRequest> {
        DaggerPipelineReadRequest::for_scope(&self.scope, idempotency_key)
    }

    pub fn propose(
        &mut self,
        request: DaggerPipelineReadRequest,
    ) -> Result<DaggerPipelineResultProposal> {
        self.check_request(&request)?;
        let proposal = match self.provider.read(&request) {
            Ok(response) => self.success_proposal(&request, response),
            Err(error) => self.failure_proposal(&request, error)?,
        };
        Ok(proposal)
    }

    pub fn read(
        &mut self,
        request: DaggerPipelineReadRequest,
    ) -> Result<DaggerPipelineResultProposal> {
        self.propose(request)
    }

    pub fn compile_evidence_proposal(
        &mut self,
        request: DaggerPipelineReadRequest,
    ) -> Result<DaggerPipelineResultProposal> {
        self.propose(request)
    }

    fn check_request(&self, request: &DaggerPipelineReadRequest) -> Result<()> {
        self.scope.validate()?;
        request.validate(&self.scope)?;
        self.registration.validate()?;
        if self.registration.scope_digest != self.scope.digest()
            || self.registration.secret_reference_digest
                != *self.secret_reference.reference_digest()
        {
            return Err(DaggerPipelineResultError::ScopeMismatch);
        }
        match self.registration.status() {
            RegistrationStatus::Active => {}
            RegistrationStatus::Revoked => {
                return Err(DaggerPipelineResultError::RegistrationRevoked);
            }
            RegistrationStatus::Reversed => {
                return Err(DaggerPipelineResultError::RegistrationReversed);
            }
        }
        if self.consent.revoked() {
            return Err(DaggerPipelineResultError::ConsentRevoked);
        }
        if !self.consent.is_valid_at(self.now_epoch_seconds) {
            return Err(DaggerPipelineResultError::ConsentExpired);
        }
        Ok(())
    }

    fn success_proposal(
        &self,
        request: &DaggerPipelineReadRequest,
        response: DaggerPipelineResultResponse,
    ) -> DaggerPipelineResultProposal {
        let state = match response.result.status {
            crate::model::DaggerRunStatus::Queued => DaggerEvidenceState::Queued,
            crate::model::DaggerRunStatus::Running => DaggerEvidenceState::Running,
            crate::model::DaggerRunStatus::Succeeded => DaggerEvidenceState::Succeeded,
            crate::model::DaggerRunStatus::Failed => DaggerEvidenceState::Failed,
        };
        let result = response.result;
        let artifacts = response.artifacts;
        let response_digest = response.response_digest;
        let receipt = DaggerObservationReceipt::new(
            request.request_digest().clone(),
            response_digest,
            Some(response.status_code),
            response.transport,
            result.observed_at_epoch_seconds,
        );
        let digests = DaggerEvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest: self.provider.definition().digest(),
            permission_digest: self.provider.definition().permissions.digest(),
            consent_digest: self.consent.digest(),
            scope_digest: self.scope.digest(),
            module_digest: self.scope.module().digest(),
            pipeline_digest: self.scope.pipeline().digest(),
            function_digest: self.scope.function().digest(),
            container_digest: self.scope.container().digest(),
            commit_digest: self.scope.commit().map(crate::model::DaggerCommit::digest),
            execution_digest: Some(result.execution.digest()),
            artifact_digests: artifacts
                .iter()
                .map(DaggerArtifactMetadata::digest)
                .collect(),
            evidence_digest: Digest::from_text("pending"),
        };
        let mut evidence = DaggerPipelineEvidence {
            state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            request_digest: request.request_digest().clone(),
            transport: response.transport,
            result: Some(result),
            artifacts,
            failure: None,
            backoff: None,
            observation_receipt: receipt,
            evidence_digests: digests,
            connected: false,
            native: false,
            durable_provider_receipt: false,
            first_party: false,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.calculate_evidence_digest();
        evidence.evidence_digests.evidence_digest = evidence.evidence_digest.clone();
        DaggerPipelineResultProposal::new(evidence)
    }

    fn failure_proposal(
        &self,
        request: &DaggerPipelineReadRequest,
        error: DaggerPipelineResultError,
    ) -> Result<DaggerPipelineResultProposal> {
        let (state, category, retry_after_seconds, status_code) = match &error {
            DaggerPipelineResultError::Transport(transport) => match transport {
                DaggerTransportError::BlockedEnv => {
                    (DaggerEvidenceState::BlockedEnv, "blocked_env", None, None)
                }
                DaggerTransportError::RateLimited {
                    retry_after_seconds,
                } => (
                    DaggerEvidenceState::RateLimited,
                    "rate_limited",
                    *retry_after_seconds,
                    transport.status_code(),
                ),
                DaggerTransportError::Unauthorized | DaggerTransportError::Forbidden => (
                    DaggerEvidenceState::Denied,
                    "denied",
                    None,
                    transport.status_code(),
                ),
                transport if transport.is_access_loss() => (
                    DaggerEvidenceState::AccessLoss,
                    "access_loss",
                    None,
                    transport.status_code(),
                ),
                DaggerTransportError::Partial => {
                    (DaggerEvidenceState::Partial, "partial", None, None)
                }
                DaggerTransportError::NotFound => (
                    DaggerEvidenceState::Failed,
                    "not_found",
                    None,
                    transport.status_code(),
                ),
                _ => (
                    DaggerEvidenceState::ProviderUnknown,
                    "provider_unknown",
                    None,
                    transport.status_code(),
                ),
            },
            DaggerPipelineResultError::TamperedEvidence
            | DaggerPipelineResultError::ScopeMismatch => {
                (DaggerEvidenceState::Tampered, "tampered", None, None)
            }
            DaggerPipelineResultError::RegistrationRevoked => (
                DaggerEvidenceState::RegistrationRevoked,
                "registration_revoked",
                None,
                None,
            ),
            _ => (
                DaggerEvidenceState::ProviderUnknown,
                "provider_unknown",
                None,
                None,
            ),
        };
        let failure = DaggerFailureEvidence::new(
            category,
            status_code,
            retry_after_seconds,
            Some(error.to_string().as_str()),
        )?;
        let backoff = retry_after_seconds
            .map(|value| DaggerBackoffHint::new(Some(value), 1))
            .transpose()?;
        let response_digest = Digest::from_parts(
            "dagger-failure-response/v1",
            &[
                ("request", request.request_digest().as_str().to_owned()),
                ("category", category.to_owned()),
                ("error", error.to_string()),
            ],
        );
        let receipt = DaggerObservationReceipt::new(
            request.request_digest().clone(),
            response_digest,
            status_code,
            self.provider.provenance(),
            self.now_epoch_seconds,
        );
        let digests = DaggerEvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest: self.provider.definition().digest(),
            permission_digest: self.provider.definition().permissions.digest(),
            consent_digest: self.consent.digest(),
            scope_digest: self.scope.digest(),
            module_digest: self.scope.module().digest(),
            pipeline_digest: self.scope.pipeline().digest(),
            function_digest: self.scope.function().digest(),
            container_digest: self.scope.container().digest(),
            commit_digest: self.scope.commit().map(crate::model::DaggerCommit::digest),
            execution_digest: None,
            artifact_digests: Vec::new(),
            evidence_digest: Digest::from_text("pending"),
        };
        let mut evidence = DaggerPipelineEvidence {
            state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            request_digest: request.request_digest().clone(),
            transport: self.provider.provenance(),
            result: None,
            artifacts: Vec::new(),
            failure: Some(failure),
            backoff,
            observation_receipt: receipt,
            evidence_digests: digests,
            connected: false,
            native: false,
            durable_provider_receipt: false,
            first_party: false,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.calculate_evidence_digest();
        evidence.evidence_digests.evidence_digest = evidence.evidence_digest.clone();
        Ok(DaggerPipelineResultProposal::new(evidence))
    }

    pub fn verify(&self, proposal: &DaggerPipelineResultProposal) -> VerificationReport {
        let evidence_digest = Some(proposal.evidence.evidence_digest.clone());
        if proposal.validate_integrity(&self.scope).is_err() {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::Tampered),
                evidence_digest,
                connected: false,
                native: false,
                durable_provider_receipt: false,
            };
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::RegistrationMismatch),
                evidence_digest,
                connected: false,
                native: false,
                durable_provider_receipt: false,
            };
        }
        if !proposal.state.is_terminal() {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::NonTerminal),
                evidence_digest,
                connected: false,
                native: false,
                durable_provider_receipt: false,
            };
        }
        if proposal.state.is_failure() {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::ProviderFailure),
                evidence_digest,
                connected: false,
                native: false,
                durable_provider_receipt: false,
            };
        }
        VerificationReport {
            valid: true,
            failure: None,
            evidence_digest,
            connected: false,
            native: false,
            durable_provider_receipt: false,
        }
    }

    pub fn record_observation_receipt(
        &mut self,
        proposal: &DaggerPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<DaggerRecordingReceipt> {
        self.check_proposal(proposal)?;
        let idempotency_key = idempotency_key.into();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
            || idempotency_key.trim() != idempotency_key
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(DaggerPipelineResultError::InvalidRequest);
        }
        let idempotency_digest =
            Digest::from_parts("dagger-recording-key/v1", &[("key", idempotency_key)]);
        if let Some(existing) = self.recordings.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(DaggerPipelineResultError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let receipt = DaggerRecordingReceipt::new(
            idempotency_digest.clone(),
            proposal.proposal_digest.clone(),
            proposal.scope_digest.clone(),
            proposal.registration_digest.clone(),
            false,
        );
        receipt.validate()?;
        self.recordings.insert(idempotency_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn record(
        &mut self,
        proposal: &DaggerPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<DaggerRecordingReceipt> {
        self.record_observation_receipt(proposal, idempotency_key)
    }

    fn check_proposal(&self, proposal: &DaggerPipelineResultProposal) -> Result<()> {
        proposal.validate_integrity(&self.scope)?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(DaggerPipelineResultError::RevisionMismatch);
        }
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn consumer(&self) -> Result<MissionDaggerPipelineConsumer> {
        MissionDaggerPipelineConsumer::new(self.scope.clone(), self.registration.clone())
    }
}

#[allow(dead_code)]
fn _service_ids_are_bound() -> Digest {
    canonical_digest(&(SERVICE_ID, PROVIDER_ID, CONSUMER_ID, MAX_METADATA_ITEMS))
}

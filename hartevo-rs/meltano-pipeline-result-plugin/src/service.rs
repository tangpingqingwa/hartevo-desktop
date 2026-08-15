use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::consumer::MissionMeltanoPipelineConsumer;
use crate::error::{MeltanoPipelineResultError, MeltanoTransportError, Result};
use crate::model::{
    Digest, MeltanoConfigMetadata, MeltanoEvidenceDigests, MeltanoEvidenceState,
    MeltanoFailureReceipt, MeltanoJobStatus, MeltanoObservationReceipt, MeltanoPipelineEvidence,
    MeltanoPipelineRegistration, MeltanoPipelineResultProposal, MeltanoPipelineResultScope,
    MeltanoRateLimitReceipt, MeltanoRecordingReceipt, MeltanoRegistration, MeltanoRetryReceipt,
    MeltanoStateMetadata, RegistrationStatus, RegistrationTransitionEvidence, SecretReference,
    canonical_digest,
};
use crate::provider::{
    MeltanoPipelineReadRequest, MeltanoPipelineResultResponse, MeltanoProvider, MeltanoTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA, FORBIDDEN_OPERATIONS, MAX_IDENTIFIER_BYTES, MAX_METADATA_ITEMS,
    PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
};

pub type MeltanoPipelineResultServiceError = MeltanoPipelineResultError;

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize)]
pub enum VerificationFailure {
    #[error("proposal integrity is invalid")]
    Tamper,
    #[error("proposal is outside the service scope")]
    ScopeMismatch,
    #[error("proposal registration or cursor is stale")]
    Stale,
    #[error("proposal registration is revoked")]
    Revoked,
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
    pub first_party: bool,
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
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub outcome_authority: bool,
    pub work_product_authority: bool,
}

pub struct MeltanoPipelineResultService<T: MeltanoTransport> {
    scope: MeltanoPipelineResultScope,
    secret_reference: SecretReference,
    provider: MeltanoProvider<T>,
    registration: MeltanoRegistration,
    recordings: BTreeMap<Digest, MeltanoRecordingReceipt>,
    now_epoch_seconds: u64,
}

impl<T: MeltanoTransport> fmt::Debug for MeltanoPipelineResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeltanoPipelineResultService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: MeltanoTransport> MeltanoPipelineResultService<T> {
    pub fn new(
        scope: MeltanoPipelineResultScope,
        secret_reference: SecretReference,
        provider: MeltanoProvider<T>,
        now_epoch_seconds: u64,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        let registration = MeltanoRegistration::new(
            &scope,
            &secret_reference,
            provider.definition().digest(),
            &provider.definition().permissions,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            recordings: BTreeMap::new(),
            now_epoch_seconds,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &MeltanoPipelineResultScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &MeltanoPipelineRegistration {
        &self.registration
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn provider(&self) -> &MeltanoProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut MeltanoProvider<T> {
        &mut self.provider
    }

    pub fn set_now_epoch_seconds(&mut self, now_epoch_seconds: u64) {
        self.now_epoch_seconds = now_epoch_seconds;
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_schema: CONTRACT_SCHEMA.to_owned(),
            operations: self.provider.definition().operations.clone(),
            forbidden_operations: FORBIDDEN_OPERATIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            outcome_authority: false,
            work_product_authority: false,
        }
    }

    pub fn default_request(
        &self,
        idempotency_key: impl Into<String>,
    ) -> Result<MeltanoPipelineReadRequest> {
        MeltanoPipelineReadRequest::for_scope(&self.scope, idempotency_key)
    }

    pub fn propose(
        &mut self,
        request: MeltanoPipelineReadRequest,
    ) -> Result<MeltanoPipelineResultProposal> {
        if let Err(error) = self.check_request(&request) {
            return match error {
                MeltanoPipelineResultError::RegistrationRevoked
                | MeltanoPipelineResultError::RegistrationReversed => {
                    self.failure_proposal(&request, error)
                }
                _ => Err(error),
            };
        }
        let proposal = match self.provider.read(&request) {
            Ok(response) => self.success_proposal(&request, response),
            Err(error) => self.failure_proposal(&request, error)?,
        };
        Ok(proposal)
    }

    pub fn read(
        &mut self,
        request: MeltanoPipelineReadRequest,
    ) -> Result<MeltanoPipelineResultProposal> {
        self.propose(request)
    }

    pub fn compile_evidence_proposal(
        &mut self,
        request: MeltanoPipelineReadRequest,
    ) -> Result<MeltanoPipelineResultProposal> {
        self.propose(request)
    }

    fn check_request(&self, request: &MeltanoPipelineReadRequest) -> Result<()> {
        self.scope.validate()?;
        request.validate(&self.scope)?;
        self.registration.validate()?;
        if self.registration.scope_digest != self.scope.digest()
            || self.registration.secret_reference_digest
                != *self.secret_reference.reference_digest()
        {
            return Err(MeltanoPipelineResultError::ScopeMismatch);
        }
        match self.registration.status() {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Revoked => Err(MeltanoPipelineResultError::RegistrationRevoked),
            RegistrationStatus::Reversed => Err(MeltanoPipelineResultError::RegistrationReversed),
        }
    }

    fn success_proposal(
        &self,
        request: &MeltanoPipelineReadRequest,
        response: MeltanoPipelineResultResponse,
    ) -> MeltanoPipelineResultProposal {
        let state = evidence_state_for_response(&response);
        let state_metadata = response.state_metadata;
        let config = response.config;
        let job = response.job;
        let pipeline = response.pipeline;
        let cursor = response.next_cursor;
        let state_digest = state_metadata
            .as_ref()
            .map(|value| value.state_digest.clone())
            .or_else(|| job.as_ref().and_then(|value| value.state_digest.clone()));
        let config_digest = config
            .as_ref()
            .map(|value| value.config_digest.clone())
            .or_else(|| {
                pipeline
                    .as_ref()
                    .and_then(|value| value.config_digest.clone())
            })
            .or_else(|| job.as_ref().and_then(|value| value.config_digest.clone()));
        let receipt = MeltanoObservationReceipt::new(
            request.request_digest().clone(),
            response.response_digest,
            Some(response.status_code),
            response.transport,
            self.now_epoch_seconds,
        );
        let mut digests = self.evidence_digests(
            state_metadata.as_ref(),
            config.as_ref(),
            cursor.as_ref(),
            state_digest,
            config_digest,
        );
        let mut evidence = MeltanoPipelineEvidence {
            state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            request_digest: request.request_digest().clone(),
            transport: response.transport,
            pipeline,
            job,
            state_metadata,
            config,
            next_cursor: cursor,
            has_more: response.has_more,
            retry: response.retry,
            rate_limit: response.rate_limit,
            failure: None,
            observation_receipt: receipt,
            evidence_digests: digests.clone(),
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.calculate_evidence_digest();
        digests.evidence_digest = evidence.evidence_digest.clone();
        evidence.evidence_digests = digests;
        MeltanoPipelineResultProposal::new(evidence)
    }

    fn failure_proposal(
        &self,
        request: &MeltanoPipelineReadRequest,
        error: MeltanoPipelineResultError,
    ) -> Result<MeltanoPipelineResultProposal> {
        let (state, category, retry_after_seconds, status_code, retryable) = match &error {
            MeltanoPipelineResultError::Transport(transport) => match transport {
                MeltanoTransportError::BlockedEnv => (
                    MeltanoEvidenceState::BlockedEnv,
                    "blocked_env",
                    None,
                    None,
                    false,
                ),
                MeltanoTransportError::RateLimited {
                    retry_after_seconds,
                } => (
                    MeltanoEvidenceState::RateLimited,
                    "rate_limited",
                    *retry_after_seconds,
                    transport.status_code(),
                    true,
                ),
                MeltanoTransportError::Expired => (
                    MeltanoEvidenceState::Expired,
                    "expired",
                    None,
                    transport.status_code(),
                    false,
                ),
                MeltanoTransportError::Stale => (
                    MeltanoEvidenceState::Stale,
                    "stale",
                    None,
                    transport.status_code(),
                    false,
                ),
                transport if transport.is_access_loss() => (
                    MeltanoEvidenceState::AccessLoss,
                    "access_loss",
                    None,
                    transport.status_code(),
                    false,
                ),
                MeltanoTransportError::Partial => {
                    (MeltanoEvidenceState::Partial, "partial", None, None, false)
                }
                _ => (
                    MeltanoEvidenceState::ProviderUnknown,
                    "provider_unknown",
                    None,
                    transport.status_code(),
                    matches!(
                        transport,
                        MeltanoTransportError::Timeout | MeltanoTransportError::ServerError { .. }
                    ),
                ),
            },
            MeltanoPipelineResultError::RegistrationRevoked
            | MeltanoPipelineResultError::RegistrationReversed => {
                (MeltanoEvidenceState::Revoked, "revoked", None, None, false)
            }
            MeltanoPipelineResultError::TamperedEvidence
            | MeltanoPipelineResultError::ScopeMismatch => {
                (MeltanoEvidenceState::Tamper, "tamper", None, None, false)
            }
            MeltanoPipelineResultError::RevisionMismatch => {
                (MeltanoEvidenceState::Stale, "stale", None, None, false)
            }
            _ => (
                MeltanoEvidenceState::ProviderUnknown,
                "provider_unknown",
                None,
                None,
                false,
            ),
        };
        let failure =
            MeltanoFailureReceipt::new(category, status_code, error.to_string(), retryable)?;
        let retry = MeltanoRetryReceipt::new(1, 1, retry_after_seconds, retryable).ok();
        let rate_limit = if matches!(state, MeltanoEvidenceState::RateLimited) {
            Some(MeltanoRateLimitReceipt::new(
                retry_after_seconds,
                self.now_epoch_seconds,
            )?)
        } else {
            None
        };
        let response_digest = Digest::from_parts(
            "meltano-failure-response/v1",
            &[
                ("request", request.request_digest().as_str().to_owned()),
                ("category", category.to_owned()),
                ("error", error.to_string()),
            ],
        );
        let receipt = MeltanoObservationReceipt::new(
            request.request_digest().clone(),
            response_digest,
            status_code,
            self.provider.provenance(),
            self.now_epoch_seconds,
        );
        let mut digests = self.evidence_digests(None, None, request.cursor(), None, None);
        let mut evidence = MeltanoPipelineEvidence {
            state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            request_digest: request.request_digest().clone(),
            transport: self.provider.provenance(),
            pipeline: None,
            job: None,
            state_metadata: None,
            config: None,
            next_cursor: None,
            has_more: false,
            retry,
            rate_limit,
            failure: Some(failure),
            observation_receipt: receipt,
            evidence_digests: digests.clone(),
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.calculate_evidence_digest();
        digests.evidence_digest = evidence.evidence_digest.clone();
        evidence.evidence_digests = digests;
        Ok(MeltanoPipelineResultProposal::new(evidence))
    }

    fn evidence_digests(
        &self,
        state_metadata: Option<&MeltanoStateMetadata>,
        config: Option<&MeltanoConfigMetadata>,
        cursor: Option<&crate::model::MeltanoCursor>,
        state_digest: Option<Digest>,
        config_digest: Option<Digest>,
    ) -> MeltanoEvidenceDigests {
        MeltanoEvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest: self.provider.definition().digest(),
            permission_digest: self.provider.definition().permissions.digest(),
            scope_digest: self.scope.digest(),
            secret_reference_digest: self.secret_reference.reference_digest().clone(),
            pipeline_digest: self.scope.pipeline().digest(),
            job_digest: self.scope.job().map(crate::model::MeltanoJobId::digest),
            plugin_digest: self
                .scope
                .plugin()
                .map(crate::model::MeltanoPluginName::digest),
            state_id_digest: self
                .scope
                .state_id()
                .map(crate::model::MeltanoStateId::digest),
            state_digest: state_digest
                .or_else(|| state_metadata.map(|value| value.state_digest.clone())),
            config_digest: config_digest
                .or_else(|| config.map(|value| value.config_digest.clone())),
            cursor_digest: cursor.map(crate::model::MeltanoCursor::digest),
            evidence_digest: Digest::from_text("pending"),
        }
    }

    pub fn verify(&self, proposal: &MeltanoPipelineResultProposal) -> VerificationReport {
        let evidence_digest = Some(proposal.evidence.evidence_digest.clone());
        if proposal.validate_integrity(&self.scope).is_err() {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::Tamper),
                evidence_digest,
                connected: false,
                native: false,
                first_party: false,
                durable_provider_receipt: false,
            };
        }
        if proposal.scope_digest != self.scope.digest() {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::ScopeMismatch),
                evidence_digest,
                connected: false,
                native: false,
                first_party: false,
                durable_provider_receipt: false,
            };
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::Stale),
                evidence_digest,
                connected: false,
                native: false,
                first_party: false,
                durable_provider_receipt: false,
            };
        }
        if !self.registration.is_active() || proposal.state == MeltanoEvidenceState::Revoked {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::Revoked),
                evidence_digest,
                connected: false,
                native: false,
                first_party: false,
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
                first_party: false,
                durable_provider_receipt: false,
            };
        }
        if proposal.state != MeltanoEvidenceState::Success {
            return VerificationReport {
                valid: false,
                failure: Some(VerificationFailure::ProviderFailure),
                evidence_digest,
                connected: false,
                native: false,
                first_party: false,
                durable_provider_receipt: false,
            };
        }
        VerificationReport {
            valid: true,
            failure: None,
            evidence_digest,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
        }
    }

    pub fn record_observation_receipt(
        &mut self,
        proposal: &MeltanoPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<MeltanoRecordingReceipt> {
        self.check_proposal(proposal)?;
        let idempotency_key = idempotency_key.into();
        if !valid_idempotency_key(&idempotency_key) {
            return Err(MeltanoPipelineResultError::InvalidRequest);
        }
        let idempotency_digest =
            Digest::from_parts("meltano-recording-key/v1", &[("key", idempotency_key)]);
        if let Some(existing) = self.recordings.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MeltanoPipelineResultError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let receipt = MeltanoRecordingReceipt::new(
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
        proposal: &MeltanoPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<MeltanoRecordingReceipt> {
        self.record_observation_receipt(proposal, idempotency_key)
    }

    fn check_proposal(&self, proposal: &MeltanoPipelineResultProposal) -> Result<()> {
        proposal.validate_integrity(&self.scope)?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(MeltanoPipelineResultError::RevisionMismatch);
        }
        if !self.registration.is_active() {
            return Err(MeltanoPipelineResultError::RegistrationInactive);
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

    pub fn consumer(&self) -> Result<MissionMeltanoPipelineConsumer> {
        MissionMeltanoPipelineConsumer::new(self.scope.clone(), self.registration.clone())
    }
}

fn evidence_state_for_response(response: &MeltanoPipelineResultResponse) -> MeltanoEvidenceState {
    if let Some(job) = &response.job {
        return match job.status {
            MeltanoJobStatus::Queued => MeltanoEvidenceState::Queued,
            MeltanoJobStatus::Running => MeltanoEvidenceState::Running,
            MeltanoJobStatus::Complete => MeltanoEvidenceState::Success,
            MeltanoJobStatus::Error => MeltanoEvidenceState::Error,
            MeltanoJobStatus::Stopped => MeltanoEvidenceState::Stopped,
            MeltanoJobStatus::Unknown => MeltanoEvidenceState::ProviderUnknown,
        };
    }
    if let Some(pipeline) = &response.pipeline {
        return match pipeline.status {
            crate::model::MeltanoPipelineStatus::Draft => MeltanoEvidenceState::Queued,
            crate::model::MeltanoPipelineStatus::Provisioning => MeltanoEvidenceState::Running,
            crate::model::MeltanoPipelineStatus::Ready => MeltanoEvidenceState::Success,
            crate::model::MeltanoPipelineStatus::Failed => MeltanoEvidenceState::Error,
            crate::model::MeltanoPipelineStatus::Unknown => MeltanoEvidenceState::ProviderUnknown,
        };
    }
    MeltanoEvidenceState::Success
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[allow(dead_code)]
fn _service_ids_are_bound() -> Digest {
    canonical_digest(&(SERVICE_ID, PROVIDER_ID, CONSUMER_ID, MAX_METADATA_ITEMS))
}

//! Mission-scoped proposal consumption and process-local recording.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Digest, EvidenceState, ModelError, TransportProvenance, VeracodeScope};
use crate::provider::{
    ReadBounds, VeracodeProvider, VeracodeProviderError, VeracodeReadRequest, VeracodeTransport,
};
pub use crate::service::ProposalDisposition;
use crate::service::{
    RegistrationTransitionReceipt, ServiceError, VeracodeEvidence, VeracodeProposal,
    VeracodeRegistration, VeracodeResultService, VeracodeVerificationReport,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionVeracodeConsumerError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("service validation failed: {0}")]
    Service(#[from] ServiceError),
    #[error("provider validation failed: {0}")]
    Provider(#[from] VeracodeProviderError),
    #[error("consumer and registration scopes differ")]
    ScopeMismatch,
    #[error("recording idempotency key is empty or too long")]
    InvalidIdempotencyKey,
    #[error("recording idempotency key was reused for different evidence")]
    RecordingConflict,
    #[error("registration is not active")]
    RegistrationInactive,
}

pub type ConsumerError = MissionVeracodeConsumerError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeMissionResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project_revision: crate::model::Revision,
    pub mission_revision: crate::model::Revision,
    pub work_product_revision: crate::model::Revision,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl VeracodeMissionResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedVeracodeResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedVeracodeResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &VeracodeProposal,
        replayed: bool,
    ) -> Result<Self, ServiceError> {
        let mut value = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.disposition,
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-veracode-recording"),
        };
        value.recording_digest = value.calculate_digest()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.idempotency_key_digest,
            &self.proposal_digest,
            self.state,
            self.disposition,
            self.provenance,
            self.replayed,
            self.connected,
            self.native,
            self.first_party,
            self.provider_receipt,
            self.outcome_adopted,
            self.work_product_adopted,
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), ConsumerError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()?
        {
            return Err(ServiceError::TamperedEvidence.into());
        }
        Ok(())
    }
}

/// A Mission consumer bound to one exact Project/Mission/Work Product scope
/// and one active registration. Its recording map is process-local and only
/// retains digests and state; it is not a durable provider receipt authority.
pub struct MissionVeracodeResultConsumer {
    scope: VeracodeScope,
    registration: VeracodeRegistration,
    service: VeracodeResultService,
    records: BTreeMap<Digest, RecordedVeracodeResult>,
}

impl fmt::Debug for MissionVeracodeResultConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionVeracodeResultConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionVeracodeResultConsumer {
    pub fn new(
        scope: VeracodeScope,
        registration: VeracodeRegistration,
    ) -> Result<Self, ConsumerError> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(ConsumerError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            service: VeracodeResultService::new(),
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &VeracodeScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &VeracodeRegistration {
        &self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn request(&self, bounds: ReadBounds) -> Result<VeracodeReadRequest, ConsumerError> {
        Ok(VeracodeReadRequest::for_registration(
            &self.scope,
            &self.registration,
            bounds,
        )?)
    }

    pub fn consume(
        &self,
        proposal: &VeracodeProposal,
    ) -> Result<VeracodeMissionResult, ConsumerError> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(ConsumerError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.project_revision != self.scope.project.revision
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.work_product_revision != self.scope.work_product.revision
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(VeracodeMissionResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project_revision: proposal.project_revision,
            mission_revision: proposal.mission_revision,
            work_product_revision: proposal.work_product_revision,
            state: proposal.state,
            disposition: proposal.disposition,
            evidence_digest: proposal.evidence_digest.clone(),
            provenance: proposal.evidence.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn read_proposal<T: VeracodeTransport>(
        &mut self,
        provider: &mut VeracodeProvider<T>,
        request: &VeracodeReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<VeracodeProposal, ConsumerError> {
        if provider.registration().registration_digest() != self.registration.registration_digest()
            || request.scope_digest != self.scope.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let evidence = match provider.read(request, observed_at) {
            Ok(read) => self
                .service
                .evidence_from_read(&self.registration, request, read)?,
            Err(error) => self.service.evidence_from_provider_error(
                &self.registration,
                request,
                provider.provenance(),
                &error,
                observed_at,
            )?,
        };
        Ok(self
            .service
            .compile_proposal(&self.registration, evidence)?)
    }

    pub fn read<T: VeracodeTransport>(
        &mut self,
        provider: &mut VeracodeProvider<T>,
        request: &VeracodeReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<VeracodeMissionResult, ConsumerError> {
        let proposal = self.read_proposal(provider, request, observed_at)?;
        self.consume(&proposal)
    }

    pub fn read_with_bounds<T: VeracodeTransport>(
        &mut self,
        provider: &mut VeracodeProvider<T>,
        bounds: ReadBounds,
        observed_at: DateTime<Utc>,
    ) -> Result<VeracodeMissionResult, ConsumerError> {
        let request = self.request(bounds)?;
        self.read(provider, &request, observed_at)
    }

    pub fn verify(&self, proposal: &VeracodeProposal) -> VeracodeVerificationReport {
        self.service
            .verify_evidence(&self.registration, &proposal.evidence)
    }

    pub fn record(
        &mut self,
        proposal: &VeracodeProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedVeracodeResult, ConsumerError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let replay = RecordedVeracodeResult::new(key_digest, proposal, true)?;
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedVeracodeResult::new(key_digest.clone(), proposal, false)?;
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn registration_transition_revoke(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, ConsumerError> {
        Ok(self.registration.revoke()?)
    }

    pub fn registration_transition_restore(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, ConsumerError> {
        Ok(self.registration.restore()?)
    }

    pub fn registration_transition_reverse(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, ConsumerError> {
        Ok(self.registration.reverse()?)
    }

    #[must_use]
    pub fn evidence_is_review_only(evidence: &VeracodeEvidence) -> bool {
        evidence.review_only && !evidence.connected && !evidence.native && !evidence.first_party
    }
}

pub type MissionVeracodeSecurityConsumer = MissionVeracodeResultConsumer;
pub type MissionVeracodeConsumer = MissionVeracodeResultConsumer;
pub type VeracodeResultConsumer = MissionVeracodeResultConsumer;
pub type VeracodeApplicationSecurityConsumer = MissionVeracodeResultConsumer;

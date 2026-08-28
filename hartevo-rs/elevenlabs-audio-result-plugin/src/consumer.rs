use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::{
    canonical::digest_serializable,
    provider::{
        AudioContentEvidence, AudioStatusProjection, ProviderProvenance, SynthesisReceipt,
        SynthesisStatus, UsageEvidence,
    },
    registration::{ElevenLabsAudioResultRegistration, RegistrationError},
    types::{AudioGenerationProposal, Digest, MissionScope, OperationId, WorkProductId},
};

/// Consumer decision. Layer 1 can propose a Work Product boundary but never
/// performs durable adoption.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDecision {
    ReadyForWorkProductProposal,
}

/// An exact-scope, digest-bound audio Work Product proposal. It contains no
/// raw text and no raw audio bytes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioWorkProductProposal {
    scope: MissionScope,
    work_product_id: WorkProductId,
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    text_digest: Digest,
    config_digest: Digest,
    usage_digest: Digest,
    audio_content_digest: Digest,
    status_receipt_digest: Digest,
    registration_digest: Digest,
    provider_provenance: ProviderProvenance,
    decision: AdoptionDecision,
    adoption_fingerprint: Digest,
}

/// Compatibility name for callers using the generic adoption proposal term.
pub type AdoptionProposal = AudioWorkProductProposal;

impl AudioWorkProductProposal {
    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub fn text_digest(&self) -> &Digest {
        &self.text_digest
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub fn usage_digest(&self) -> &Digest {
        &self.usage_digest
    }

    pub fn audio_content_digest(&self) -> &Digest {
        &self.audio_content_digest
    }

    pub fn status_receipt_digest(&self) -> &Digest {
        &self.status_receipt_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn provider_provenance(&self) -> ProviderProvenance {
        self.provider_provenance
    }

    pub const fn decision(&self) -> AdoptionDecision {
        self.decision
    }

    pub fn adoption_fingerprint(&self) -> &Digest {
        &self.adoption_fingerprint
    }

    pub fn verify_fingerprint(&self) -> bool {
        digest_serializable(&AdoptionMaterial {
            scope_digest: self.scope.digest(),
            operation_id: self.operation_id.clone(),
            proposal_fingerprint: self.proposal_fingerprint.clone(),
            text_digest: self.text_digest.clone(),
            config_digest: self.config_digest.clone(),
            usage_digest: self.usage_digest.clone(),
            audio_content_digest: self.audio_content_digest.clone(),
            status_receipt_digest: self.status_receipt_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            decision: self.decision,
        }) == self.adoption_fingerprint
    }
}

/// Mission consumer validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("status receipt does not bind the exact Mission proposal")]
    ProposalMismatch,
    #[error("status receipt operation identity does not match the proposal")]
    OperationMismatch,
    #[error("status receipt does not bind the Mission consumer scope")]
    ScopeMismatch,
    #[error("status receipt is stale or regresses the observed projection")]
    StaleStatus,
    #[error("completed status is required before a Work Product proposal")]
    NotCompleted,
    #[error("completed status is missing usage evidence")]
    MissingUsage,
    #[error("completed status is missing exact audio content evidence")]
    MissingContentDigest,
    #[error("usage receipt digest is invalid or tampered")]
    UsageDigestMismatch,
    #[error("usage evidence does not match the exact bounded objective")]
    UsageMismatch,
    #[error("usage or duration exceeds the bounded objective")]
    UsageLimitExceeded,
    #[error("audio content receipt digest is invalid or tampered")]
    ContentEvidenceTampered,
    #[error("provider and independent audio content digests disagree")]
    ContentDigestMismatch,
    #[error("status receipt digest is invalid or tampered")]
    ReceiptDigestMismatch,
    #[error("redacted evidence is truncated and cannot form an adoption proposal")]
    RedactedEvidence,
    #[error("adoption proposal fingerprint was already emitted")]
    DuplicateFingerprint,
    #[error("invalid current time")]
    InvalidTime,
}

/// Typed Mission consumer with status and Work Product proposal idempotency
/// fences.
pub struct MissionAudioResultConsumer {
    registration: ElevenLabsAudioResultRegistration,
    observed_statuses: BTreeMap<Digest, ObservedStatus>,
    adoption_fingerprints: BTreeSet<Digest>,
}

impl MissionAudioResultConsumer {
    pub fn new(registration: ElevenLabsAudioResultRegistration) -> Result<Self, ConsumerError> {
        registration.ensure_active()?;
        Ok(Self {
            registration,
            observed_statuses: BTreeMap::new(),
            adoption_fingerprints: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &ElevenLabsAudioResultRegistration {
        &self.registration
    }

    /// Project and retain every bounded async status state.
    pub fn project_status(
        &mut self,
        receipt: &SynthesisReceipt,
    ) -> Result<AudioStatusProjection, ConsumerError> {
        self.registration.ensure_active()?;
        if !self.registration.verify_digest() {
            return Err(ConsumerError::Registration(
                RegistrationError::InvalidDigest,
            ));
        }
        self.registration.ensure_scope(receipt.scope())?;
        self.validate_receipt_registration(receipt)?;
        if !receipt.verify_digest() {
            return Err(ConsumerError::ReceiptDigestMismatch);
        }
        let fingerprint = receipt.proposal_fingerprint().clone();
        if let Some(previous) = self.observed_statuses.get(&fingerprint) {
            if previous.operation_id != *receipt.operation_id()
                || receipt.status().rank() < previous.status.rank()
                || (previous.status.is_terminal() && previous.status != receipt.status())
            {
                return Err(ConsumerError::StaleStatus);
            }
            if previous.status == receipt.status()
                && previous.receipt_digest == *receipt.receipt_digest()
            {
                return Ok(receipt.projection());
            }
        }
        self.observed_statuses.insert(
            fingerprint,
            ObservedStatus {
                operation_id: receipt.operation_id().clone(),
                status: receipt.status(),
                receipt_digest: receipt.receipt_digest().clone(),
            },
        );
        Ok(receipt.projection())
    }

    /// Emit a reversible Work Product proposal from exact completed evidence.
    /// This does not persist, download, or adopt an audio file.
    pub fn propose_work_product(
        &mut self,
        proposal: &AudioGenerationProposal,
        receipt: &SynthesisReceipt,
    ) -> Result<AudioWorkProductProposal, ConsumerError> {
        self.registration.ensure_active()?;
        if !self.registration.verify_digest() || !proposal.verify_digest() {
            return Err(ConsumerError::ProposalMismatch);
        }
        self.registration.ensure_scope(proposal.scope())?;
        self.registration.ensure_scope(receipt.scope())?;
        self.validate_receipt_registration(receipt)?;
        if proposal.registration_digest() != self.registration.registration_digest()
            || proposal.provider_version() != self.registration.provider_version()
            || receipt.proposal_fingerprint() != proposal.fence().fingerprint()
            || receipt.binding() != proposal.binding()
        {
            return Err(ConsumerError::ProposalMismatch);
        }
        if receipt.operation_id() != proposal.fence().operation_id() {
            return Err(ConsumerError::OperationMismatch);
        }
        if !receipt.verify_digest() {
            return Err(ConsumerError::ReceiptDigestMismatch);
        }
        if receipt.status() != SynthesisStatus::Completed {
            return Err(ConsumerError::NotCompleted);
        }
        let usage = receipt.usage().ok_or(ConsumerError::MissingUsage)?;
        let content = receipt
            .content()
            .ok_or(ConsumerError::MissingContentDigest)?;
        validate_usage(proposal, usage)?;
        validate_content(proposal.scope(), usage, content)?;
        if usage.redaction().is_truncated() || content.redaction().is_truncated() {
            return Err(ConsumerError::RedactedEvidence);
        }
        let adoption_fingerprint = digest_serializable(&AdoptionMaterial {
            scope_digest: proposal.scope().digest(),
            operation_id: receipt.operation_id().clone(),
            proposal_fingerprint: proposal.fence().fingerprint().clone(),
            text_digest: proposal.text_digest(),
            config_digest: proposal.config_digest(),
            usage_digest: usage.usage_digest().clone(),
            audio_content_digest: content.audio_content_digest().clone(),
            status_receipt_digest: receipt.receipt_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            decision: AdoptionDecision::ReadyForWorkProductProposal,
        });
        if !self
            .adoption_fingerprints
            .insert(adoption_fingerprint.clone())
        {
            return Err(ConsumerError::DuplicateFingerprint);
        }
        Ok(AudioWorkProductProposal {
            scope: proposal.scope().clone(),
            work_product_id: proposal.scope().work_product().work_product_id().clone(),
            operation_id: receipt.operation_id().clone(),
            proposal_fingerprint: proposal.fence().fingerprint().clone(),
            text_digest: proposal.text_digest(),
            config_digest: proposal.config_digest(),
            usage_digest: usage.usage_digest().clone(),
            audio_content_digest: content.audio_content_digest().clone(),
            status_receipt_digest: receipt.receipt_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_provenance: receipt.evidence().provenance(),
            decision: AdoptionDecision::ReadyForWorkProductProposal,
            adoption_fingerprint,
        })
    }

    /// Compatibility name for consumers using generic adoption terminology.
    pub fn propose_adoption(
        &mut self,
        proposal: &AudioGenerationProposal,
        receipt: &SynthesisReceipt,
    ) -> Result<AudioWorkProductProposal, ConsumerError> {
        self.propose_work_product(proposal, receipt)
    }

    fn validate_receipt_registration(
        &self,
        receipt: &SynthesisReceipt,
    ) -> Result<(), ConsumerError> {
        if receipt.registration_digest() != self.registration.registration_digest()
            || receipt.provider_version() != self.registration.provider_version()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Debug for MissionAudioResultConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAudioResultConsumer")
            .field("registration", &self.registration)
            .field("observed_status_count", &self.observed_statuses.len())
            .field("adoption_count", &self.adoption_fingerprints.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct ObservedStatus {
    operation_id: OperationId,
    status: SynthesisStatus,
    receipt_digest: Digest,
}

fn validate_usage(
    proposal: &AudioGenerationProposal,
    usage: &UsageEvidence,
) -> Result<(), ConsumerError> {
    if !usage.verify_digest() {
        return Err(ConsumerError::UsageDigestMismatch);
    }
    if usage.input_character_count() != proposal.text_character_count()
        || usage.output_format() != proposal.scope().output_format()
    {
        return Err(ConsumerError::UsageMismatch);
    }
    if usage.input_character_count() > proposal.scope().config().max_character_count()
        || usage
            .billed_character_count()
            .is_some_and(|count| count > proposal.scope().config().max_character_count())
    {
        return Err(ConsumerError::UsageLimitExceeded);
    }
    if usage.duration_milliseconds().is_none() {
        return Err(ConsumerError::UsageMismatch);
    }
    Ok(())
}

fn validate_content(
    scope: &MissionScope,
    usage: &UsageEvidence,
    content: &AudioContentEvidence,
) -> Result<(), ConsumerError> {
    if !content.verify_digest() {
        return Err(ConsumerError::ContentEvidenceTampered);
    }
    if !content.is_consistent() {
        return Err(ConsumerError::ContentDigestMismatch);
    }
    if !content.audio_content_digest().is_valid() {
        return Err(ConsumerError::ContentEvidenceTampered);
    }
    if content.output_format() != scope.output_format()
        || content.duration_milliseconds() > scope.config().max_duration_milliseconds()
        || usage.duration_milliseconds() != Some(content.duration_milliseconds())
    {
        return Err(ConsumerError::UsageMismatch);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptionMaterial {
    scope_digest: Digest,
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    text_digest: Digest,
    config_digest: Digest,
    usage_digest: Digest,
    audio_content_digest: Digest,
    status_receipt_digest: Digest,
    registration_digest: Digest,
    decision: AdoptionDecision,
}

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::{
    canonical::digest_serializable,
    provider::{ArtifactReceipt, OperationReceipt},
    registration::{HeyGenVideoResultRegistration, RegistrationError},
    types::{
        AdoptionFingerprint, AsyncVideoStatus, Digest, GenerationProposal,
        GenerationStatusProjection, MissionScope, OperationId, VideoId,
    },
};

/// Consumer decision for a completed operation. There is deliberately no
/// `Verified` or `Adopted` Layer-1 variant.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDecision {
    BlockedPendingIndependentByteDigest,
    ReadyForLayer2Verification,
}

/// A Mission-bound adoption proposal, never a durable Work Product.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptionProposal {
    scope: MissionScope,
    operation_id: crate::OperationId,
    video_id: crate::VideoId,
    source_digest: Digest,
    artifact_id: crate::ArtifactId,
    artifact_receipt_digest: Digest,
    registration_digest: Digest,
    decision: AdoptionDecision,
    adoption_fingerprint: AdoptionFingerprint,
}

impl AdoptionProposal {
    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn operation_id(&self) -> &crate::OperationId {
        &self.operation_id
    }

    pub fn video_id(&self) -> &crate::VideoId {
        &self.video_id
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub fn artifact_id(&self) -> &crate::ArtifactId {
        &self.artifact_id
    }

    pub fn artifact_receipt_digest(&self) -> &Digest {
        &self.artifact_receipt_digest
    }

    pub fn decision(&self) -> AdoptionDecision {
        self.decision
    }

    pub fn adoption_fingerprint(&self) -> &AdoptionFingerprint {
        &self.adoption_fingerprint
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
}

/// Mission consumer validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("status receipt is missing the provider operation identity")]
    MissingOperationIdentity,
    #[error("status receipt does not bind the exact generation proposal")]
    ProposalMismatch,
    #[error("status receipt is stale or regresses the observed projection")]
    StaleStatus,
    #[error("completed status is required before an adoption proposal")]
    NotCompleted,
    #[error("receipt scope does not match the Mission consumer scope")]
    ScopeMismatch,
    #[error("artifact does not bind the exact provider operation")]
    ArtifactOperationMismatch,
    #[error("artifact metadata does not match exact render expectations")]
    ArtifactMetadataMismatch,
    #[error("artifact receipt digest is invalid or tampered")]
    ArtifactReceiptTampered,
    #[error("artifact URL expired before independent byte evidence was available")]
    ExpiredUrl,
    #[error("provider and independent content digests disagree")]
    ContentDigestMismatch,
    #[error("adoption idempotency fingerprint was already proposed")]
    DuplicateFingerprint,
    #[error("invalid current time")]
    InvalidTime,
}

/// Typed Mission consumer with status and adoption idempotency fences.
pub struct MissionVideoResultConsumer {
    registration: HeyGenVideoResultRegistration,
    observed_statuses: BTreeMap<Digest, ObservedStatus>,
    adoption_fingerprints: BTreeSet<Digest>,
}

impl MissionVideoResultConsumer {
    pub fn new(registration: HeyGenVideoResultRegistration) -> Result<Self, ConsumerError> {
        registration.ensure_active()?;
        Ok(Self {
            registration,
            observed_statuses: BTreeMap::new(),
            adoption_fingerprints: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &HeyGenVideoResultRegistration {
        &self.registration
    }

    /// Project and retain a status receipt, preserving every async state.
    pub fn project_status(
        &mut self,
        receipt: &OperationReceipt,
    ) -> Result<GenerationStatusProjection, ConsumerError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(receipt.scope())?;
        if receipt.registration_digest() != self.registration.registration_digest()
            || receipt.video_id().is_none()
        {
            return Err(ConsumerError::MissingOperationIdentity);
        }
        let fingerprint = receipt.proposal_fingerprint().clone();
        if let Some(previous) = self.observed_statuses.get(&fingerprint)
            && (previous.operation_id.as_str() != receipt.operation_id().as_str()
                || previous.video_id.as_str()
                    != receipt.video_id().expect("checked above").as_str()
                || status_rank(receipt.status()) < status_rank(&previous.status)
                || (previous.status.is_terminal() && previous.status != *receipt.status()))
        {
            return Err(ConsumerError::StaleStatus);
        }
        self.observed_statuses.insert(
            fingerprint,
            ObservedStatus {
                operation_id: receipt.operation_id().clone(),
                video_id: receipt.video_id().expect("checked above").clone(),
                status: receipt.status().clone(),
            },
        );
        Ok(receipt.projection())
    }

    /// Propose adoption only from an exact completed operation and matching
    /// artifact metadata. A missing independent byte digest yields a typed
    /// blocked proposal rather than a false verified result.
    pub fn propose_adoption(
        &mut self,
        proposal: &GenerationProposal,
        status: &OperationReceipt,
        artifact: &ArtifactReceipt,
        now: u64,
    ) -> Result<AdoptionProposal, ConsumerError> {
        self.registration.ensure_active()?;
        if now == 0 {
            return Err(ConsumerError::InvalidTime);
        }
        self.registration.ensure_scope(proposal.scope())?;
        self.registration.ensure_scope(status.scope())?;
        self.registration.ensure_scope(artifact.scope())?;
        if proposal.registration_digest() != self.registration.registration_digest()
            || status.registration_digest() != self.registration.registration_digest()
        {
            return Err(ConsumerError::ProposalMismatch);
        }
        if status.provider_version() != self.registration.provider_version()
            || artifact.registration_digest() != self.registration.registration_digest()
            || artifact.provider_version() != self.registration.provider_version()
            || artifact.operation_receipt_digest() != status.receipt_digest()
        {
            return Err(ConsumerError::ArtifactReceiptTampered);
        }
        if status.proposal_fingerprint() != proposal.fence().fingerprint()
            || status.source_digests() != proposal.source_digests()
        {
            return Err(ConsumerError::ProposalMismatch);
        }
        if !status.status().is_completed() {
            return Err(ConsumerError::NotCompleted);
        }
        let Some(video_id) = status.video_id() else {
            return Err(ConsumerError::MissingOperationIdentity);
        };
        if artifact.operation_id() != status.operation_id() || artifact.video_id() != video_id {
            return Err(ConsumerError::ArtifactOperationMismatch);
        }
        if artifact.metadata_digest() != &artifact.metadata().digest() {
            return Err(ConsumerError::ArtifactReceiptTampered);
        }
        let expected = proposal.scope();
        let render = proposal.render();
        let metadata = artifact.metadata();
        if metadata.dimensions() != render.dimensions()
            || metadata.duration_seconds() < render.duration().minimum_seconds()
            || metadata.duration_seconds() > render.duration().maximum_seconds()
            || metadata.captions() != render.captions()
        {
            return Err(ConsumerError::ArtifactMetadataMismatch);
        }
        if artifact
            .provider_artifact_digest()
            .zip(artifact.independent_content_digest())
            .is_some_and(|(provider, independent)| provider != independent)
        {
            return Err(ConsumerError::ContentDigestMismatch);
        }
        let decision = if artifact.independent_content_digest().is_some() {
            AdoptionDecision::ReadyForLayer2Verification
        } else {
            if artifact.url_expires_at() <= now {
                return Err(ConsumerError::ExpiredUrl);
            }
            AdoptionDecision::BlockedPendingIndependentByteDigest
        };
        let fingerprint = digest_serializable(&AdoptionFingerprintMaterial {
            scope_digest: expected.digest(),
            operation_id: status.operation_id().clone(),
            video_id: video_id.clone(),
            source_digest: proposal.source_digests().source_digest().clone(),
            artifact_id: artifact.artifact_id().clone(),
            artifact_receipt_digest: artifact.receipt_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            decision,
        });
        if !self.adoption_fingerprints.insert(fingerprint.clone()) {
            return Err(ConsumerError::DuplicateFingerprint);
        }
        Ok(AdoptionProposal {
            scope: expected.clone(),
            operation_id: status.operation_id().clone(),
            video_id: video_id.clone(),
            source_digest: proposal.source_digests().source_digest().clone(),
            artifact_id: artifact.artifact_id().clone(),
            artifact_receipt_digest: artifact.receipt_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            decision,
            adoption_fingerprint: AdoptionFingerprint::new(fingerprint),
        })
    }
}

impl std::fmt::Debug for MissionVideoResultConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionVideoResultConsumer")
            .field("registration", &self.registration)
            .field("observed_status_count", &self.observed_statuses.len())
            .field(
                "adoption_fingerprint_count",
                &self.adoption_fingerprints.len(),
            )
            .finish()
    }
}

fn status_rank(status: &AsyncVideoStatus) -> u8 {
    match status {
        AsyncVideoStatus::Pending => 1,
        AsyncVideoStatus::Waiting => 2,
        AsyncVideoStatus::Processing => 3,
        AsyncVideoStatus::Completed
        | AsyncVideoStatus::Failed { .. }
        | AsyncVideoStatus::Cancelled
        | AsyncVideoStatus::ProviderUnknown { .. } => 4,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedStatus {
    operation_id: OperationId,
    video_id: VideoId,
    status: AsyncVideoStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptionFingerprintMaterial {
    scope_digest: Digest,
    operation_id: crate::OperationId,
    video_id: crate::VideoId,
    source_digest: Digest,
    artifact_id: crate::ArtifactId,
    artifact_receipt_digest: Digest,
    registration_digest: Digest,
    decision: AdoptionDecision,
}

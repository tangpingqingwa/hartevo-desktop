use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::AssemblyAiResultError;
use crate::model::{
    AssemblyAiScope, Digest, MissionReference, PluginVersion, ProjectReference, RegistrationState,
    SourceReference, TranscriptReference, TranscriptResultProjection, TranscriptStatusProjection,
    WorkProductReference, canonical_digest,
};
use crate::service::AssemblyAiRegistration;
use crate::{CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID};

/// A proposal is prepared for the next Mission decision but never adopted by
/// Layer 1. Non-completed provider statuses remain review-only and not ready.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    DecisionPending,
    NotReady,
}

impl ProposalDisposition {
    #[must_use]
    pub const fn eligible_for_next_decision(self) -> bool {
        matches!(self, Self::DecisionPending)
    }
}

/// Redacted transcript Work Product proposal. It is an input to the next
/// Mission decision, not a Work Product mutation or verified adoption.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranscriptWorkProductProposal {
    pub proposal_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub mission: MissionReference,
    pub project: ProjectReference,
    pub work_product: WorkProductReference,
    pub source: SourceReference,
    pub transcript: TranscriptReference,
    pub status: TranscriptStatusProjection,
    pub content_digest: Digest,
    pub evidence_digest: Digest,
    pub disposition: ProposalDisposition,
    pub requires_next_mission_decision: bool,
    pub adoption_authorized: bool,
    pub outcome_adoption: bool,
    pub proposal_digest: Digest,
}

impl TranscriptWorkProductProposal {
    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        true
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub fn eligible_for_next_decision(&self) -> bool {
        self.disposition.eligible_for_next_decision()
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        crate::model::validate_text(&self.proposal_id, "proposal_id", 128)?;
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.consumer_id != CONSUMER_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_version != crate::model::PluginVersion::V1
            || !self.scope_digest.is_valid()
            || !self.registration_digest.is_valid()
            || !self.content_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || !self.requires_next_mission_decision
            || self.adoption_authorized
            || self.outcome_adoption
        {
            return Err(AssemblyAiResultError::InvalidProposal);
        }
        if self.proposal_digest != self.calculate_digest() {
            return Err(AssemblyAiResultError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&ProposalDigestMaterial {
            proposal_id: &self.proposal_id,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            consumer_id: &self.consumer_id,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            mission: &self.mission,
            project: &self.project,
            work_product: &self.work_product,
            source: &self.source,
            transcript: &self.transcript,
            status: &self.status,
            content_digest: &self.content_digest,
            evidence_digest: &self.evidence_digest,
            disposition: &self.disposition,
            requires_next_mission_decision: self.requires_next_mission_decision,
            adoption_authorized: self.adoption_authorized,
            outcome_adoption: self.outcome_adoption,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalDigestMaterial<'a> {
    proposal_id: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    consumer_id: &'a str,
    provider_id: &'a str,
    provider_version: &'a PluginVersion,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    mission: &'a MissionReference,
    project: &'a ProjectReference,
    work_product: &'a WorkProductReference,
    source: &'a SourceReference,
    transcript: &'a TranscriptReference,
    status: &'a TranscriptStatusProjection,
    content_digest: &'a Digest,
    evidence_digest: &'a Digest,
    disposition: &'a ProposalDisposition,
    requires_next_mission_decision: bool,
    adoption_authorized: bool,
    outcome_adoption: bool,
}

/// Bounded in-memory recording result. This is not a durable provider receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedTranscriptProposal {
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type TranscriptProposalRecording = RecordedTranscriptProposal;

/// Mission-side read/proposal/recording consumer. It has no Outcome, Effect,
/// Store, speaker identity, or Work Product adoption authority.
#[derive(Clone, Debug)]
pub struct MissionTranscriptResultConsumer {
    scope: AssemblyAiScope,
    registration_digest: Option<Digest>,
    recordings: BTreeMap<Digest, RecordedTranscriptProposal>,
}

impl MissionTranscriptResultConsumer {
    pub fn new(scope: AssemblyAiScope) -> Result<Self, AssemblyAiResultError> {
        scope.validate()?;
        Ok(Self {
            scope,
            registration_digest: None,
            recordings: BTreeMap::new(),
        })
    }

    pub fn for_registration(
        registration: &AssemblyAiRegistration,
    ) -> Result<Self, AssemblyAiResultError> {
        let mut consumer = Self::new(registration.scope().clone())?;
        consumer.registration_digest = Some(registration.binding_digest().clone());
        Ok(consumer)
    }

    #[must_use]
    pub fn scope(&self) -> &AssemblyAiScope {
        &self.scope
    }

    #[must_use]
    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    /// Compile a redacted proposal for the next Mission decision.
    pub fn compile_proposal(
        &self,
        projection: &TranscriptResultProjection,
        proposal_id: impl Into<String>,
    ) -> Result<TranscriptWorkProductProposal, AssemblyAiResultError> {
        projection.validate_integrity()?;
        if projection.scope_digest != self.scope.digest()
            || projection.source != self.scope.source
            || projection.transcript != self.scope.transcript
        {
            return Err(AssemblyAiResultError::ScopeMismatch);
        }
        if let Some(registration_digest) = &self.registration_digest
            && projection.registration_digest != *registration_digest
        {
            return Err(AssemblyAiResultError::RegistrationDrift);
        }
        let disposition = if projection.status.is_completed() && projection.complete {
            ProposalDisposition::DecisionPending
        } else {
            ProposalDisposition::NotReady
        };
        let mut proposal = TranscriptWorkProductProposal {
            proposal_id: proposal_id.into(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST.to_owned())?,
            consumer_id: CONSUMER_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION,
            scope_digest: self.scope.digest(),
            registration_digest: projection.registration_digest.clone(),
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            source: self.scope.source.clone(),
            transcript: self.scope.transcript.clone(),
            status: projection.status.clone(),
            content_digest: projection.content_digest.clone(),
            evidence_digest: projection.evidence_digest.clone(),
            disposition,
            requires_next_mission_decision: true,
            adoption_authorized: false,
            outcome_adoption: false,
            proposal_digest: Digest::from_text("unsealed-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    /// Record idempotently in memory. Replaying the same proposal returns the
    /// same bounded recording; reusing the key for different evidence fails.
    pub fn record_proposal(
        &mut self,
        proposal: &TranscriptWorkProductProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedTranscriptProposal, AssemblyAiResultError> {
        proposal.validate()?;
        let key = idempotency_key.as_ref();
        crate::model::validate_text(key, "idempotency_key", 128)?;
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.recordings.get(&key_digest) {
            if existing.proposal_digest != *proposal.proposal_digest() {
                return Err(AssemblyAiResultError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        if self.recordings.len() >= 64 {
            return Err(AssemblyAiResultError::SegmentLimit);
        }
        let recording = RecordedTranscriptProposal {
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            idempotency_key_digest: key_digest.clone(),
            recording_digest: canonical_digest(&(
                &proposal.proposal_digest,
                &proposal.registration_digest,
                &key_digest,
            )),
            replayed: false,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        };
        self.recordings.insert(key_digest, recording.clone());
        Ok(recording)
    }

    #[must_use]
    pub fn recording_count(&self) -> usize {
        self.recordings.len()
    }

    /// The consumer never turns a proposal into a Work Product or Outcome.
    #[must_use]
    pub const fn can_adopt_work_product(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn can_adopt_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn registration_state_is_active(state: RegistrationState) -> bool {
        matches!(state, RegistrationState::Active)
    }
}

// Typed fields kept in this module make the ownership boundary explicit.
#[allow(dead_code)]
const _CONSUMER_SCOPE_TYPES: Option<(MissionReference, ProjectReference, WorkProductReference)> =
    None;

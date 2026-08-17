use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::DeepgramResultError;
use crate::model::{
    DeepgramScope, DeepgramTranscriptResultEvidence, Digest, TranscriptStatus, canonical_digest,
};
use crate::provider::{DeepgramCredentialResolver, DeepgramProvider};
use crate::service::DeepgramRegistration;
use crate::{CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeepgramProposalDisposition {
    DecisionPending,
    NotReady,
}

impl DeepgramProposalDisposition {
    #[must_use]
    pub const fn eligible_for_next_decision(self) -> bool {
        matches!(self, Self::DecisionPending)
    }
}

/// Review-only redacted proposal. It is an input to the next Mission decision,
/// never a Work Product mutation or verified adoption.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTranscriptResultProposal {
    pub proposal_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub provider_id: String,
    pub provider_version: crate::model::PluginVersion,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub model_digest: Digest,
    pub audio_fingerprint_digest: Digest,
    pub utterance_window_digest: Digest,
    pub status: TranscriptStatus,
    pub evidence_digest: Digest,
    pub disposition: DeepgramProposalDisposition,
    pub requires_next_mission_decision: bool,
    pub adoption_authorized: bool,
    pub outcome_adoption: bool,
    pub proposal_digest: Digest,
}

impl DeepgramTranscriptResultProposal {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn verify_integrity(&self) -> Result<(), DeepgramResultError> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.consumer_id != CONSUMER_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PLUGIN_VERSION
            || !self.scope_digest.is_valid()
            || !self.registration_digest.is_valid()
            || !self.project_digest.is_valid()
            || !self.mission_digest.is_valid()
            || !self.work_product_digest.is_valid()
            || !self.consent_digest.is_valid()
            || !self.request_digest.is_valid()
            || !self.model_digest.is_valid()
            || !self.audio_fingerprint_digest.is_valid()
            || !self.utterance_window_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || !self.requires_next_mission_decision
            || self.adoption_authorized
            || self.outcome_adoption
        {
            return Err(DeepgramResultError::InvalidProposal);
        }
        crate::model::validate_text(&self.proposal_id, "proposal_id", 128)?;
        if self.proposal_digest != calculate_proposal_digest(self) {
            return Err(DeepgramResultError::Tamper);
        }
        Ok(())
    }
}

fn calculate_proposal_digest(proposal: &DeepgramTranscriptResultProposal) -> Digest {
    canonical_digest(&ProposalDigestMaterial {
        proposal_id: &proposal.proposal_id,
        contract_version: &proposal.contract_version,
        contract_digest: &proposal.contract_digest,
        consumer_id: &proposal.consumer_id,
        provider_id: &proposal.provider_id,
        provider_version: &proposal.provider_version,
        scope_digest: &proposal.scope_digest,
        registration_digest: &proposal.registration_digest,
        project_digest: &proposal.project_digest,
        mission_digest: &proposal.mission_digest,
        work_product_digest: &proposal.work_product_digest,
        consent_digest: &proposal.consent_digest,
        request_digest: &proposal.request_digest,
        model_digest: &proposal.model_digest,
        audio_fingerprint_digest: &proposal.audio_fingerprint_digest,
        utterance_window_digest: &proposal.utterance_window_digest,
        status: &proposal.status,
        evidence_digest: &proposal.evidence_digest,
        disposition: proposal.disposition,
        requires_next_mission_decision: proposal.requires_next_mission_decision,
        adoption_authorized: proposal.adoption_authorized,
        outcome_adoption: proposal.outcome_adoption,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalDigestMaterial<'a> {
    proposal_id: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    consumer_id: &'a str,
    provider_id: &'a str,
    provider_version: &'a crate::model::PluginVersion,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    project_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    request_digest: &'a Digest,
    model_digest: &'a Digest,
    audio_fingerprint_digest: &'a Digest,
    utterance_window_digest: &'a Digest,
    status: &'a TranscriptStatus,
    evidence_digest: &'a Digest,
    disposition: DeepgramProposalDisposition,
    requires_next_mission_decision: bool,
    adoption_authorized: bool,
    outcome_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTranscriptProposalRecording {
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTranscriptResultObservation {
    pub consumer_id: String,
    pub consumer_version: crate::model::PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub status: TranscriptStatus,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_write_performed: bool,
    pub work_product_adoption: bool,
    pub outcome_adoption: bool,
    pub observation_digest: Digest,
}

impl DeepgramTranscriptResultObservation {
    fn from_evidence(evidence: &DeepgramTranscriptResultEvidence) -> Self {
        let mut observation = Self {
            consumer_id: CONSUMER_ID.to_owned(),
            consumer_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST.to_owned())
                .expect("contract digest constant is valid"),
            provider_id: PROVIDER_ID.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status.clone(),
            review_only: true,
            connected: false,
            native: false,
            external_write_performed: false,
            work_product_adoption: false,
            outcome_adoption: false,
            observation_digest: Digest::from_text("unsealed-observation"),
        };
        observation.observation_digest = canonical_digest(&(
            &observation.consumer_id,
            observation.consumer_version,
            &observation.contract_version,
            &observation.contract_digest,
            &observation.provider_id,
            &observation.scope_digest,
            &observation.registration_digest,
            &observation.evidence_digest,
            &observation.status,
            observation.review_only,
            observation.connected,
            observation.native,
            observation.external_write_performed,
            observation.work_product_adoption,
            observation.outcome_adoption,
        ));
        observation
    }

    pub fn verify_integrity(&self) -> Result<(), DeepgramResultError> {
        let expected = canonical_digest(&(
            &self.consumer_id,
            self.consumer_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.scope_digest,
            &self.registration_digest,
            &self.evidence_digest,
            &self.status,
            self.review_only,
            self.connected,
            self.native,
            self.external_write_performed,
            self.work_product_adoption,
            self.outcome_adoption,
        ));
        if self.observation_digest != expected
            || self.consumer_id != CONSUMER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.provider_id != PROVIDER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.external_write_performed
            || self.work_product_adoption
            || self.outcome_adoption
        {
            return Err(DeepgramResultError::Tamper);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDeepgramTranscriptResult {
    pub proposal: DeepgramTranscriptResultProposal,
    pub evidence: DeepgramTranscriptResultEvidence,
    pub observation: DeepgramTranscriptResultObservation,
}

impl MissionDeepgramTranscriptResult {
    pub fn validate(&self, scope: &DeepgramScope) -> Result<(), DeepgramResultError> {
        self.proposal.verify_integrity()?;
        self.evidence.validate_integrity()?;
        self.observation.verify_integrity()?;
        if self.proposal.scope_digest != scope.digest()
            || self.evidence.scope_digest != scope.digest()
            || self.observation.scope_digest != scope.digest()
            || self.proposal.project_digest != scope.project.digest()
            || self.proposal.mission_digest != scope.mission.digest()
            || self.proposal.work_product_digest != scope.work_product.digest()
            || self.proposal.consent_digest != scope.consent.digest()
        {
            return Err(DeepgramResultError::ScopeMismatch);
        }
        if self.proposal.evidence_digest != self.evidence.evidence_digest
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.proposal.registration_digest != self.evidence.registration_digest
            || self.proposal.registration_digest != self.observation.registration_digest
        {
            return Err(DeepgramResultError::Tamper);
        }
        Ok(())
    }
}

/// Mission-scoped consumer for exact Project/Mission/Work Product and consent
/// bindings. It only consumes redacted evidence below kernel authority.
#[derive(Clone, Debug)]
pub struct MissionDeepgramTranscriptConsumer {
    registration: DeepgramRegistration,
    consumed_proposals: BTreeSet<Digest>,
    consumed_evidence: BTreeSet<Digest>,
    idempotency: BTreeMap<Digest, Digest>,
}

impl MissionDeepgramTranscriptConsumer {
    pub fn new(registration: DeepgramRegistration) -> Result<Self, DeepgramResultError> {
        registration.validate()?;
        registration.ensure_active()?;
        Ok(Self {
            registration,
            consumed_proposals: BTreeSet::new(),
            consumed_evidence: BTreeSet::new(),
            idempotency: BTreeMap::new(),
        })
    }

    pub fn for_registration(
        registration: &DeepgramRegistration,
    ) -> Result<Self, DeepgramResultError> {
        Self::new(registration.clone())
    }

    #[must_use]
    pub fn registration(&self) -> &DeepgramRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        self.registration.binding_digest()
    }

    #[must_use]
    pub fn scope(&self) -> &DeepgramScope {
        self.registration.scope()
    }

    #[must_use]
    pub const fn can_adopt_work_product(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn can_adopt_outcome(&self) -> bool {
        false
    }

    pub fn compile_proposal(
        &self,
        evidence: &DeepgramTranscriptResultEvidence,
        proposal_id: impl Into<String>,
    ) -> Result<DeepgramTranscriptResultProposal, DeepgramResultError> {
        self.registration.ensure_active()?;
        evidence.validate_integrity()?;
        if evidence.scope_digest != *self.registration.scope_digest()
            || evidence.registration_digest != *self.registration.binding_digest()
        {
            return Err(DeepgramResultError::ScopeMismatch);
        }
        let proposal_id = proposal_id.into();
        crate::model::validate_text(&proposal_id, "proposal_id", 128)?;
        let disposition = if evidence.status.is_complete() {
            DeepgramProposalDisposition::DecisionPending
        } else {
            DeepgramProposalDisposition::NotReady
        };
        let mut proposal = DeepgramTranscriptResultProposal {
            proposal_id,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST.to_owned())?,
            consumer_id: CONSUMER_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION,
            scope_digest: self.registration.scope_digest().clone(),
            registration_digest: self.registration.binding_digest().clone(),
            project_digest: self.scope().project.digest(),
            mission_digest: self.scope().mission.digest(),
            work_product_digest: self.scope().work_product.digest(),
            consent_digest: self.scope().consent.digest(),
            request_digest: self.scope().request.digest(),
            model_digest: self.scope().model.digest(),
            audio_fingerprint_digest: self.scope().audio_fingerprint.scope_digest(),
            utterance_window_digest: self.scope().utterance_window.digest(),
            status: evidence.status.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            disposition,
            requires_next_mission_decision: true,
            adoption_authorized: false,
            outcome_adoption: false,
            proposal_digest: Digest::from_text("unsealed-proposal"),
        };
        proposal.proposal_digest = calculate_proposal_digest(&proposal);
        proposal.verify_integrity()?;
        Ok(proposal)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &DeepgramTranscriptResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<DeepgramTranscriptProposalRecording, DeepgramResultError> {
        self.registration.ensure_active()?;
        proposal.verify_integrity()?;
        if proposal.registration_digest != *self.registration.binding_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
        {
            return Err(DeepgramResultError::ScopeMismatch);
        }
        let idempotency_key = idempotency_key.into();
        crate::model::validate_text(&idempotency_key, "idempotency_key", 128)?;
        let idempotency_digest = Digest::from_text(&idempotency_key);
        if let Some(existing) = self.idempotency.get(&idempotency_digest) {
            if existing != proposal.digest() {
                return Err(DeepgramResultError::IdempotencyConflict);
            }
            return Ok(Self::make_recording(proposal, idempotency_digest, true));
        }
        if !self.consumed_proposals.insert(proposal.digest().clone()) {
            return Err(DeepgramResultError::DuplicateProposal);
        }
        self.idempotency
            .insert(idempotency_digest.clone(), proposal.digest().clone());
        Ok(Self::make_recording(proposal, idempotency_digest, false))
    }

    pub fn consume(
        &mut self,
        proposal: DeepgramTranscriptResultProposal,
        evidence: DeepgramTranscriptResultEvidence,
    ) -> Result<MissionDeepgramTranscriptResult, DeepgramResultError> {
        self.registration.ensure_active()?;
        proposal.verify_integrity()?;
        evidence.validate_integrity()?;
        if proposal.scope_digest != *self.registration.scope_digest()
            || evidence.scope_digest != *self.registration.scope_digest()
            || proposal.registration_digest != *self.registration.binding_digest()
            || evidence.registration_digest != *self.registration.binding_digest()
            || proposal.evidence_digest != evidence.evidence_digest
        {
            return Err(DeepgramResultError::ScopeMismatch);
        }
        if !self.consumed_proposals.insert(proposal.digest().clone())
            || !self
                .consumed_evidence
                .insert(evidence.evidence_digest.clone())
        {
            return Err(DeepgramResultError::DuplicateProposal);
        }
        let observation = DeepgramTranscriptResultObservation::from_evidence(&evidence);
        let result = MissionDeepgramTranscriptResult {
            proposal,
            evidence,
            observation,
        };
        result.validate(self.scope())?;
        Ok(result)
    }

    pub fn read<T, R>(
        &mut self,
        provider: &mut DeepgramProvider<T, R>,
        proposal_id: impl Into<String>,
    ) -> Result<MissionDeepgramTranscriptResult, DeepgramResultError>
    where
        T: crate::transport::DeepgramTransport,
        R: DeepgramCredentialResolver,
    {
        if provider.registration().binding_digest() != self.registration.binding_digest() {
            return Err(DeepgramResultError::RegistrationDrift);
        }
        let evidence = provider
            .read_transcript_result()
            .map_err(reduce_provider_error)?;
        let proposal = self.compile_proposal(&evidence, proposal_id)?;
        self.consume(proposal, evidence)
    }

    pub fn revoke(&self) -> Result<(), DeepgramResultError> {
        self.registration.revoke()
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed_evidence.len()
    }

    fn make_recording(
        proposal: &DeepgramTranscriptResultProposal,
        idempotency_digest: Digest,
        replayed: bool,
    ) -> DeepgramTranscriptProposalRecording {
        let recording_digest = canonical_digest(&(
            CONSUMER_ID,
            proposal.digest(),
            &proposal.evidence_digest,
            &idempotency_digest,
            replayed,
            false,
            false,
        ));
        DeepgramTranscriptProposalRecording {
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.digest().clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            idempotency_digest,
            recording_digest,
            replayed,
            durable_provider_receipt: false,
            kernel_authority: false,
        }
    }
}

// A provider error is deliberately reduced to the typed Layer-1 tamper/error
// boundary at this consumer seam; raw provider diagnostics never cross it.
fn reduce_provider_error(error: crate::error::DeepgramProviderError) -> DeepgramResultError {
    match error {
        crate::error::DeepgramProviderError::Denied => DeepgramResultError::Denied,
        crate::error::DeepgramProviderError::Partial => DeepgramResultError::Partial,
        crate::error::DeepgramProviderError::Expired => DeepgramResultError::Expired,
        crate::error::DeepgramProviderError::RateLimited { .. } => DeepgramResultError::RateLimited,
        crate::error::DeepgramProviderError::ProviderUnknown => {
            DeepgramResultError::ProviderUnknown
        }
        _ => DeepgramResultError::Tamper,
    }
}

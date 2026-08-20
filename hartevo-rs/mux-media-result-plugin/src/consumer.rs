//! Mission-scoped consumer for redacted Mux media-result evidence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, MuxError, MuxMediaResultEvidence, MuxMediaResultProposal, MuxMediaResultRequest,
    MuxRegistration, MuxScope, RegistrationState, digest_serializable,
};
use crate::provider::MuxProvider;
use crate::transport::MuxTransport;
use crate::{
    MISSION_MUX_MEDIA_RESULT_CONSUMER_ID, MUX_MEDIA_RESULT_CONTRACT_VERSION,
    MUX_MEDIA_RESULT_PLUGIN_VERSION, contract_digest, plugin_version_digest, provider_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionMuxMediaObservation {
    pub consumer_id: String,
    pub consumer_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub state: crate::model::MuxAssetState,
    pub metadata_ready: bool,
    pub native_connected: bool,
    pub external_write_performed: bool,
    pub playback_success_proven: bool,
    pub content_correctness_proven: bool,
    pub publication_authority: bool,
    pub outcome_authority: bool,
    pub observation_digest: Digest,
}

impl MissionMuxMediaObservation {
    fn from_evidence(evidence: &MuxMediaResultEvidence) -> Self {
        let mut observation = Self {
            consumer_id: MISSION_MUX_MEDIA_RESULT_CONSUMER_ID.to_owned(),
            consumer_version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: MUX_MEDIA_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_digest: provider_digest(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.delivery.state,
            metadata_ready: evidence.delivery.metadata_ready,
            native_connected: false,
            external_write_performed: false,
            playback_success_proven: false,
            content_correctness_proven: false,
            publication_authority: false,
            outcome_authority: false,
            observation_digest: Digest::sha256([]),
        };
        observation.observation_digest = digest_serializable(&(
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.contract_version,
            &observation.contract_digest,
            &observation.provider_digest,
            &observation.scope_digest,
            &observation.registration_digest,
            &observation.evidence_digest,
            observation.state,
            observation.metadata_ready,
            observation.native_connected,
            observation.external_write_performed,
            observation.playback_success_proven,
            observation.content_correctness_proven,
            observation.publication_authority,
            observation.outcome_authority,
        ));
        observation
    }

    pub fn verify_integrity(&self) -> Result<(), MuxError> {
        let expected = digest_serializable(&(
            &self.consumer_id,
            &self.consumer_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_digest,
            &self.scope_digest,
            &self.registration_digest,
            &self.evidence_digest,
            self.state,
            self.metadata_ready,
            self.native_connected,
            self.external_write_performed,
            self.playback_success_proven,
            self.content_correctness_proven,
            self.publication_authority,
            self.outcome_authority,
        ));
        if self.observation_digest != expected
            || self.native_connected
            || self.external_write_performed
            || self.playback_success_proven
            || self.content_correctness_proven
            || self.publication_authority
            || self.outcome_authority
        {
            return Err(MuxError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.observation_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionMuxMediaResult {
    pub proposal: MuxMediaResultProposal,
    pub evidence: MuxMediaResultEvidence,
    pub observation: MissionMuxMediaObservation,
}

impl MissionMuxMediaResult {
    pub fn validate(&self, scope: &MuxScope) -> Result<(), MuxError> {
        self.proposal.verify_integrity()?;
        self.evidence.verify_integrity()?;
        self.observation.verify_integrity()?;
        if self.proposal.scope_digest != scope.digest()
            || self.evidence.scope_digest != scope.digest()
            || self.observation.scope_digest != scope.digest()
            || self.proposal.static_rendition_digest != scope.static_rendition_digest()
            || self.proposal.project_digest != scope.project().digest()
            || self.proposal.mission_digest != scope.mission().digest()
            || self.proposal.work_product_digest != scope.work_product().digest()
            || self.proposal.consent_digest != scope.consent().digest()
            || self.evidence.static_rendition_digest != scope.static_rendition_digest()
            || self.evidence.proposal_digest != *self.proposal.digest()
            || self.evidence.registration_digest != self.proposal.registration_digest
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.evidence.contract_digest != contract_digest()
            || self.evidence.contract_version != MUX_MEDIA_RESULT_CONTRACT_VERSION
            || self.evidence.provider_digest != provider_digest()
            || self.evidence.consumer_id != MISSION_MUX_MEDIA_RESULT_CONSUMER_ID
        {
            return Err(MuxError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MissionMuxMediaConsumer {
    scope: MuxScope,
    registration: MuxRegistration,
    consumed_proposals: BTreeSet<Digest>,
    consumed_evidence: BTreeSet<Digest>,
}

impl MissionMuxMediaConsumer {
    pub fn new(scope: MuxScope) -> Result<Self, MuxError> {
        let registration = MuxRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            consumed_proposals: BTreeSet::new(),
            consumed_evidence: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &MuxScope {
        &self.scope
    }

    pub fn registration(&self) -> &MuxRegistration {
        &self.registration
    }

    pub fn compile_media_result_proposal(
        &self,
        request: &MuxMediaResultRequest,
    ) -> Result<MuxMediaResultProposal, MuxError> {
        self.ensure_active()?;
        MuxMediaResultProposal::compile(&self.scope, &self.registration, request)
    }

    pub fn consume(
        &mut self,
        proposal: MuxMediaResultProposal,
        evidence: MuxMediaResultEvidence,
    ) -> Result<MissionMuxMediaResult, MuxError> {
        self.ensure_active()?;
        proposal.verify_integrity()?;
        evidence.verify_integrity()?;
        if proposal.scope_digest != self.scope.digest()
            || evidence.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.static_rendition_digest != self.scope.static_rendition_digest()
            || proposal.static_rendition_digest != self.scope.static_rendition_digest()
            || proposal.project_digest != self.scope.project().digest()
            || proposal.mission_digest != self.scope.mission().digest()
            || proposal.work_product_digest != self.scope.work_product().digest()
            || proposal.consent_digest != self.scope.consent().digest()
            || evidence.proposal_digest != *proposal.digest()
            || evidence.request_digest != proposal.request_digest
            || evidence.plugin_version_digest != plugin_version_digest()
            || evidence.contract_digest != contract_digest()
            || evidence.provider_digest != provider_digest()
            || evidence.consumer_id != MISSION_MUX_MEDIA_RESULT_CONSUMER_ID
        {
            return Err(MuxError::ScopeMismatch(
                "consumer binding differs from evidence",
            ));
        }
        if !self.consumed_proposals.insert(proposal.digest().clone())
            || !self.consumed_evidence.insert(evidence.digest().clone())
        {
            return Err(MuxError::DuplicateEvidence);
        }
        let observation = MissionMuxMediaObservation::from_evidence(&evidence);
        let result = MissionMuxMediaResult {
            proposal,
            evidence,
            observation,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T>(
        &mut self,
        provider: &mut MuxProvider<T>,
        request: &MuxMediaResultRequest,
        at_epoch_seconds: i64,
    ) -> Result<MissionMuxMediaResult, MuxError>
    where
        T: MuxTransport,
    {
        if provider.scope() != &self.scope
            || provider.registration().registration_digest()
                != self.registration.registration_digest()
        {
            return Err(MuxError::ScopeMismatch(
                "consumer and provider registrations differ",
            ));
        }
        let proposal = self.compile_media_result_proposal(request)?;
        let evidence = provider.read_proposal(&proposal, request, at_epoch_seconds)?;
        self.consume(proposal, evidence)
    }

    pub fn revoke_registration(&mut self) -> Result<(), MuxError> {
        self.registration
            .revoke(crate::model::RevocationReason::HostRequested)
    }

    pub fn consumed_count(&self) -> usize {
        self.consumed_evidence.len()
    }

    fn ensure_active(&self) -> Result<(), MuxError> {
        if self.registration.state != RegistrationState::Active {
            return Err(MuxError::RegistrationRevoked);
        }
        self.registration.validate_against(&self.scope)
    }
}

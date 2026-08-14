use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::DovetailResearchResultError;
use crate::model::{
    Digest, DovetailResearchObservation, DovetailResearchReadRequest, DovetailResearchScope,
    ObservationCompleteness, ResearchEvidenceState, TransportProvenance,
};
use crate::provider::DovetailTransport;
use crate::service::DovetailResearchResultService;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    Processing,
    PartialEvidence,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

/// A canonical, Mission/Project/Work Product/Consent-bound review proposal.
/// It contains only bounded counts, IDs, timestamps, and digests; it cannot be
/// adopted as a kernel Outcome or as a Work Product write.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailResearchProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provider_revision_digest: Digest,
    pub workspace_digest: Digest,
    pub dovetail_project_digest: Digest,
    pub dovetail_folder_digest: Option<Digest>,
    pub dovetail_data_scope_digest: Digest,
    pub hartevo_project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub mission_id: String,
    pub work_product_id: String,
    pub observation_digest: Digest,
    pub result_digest: Digest,
    pub revision_digests: crate::RevisionDigests,
    pub counts: crate::ObservationCounts,
    pub state: ResearchEvidenceState,
    pub completeness: ObservationCompleteness,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub raw_provider_payload_retained: bool,
    pub participant_pii_retained: bool,
    pub transcripts_retained: bool,
    pub media_retained: bool,
    pub raw_notes_or_comments_retained: bool,
    pub free_form_bodies_retained: bool,
    pub sentiment_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl DovetailResearchProposal {
    fn from_observation(
        scope: &DovetailResearchScope,
        registration_digest: &Digest,
        observation: &DovetailResearchObservation,
        idempotency_key: &str,
    ) -> crate::Result<Self> {
        scope.validate()?;
        observation.validate_integrity()?;
        if observation.scope_digest != scope.scope_digest
            || observation.provider_digest != scope.provider.digest
        {
            return Err(DovetailResearchResultError::ScopeMismatch);
        }
        crate::model::validate_text(idempotency_key, "idempotencyKey", 256)?;
        let disposition = match observation.state {
            ResearchEvidenceState::Processing => ProposalDisposition::Processing,
            ResearchEvidenceState::RetentionGap => ProposalDisposition::RetentionGap,
            ResearchEvidenceState::AccessLost => ProposalDisposition::AccessLost,
            ResearchEvidenceState::ProviderUnknown => ProposalDisposition::ProviderUnknown,
            ResearchEvidenceState::Partial => ProposalDisposition::PartialEvidence,
            ResearchEvidenceState::Indexed | ResearchEvidenceState::Present => {
                ProposalDisposition::ReviewOnly
            }
        };
        let mut proposal = Self {
            proposal_version: format!("{}/proposal", crate::CONTRACT_VERSION),
            service_id: String::from(crate::SERVICE_ID),
            provider_id: String::from(crate::PROVIDER_ID),
            consumer_id: String::from(crate::CONSUMER_ID),
            registration_digest: registration_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            provider_revision_digest: observation.provider_digest.clone(),
            workspace_digest: scope.workspace.revision_digest.clone(),
            dovetail_project_digest: scope.dovetail_project.revision_digest.clone(),
            dovetail_folder_digest: scope
                .dovetail_folder
                .as_ref()
                .map(|folder| folder.revision_digest.clone()),
            dovetail_data_scope_digest: scope.dovetail_data.scope_digest.clone(),
            hartevo_project_digest: scope.hartevo_project.revision_digest.clone(),
            mission_digest: scope.mission.revision_digest.clone(),
            work_product_digest: scope.work_product.revision_digest.clone(),
            consent_digest: scope.consent.digest.clone(),
            mission_id: scope.mission.id.as_str().to_owned(),
            work_product_id: scope.work_product.id.as_str().to_owned(),
            observation_digest: observation.result_digest.clone(),
            result_digest: observation.result_digest.clone(),
            revision_digests: observation.revision_digests.clone(),
            counts: observation.counts.clone(),
            state: observation.state,
            completeness: observation.completeness,
            disposition,
            provenance: observation.provenance,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            connected: false,
            native: false,
            raw_provider_payload_retained: false,
            participant_pii_retained: false,
            transcripts_retained: false,
            media_retained: false,
            raw_notes_or_comments_retained: false,
            free_form_bodies_retained: false,
            sentiment_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-dovetail-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> crate::Result<()> {
        if self.proposal_version != format!("{}/proposal", crate::CONTRACT_VERSION)
            || self.service_id != crate::SERVICE_ID
            || self.provider_id != crate::PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.connected
            || self.native
            || self.raw_provider_payload_retained
            || self.participant_pii_retained
            || self.transcripts_retained
            || self.media_retained
            || self.raw_notes_or_comments_retained
            || self.free_form_bodies_retained
            || self.sentiment_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || !self.provenance.is_non_native()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(DovetailResearchResultError::TamperedResult);
        }
        for (field, digest) in [
            ("registrationDigest", &self.registration_digest),
            ("scopeDigest", &self.scope_digest),
            ("providerRevisionDigest", &self.provider_revision_digest),
            ("workspaceDigest", &self.workspace_digest),
            ("dovetailProjectDigest", &self.dovetail_project_digest),
            ("dovetailDataScopeDigest", &self.dovetail_data_scope_digest),
            ("hartevoProjectDigest", &self.hartevo_project_digest),
            ("missionDigest", &self.mission_digest),
            ("workProductDigest", &self.work_product_digest),
            ("consentDigest", &self.consent_digest),
            ("observationDigest", &self.observation_digest),
            ("resultDigest", &self.result_digest),
            ("idempotencyKeyDigest", &self.idempotency_key_digest),
        ] {
            digest.validate(field)?;
        }
        if let Some(digest) = &self.dovetail_folder_digest {
            digest.validate("dovetailFolderDigest")?;
        }
        self.revision_digests
            .project
            .validate("projectRevisionDigest")?;
        if let Some(folder) = &self.revision_digests.folder {
            folder.validate("folderRevisionDigest")?;
        }
        self.revision_digests.data.validate("dataRevisionDigest")?;
        self.revision_digests
            .highlights
            .validate("highlightRevisionDigest")?;
        self.revision_digests
            .themes
            .validate("themeRevisionDigest")?;
        self.revision_digests
            .insights
            .validate("insightRevisionDigest")?;
        self.revision_digests
            .documents
            .validate("documentRevisionDigest")?;
        Ok(())
    }

    pub fn calculate_digest(&self) -> Digest {
        let identity = (
            &self.proposal_version,
            &self.service_id,
            &self.provider_id,
            &self.consumer_id,
            &self.registration_digest,
            &self.scope_digest,
            &self.provider_revision_digest,
            &self.workspace_digest,
            &self.dovetail_project_digest,
            &self.dovetail_folder_digest,
            &self.dovetail_data_scope_digest,
            &self.hartevo_project_digest,
            &self.mission_digest,
            &self.work_product_digest,
            &self.consent_digest,
        );
        let result = (
            &self.mission_id,
            &self.work_product_id,
            &self.observation_digest,
            &self.result_digest,
            &self.revision_digests,
            &self.counts,
            self.state,
            self.completeness,
            self.disposition,
            self.provenance,
            &self.idempotency_key_digest,
        );
        Digest::from_serialized(&(identity, result))
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A local, idempotent recording of a proposal. It is not a Dovetail receipt,
/// provider verification, Connected claim, or kernel fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailResearchRecording {
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub observation_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub state: ResearchEvidenceState,
    pub disposition: ProposalDisposition,
    pub completeness: ObservationCompleteness,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub raw_provider_payload_retained: bool,
    pub participant_pii_retained: bool,
    pub recording_digest: Digest,
}

impl DovetailResearchRecording {
    fn from_proposal(proposal: &DovetailResearchProposal, replayed: bool) -> Self {
        let mut recording = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            observation_digest: proposal.observation_digest.clone(),
            idempotency_key_digest: proposal.idempotency_key_digest.clone(),
            state: proposal.state,
            disposition: proposal.disposition,
            completeness: proposal.completeness,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            raw_provider_payload_retained: false,
            participant_pii_retained: false,
            recording_digest: Digest::from_text("unsealed-dovetail-recording"),
        };
        recording.recording_digest = recording.calculate_digest();
        recording
    }

    pub fn validate_integrity(&self) -> crate::Result<()> {
        for (field, digest) in [
            ("proposalDigest", &self.proposal_digest),
            ("registrationDigest", &self.registration_digest),
            ("scopeDigest", &self.scope_digest),
            ("observationDigest", &self.observation_digest),
            ("idempotencyKeyDigest", &self.idempotency_key_digest),
            ("recordingDigest", &self.recording_digest),
        ] {
            digest.validate(field)?;
        }
        if self.connected
            || self.native
            || self.provider_receipt
            || self.raw_provider_payload_retained
            || self.participant_pii_retained
            || !self.provenance.is_non_native()
            || self.recording_digest != self.calculate_digest()
        {
            return Err(DovetailResearchResultError::TamperedResult);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.proposal_digest,
            &self.registration_digest,
            &self.scope_digest,
            &self.observation_digest,
            &self.idempotency_key_digest,
            self.state,
            self.disposition,
            self.completeness,
            self.provenance,
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct DovetailResearchRecordingLog {
    records: BTreeMap<Digest, DovetailResearchRecording>,
}

impl DovetailResearchRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&DovetailResearchRecording> {
        self.records.get(idempotency_key_digest)
    }
}

#[derive(Clone, Debug)]
pub struct MissionDovetailResearchConsumer<T: DovetailTransport = crate::DovetailFixtureTransport> {
    service: DovetailResearchResultService<T>,
}

impl<T> MissionDovetailResearchConsumer<T>
where
    T: DovetailTransport,
{
    pub fn new(service: DovetailResearchResultService<T>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &DovetailResearchResultService<T> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut DovetailResearchResultService<T> {
        &mut self.service
    }

    pub fn scope(&self) -> &DovetailResearchScope {
        &self.service.registration().scope
    }

    pub fn read(
        &mut self,
        request: &DovetailResearchReadRequest,
    ) -> crate::Result<DovetailResearchObservation> {
        self.service.read(request)
    }

    pub fn compile_proposal(
        &self,
        observation: &DovetailResearchObservation,
        idempotency_key: &str,
    ) -> crate::Result<DovetailResearchProposal> {
        DovetailResearchProposal::from_observation(
            self.scope(),
            &self.service.current_registration_digest(),
            observation,
            idempotency_key,
        )
    }

    pub fn propose(
        &mut self,
        request: &DovetailResearchReadRequest,
        idempotency_key: &str,
    ) -> crate::Result<DovetailResearchProposal> {
        let observation = self.read(request)?;
        self.compile_proposal(&observation, idempotency_key)
    }

    pub fn record(
        &self,
        log: &mut DovetailResearchRecordingLog,
        proposal: &DovetailResearchProposal,
    ) -> crate::Result<DovetailResearchRecording> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.service.current_registration_digest()
            || proposal.scope_digest != self.service.current_scope_digest()
        {
            return Err(DovetailResearchResultError::ScopeMismatch);
        }
        self.service.registration().ensure_active()?;
        match log.records.get(&proposal.idempotency_key_digest) {
            Some(existing) if existing.proposal_digest == proposal.proposal_digest => {
                let replay = DovetailResearchRecording::from_proposal(proposal, true);
                replay.validate_integrity()?;
                Ok(replay)
            }
            Some(_) => Err(DovetailResearchResultError::ReplayConflict),
            None => {
                let recording = DovetailResearchRecording::from_proposal(proposal, false);
                recording.validate_integrity()?;
                log.records
                    .insert(proposal.idempotency_key_digest.clone(), recording.clone());
                Ok(recording)
            }
        }
    }

    pub fn consume(
        &mut self,
        request: &DovetailResearchReadRequest,
        idempotency_key: &str,
        log: &mut DovetailResearchRecordingLog,
    ) -> crate::Result<DovetailMissionResearchResult> {
        let observation = self.read(request)?;
        let proposal = self.compile_proposal(&observation, idempotency_key)?;
        let recording = self.record(log, &proposal)?;
        Ok(DovetailMissionResearchResult {
            observation,
            proposal,
            recording,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DovetailMissionResearchResult {
    pub observation: DovetailResearchObservation,
    pub proposal: DovetailResearchProposal,
    pub recording: DovetailResearchRecording,
}

#[cfg(test)]
mod consumer_tests {
    use super::*;
    use crate::{
        ConsentId, ConsentScope, Digest, DovetailDataScope, DovetailPermissionSnapshot,
        DovetailProjectBinding, DovetailProjectId, DovetailProviderIdentity, HartevoProjectBinding,
        MissionBinding, MissionId, PluginVersion, ProjectId, SecretReference, WorkProductBinding,
        WorkProductId, WorkspaceBinding, WorkspaceId,
    };

    fn scope() -> DovetailResearchScope {
        let permission = DovetailPermissionSnapshot::read_only(1).expect("permission");
        DovetailResearchScope::new(
            PluginVersion::V1,
            crate::CONTRACT_VERSION,
            crate::contract_digest(),
            DovetailProviderIdentity::layer1().expect("provider"),
            WorkspaceBinding::new(WorkspaceId::new("workspace-1").expect("workspace"), 1)
                .expect("workspace"),
            DovetailProjectBinding::new(
                DovetailProjectId::new("project-dovetail").expect("Dovetail project"),
                1,
            )
            .expect("Dovetail project"),
            None,
            DovetailDataScope::new(
                vec![crate::DataId::new("data-1").expect("data")],
                Digest::from_text("data-revision"),
            )
            .expect("data"),
            HartevoProjectBinding::new(ProjectId::new("project-hartevo").expect("project"), 1)
                .expect("project"),
            MissionBinding::new(MissionId::new("mission-1").expect("mission"), 1).expect("mission"),
            WorkProductBinding::new(
                WorkProductId::new("work-product-1").expect("Work Product"),
                1,
            )
            .expect("Work Product"),
            ConsentScope::metadata_only(ConsentId::new("consent-1").expect("consent"), 1)
                .expect("consent"),
            permission.digest,
        )
        .expect("scope")
    }

    #[test]
    fn proposal_and_recording_are_revision_fenced_and_idempotent() {
        let scope = scope();
        let provider = crate::DovetailProvider::fixture(scope.clone()).expect("provider");
        let service = crate::DovetailResearchResultService::new(provider).expect("service");
        let mut consumer = MissionDovetailResearchConsumer::new(service);
        let request = crate::DovetailResearchReadRequest::for_scope(
            &scope,
            crate::DovetailReadBounds::default(),
        )
        .expect("request");
        let proposal = consumer
            .propose(&request, "idempotency-1")
            .expect("proposal");
        assert!(proposal.is_review_only());
        assert!(!proposal.can_be_adopted());
        proposal.validate_integrity().expect("proposal integrity");
        let mut log = DovetailResearchRecordingLog::default();
        let first = consumer.record(&mut log, &proposal).expect("record");
        let replay = consumer.record(&mut log, &proposal).expect("replay");
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(log.len(), 1);
        assert!(!first.connected);
        assert!(!first.native);
    }

    #[test]
    fn secret_reference_serializes_only_opaque_digest() {
        let secret =
            SecretReference::api_token("opaque-dovetail-token-fixture", 7).expect("secret");
        let serialized = serde_json::to_string(&secret).expect("secret JSON");
        assert!(!serialized.contains("opaque-dovetail-token-fixture"));
        assert!(serialized.contains("referenceDigest"));
        let restored: SecretReference =
            serde_json::from_str(&serialized).expect("safe secret JSON");
        assert_eq!(restored.reference_digest(), secret.reference_digest());
        assert_eq!(restored.revision(), 7);
    }
}

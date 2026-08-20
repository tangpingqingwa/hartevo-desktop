use crate::error::BoxArtifactError;
use crate::model::{
    ArtifactAdoptionProposal, ArtifactAvailability, ArtifactRevisionFence, BoxArtifactScope,
    BoxFileMetadata, ContentDigest, ContentReadProjection, MissionArtifactResult,
    MissionArtifactResultStatus, MissionResultBinding, ProviderProvenance, Sha1Digest,
    digest_parts,
};

/// Mission-facing result consumer. It accepts only a complete, digest-checked
/// read receipt and produces a non-mutating proposal; it never copies bytes,
/// writes to Box, or claims a verified Work Product adoption.
#[derive(Clone, Debug)]
pub struct MissionArtifactResultConsumer {
    scope: BoxArtifactScope,
    provider_version: u64,
    registration_digest: ContentDigest,
}

impl MissionArtifactResultConsumer {
    pub fn new(
        scope: BoxArtifactScope,
        provider_version: u64,
        registration_digest: ContentDigest,
    ) -> Result<Self, BoxArtifactError> {
        scope.validate()?;
        if provider_version != crate::BOX_ARTIFACT_PROVIDER_VERSION {
            return Err(BoxArtifactError::ProviderVersionMismatch);
        }
        Ok(Self {
            scope,
            provider_version,
            registration_digest,
        })
    }

    pub fn scope(&self) -> &BoxArtifactScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &ContentDigest {
        &self.registration_digest
    }

    pub fn consume(
        &self,
        source: &MissionResultBinding,
        file: BoxFileMetadata,
        content: ContentReadProjection,
    ) -> Result<MissionArtifactResult, BoxArtifactError> {
        let proposal = self.propose(source, file, content)?;
        let result_digest = ContentDigest::from_bytes(
            format!(
                "mission-artifact-result/v1\n{}\n{}",
                proposal.proposal_digest.as_str(),
                proposal.scope.digest().as_str()
            )
            .as_bytes(),
        );
        let result = MissionArtifactResult {
            result_id: format!("mission-artifact-{}", &result_digest.as_str()[..24]),
            result_digest,
            status: MissionArtifactResultStatus::Proposed,
            source_mission_revision: source.mission_revision,
            source_result_revision: source.result_revision,
            proposal,
            model_visible: true,
            adopted: true,
            external_write_performed: false,
            native_connected: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn adopt(
        &self,
        source: &MissionResultBinding,
        file: BoxFileMetadata,
        content: ContentReadProjection,
    ) -> Result<MissionArtifactResult, BoxArtifactError> {
        self.consume(source, file, content)
    }

    fn propose(
        &self,
        source: &MissionResultBinding,
        file: BoxFileMetadata,
        content: ContentReadProjection,
    ) -> Result<ArtifactAdoptionProposal, BoxArtifactError> {
        source.validate()?;
        if file.availability() != ArtifactAvailability::Present {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "deleted, trashed, or unavailable file cannot be proposed",
            });
        }
        if file.enterprise_id != self.scope.enterprise_id
            || file.owner_user_id != self.scope.user_id
            || file.project_scope_mismatch(&self.scope)
            || content.scope != self.scope
            || content.registration_digest != self.registration_digest
            || content.provider_version != self.provider_version
            || content.native_transport != content.provenance.is_native()
            || content.native_connected
            || !content.complete
            || !content.sha1_verified
            || content.requested_range != content.returned_range
            || !content.requested_range.is_full_file(file.size)
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "receipt is outside the Mission scope or is partial/ambiguous",
            });
        }
        if content.revision != file.revision()
            || content.bytes.len() as u64 != file.size
            || content.content_digest != ContentDigest::from_bytes(&content.bytes)
            || Sha1Digest::from_bytes(&content.bytes) != file.sha1
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "receipt digest or revision does not match file metadata",
            });
        }
        if source.project_id != self.scope.project_id || source.mission_id != self.scope.mission_id
        {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        let provenance = content.provenance.clone();
        let mut proposal = ArtifactAdoptionProposal {
            proposal_id: String::new(),
            proposal_digest: ContentDigest::from_bytes(b"unsealed"),
            scope: self.scope.clone(),
            source: source.clone(),
            file_id: file.file_id,
            version_id: file.version_id,
            sha1: file.sha1,
            content_digest: content.content_digest,
            size: file.size,
            media_type: file.media_type,
            provider_version: self.provider_version,
            registration_digest: self.registration_digest.clone(),
            provenance,
            native_transport: content.native_transport,
            native_connected: false,
            status: crate::ArtifactProposalStatus::Proposed,
            non_mutating: true,
            external_write_performed: false,
            durable_readback_verified: false,
        };
        let digest = ContentDigest::new(proposal.compute_digest())?;
        proposal.proposal_digest = digest.clone();
        proposal.proposal_id = crate::model::proposal_id_for(&digest);
        proposal.validate()?;
        Ok(proposal)
    }
}

trait FileScopeCheck {
    fn project_scope_mismatch(&self, scope: &BoxArtifactScope) -> bool;
}

impl FileScopeCheck for BoxFileMetadata {
    fn project_scope_mismatch(&self, scope: &BoxArtifactScope) -> bool {
        !scope.permits_file(&self.file_id)
            || scope
                .folder_id
                .as_ref()
                .is_some_and(|folder| folder != &self.parent_folder_id)
    }
}

#[allow(dead_code)]
fn _type_surface_markers(
    _digest: &ContentDigest,
    _fence: &ArtifactRevisionFence,
    _parts: &[&str],
    _provenance: &ProviderProvenance,
) {
    let _ = digest_parts(std::iter::empty());
}

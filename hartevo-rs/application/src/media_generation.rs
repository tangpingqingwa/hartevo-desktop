//! One durable media request and one atomic WorkProduct completion.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::media_generation::{
    MediaAssetMetadata, MediaGeneration, MediaGenerationError, MediaGenerationRequest,
    MediaGenerationState, MediaKind,
};
use hartevo_domain_kernel::{
    MissionId, MissionStage, ProjectId, WorkProduct, WorkProductDependencies, WorkProductId,
    WorkProductManifest, WorkProductPreview, WorkProductStatus,
};
use hartevo_storage::MediaWorkProductCommit;
use thiserror::Error;

use crate::{ApplicationError, ApplicationService};

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum MediaApplicationError {
    #[error(transparent)]
    Application(#[from] ApplicationError),
    #[error(transparent)]
    Storage(#[from] hartevo_storage::StorageError),
    #[error(transparent)]
    Domain(#[from] MediaGenerationError),
    #[error("MEDIA_STALE_SOURCE")]
    StaleSource,
    #[error("MEDIA_SCOPE_MISMATCH")]
    ScopeMismatch,
    #[error("MEDIA_MISSION_NOT_RUNNING")]
    MissionNotRunning,
    #[error("MEDIA_REQUEST_CONFLICT")]
    RequestConflict,
    #[error("MEDIA_NOT_FOUND")]
    NotFound,
}

impl ApplicationService {
    pub fn begin_media_generation(
        &mut self,
        request: MediaGenerationRequest,
        now: DateTime<Utc>,
    ) -> Result<(MediaGeneration, bool), MediaApplicationError> {
        request.validate()?;
        if let Some(previous) = self.store.load_media_generation(
            &request.project_id,
            &request.mission_id,
            &request.id,
        )? {
            if previous.request != request {
                return Err(MediaApplicationError::RequestConflict);
            }
            return Ok((previous, false));
        }
        let mission = self
            .store
            .load_mission(&request.project_id, &request.mission_id)?;
        if mission.revision != request.expected_mission_revision {
            return Err(MediaApplicationError::StaleSource);
        }
        if mission.stage != MissionStage::Running {
            return Err(MediaApplicationError::MissionNotRunning);
        }
        let parent = request
            .revises_job_id
            .as_ref()
            .map(|id| self.media_generation(&request.project_id, &request.mission_id, id))
            .transpose()?;
        if parent.as_ref().is_some_and(|p| {
            p.request.kind != request.kind
                || !matches!(
                    p.state,
                    MediaGenerationState::Ready | MediaGenerationState::Rejected
                )
        }) {
            return Err(MediaApplicationError::StaleSource);
        }
        let product_id = parent.as_ref().map_or_else(
            || WorkProductId::from_stable(format!("media-{}", request.id)),
            |p| p.work_product_id.clone(),
        );
        let source = mission.work_products.iter().find(|p| p.id == product_id);
        if parent.is_none() && source.is_some() {
            return Err(MediaApplicationError::RequestConflict);
        }
        if source.is_some_and(|p| p.status != WorkProductStatus::ReadyForReview) {
            return Err(MediaApplicationError::StaleSource);
        }
        let manifest = source
            .map(|p| self.load_work_product_manifest(&request.project_id, &p.id))
            .transpose()?;
        if let Some(parent) = &parent
            && parent.state == MediaGenerationState::Ready
            && (manifest.as_ref().and_then(|m| m.file_digest.as_ref())
                != parent.asset.as_ref().map(|asset| &asset.sha256)
                || source.is_none_or(|p| {
                    serde_json::from_str::<serde_json::Value>(&p.body)
                        .ok()
                        .is_none_or(|body| {
                            body["generationId"].as_str() != Some(parent.request.id.as_str())
                        })
                }))
        {
            return Err(MediaApplicationError::StaleSource);
        }
        if let Some(parent) = &parent
            && parent.state == MediaGenerationState::Rejected
            && (parent.source_work_product_revision != source.map(|p| p.revision)
                || parent.source_manifest_version != manifest.as_ref().map(|m| m.version))
        {
            return Err(MediaApplicationError::StaleSource);
        }
        let job = MediaGeneration {
            tenant_id: mission.tenant_id,
            request,
            revision: 1,
            state: MediaGenerationState::Submitting,
            provider_request_id: None,
            work_product_id: product_id,
            source_work_product_revision: source.map(|p| p.revision),
            source_manifest_version: manifest.map(|m| m.version),
            asset: None,
            failure_code: None,
            created_at: now,
            updated_at: now,
        };
        let inserted = self.store.begin_media_generation(&job)?;
        if !inserted {
            return Ok((
                self.media_generation(
                    &job.request.project_id,
                    &job.request.mission_id,
                    &job.request.id,
                )?,
                false,
            ));
        }
        Ok((job, inserted))
    }

    pub fn media_generation(
        &self,
        project: &ProjectId,
        mission: &MissionId,
        id: &str,
    ) -> Result<MediaGeneration, MediaApplicationError> {
        self.store
            .load_media_generation(project, mission, id)?
            .ok_or(MediaApplicationError::NotFound)
    }

    pub fn media_generations(
        &self,
        project: &ProjectId,
        mission: &MissionId,
    ) -> Result<Vec<MediaGeneration>, MediaApplicationError> {
        let _ = self.load_mission(project, mission)?;
        Ok(self.store.list_media_generations(project, mission)?)
    }

    pub fn media_generation_bytes(
        &self,
        project: &ProjectId,
        mission: &MissionId,
        id: &str,
    ) -> Result<(MediaGeneration, Vec<u8>), MediaApplicationError> {
        let job = self.media_generation(project, mission, id)?;
        let bytes = self.store.media_generation_bytes(&job)?;
        Ok((job, bytes))
    }

    pub fn record_media_submission(
        &mut self,
        previous: &MediaGeneration,
        request_id: String,
        now: DateTime<Utc>,
    ) -> Result<MediaGeneration, MediaApplicationError> {
        let mut next = previous.clone();
        next.revision += 1;
        next.updated_at = now;
        next.state = MediaGenerationState::Submitted;
        next.provider_request_id = Some(request_id);
        self.store.commit_media_generation(&next, None, None)?;
        Ok(next)
    }

    pub fn record_media_failure(
        &mut self,
        previous: &MediaGeneration,
        uncertain: bool,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<MediaGeneration, MediaApplicationError> {
        let mut next = previous.clone();
        next.revision += 1;
        next.updated_at = now;
        next.state = if uncertain {
            MediaGenerationState::Uncertain
        } else {
            MediaGenerationState::Failed
        };
        next.failure_code = Some(code.into());
        self.store.commit_media_generation(&next, None, None)?;
        Ok(next)
    }

    pub fn complete_media_generation(
        &mut self,
        previous: &MediaGeneration,
        metadata: MediaAssetMetadata,
        bytes: &[u8],
        now: DateTime<Utc>,
    ) -> Result<MediaGeneration, MediaApplicationError> {
        self.complete_media_attempt(previous, metadata, bytes, now, 1, &mut || {})
    }

    /// Drain an already dispatched response without granting a WorkProduct
    /// write after its live desktop context has been revoked.
    pub fn quarantine_media_generation(
        &mut self,
        previous: &MediaGeneration,
        metadata: MediaAssetMetadata,
        bytes: &[u8],
        now: DateTime<Utc>,
    ) -> Result<MediaGeneration, MediaApplicationError> {
        metadata.validate_bytes(bytes)?;
        let mut next = previous.clone();
        next.revision += 1;
        next.updated_at = now;
        next.asset = Some(metadata);
        next.state = MediaGenerationState::Rejected;
        next.failure_code = Some("MEDIA_CONTEXT_REVOKED".into());
        self.store
            .commit_media_generation(&next, Some(bytes), None)?;
        Ok(next)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "atomic asset settlement keeps the revision checks and bounded conflict recovery together"
    )]
    fn complete_media_attempt(
        &mut self,
        previous: &MediaGeneration,
        metadata: MediaAssetMetadata,
        bytes: &[u8],
        now: DateTime<Utc>,
        retries: u8,
        before_commit: &mut dyn FnMut(),
    ) -> Result<MediaGeneration, MediaApplicationError> {
        metadata.validate_bytes(bytes)?;
        let mut next = previous.clone();
        next.revision += 1;
        next.updated_at = now;
        next.asset = Some(metadata.clone());
        if !metadata.meets_requested_format(next.request.kind) {
            next.state = MediaGenerationState::Rejected;
            next.failure_code = Some("MEDIA_FORMAT_MISMATCH".into());
            self.store
                .commit_media_generation(&next, Some(bytes), None)?;
            return Ok(next);
        }
        let mut mission = self.load_mission(&next.request.project_id, &next.request.mission_id)?;
        if mission.tenant_id != next.tenant_id {
            return Err(MediaApplicationError::ScopeMismatch);
        }
        let expected_revision = mission.revision;
        let body = serde_json::json!({"schemaVersion":"hartevo-media-artifact/v1","generationId":next.request.id,
            "prompt":next.request.prompt,"model":next.request.model,"provider":next.request.provider,
            "revisesGenerationId":next.request.revises_job_id,"asset":metadata}).to_string();
        let title = match next.request.kind {
            MediaKind::Image => "生成图片",
            MediaKind::Video => "生成视频",
        };
        let preview = WorkProductPreview::new("application/vnd.hartevo.media+json", body.clone())
            .map_err(ApplicationError::from)?;
        let existing = mission
            .work_products
            .iter()
            .find(|p| p.id == next.work_product_id)
            .cloned();
        let manifest = if let Some(existing) = existing {
            let previous_manifest =
                self.load_work_product_manifest(&mission.project_id, &existing.id)?;
            if !matches!(
                mission.stage,
                MissionStage::Running
                    | MissionStage::WaitingUser
                    | MissionStage::WaitingApproval
                    | MissionStage::Verifying
            ) || Some(existing.revision) != next.source_work_product_revision
                || Some(previous_manifest.version) != next.source_manifest_version
                || existing.status != WorkProductStatus::ReadyForReview
            {
                return self.reject_stale_media(&next, bytes);
            }
            let revised = existing
                .revise_content(title, body, existing.evidence_ids.clone())
                .map_err(ApplicationError::from)?;
            mission
                .revise_work_product(revised.clone(), now)
                .map_err(ApplicationError::from)?;
            previous_manifest
                .revise(
                    &revised,
                    previous_manifest.dependencies.clone(),
                    Some(metadata.sha256.clone()),
                    preview,
                    BTreeSet::from(["/prompt".into()]),
                    now,
                )
                .map_err(ApplicationError::from)?
        } else {
            if next.source_work_product_revision.is_some() || mission.stage != MissionStage::Running
            {
                return self.reject_stale_media(&next, bytes);
            }
            mission
                .record_work_product(
                    WorkProduct::draft(next.work_product_id.clone(), title, body, []),
                    now,
                )
                .map_err(ApplicationError::from)?;
            let product = mission
                .work_products
                .last()
                .ok_or(MediaApplicationError::NotFound)?;
            WorkProductManifest::create(
                mission.tenant_id.clone(),
                mission.project_id.clone(),
                mission.id.clone(),
                product,
                match next.request.kind {
                    MediaKind::Image => "generated_image",
                    MediaKind::Video => "generated_video",
                },
                WorkProductDependencies::default(),
                Some(metadata.sha256.clone()),
                preview,
                BTreeSet::from(["/prompt".into()]),
                now,
            )
            .map_err(ApplicationError::from)?
        };
        next.state = MediaGenerationState::Ready;
        before_commit();
        let commit = self.store.commit_media_generation(
            &next,
            Some(bytes),
            Some(MediaWorkProductCommit {
                mission: &mission,
                expected_mission_revision: expected_revision,
                manifest: &manifest,
                expected_manifest_version: next.source_manifest_version,
            }),
        );
        if let Err(error) = commit {
            let current = self.media_generation(
                &previous.request.project_id,
                &previous.request.mission_id,
                &previous.request.id,
            )?;
            if current.asset.as_ref() == Some(&metadata)
                && matches!(
                    current.state,
                    MediaGenerationState::Ready | MediaGenerationState::Rejected
                )
            {
                return Ok(current);
            }
            if matches!(
                error,
                hartevo_storage::StorageError::OptimisticConflict { .. }
                    | hartevo_storage::StorageError::UnexpectedNewerRevision { .. }
            ) {
                if retries > 0 {
                    return self.complete_media_attempt(
                        previous,
                        metadata,
                        bytes,
                        now,
                        retries - 1,
                        before_commit,
                    );
                }
                return self.reject_stale_media(&next, bytes);
            }
            return Err(error.into());
        }
        Ok(next)
    }

    fn reject_stale_media(
        &mut self,
        next: &MediaGeneration,
        bytes: &[u8],
    ) -> Result<MediaGeneration, MediaApplicationError> {
        let mut rejected = next.clone();
        rejected.state = MediaGenerationState::Rejected;
        rejected.failure_code = Some("MEDIA_STALE_SOURCE".into());
        self.store
            .commit_media_generation(&rejected, Some(bytes), None)?;
        Ok(rejected)
    }
}

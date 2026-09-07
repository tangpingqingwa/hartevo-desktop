//! Durable creative generation. Provider work does not authorize publication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{MissionId, ProjectId, TenantId, WorkProductId};

pub const MAX_MEDIA_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    Video,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaProvider {
    OpenAi,
    Grok,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaGenerationState {
    Submitting,
    Submitted,
    Ready,
    Rejected,
    Uncertain,
    Failed,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaGenerationRequest {
    pub id: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub expected_mission_revision: u64,
    pub kind: MediaKind,
    pub provider: MediaProvider,
    pub model: String,
    pub endpoint_digest: String,
    pub prompt: String,
    /// Regenerate from a revised description, preserving the previous candidate.
    pub revises_job_id: Option<String>,
}

impl MediaGenerationRequest {
    pub fn validate(&self) -> Result<(), MediaGenerationError> {
        if !valid_token(&self.id)
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.expected_mission_revision == 0
            || !valid_token(&self.model)
            || self.endpoint_digest.len() != 64
            || !self.endpoint_digest.bytes().all(|b| b.is_ascii_hexdigit())
            || self.prompt.trim().is_empty()
            || self.prompt.len() > 4096
            || self
                .prompt
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            || self
                .revises_job_id
                .as_ref()
                .is_some_and(|id| !valid_token(id) || id == &self.id)
            || (self.provider == MediaProvider::OpenAi && self.kind == MediaKind::Video)
        {
            return Err(MediaGenerationError::InvalidRequest);
        }
        Ok(())
    }
}

impl std::fmt::Debug for MediaGenerationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaGenerationRequest")
            .field("kind", &self.kind)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaAssetMetadata {
    pub sha256: String,
    pub media_type: String,
    pub byte_length: usize,
    pub width: u32,
    pub height: u32,
    pub duration_millis: Option<u64>,
}

impl MediaAssetMetadata {
    pub fn validate_bytes(&self, bytes: &[u8]) -> Result<(), MediaGenerationError> {
        if bytes.is_empty()
            || bytes.len() > MAX_MEDIA_BYTES
            || self.byte_length != bytes.len()
            || self.sha256 != format!("{:x}", Sha256::digest(bytes))
            || self.width == 0
            || self.height == 0
            || !matches!(
                self.media_type.as_str(),
                "image/png" | "image/jpeg" | "video/mp4"
            )
        {
            return Err(MediaGenerationError::InvalidAsset);
        }
        Ok(())
    }

    pub fn meets_requested_format(&self, kind: MediaKind) -> bool {
        match kind {
            MediaKind::Image => {
                self.media_type.starts_with("image/")
                    && self.width == 1024
                    && self.height == 1024
                    && self.duration_millis.is_none()
            }
            MediaKind::Video => {
                self.media_type == "video/mp4"
                    && self.width == 480
                    && self.height == 480
                    && self
                        .duration_millis
                        .is_some_and(|ms| (2750..=3500).contains(&ms))
            }
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaGeneration {
    pub tenant_id: TenantId,
    pub request: MediaGenerationRequest,
    pub revision: u64,
    pub state: MediaGenerationState,
    pub provider_request_id: Option<String>,
    pub work_product_id: WorkProductId,
    pub source_work_product_revision: Option<u64>,
    pub source_manifest_version: Option<u64>,
    pub asset: Option<MediaAssetMetadata>,
    pub failure_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for MediaGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaGeneration")
            .field("revision", &self.revision)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl MediaGeneration {
    pub fn validate(&self) -> Result<(), MediaGenerationError> {
        self.request.validate()?;
        if self.tenant_id.as_str().trim().is_empty()
            || self.revision == 0
            || self.work_product_id.as_str().trim().is_empty()
            || self.created_at > self.updated_at
            || self.source_work_product_revision.is_some() != self.source_manifest_version.is_some()
            || self
                .provider_request_id
                .as_ref()
                .is_some_and(|id| !valid_token(id))
            || self
                .failure_code
                .as_ref()
                .is_some_and(|code| !valid_token(code))
            || (self.state == MediaGenerationState::Submitted && self.provider_request_id.is_none())
            || (matches!(
                self.state,
                MediaGenerationState::Ready | MediaGenerationState::Rejected
            ) && self.asset.is_none())
            || (self.state == MediaGenerationState::Ready
                && (self.failure_code.is_some()
                    || !self
                        .asset
                        .as_ref()
                        .is_some_and(|asset| asset.meets_requested_format(self.request.kind))))
        {
            return Err(MediaGenerationError::InvalidState);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, MediaGenerationError> {
        self.validate()?;
        previous.validate()?;
        Ok(self.request == previous.request
            && self.tenant_id == previous.tenant_id
            && self.work_product_id == previous.work_product_id
            && self.source_work_product_revision == previous.source_work_product_revision
            && self.source_manifest_version == previous.source_manifest_version
            && self.created_at == previous.created_at
            && self.updated_at >= previous.updated_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && (previous.provider_request_id.is_none()
                || self.provider_request_id == previous.provider_request_id)
            && matches!(
                (previous.state, self.state),
                (
                    MediaGenerationState::Submitting,
                    MediaGenerationState::Submitted
                        | MediaGenerationState::Ready
                        | MediaGenerationState::Rejected
                        | MediaGenerationState::Uncertain
                        | MediaGenerationState::Failed
                ) | (
                    MediaGenerationState::Submitted,
                    MediaGenerationState::Ready
                        | MediaGenerationState::Rejected
                        | MediaGenerationState::Failed
                )
            ))
    }
}

pub fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MediaGenerationError {
    #[error("MEDIA_INVALID_REQUEST")]
    InvalidRequest,
    #[error("MEDIA_INVALID_ASSET")]
    InvalidAsset,
    #[error("MEDIA_INVALID_STATE")]
    InvalidState,
}

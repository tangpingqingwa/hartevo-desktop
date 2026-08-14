//! Typed, bounded and redacted Frame.io review-result model.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    FRAME_IO_MAX_COMMENT_SUMMARIES, FRAME_IO_MAX_PAGES, FRAME_IO_MAX_RESPONSE_BYTES,
    FRAME_IO_MAX_RETRY_ATTEMPTS, FRAME_IO_MAX_WINDOW_SECONDS,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("Frame.io scope is invalid")]
    InvalidScope,
    #[error("consent scope must allow at least one read operation")]
    InvalidConsentScope,
    #[error("observation window is empty, future-dated, or exceeds the Layer-1 ceiling")]
    InvalidObservationWindow,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("comment summary is invalid or exceeds the Layer-1 ceiling")]
    InvalidCommentSummary,
    #[error("cursor is empty or too large")]
    InvalidCursor,
    #[error("duplicate read operation")]
    DuplicateOperation,
    #[error("safe value could not be serialized: {0}")]
    Serialization(String),
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

string_identifier!(AccountId);
string_identifier!(FrameIoProjectId);
string_identifier!(AssetId);
string_identifier!(AssetVersionId);
string_identifier!(ReviewLinkId);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ProviderId);
string_identifier!(ServiceId);
string_identifier!(ConsumerId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoReadOperation {
    AssetMetadata,
    AssetVersion,
    ReviewLink,
    ApprovalStatus,
    CommentSummary,
}

impl FrameIoReadOperation {
    pub const fn is_comment_summary(self) -> bool {
        matches!(self, Self::CommentSummary)
    }

    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::AssetMetadata => "read_asset_metadata",
            Self::AssetVersion => "read_asset_version",
            Self::ReviewLink => "read_review_link",
            Self::ApprovalStatus => "read_approval_status",
            Self::CommentSummary => "read_comment_summary",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservationWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl ObservationWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        let seconds = (end - start).num_seconds();
        if seconds <= 0 || seconds > FRAME_IO_MAX_WINDOW_SECONDS {
            return Err(ModelError::InvalidObservationWindow);
        }
        Ok(Self { start, end })
    }

    pub const fn duration_seconds(&self) -> i64 {
        self.end.timestamp() - self.start.timestamp()
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        self.start <= timestamp && timestamp <= self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FrameIoBounds {
    pub max_response_bytes: usize,
    pub max_comment_summaries: u32,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_window_seconds: i64,
    pub max_retry_attempts: u8,
}

impl FrameIoBounds {
    pub fn new(
        max_response_bytes: usize,
        max_comment_summaries: u32,
        max_pages: u16,
        page_size: u16,
        max_window_seconds: i64,
        max_retry_attempts: u8,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            max_response_bytes,
            max_comment_summaries,
            max_pages,
            page_size,
            max_window_seconds,
            max_retry_attempts,
        };
        if bounds.max_response_bytes == 0
            || bounds.max_response_bytes > FRAME_IO_MAX_RESPONSE_BYTES
            || bounds.max_comment_summaries == 0
            || bounds.max_comment_summaries > FRAME_IO_MAX_COMMENT_SUMMARIES
            || bounds.max_pages == 0
            || bounds.max_pages > FRAME_IO_MAX_PAGES
            || bounds.page_size == 0
            || bounds.page_size > crate::FRAME_IO_PAGE_SIZE
            || bounds.max_window_seconds <= 0
            || bounds.max_window_seconds > FRAME_IO_MAX_WINDOW_SECONDS
            || bounds.max_retry_attempts == 0
            || bounds.max_retry_attempts > FRAME_IO_MAX_RETRY_ATTEMPTS
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(bounds)
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn max_comment_summaries(&self) -> u32 {
        self.max_comment_summaries
    }

    pub const fn max_retry_attempts(&self) -> u8 {
        self.max_retry_attempts
    }
}

impl Default for FrameIoBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: FRAME_IO_MAX_RESPONSE_BYTES,
            max_comment_summaries: FRAME_IO_MAX_COMMENT_SUMMARIES,
            max_pages: FRAME_IO_MAX_PAGES,
            page_size: crate::FRAME_IO_PAGE_SIZE,
            max_window_seconds: FRAME_IO_MAX_WINDOW_SECONDS,
            max_retry_attempts: 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsentScope {
    pub allowed_operations: BTreeSet<FrameIoReadOperation>,
    pub expires_at: DateTime<Utc>,
    pub consent_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        allowed_operations: impl IntoIterator<Item = FrameIoReadOperation>,
        expires_at: DateTime<Utc>,
        consent_seed: Digest,
    ) -> Result<Self, ModelError> {
        let allowed_operations = allowed_operations.into_iter().collect::<BTreeSet<_>>();
        if allowed_operations.is_empty() {
            return Err(ModelError::InvalidConsentScope);
        }
        let consent_digest = Digest::from_fields(
            "frameio-consent-scope/v1",
            &[
                allowed_operations
                    .iter()
                    .map(|operation| operation.contract_name().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                expires_at.to_rfc3339(),
                consent_seed.as_str().to_owned(),
            ],
        );
        Ok(Self {
            allowed_operations,
            expires_at,
            consent_digest,
        })
    }

    pub fn allows(&self, operation: FrameIoReadOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn is_expired(&self, at: DateTime<Utc>) -> bool {
        at >= self.expires_at
    }

    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FrameIoRevisionFence {
    pub asset_revision: Revision,
    pub version_revision: Revision,
    pub review_link_revision: Revision,
    pub comment_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FrameIoScope {
    pub account_id: AccountId,
    pub frameio_project_id: FrameIoProjectId,
    pub asset_id: AssetId,
    pub asset_version_id: AssetVersionId,
    pub review_link_id: ReviewLinkId,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
    pub consent_scope: ConsentScope,
    pub revision_fence: FrameIoRevisionFence,
    pub scope_digest: Digest,
}

impl FrameIoScope {
    pub fn new(
        account_id: AccountId,
        frameio_project_id: FrameIoProjectId,
        asset_id: AssetId,
        asset_version_id: AssetVersionId,
        review_link_id: ReviewLinkId,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_scope: ConsentScope,
        revision_fence: FrameIoRevisionFence,
    ) -> Result<Self, ModelError> {
        if permission_digest.as_str().is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "frameio-scope/v1",
            &[
                account_id.as_str().to_owned(),
                frameio_project_id.as_str().to_owned(),
                asset_id.as_str().to_owned(),
                asset_version_id.as_str().to_owned(),
                review_link_id.as_str().to_owned(),
                project_id.as_str().to_owned(),
                project_revision.get().to_string(),
                mission_id.as_str().to_owned(),
                mission_revision.get().to_string(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_scope.digest().as_str().to_owned(),
                revision_fence.asset_revision.get().to_string(),
                revision_fence.version_revision.get().to_string(),
                revision_fence.review_link_revision.get().to_string(),
                revision_fence.comment_revision.get().to_string(),
            ],
        );
        Ok(Self {
            account_id,
            frameio_project_id,
            asset_id,
            asset_version_id,
            review_link_id,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            permission_digest,
            consent_scope,
            revision_fence,
            scope_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent_scope.digest().clone()
    }

    pub const fn fence(&self) -> FrameIoRevisionFence {
        self.revision_fence
    }
}

/// An opaque host-keyring handle.  The supplied reference id is immediately
/// reduced to a digest and is never retained, serialized, or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &FrameIoScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "frameio-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::InvalidScope)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoReviewStatus {
    Uploaded,
    Processing,
    Ready,
    InReview,
    Approved,
    ChangesRequested,
    Rejected,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoReviewLinkState {
    Active,
    Expired,
    Revoked,
    Missing,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoApprovalStatus {
    Pending,
    Approved,
    ChangesRequested,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoAssetSummary {
    pub asset_id: AssetId,
    pub frameio_project_id: FrameIoProjectId,
    pub status: FrameIoReviewStatus,
    pub observed_at: DateTime<Utc>,
    pub revision: Revision,
    pub asset_digest: Digest,
}

impl FrameIoAssetSummary {
    pub fn new(
        asset_id: AssetId,
        frameio_project_id: FrameIoProjectId,
        status: FrameIoReviewStatus,
        observed_at: DateTime<Utc>,
        revision: Revision,
    ) -> Self {
        let asset_digest = Digest::from_fields(
            "frameio-asset-summary/v1",
            &[
                asset_id.as_str().to_owned(),
                frameio_project_id.as_str().to_owned(),
                format!("{status:?}"),
                observed_at.to_rfc3339(),
                revision.get().to_string(),
            ],
        );
        Self {
            asset_id,
            frameio_project_id,
            status,
            observed_at,
            revision,
            asset_digest,
        }
    }

    pub fn digest_is_valid(&self) -> bool {
        Self::new(
            self.asset_id.clone(),
            self.frameio_project_id.clone(),
            self.status,
            self.observed_at,
            self.revision,
        )
        .asset_digest
            == self.asset_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoVersionSummary {
    pub asset_id: AssetId,
    pub version_id: AssetVersionId,
    pub status: FrameIoReviewStatus,
    pub observed_at: DateTime<Utc>,
    pub revision: Revision,
    pub version_digest: Digest,
}

impl FrameIoVersionSummary {
    pub fn new(
        asset_id: AssetId,
        version_id: AssetVersionId,
        status: FrameIoReviewStatus,
        observed_at: DateTime<Utc>,
        revision: Revision,
    ) -> Self {
        let version_digest = Digest::from_fields(
            "frameio-version-summary/v1",
            &[
                asset_id.as_str().to_owned(),
                version_id.as_str().to_owned(),
                format!("{status:?}"),
                observed_at.to_rfc3339(),
                revision.get().to_string(),
            ],
        );
        Self {
            asset_id,
            version_id,
            status,
            observed_at,
            revision,
            version_digest,
        }
    }

    pub fn digest_is_valid(&self) -> bool {
        Self::new(
            self.asset_id.clone(),
            self.version_id.clone(),
            self.status,
            self.observed_at,
            self.revision,
        )
        .version_digest
            == self.version_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoReviewLinkSummary {
    pub review_link_id: ReviewLinkId,
    pub state: FrameIoReviewLinkState,
    pub approval: FrameIoApprovalStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub reviewer_count: u32,
    pub observed_at: DateTime<Utc>,
    pub revision: Revision,
    pub review_link_digest: Digest,
}

impl FrameIoReviewLinkSummary {
    pub fn new(
        review_link_id: ReviewLinkId,
        state: FrameIoReviewLinkState,
        approval: FrameIoApprovalStatus,
        expires_at: Option<DateTime<Utc>>,
        reviewer_count: u32,
        observed_at: DateTime<Utc>,
        revision: Revision,
    ) -> Self {
        let review_link_digest = Digest::from_fields(
            "frameio-review-link-summary/v1",
            &[
                review_link_id.as_str().to_owned(),
                format!("{state:?}"),
                format!("{approval:?}"),
                expires_at.map_or_else(String::new, |value| value.to_rfc3339()),
                reviewer_count.to_string(),
                observed_at.to_rfc3339(),
                revision.get().to_string(),
            ],
        );
        Self {
            review_link_id,
            state,
            approval,
            expires_at,
            reviewer_count,
            observed_at,
            revision,
            review_link_digest,
        }
    }

    pub fn digest_is_valid(&self) -> bool {
        Self::new(
            self.review_link_id.clone(),
            self.state,
            self.approval,
            self.expires_at,
            self.reviewer_count,
            self.observed_at,
            self.revision,
        )
        .review_link_digest
            == self.review_link_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoApprovalSummary {
    pub status: FrameIoApprovalStatus,
    pub observed_at: DateTime<Utc>,
    pub revision: Revision,
    pub approval_digest: Digest,
}

impl FrameIoApprovalSummary {
    pub fn new(
        status: FrameIoApprovalStatus,
        observed_at: DateTime<Utc>,
        revision: Revision,
    ) -> Self {
        let approval_digest = Digest::from_fields(
            "frameio-approval-summary/v1",
            &[
                format!("{status:?}"),
                observed_at.to_rfc3339(),
                revision.get().to_string(),
            ],
        );
        Self {
            status,
            observed_at,
            revision,
            approval_digest,
        }
    }

    pub fn digest_is_valid(&self) -> bool {
        Self::new(self.status, self.observed_at, self.revision).approval_digest
            == self.approval_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoCommentSummary {
    pub total_count: u32,
    pub open_count: u32,
    pub completed_count: u32,
    pub reply_count: u32,
    pub redacted_annotation_count: u32,
    pub first_observed_at: Option<DateTime<Utc>>,
    pub last_observed_at: Option<DateTime<Utc>>,
    pub partial: bool,
    pub revision: Revision,
    pub comment_digest: Digest,
}

impl FrameIoCommentSummary {
    pub fn new(
        total_count: u32,
        open_count: u32,
        completed_count: u32,
        reply_count: u32,
        redacted_annotation_count: u32,
        first_observed_at: Option<DateTime<Utc>>,
        last_observed_at: Option<DateTime<Utc>>,
        partial: bool,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        if total_count > FRAME_IO_MAX_COMMENT_SUMMARIES
            || open_count.saturating_add(completed_count) > total_count
            || reply_count > FRAME_IO_MAX_COMMENT_SUMMARIES
            || redacted_annotation_count > FRAME_IO_MAX_COMMENT_SUMMARIES
            || matches!((first_observed_at, last_observed_at), (Some(first), Some(last)) if first > last)
        {
            return Err(ModelError::InvalidCommentSummary);
        }
        let comment_digest = Digest::from_fields(
            "frameio-comment-summary/v1",
            &[
                total_count.to_string(),
                open_count.to_string(),
                completed_count.to_string(),
                reply_count.to_string(),
                redacted_annotation_count.to_string(),
                first_observed_at.map_or_else(String::new, |value| value.to_rfc3339()),
                last_observed_at.map_or_else(String::new, |value| value.to_rfc3339()),
                partial.to_string(),
                revision.get().to_string(),
            ],
        );
        Ok(Self {
            total_count,
            open_count,
            completed_count,
            reply_count,
            redacted_annotation_count,
            first_observed_at,
            last_observed_at,
            partial,
            revision,
            comment_digest,
        })
    }

    pub fn empty(observed_at: DateTime<Utc>, revision: Revision) -> Self {
        Self::new(
            0,
            0,
            0,
            0,
            0,
            Some(observed_at),
            Some(observed_at),
            false,
            revision,
        )
        .expect("empty comment summary is valid")
    }

    pub fn merge(&self, other: &Self, max_total: u32) -> Result<Self, ModelError> {
        let total_count = self.total_count.saturating_add(other.total_count);
        if total_count > max_total {
            return Err(ModelError::InvalidCommentSummary);
        }
        let first_observed_at = match (self.first_observed_at, other.first_observed_at) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let last_observed_at = match (self.last_observed_at, other.last_observed_at) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        Self::new(
            total_count,
            self.open_count.saturating_add(other.open_count),
            self.completed_count.saturating_add(other.completed_count),
            self.reply_count.saturating_add(other.reply_count),
            self.redacted_annotation_count
                .saturating_add(other.redacted_annotation_count),
            first_observed_at,
            last_observed_at,
            self.partial || other.partial,
            self.revision,
        )
    }

    pub fn digest_is_valid(&self) -> bool {
        Self::new(
            self.total_count,
            self.open_count,
            self.completed_count,
            self.reply_count,
            self.redacted_annotation_count,
            self.first_observed_at,
            self.last_observed_at,
            self.partial,
            self.revision,
        )
        .is_ok_and(|summary| summary.comment_digest == self.comment_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoPayload {
    Asset(FrameIoAssetSummary),
    Version(FrameIoVersionSummary),
    ReviewLink(FrameIoReviewLinkSummary),
    Approval(FrameIoApprovalSummary),
    Comments(FrameIoCommentSummary),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum FrameIoHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum FrameIoApiEndpoint {
    AssetMetadata,
    AssetVersion,
    ReviewLink,
    ApprovalStatus,
    CommentSummary,
}

impl FrameIoApiEndpoint {
    pub const fn for_operation(operation: FrameIoReadOperation) -> Self {
        match operation {
            FrameIoReadOperation::AssetMetadata => Self::AssetMetadata,
            FrameIoReadOperation::AssetVersion => Self::AssetVersion,
            FrameIoReadOperation::ReviewLink => Self::ReviewLink,
            FrameIoReadOperation::ApprovalStatus => Self::ApprovalStatus,
            FrameIoReadOperation::CommentSummary => Self::CommentSummary,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FrameIoRedactions {
    pub media_urls: bool,
    pub signed_urls: bool,
    pub thumbnails: bool,
    pub raw_comments: bool,
    pub reviewer_pii: bool,
    pub drawings: bool,
    pub binaries: bool,
    pub provider_payload: bool,
}

impl FrameIoRedactions {
    pub const fn layer_one() -> Self {
        Self {
            media_urls: true,
            signed_urls: true,
            thumbnails: true,
            raw_comments: true,
            reviewer_pii: true,
            drawings: true,
            binaries: true,
            provider_payload: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FrameIoAuthority {
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub external_writes: bool,
    pub media_download: bool,
    pub signed_url_exposure: bool,
    pub raw_comments: bool,
    pub reviewer_pii: bool,
    pub drawings: bool,
    pub binaries: bool,
    pub webhook_registration: bool,
    pub publication: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl FrameIoAuthority {
    pub const fn layer_one() -> Self {
        Self {
            read_only: true,
            live_execution: false,
            connected: false,
            native_provider: false,
            external_writes: false,
            media_download: false,
            signed_url_exposure: false,
            raw_comments: false,
            reviewer_pii: false,
            drawings: false,
            binaries: false,
            webhook_registration: false,
            publication: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::from_bytes(&bytes))
        .map_err(|error| ModelError::Serialization(error.to_string()))
}

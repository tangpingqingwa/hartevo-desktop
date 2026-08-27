//! Mission-side admission for exact YouTube publish evidence.

use chrono::{DateTime, Utc};

use super::{
    DraftVideoPublishRequest, YouTubeCredential, YouTubeDispatchOperation, YouTubeError,
    YouTubeEvidenceProvenance, YouTubePublishBinding, YouTubePublishedVideo,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionYouTubePublishConsumer {
    binding: YouTubePublishBinding,
    expected_request_digest: String,
}

impl MissionYouTubePublishConsumer {
    pub fn new(
        binding: YouTubePublishBinding,
        request: &DraftVideoPublishRequest,
    ) -> Result<Self, YouTubeError> {
        if request.binding() != &binding {
            return Err(YouTubeError::ScopeMismatch);
        }
        Ok(Self {
            binding,
            expected_request_digest: request.request_digest(),
        })
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub fn expected_request_digest(&self) -> &str {
        &self.expected_request_digest
    }

    pub fn accept(
        &self,
        request: &DraftVideoPublishRequest,
        published: YouTubePublishedVideo,
        credential: &YouTubeCredential,
        now: DateTime<Utc>,
    ) -> Result<YouTubeMissionAcceptedPublish, YouTubeError> {
        request.validate_at(now)?;
        if request.binding() != &self.binding
            || request.request_digest() != self.expected_request_digest
            || published.request_digest() != request.request_digest()
        {
            return Err(YouTubeError::ScopeMismatch);
        }
        credential.require_for(YouTubeDispatchOperation::Readback, &self.binding, now)?;
        if published.credential_generation() != credential.generation()
            || published.provenance() != YouTubeEvidenceProvenance::ProductionProvider
            || published.probe().provenance() != YouTubeEvidenceProvenance::ProductionProvider
            || published.provider_receipt().provenance()
                != YouTubeEvidenceProvenance::ProductionProvider
            || published.readback().provenance() != YouTubeEvidenceProvenance::ProductionProvider
        {
            return Err(YouTubeError::ProviderRejected(
                "Mission requires production YouTube evidence".to_owned(),
            ));
        }
        published.probe().validate_at(now)?;
        published.readback().validate_at(now)?;
        published
            .readback()
            .verify_against(request, published.provider_receipt())?;
        if !published.readback().is_ready() {
            return Err(YouTubeError::ReadbackPending);
        }
        Ok(YouTubeMissionAcceptedPublish {
            request: request.clone(),
            published,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YouTubeMissionAcceptedPublish {
    request: DraftVideoPublishRequest,
    published: YouTubePublishedVideo,
}

impl YouTubeMissionAcceptedPublish {
    pub const fn request(&self) -> &DraftVideoPublishRequest {
        &self.request
    }

    pub const fn published(&self) -> &YouTubePublishedVideo {
        &self.published
    }
}

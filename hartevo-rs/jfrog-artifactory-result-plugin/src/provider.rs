//! Typed JFrog Artifactory provider and bounded non-native transport fixtures.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::model::{
    AqlMetadataQuery, AqlMetadataRecord, AqlRange, ArtifactChecksums, ArtifactMetadata,
    ArtifactStatus, BuildInfoEvidence, Digest, JfrogScope, ProjectionCompleteness,
    PromotionEvidence, TransportProvenance,
};
use crate::service::JfrogRegistration;
use crate::{
    JfrogArtifactoryResultError, JfrogProviderError, JfrogTransportError, MAX_AQL_RESULTS,
    MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES, MAX_PAGES, MAX_RESPONSE_BYTES, Result, validate_text,
};

/// A single bounded request for Artifactory build/artifact metadata. It never
/// contains a credential or an arbitrary AQL string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadataReadRequest {
    pub scope: JfrogScope,
    pub request_id: String,
    pub page_size: usize,
    pub page_token: Option<String>,
    pub expected_checksums: Option<ArtifactChecksums>,
    pub aql_query: AqlMetadataQuery,
}

impl ArtifactMetadataReadRequest {
    pub fn new(
        scope: JfrogScope,
        request_id: impl Into<String>,
        page_size: usize,
        page_token: Option<String>,
        expected_checksums: Option<ArtifactChecksums>,
    ) -> Result<Self> {
        let request = Self {
            aql_query: AqlMetadataQuery::for_scope(&scope, page_size, 0)?,
            scope,
            request_id: request_id.into(),
            page_size,
            page_token,
            expected_checksums,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        validate_text(&self.request_id, "requestId", 128, false)?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        if let Some(token) = &self.page_token {
            validate_text(token, "pageToken", MAX_PAGE_TOKEN_BYTES, false)?;
        }
        if let Some(checksums) = &self.expected_checksums {
            checksums.validate()?;
        }
        self.aql_query.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// A closed, allowlisted provider response. There is no raw JSON, artifact
/// byte payload, download URL, raw log, or arbitrary AQL field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JfrogArtifactoryResponse {
    pub scope: JfrogScope,
    pub status: ArtifactStatus,
    pub artifact_metadata: Option<ArtifactMetadata>,
    pub build_info: Option<BuildInfoEvidence>,
    pub promotion: Option<PromotionEvidence>,
    pub aql_query_digest: Digest,
    pub aql_results: Vec<AqlMetadataRecord>,
    pub aql_range: Option<AqlRange>,
    pub truncated: bool,
    pub response_bytes: usize,
    pub provider_request_id_digest: Digest,
    pub request_page_token: Option<String>,
    pub next_page_token: Option<String>,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl JfrogArtifactoryResponse {
    pub fn for_scope(scope: &JfrogScope, provenance: TransportProvenance) -> Self {
        let mut response = Self {
            scope: scope.clone(),
            status: ArtifactStatus::Missing,
            artifact_metadata: None,
            build_info: None,
            promotion: None,
            aql_query_digest: AqlMetadataQuery::for_scope(scope, 1, 0).map_or_else(
                |_| Digest::from_text("invalid-fixture-query"),
                |query| query.query_digest,
            ),
            aql_results: Vec::new(),
            aql_range: None,
            truncated: false,
            response_bytes: 256,
            provider_request_id_digest: Digest::from_text("jfrog-fixture-request"),
            request_page_token: None,
            next_page_token: None,
            provenance,
            response_digest: Digest::from_text("unsealed-jfrog-response"),
        };
        response.seal();
        response
    }

    pub fn missing(scope: &JfrogScope, provenance: TransportProvenance) -> Self {
        Self::for_scope(scope, provenance)
    }

    pub fn partial(scope: &JfrogScope, provenance: TransportProvenance) -> Self {
        Self::for_scope(scope, provenance).with_status(ArtifactStatus::Partial)
    }

    pub fn rejected(scope: &JfrogScope, provenance: TransportProvenance) -> Self {
        Self::for_scope(scope, provenance).with_status(ArtifactStatus::Rejected)
    }

    pub fn access_lost(scope: &JfrogScope, provenance: TransportProvenance) -> Self {
        Self::for_scope(scope, provenance).with_status(ArtifactStatus::AccessLost)
    }

    pub fn provider_unknown(scope: &JfrogScope, provenance: TransportProvenance) -> Self {
        Self::for_scope(scope, provenance).with_status(ArtifactStatus::ProviderUnknown)
    }

    pub fn present(
        scope: &JfrogScope,
        artifact_metadata: ArtifactMetadata,
        build_info: Option<BuildInfoEvidence>,
        promotion: Option<PromotionEvidence>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut response = Self::for_scope(scope, provenance);
        response.status = if promotion
            .as_ref()
            .is_some_and(|value| value.state == crate::PromotionState::Promoted)
        {
            ArtifactStatus::Promoted
        } else {
            ArtifactStatus::Present
        };
        response.artifact_metadata = Some(artifact_metadata);
        response.build_info = build_info;
        response.promotion = promotion;
        response.response_bytes = 512;
        response.seal();
        response.validate_semantics(None)?;
        Ok(response)
    }

    #[must_use]
    pub fn with_status(mut self, status: ArtifactStatus) -> Self {
        self.status = status;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_artifact_metadata(mut self, artifact_metadata: ArtifactMetadata) -> Self {
        if self.status == ArtifactStatus::Missing {
            self.status = ArtifactStatus::Present;
        }
        self.artifact_metadata = Some(artifact_metadata);
        self.seal();
        self
    }

    #[must_use]
    pub fn with_build_info(mut self, build_info: BuildInfoEvidence) -> Self {
        if self.status == ArtifactStatus::Missing {
            self.status = ArtifactStatus::Present;
        }
        self.build_info = Some(build_info);
        self.seal();
        self
    }

    #[must_use]
    pub fn with_promotion(mut self, promotion: PromotionEvidence) -> Self {
        if promotion.state == crate::PromotionState::Promoted {
            self.status = ArtifactStatus::Promoted;
        }
        self.promotion = Some(promotion);
        self.seal();
        self
    }

    #[must_use]
    pub fn with_aql_results(
        mut self,
        results: Vec<AqlMetadataRecord>,
        range: Option<AqlRange>,
    ) -> Self {
        self.aql_results = results;
        self.aql_range = range;
        self.response_bytes = 256 + self.aql_results.len() * 384;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_next_page_token(mut self, next_page_token: impl Into<String>) -> Self {
        self.next_page_token = Some(next_page_token.into());
        self.seal();
        self
    }

    #[must_use]
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_provider_request_digest(mut self, digest: Digest) -> Self {
        self.provider_request_id_digest = digest;
        self.seal();
        self
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES || self.aql_results.len() > MAX_AQL_RESULTS {
            return Err(JfrogArtifactoryResultError::ResponseTooLarge);
        }
        self.aql_query_digest.validate()?;
        self.provider_request_id_digest.validate()?;
        if let Some(token) = &self.request_page_token {
            validate_text(token, "requestPageToken", MAX_PAGE_TOKEN_BYTES, false)?;
        }
        if let Some(token) = &self.next_page_token {
            validate_text(token, "nextPageToken", MAX_PAGE_TOKEN_BYTES, false)?;
        }
        if let Some(range) = &self.aql_range {
            range.validate()?;
        }
        for record in &self.aql_results {
            record.validate()?;
        }
        if self.provenance.is_native() || self.provenance.claims_connected() {
            return Err(JfrogArtifactoryResultError::ProvenanceMismatch);
        }
        if self.response_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_semantics(&self, expected_checksums: Option<&ArtifactChecksums>) -> Result<()> {
        self.validate()?;
        if let Some(artifact) = &self.artifact_metadata {
            artifact.validate_for_scope(&self.scope)?;
            if expected_checksums.is_some_and(|expected| expected != &artifact.checksums) {
                return Err(JfrogArtifactoryResultError::ChecksumMismatch);
            }
        }
        if let Some(build_info) = &self.build_info {
            build_info.validate_for_scope(&self.scope)?;
        }
        if let Some(promotion) = &self.promotion {
            promotion.validate_for_scope(&self.scope)?;
        }
        for record in &self.aql_results {
            record.validate_for_scope(&self.scope)?;
        }
        match self.status {
            ArtifactStatus::Present | ArtifactStatus::Promoted
                if self.artifact_metadata.is_none() =>
            {
                Err(JfrogArtifactoryResultError::MalformedResponse)
            }
            ArtifactStatus::Missing
                if self.artifact_metadata.is_some() || self.build_info.is_some() =>
            {
                Err(JfrogArtifactoryResultError::MalformedResponse)
            }
            ArtifactStatus::AccessLost | ArtifactStatus::ProviderUnknown
                if self.artifact_metadata.is_some() =>
            {
                Err(JfrogArtifactoryResultError::MalformedResponse)
            }
            ArtifactStatus::Promoted
                if self
                    .promotion
                    .as_ref()
                    .is_none_or(|promotion| promotion.state != crate::PromotionState::Promoted) =>
            {
                Err(JfrogArtifactoryResultError::PromotionMismatch)
            }
            ArtifactStatus::Rejected
                if self.promotion.as_ref().is_some_and(|promotion| {
                    promotion.state != crate::PromotionState::Rejected
                }) =>
            {
                Err(JfrogArtifactoryResultError::PromotionMismatch)
            }
            _ => Ok(()),
        }
    }

    fn seal(&mut self) {
        self.response_digest = self.calculate_digest();
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope,
            self.status,
            &self.artifact_metadata,
            &self.build_info,
            &self.promotion,
            &self.aql_query_digest,
            &self.aql_results,
            &self.aql_range,
            self.truncated,
            self.response_bytes,
            &self.provider_request_id_digest,
            &self.request_page_token,
            &self.next_page_token,
            self.provenance,
        ))
    }

    fn for_request(
        &self,
        request: &ArtifactMetadataReadRequest,
        provenance: TransportProvenance,
    ) -> Self {
        let mut response = self.clone();
        response.request_page_token.clone_from(&request.page_token);
        response.aql_query_digest = request.aql_query.query_digest.clone();
        response.provenance = provenance;
        response.seal();
        response
    }
}

/// A safe bounded projection merged across at most MAX_PAGES AQL pages.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JfrogArtifactProjection {
    pub scope: JfrogScope,
    pub scope_digest: Digest,
    pub status: ArtifactStatus,
    pub artifact_metadata: Option<ArtifactMetadata>,
    pub build_info: Option<BuildInfoEvidence>,
    pub promotion: Option<PromotionEvidence>,
    pub aql_query_digest: Digest,
    pub aql_results: Vec<AqlMetadataRecord>,
    pub aql_range: Option<AqlRange>,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub response_bytes: usize,
    pub provider_request_id_digest: Digest,
    pub provenance: TransportProvenance,
    pub provenance_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub artifact_bytes_retained: bool,
    pub raw_logs_retained: bool,
    pub projection_digest: Digest,
}

impl JfrogArtifactProjection {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        scope: JfrogScope,
        status: ArtifactStatus,
        artifact_metadata: Option<ArtifactMetadata>,
        build_info: Option<BuildInfoEvidence>,
        promotion: Option<PromotionEvidence>,
        aql_query_digest: Digest,
        aql_results: Vec<AqlMetadataRecord>,
        aql_range: Option<AqlRange>,
        response_truncated: bool,
        response_bytes: usize,
        provider_request_id_digest: Digest,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let completeness = if response_truncated || status == ArtifactStatus::Partial {
            if response_truncated {
                ProjectionCompleteness::Truncated
            } else {
                ProjectionCompleteness::Partial
            }
        } else {
            ProjectionCompleteness::Complete
        };
        let provenance_digest = Digest::from_parts(
            "jfrog-provider-provenance/v1",
            &[
                ("provenance", provenance.as_str().to_owned()),
                ("request", provider_request_id_digest.as_str().to_owned()),
                ("scope", scope.digest().as_str().to_owned()),
            ],
        );
        let mut projection = Self {
            scope_digest: scope.digest(),
            scope,
            status,
            artifact_metadata,
            build_info,
            promotion,
            aql_query_digest,
            aql_results,
            aql_range,
            completeness,
            response_truncated,
            response_bytes,
            provider_request_id_digest,
            provenance,
            provenance_digest,
            connected: false,
            native: false,
            artifact_bytes_retained: false,
            raw_logs_retained: false,
            projection_digest: Digest::from_text("unsealed-jfrog-projection"),
        };
        projection.projection_digest = projection.calculate_digest();
        projection.validate_integrity()?;
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        if self.scope_digest != self.scope.digest()
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.aql_results.len() > MAX_AQL_RESULTS
            || self.connected
            || self.native
            || self.artifact_bytes_retained
            || self.raw_logs_retained
            || self.provenance.is_native()
            || self.provenance.claims_connected()
            || self.projection_digest != self.calculate_digest()
        {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        self.aql_query_digest.validate()?;
        self.provider_request_id_digest.validate()?;
        self.provenance_digest.validate()?;
        if let Some(artifact) = &self.artifact_metadata {
            artifact.validate_for_scope(&self.scope)?;
        }
        if let Some(build_info) = &self.build_info {
            build_info.validate_for_scope(&self.scope)?;
        }
        if let Some(promotion) = &self.promotion {
            promotion.validate_for_scope(&self.scope)?;
        }
        for record in &self.aql_results {
            record.validate_for_scope(&self.scope)?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn is_adoptable(&self) -> bool {
        false
    }

    pub fn artifact_metadata_digest(&self) -> Option<&Digest> {
        self.artifact_metadata
            .as_ref()
            .map(|metadata| &metadata.metadata_digest)
    }

    pub fn build_info_digest(&self) -> Option<&Digest> {
        self.build_info
            .as_ref()
            .map(|build_info| &build_info.build_info_digest)
    }

    pub fn checksum_digest(&self) -> Option<Digest> {
        self.artifact_metadata
            .as_ref()
            .map(|metadata| metadata.checksums.digest())
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            self.status,
            &self.artifact_metadata,
            &self.build_info,
            &self.promotion,
            &self.aql_query_digest,
            &self.aql_results,
            &self.aql_range,
            self.completeness,
            self.response_truncated,
            self.response_bytes,
            &self.provider_request_id_digest,
            self.provenance,
            &self.provenance_digest,
        ))
    }
}

pub type JfrogArtifactoryResultProjection = JfrogArtifactProjection;

/// The only transport seam. Layer 1 implementations are deterministic
/// fixtures; a live HTTPS implementation is intentionally Layer 2.
pub trait JfrogArtifactoryTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<JfrogArtifactoryResponse, JfrogTransportError>;
}

#[derive(Clone, Debug)]
struct FixtureQueue {
    responses: VecDeque<JfrogArtifactoryResponse>,
    fallback: Option<JfrogArtifactoryResponse>,
    error: Option<JfrogTransportError>,
    requests: Vec<Digest>,
}

impl FixtureQueue {
    fn new(response: JfrogArtifactoryResponse) -> Self {
        Self {
            responses: VecDeque::from([response.clone()]),
            fallback: Some(response),
            error: None,
            requests: Vec::new(),
        }
    }

    fn with_pages(mut self, responses: Vec<JfrogArtifactoryResponse>) -> Self {
        self.fallback = responses.last().cloned();
        self.responses = responses.into();
        self
    }

    fn with_error(mut self, error: JfrogTransportError) -> Self {
        self.error = Some(error);
        self
    }

    fn next(
        &mut self,
        request: &ArtifactMetadataReadRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<JfrogArtifactoryResponse, JfrogTransportError> {
        self.requests.push(request.digest());
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let response = self
            .responses
            .pop_front()
            .or_else(|| self.fallback.clone())
            .ok_or(JfrogTransportError::MalformedResponse)?;
        Ok(response.for_request(request, provenance))
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    queue: FixtureQueue,
}

impl RecordingTransport {
    pub fn new(response: JfrogArtifactoryResponse) -> Self {
        Self {
            queue: FixtureQueue::new(response),
        }
    }

    #[must_use]
    pub fn with_pages(mut self, responses: Vec<JfrogArtifactoryResponse>) -> Self {
        self.queue = self.queue.with_pages(responses);
        self
    }

    #[must_use]
    pub fn with_error(mut self, error: JfrogTransportError) -> Self {
        self.queue = self.queue.with_error(error);
        self
    }

    pub fn request_count(&self) -> usize {
        self.queue.requests.len()
    }

    pub fn request_digests(&self) -> &[Digest] {
        &self.queue.requests
    }
}

impl JfrogArtifactoryTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<JfrogArtifactoryResponse, JfrogTransportError> {
        self.queue.next(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    queue: FixtureQueue,
}

impl FakeTransport {
    pub fn new(response: JfrogArtifactoryResponse) -> Self {
        Self {
            queue: FixtureQueue::new(response),
        }
    }

    #[must_use]
    pub fn with_pages(mut self, responses: Vec<JfrogArtifactoryResponse>) -> Self {
        self.queue = self.queue.with_pages(responses);
        self
    }

    #[must_use]
    pub fn with_error(mut self, error: JfrogTransportError) -> Self {
        self.queue = self.queue.with_error(error);
        self
    }

    pub const fn request_count(&self) -> usize {
        self.queue.requests.len()
    }
}

impl JfrogArtifactoryTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<JfrogArtifactoryResponse, JfrogTransportError> {
        self.queue.next(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    queue: FixtureQueue,
}

impl LoopbackTransport {
    pub fn new(response: JfrogArtifactoryResponse) -> Self {
        Self {
            queue: FixtureQueue::new(response),
        }
    }

    #[must_use]
    pub fn with_pages(mut self, responses: Vec<JfrogArtifactoryResponse>) -> Self {
        self.queue = self.queue.with_pages(responses);
        self
    }

    #[must_use]
    pub fn with_error(mut self, error: JfrogTransportError) -> Self {
        self.queue = self.queue.with_error(error);
        self
    }
}

impl JfrogArtifactoryTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<JfrogArtifactoryResponse, JfrogTransportError> {
        self.queue.next(request, self.provenance())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl BlockedEnvTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl JfrogArtifactoryTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_artifact_metadata(
        &mut self,
        _request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<JfrogArtifactoryResponse, JfrogTransportError> {
        Err(JfrogTransportError::EnvironmentBlocked)
    }
}

pub type JfrogRecordingTransport = RecordingTransport;
pub type JfrogFakeTransport = FakeTransport;
pub type JfrogLoopbackTransport = LoopbackTransport;

/// Typed, read-only JFrog provider. It checks the complete registration and
/// exact identity fence before projecting any fixture response.
#[derive(Clone, Debug)]
pub struct JfrogArtifactoryProvider<T> {
    registration: JfrogRegistration,
    transport: T,
}

impl<T: JfrogArtifactoryTransport> JfrogArtifactoryProvider<T> {
    pub fn new(
        registration: JfrogRegistration,
        transport: T,
    ) -> std::result::Result<Self, JfrogProviderError> {
        registration
            .validate()
            .map_err(JfrogProviderError::Registration)?;
        if registration.secret_reference().is_revoked() {
            return Err(JfrogProviderError::SecretRevoked);
        }
        match registration.status() {
            crate::RegistrationStatus::Active => Ok(Self {
                registration,
                transport,
            }),
            crate::RegistrationStatus::Revoked => Err(JfrogProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => Err(JfrogProviderError::RegistrationReversed),
        }
    }

    pub fn registration(&self) -> &JfrogRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut JfrogRegistration {
        &mut self.registration
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read_artifact_metadata<S: Into<ArtifactReadSelector>>(
        &mut self,
        selector: S,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        let selector = selector.into();
        let request_id = selector.request_id();
        self.read_with_options(&request_id, selector.page_size(), None)
    }

    pub fn read_release_evidence(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        let request_id = request_id.into();
        self.read_with_options(&request_id, MAX_PAGE_SIZE, None)
    }

    pub fn read_build_info(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.read_release_evidence(request_id)
    }

    pub fn read_artifact_metadata_with_page_size(
        &mut self,
        request_id: impl Into<String>,
        page_size: usize,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        let request_id = request_id.into();
        self.read_with_options(&request_id, page_size, None)
    }

    pub fn read_artifact_with_expected_checksums(
        &mut self,
        request_id: impl Into<String>,
        expected_checksums: impl AsRef<ArtifactChecksums>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        let request_id = request_id.into();
        self.read_with_options(
            &request_id,
            MAX_PAGE_SIZE,
            Some(expected_checksums.as_ref()),
        )
    }

    pub fn read_aql_metadata(
        &mut self,
        request_id: impl Into<String>,
        page_size: usize,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        let request_id = request_id.into();
        self.read_with_options(&request_id, page_size, None)
    }

    #[allow(clippy::too_many_lines)]
    fn read_with_options(
        &mut self,
        request_id: &str,
        page_size: usize,
        expected_checksums: Option<&ArtifactChecksums>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.ensure_registration_active()?;
        let scope = self.registration.scope().clone();
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut pages = 0;
        let mut total_response_bytes = 0_usize;
        let mut all_aql_results = Vec::new();
        let mut seen_aql_results = BTreeSet::new();
        let mut seen_aql_identities = BTreeSet::new();
        let mut artifact_metadata = None;
        let mut build_info = None;
        let mut promotion = None;
        let mut status = None;
        let mut truncated = false;
        let mut aql_range = None;
        let mut provider_request_id_digest = None;
        let mut aql_query_digest = None;

        loop {
            pages += 1;
            let request = ArtifactMetadataReadRequest::new(
                scope.clone(),
                request_id.to_owned(),
                page_size,
                page_token.clone(),
                expected_checksums.cloned(),
            )
            .map_err(JfrogProviderError::Registration)?;
            let response = self.transport.read_artifact_metadata(&request)?;
            self.validate_response(&response, &request)?;
            total_response_bytes = total_response_bytes
                .checked_add(response.response_bytes)
                .ok_or(JfrogProviderError::ResponseTooLarge)?;
            if total_response_bytes > MAX_RESPONSE_BYTES {
                return Err(JfrogProviderError::ResponseTooLarge);
            }
            if let Some(existing) = &status {
                if existing != &response.status {
                    return Err(JfrogProviderError::TamperedEvidence);
                }
            } else {
                status = Some(response.status);
            }
            merge_optional(&mut artifact_metadata, response.artifact_metadata)?;
            merge_optional(&mut build_info, response.build_info)?;
            merge_optional(&mut promotion, response.promotion)?;
            if let Some(existing) = &provider_request_id_digest {
                if existing != &response.provider_request_id_digest {
                    return Err(JfrogProviderError::TamperedEvidence);
                }
            } else {
                provider_request_id_digest = Some(response.provider_request_id_digest.clone());
            }
            if let Some(existing) = &aql_query_digest {
                if existing != &response.aql_query_digest {
                    return Err(JfrogProviderError::TamperedEvidence);
                }
            } else {
                aql_query_digest = Some(response.aql_query_digest.clone());
            }
            if let Some(range) = response.aql_range {
                aql_range = Some(range);
            }
            for record in response.aql_results {
                let identity = (
                    record.repository.id().to_owned(),
                    record.artifact_path.as_str().to_owned(),
                    record.artifact.id().to_owned(),
                );
                if !seen_aql_identities.insert(identity) {
                    return Err(JfrogProviderError::DuplicateEvidence);
                }
                if !seen_aql_results.insert(record.metadata_digest.clone()) {
                    return Err(JfrogProviderError::DuplicateEvidence);
                }
                if all_aql_results.len() >= MAX_AQL_RESULTS {
                    return Err(JfrogProviderError::EvidenceLimit);
                }
                all_aql_results.push(record);
            }
            truncated |= response.truncated;

            let Some(next_page_token) = response.next_page_token else {
                break;
            };
            validate_text(
                &next_page_token,
                "nextPageToken",
                MAX_PAGE_TOKEN_BYTES,
                false,
            )
            .map_err(|_| JfrogProviderError::TamperedEvidence)?;
            if !seen_tokens.insert(next_page_token.clone()) {
                return Err(JfrogProviderError::PaginationLoop);
            }
            if pages >= MAX_PAGES {
                return Err(JfrogProviderError::PaginationLimit);
            }
            page_token = Some(next_page_token);
        }

        JfrogArtifactProjection::from_parts(
            scope,
            status.ok_or(JfrogProviderError::TamperedEvidence)?,
            artifact_metadata,
            build_info,
            promotion,
            aql_query_digest.ok_or(JfrogProviderError::TamperedEvidence)?,
            all_aql_results,
            aql_range,
            truncated,
            total_response_bytes,
            provider_request_id_digest.ok_or(JfrogProviderError::TamperedEvidence)?,
            self.transport.provenance(),
        )
        .map_err(JfrogProviderError::Registration)
    }

    fn ensure_registration_active(&self) -> std::result::Result<(), JfrogProviderError> {
        self.registration
            .validate()
            .map_err(|_| JfrogProviderError::RegistrationDrift)?;
        if self.registration.secret_reference().is_revoked() {
            return Err(JfrogProviderError::SecretRevoked);
        }
        match self.registration.status() {
            crate::RegistrationStatus::Active => Ok(()),
            crate::RegistrationStatus::Revoked => Err(JfrogProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => Err(JfrogProviderError::RegistrationReversed),
        }
    }

    fn validate_response(
        &self,
        response: &JfrogArtifactoryResponse,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<(), JfrogProviderError> {
        response
            .validate()
            .map_err(|error| map_model_error(&error))?;
        let expected = request.scope.clone();
        let actual = &response.scope;
        if actual.host != expected.host {
            return Err(JfrogProviderError::HostDrift);
        }
        if actual.organization != expected.organization {
            return Err(JfrogProviderError::OrganizationDrift);
        }
        if actual.repository != expected.repository {
            return Err(JfrogProviderError::RepositoryDrift);
        }
        if actual.artifact_path != expected.artifact_path {
            return Err(JfrogProviderError::ArtifactPathDrift);
        }
        if actual.build != expected.build {
            return Err(JfrogProviderError::BuildDrift);
        }
        if actual.module != expected.module {
            return Err(JfrogProviderError::ModuleDrift);
        }
        if actual.artifact != expected.artifact {
            return Err(JfrogProviderError::ArtifactDrift);
        }
        if actual.commit != expected.commit {
            return Err(JfrogProviderError::CommitDrift);
        }
        if actual.mission != expected.mission {
            return Err(JfrogProviderError::MissionDrift);
        }
        if actual.project != expected.project {
            return Err(JfrogProviderError::ProjectDrift);
        }
        if actual.work_product != expected.work_product {
            return Err(JfrogProviderError::WorkProductDrift);
        }
        if response.request_page_token != request.page_token {
            return Err(JfrogProviderError::TamperedEvidence);
        }
        if response.aql_query_digest != request.aql_query.query_digest {
            return Err(JfrogProviderError::AqlNotAllowlisted);
        }
        if response.provenance != self.transport.provenance() {
            return Err(JfrogProviderError::TamperedEvidence);
        }
        response
            .validate_semantics(request.expected_checksums.as_ref())
            .map_err(|error| map_model_error(&error))?;
        Ok(())
    }
}

/// A selector keeps both the common page-size API and request-id API typed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactReadSelector {
    RequestId(String),
    PageSize(usize),
}

impl ArtifactReadSelector {
    fn request_id(&self) -> String {
        match self {
            Self::RequestId(request_id) => request_id.clone(),
            Self::PageSize(page_size) => format!("jfrog-artifact-read-page-{page_size}"),
        }
    }

    fn page_size(&self) -> usize {
        match self {
            Self::RequestId(_) => MAX_PAGE_SIZE,
            Self::PageSize(page_size) => *page_size,
        }
    }
}

impl From<usize> for ArtifactReadSelector {
    fn from(value: usize) -> Self {
        Self::PageSize(value)
    }
}

impl From<String> for ArtifactReadSelector {
    fn from(value: String) -> Self {
        Self::RequestId(value)
    }
}

impl From<&str> for ArtifactReadSelector {
    fn from(value: &str) -> Self {
        Self::RequestId(value.to_owned())
    }
}

macro_rules! impl_integer_selector {
    ($($type:ty),+ $(,)?) => {
        $(
            impl From<$type> for ArtifactReadSelector {
                fn from(value: $type) -> Self {
                    let page_size = usize::try_from(value).unwrap_or(usize::MAX);
                    Self::PageSize(page_size)
                }
            }
        )+
    };
}

impl_integer_selector!(u8, u16, u32, u64, i8, i16, i32, i64);

fn merge_optional<T: Eq>(
    destination: &mut Option<T>,
    incoming: Option<T>,
) -> std::result::Result<(), JfrogProviderError> {
    if let Some(incoming) = incoming {
        if let Some(existing) = destination {
            if existing != &incoming {
                return Err(JfrogProviderError::TamperedEvidence);
            }
        } else {
            *destination = Some(incoming);
        }
    }
    Ok(())
}

fn map_model_error(error: &JfrogArtifactoryResultError) -> JfrogProviderError {
    match error {
        JfrogArtifactoryResultError::ChecksumMismatch => JfrogProviderError::ChecksumMismatch,
        JfrogArtifactoryResultError::MetadataMismatch => JfrogProviderError::MetadataMismatch,
        JfrogArtifactoryResultError::BuildInfoRevisionMismatch => {
            JfrogProviderError::BuildInfoRevisionMismatch
        }
        JfrogArtifactoryResultError::PromotionMismatch => JfrogProviderError::PromotionMismatch,
        JfrogArtifactoryResultError::AqlNotAllowlisted => JfrogProviderError::AqlNotAllowlisted,
        JfrogArtifactoryResultError::AqlOutOfScope => JfrogProviderError::AqlOutOfScope,
        JfrogArtifactoryResultError::DuplicateEvidence => JfrogProviderError::DuplicateEvidence,
        JfrogArtifactoryResultError::EvidenceLimit => JfrogProviderError::EvidenceLimit,
        JfrogArtifactoryResultError::ResponseTooLarge => JfrogProviderError::ResponseTooLarge,
        _ => JfrogProviderError::TamperedEvidence,
    }
}

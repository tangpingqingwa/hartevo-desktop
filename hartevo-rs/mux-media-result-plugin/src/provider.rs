//! Mux provider seam: bounded GET metadata reads, redacted receipts, and
//! deterministic retry handling.  No native HTTP client or mutating method is
//! implemented in this Layer-1 root.

use std::collections::BTreeSet;

use crate::model::{
    AssetMetadataProjection, Digest, MuxAssetState, MuxError, MuxMediaResultEvidence,
    MuxMediaResultProposal, MuxMediaResultRequest, MuxPlaybackProjection, MuxReadReceipt, MuxScope,
    MuxTrackProjection, MuxTransportMode, RegistrationState, access_lost_asset,
    delivery_projection, project_playback_association,
};
use crate::service::MuxProviderDefinition;
use crate::transport::{
    MuxEndpoint, MuxHttpRequest, MuxHttpResponse, MuxResponseBody, MuxTransport, MuxTransportError,
};
use crate::{
    MISSION_MUX_MEDIA_RESULT_CONSUMER_ID, MUX_MAX_BACKOFF_SECONDS, MUX_MAX_CURSOR_BYTES,
    MUX_MAX_PAGES, MUX_MAX_PLAYBACK_IDS, MUX_MAX_RESPONSE_BYTES, MUX_MAX_RETRY_ATTEMPTS,
    MUX_MAX_TRACKS, MUX_MEDIA_RESULT_CONTRACT_VERSION, MUX_MEDIA_RESULT_PLUGIN_VERSION,
    MUX_MEDIA_RESULT_PROVIDER_ID, MUX_MEDIA_RESULT_PROVIDER_REVISION, contract_digest,
    plugin_version_digest, provider_digest,
};

pub use crate::model::MuxReadRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Timeout,
    ServerError,
    TransportUnavailable,
    MalformedResponse,
    UnexpectedStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl From<MuxTransportMode> for ProviderProvenance {
    fn from(mode: MuxTransportMode) -> Self {
        match mode {
            MuxTransportMode::Recording => Self::Recording,
            MuxTransportMode::Fixture => Self::Fixture,
            MuxTransportMode::Loopback => Self::Loopback,
            MuxTransportMode::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MuxReadBounds {
    pub max_response_bytes: usize,
    pub max_tracks: usize,
    pub max_playback_ids: usize,
    pub max_pages: u16,
    pub max_cursor_bytes: usize,
}

impl Default for MuxReadBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: MUX_MAX_RESPONSE_BYTES,
            max_tracks: MUX_MAX_TRACKS,
            max_playback_ids: MUX_MAX_PLAYBACK_IDS,
            max_pages: MUX_MAX_PAGES,
            max_cursor_bytes: MUX_MAX_CURSOR_BYTES,
        }
    }
}

impl MuxReadBounds {
    pub fn new(
        max_response_bytes: usize,
        max_tracks: usize,
        max_playback_ids: usize,
        max_pages: u16,
        max_cursor_bytes: usize,
    ) -> Result<Self, MuxError> {
        if max_response_bytes == 0
            || max_response_bytes > MUX_MAX_RESPONSE_BYTES
            || max_tracks == 0
            || max_tracks > MUX_MAX_TRACKS
            || max_playback_ids == 0
            || max_playback_ids > MUX_MAX_PLAYBACK_IDS
            || max_pages == 0
            || max_pages > MUX_MAX_PAGES
            || max_cursor_bytes == 0
            || max_cursor_bytes > MUX_MAX_CURSOR_BYTES
        {
            return Err(MuxError::InvalidField {
                field: "mux_read_bounds",
                reason: "bounds exceed the contract maximums",
            });
        }
        Ok(Self {
            max_response_bytes,
            max_tracks,
            max_playback_ids,
            max_pages,
            max_cursor_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MuxRetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_seconds: u32,
}

impl Default for MuxRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MUX_MAX_RETRY_ATTEMPTS,
            max_backoff_seconds: MUX_MAX_BACKOFF_SECONDS,
        }
    }
}

impl MuxRetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_seconds: u32) -> Result<Self, MuxError> {
        if max_attempts == 0
            || max_attempts > MUX_MAX_RETRY_ATTEMPTS
            || max_backoff_seconds > MUX_MAX_BACKOFF_SECONDS
        {
            return Err(MuxError::InvalidField {
                field: "mux_retry_policy",
                reason: "retry bounds exceed the contract maximums",
            });
        }
        Ok(Self {
            max_attempts,
            max_backoff_seconds,
        })
    }
}

/// The typed provider response alias is intentionally the redacted evidence
/// envelope rather than a raw provider payload.
pub type MuxProviderResponse = MuxMediaResultEvidence;

#[derive(Clone, Debug)]
pub struct MuxProvider<T> {
    scope: MuxScope,
    registration: crate::model::MuxRegistration,
    transport: T,
    bounds: MuxReadBounds,
    retry_policy: MuxRetryPolicy,
    recorded_proposals: BTreeSet<Digest>,
}

impl<T> MuxProvider<T>
where
    T: MuxTransport,
{
    pub fn new(scope: MuxScope, transport: T) -> Result<Self, MuxError> {
        Self::with_options(
            scope,
            transport,
            MuxReadBounds::default(),
            MuxRetryPolicy::default(),
        )
    }

    pub fn with_options(
        scope: MuxScope,
        transport: T,
        bounds: MuxReadBounds,
        retry_policy: MuxRetryPolicy,
    ) -> Result<Self, MuxError> {
        let registration = crate::model::MuxRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            transport,
            bounds,
            retry_policy,
            recorded_proposals: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &MuxScope {
        &self.scope
    }

    pub fn registration(&self) -> &crate::model::MuxRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn bounds(&self) -> MuxReadBounds {
        self.bounds
    }

    pub fn retry_policy(&self) -> MuxRetryPolicy {
        self.retry_policy
    }

    pub fn provider_definition(&self) -> MuxProviderDefinition {
        MuxProviderDefinition::default()
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.mode().into()
    }

    pub fn revoke_registration(&mut self) -> Result<(), MuxError> {
        self.registration
            .revoke(crate::model::RevocationReason::HostRequested)
    }

    pub fn read(
        &mut self,
        request: &MuxMediaResultRequest,
        at_epoch_seconds: i64,
    ) -> Result<MuxMediaResultEvidence, MuxError> {
        let proposal = MuxMediaResultProposal::compile(&self.scope, &self.registration, request)?;
        self.read_proposal(&proposal, request, at_epoch_seconds)
    }

    pub fn read_proposal(
        &mut self,
        proposal: &MuxMediaResultProposal,
        request: &MuxMediaResultRequest,
        _at_epoch_seconds: i64,
    ) -> Result<MuxMediaResultEvidence, MuxError> {
        self.ensure_active()?;
        proposal.verify_integrity()?;
        self.scope.validate_request(request)?;
        if request.page > self.bounds.max_pages
            || request
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.byte_len() > self.bounds.max_cursor_bytes)
        {
            return Err(MuxError::CursorLimitExceeded);
        }
        if proposal.request_digest != request.digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.asset_digest != self.scope.asset_digest()
            || proposal.playback_digest != self.scope.playback_digest()
            || proposal.playback_policy_digest
                != self
                    .scope
                    .playback()
                    .map(crate::model::PlaybackScope::policy_digest)
            || proposal.track_digest != self.scope.track_digest()
            || proposal.static_rendition_digest != self.scope.static_rendition_digest()
            || proposal.encoding_digest != self.scope.encoding_digest()
            || proposal.project_digest != self.scope.project().digest()
            || proposal.mission_digest != self.scope.mission().digest()
            || proposal.work_product_digest != self.scope.work_product().digest()
            || proposal.consent_digest != self.scope.consent().digest()
        {
            return Err(MuxError::ProposalTampered);
        }
        if !self.recorded_proposals.insert(proposal.digest().clone()) {
            return Err(MuxError::DuplicateEvidence);
        }

        let request_digest = request.digest();
        let asset_endpoint = if request.page == 1 && request.cursor.is_none() {
            MuxEndpoint::AssetMetadata {
                asset_id: self.scope.asset().id.clone(),
            }
        } else {
            MuxEndpoint::AssetListMetadata {
                page: request.page,
                limit: 25,
                cursor: request.cursor.clone(),
            }
        };
        let (asset_response, asset_receipt) =
            self.get_with_retry(asset_endpoint, request_digest.clone())?;

        if matches!(asset_response.status, 401 | 403 | 404) {
            return self.access_lost_evidence(proposal, request, asset_receipt);
        }
        if asset_response.status != 200 {
            return Err(MuxError::UnsupportedStatus(asset_response.status));
        }
        if asset_response.response_size > self.bounds.max_response_bytes {
            return Err(MuxError::ResponseLimitExceeded);
        }
        let payload = match asset_response.body {
            MuxResponseBody::Asset(payload) => payload,
            MuxResponseBody::AssetList { assets, .. } => assets
                .into_iter()
                .find(|candidate| candidate.id == self.scope.asset().id)
                .ok_or(MuxError::AssetRevisionDrift)?,
            MuxResponseBody::PlaybackAssociation(_) | MuxResponseBody::Empty => {
                return Err(MuxError::MalformedResponse);
            }
        };
        if payload.id != self.scope.asset().id {
            return Err(MuxError::ScopeMismatch(
                "asset response does not match scope",
            ));
        }
        let asset = payload.project(&self.scope)?;
        if let Some(expected) = &request.expected_asset_digest
            && expected != &asset.asset_snapshot_digest
        {
            return Err(MuxError::AssetRevisionDrift);
        }
        if asset.tracks.len() > self.bounds.max_tracks {
            return Err(MuxError::TrackLimitExceeded);
        }
        if asset.playback_ids.len() > self.bounds.max_playback_ids {
            return Err(MuxError::PlaybackIdLimitExceeded);
        }

        let mut receipts = vec![asset_receipt];
        let playback = if request.include_playback_association {
            let endpoint = MuxEndpoint::PlaybackAssociation {
                playback_id: self
                    .scope
                    .playback()
                    .ok_or(MuxError::ScopeMismatch("playback association is unscoped"))?
                    .id
                    .clone(),
            };
            let (response, receipt) = self.get_with_retry(endpoint, request_digest.clone())?;
            receipts.push(receipt);
            if matches!(response.status, 401 | 403 | 404) {
                Some(MuxPlaybackProjection {
                    playback_digest: self
                        .scope
                        .playback()
                        .ok_or(MuxError::PlaybackNotFound)?
                        .id
                        .digest(),
                    playback_snapshot_digest: crate::model::domain_digest(
                        "hartevo:mux-media-result:access-lost-playback:v1",
                        &self.scope.digest(),
                    ),
                    policy: crate::model::MuxPlaybackPolicy::Unknown,
                    policy_digest: crate::model::domain_digest(
                        "hartevo:mux-media-result:unknown-playback-policy:v1",
                        &self.scope.digest(),
                    ),
                    associated_asset_digest: None,
                    association_state: MuxAssetState::AccessLost,
                    playback_token_redacted: true,
                    signed_url_redacted: true,
                })
            } else if response.status != 200 {
                return Err(MuxError::UnsupportedStatus(response.status));
            } else {
                let MuxResponseBody::PlaybackAssociation(payload) = response.body else {
                    return Err(MuxError::MalformedResponse);
                };
                let projection = project_playback_association(&payload, &self.scope, asset.state)?;
                if let Some(expected) = &request.expected_playback_digest
                    && expected != &projection.playback_snapshot_digest
                {
                    return Err(MuxError::PlaybackRevisionDrift);
                }
                Some(projection)
            }
        } else {
            None
        };

        let track = if request.include_track_metadata {
            let expected_track = self
                .scope
                .track()
                .ok_or(MuxError::ScopeMismatch("track metadata is unscoped"))?;
            let track = asset
                .tracks
                .iter()
                .find(|candidate| candidate.track_digest == expected_track.id.digest())
                .cloned()
                .ok_or(MuxError::TrackNotFound)?;
            if let Some(expected) = &request.expected_track_digest
                && expected != &track.track_snapshot_digest
            {
                return Err(MuxError::TrackRevisionDrift);
            }
            Some(track)
        } else {
            None
        };

        if let Some(expected) = &request.expected_encoding_digest
            && expected != &asset.encoding.encoding_digest
        {
            return Err(MuxError::EncodingRevisionDrift);
        }
        let delivery = delivery_projection(&asset, playback.as_ref(), track.as_ref());
        let evidence = self.make_evidence(
            proposal, request, asset, playback, track, delivery, receipts,
        );
        evidence.verify_integrity()?;
        Ok(evidence)
    }

    pub fn read_asset_metadata(
        &mut self,
        request: &MuxMediaResultRequest,
        at_epoch_seconds: i64,
    ) -> Result<AssetMetadataProjection, MuxError> {
        let proposal = MuxMediaResultProposal::compile(&self.scope, &self.registration, request)?;
        let evidence = self.read_proposal(&proposal, request, at_epoch_seconds)?;
        Ok(evidence.asset)
    }

    pub fn read_playback_association(
        &mut self,
        request: &MuxMediaResultRequest,
        at_epoch_seconds: i64,
    ) -> Result<Option<MuxPlaybackProjection>, MuxError> {
        let proposal = MuxMediaResultProposal::compile(&self.scope, &self.registration, request)?;
        let evidence = self.read_proposal(&proposal, request, at_epoch_seconds)?;
        Ok(evidence.playback)
    }

    fn ensure_active(&self) -> Result<(), MuxError> {
        if self.registration.state != RegistrationState::Active {
            return Err(MuxError::RegistrationRevoked);
        }
        self.registration.validate_against(&self.scope)
    }

    fn get_with_retry(
        &mut self,
        endpoint: MuxEndpoint,
        request_digest: Digest,
    ) -> Result<(MuxHttpResponse, MuxReadReceipt), MuxError> {
        let mut attempt = 0_u8;
        let mut last_retry_after = None;
        loop {
            attempt = attempt.saturating_add(1);
            let request = MuxHttpRequest::get(
                endpoint.clone(),
                request_digest.clone(),
                self.scope.digest(),
                self.bounds.max_response_bytes,
            )
            .map_err(|_| MuxError::MalformedResponse)?;
            let response = match self.transport.get(&request) {
                Ok(response) => response,
                Err(error) => match error {
                    MuxTransportError::BlockedEnv | MuxTransportError::CredentialUnavailable => {
                        return Err(MuxError::BlockedEnv);
                    }
                    MuxTransportError::ResponseTooLarge => {
                        return Err(MuxError::ResponseLimitExceeded);
                    }
                    MuxTransportError::MalformedResponse => {
                        return Err(MuxError::MalformedResponse);
                    }
                    MuxTransportError::RateLimited {
                        retry_after_seconds,
                    } => {
                        last_retry_after = retry_after_seconds;
                        if attempt >= self.retry_policy.max_attempts {
                            return Err(MuxError::RetryLimitExceeded);
                        }
                        if retry_after_seconds.unwrap_or(0) > self.retry_policy.max_backoff_seconds
                        {
                            return Err(MuxError::RetryLimitExceeded);
                        }
                        continue;
                    }
                    MuxTransportError::Timeout | MuxTransportError::TransportUnavailable => {
                        if attempt >= self.retry_policy.max_attempts {
                            return Err(MuxError::RetryLimitExceeded);
                        }
                        continue;
                    }
                    MuxTransportError::HttpStatus(status) => MuxHttpResponse::empty(status, None),
                    MuxTransportError::InvalidRequest => return Err(MuxError::MalformedResponse),
                },
            };
            let retryable_status = matches!(response.status, 408 | 429 | 500 | 502 | 503 | 504);
            if retryable_status && attempt < self.retry_policy.max_attempts {
                let retry_after = response.retry_after_seconds;
                if retry_after.unwrap_or(0) > self.retry_policy.max_backoff_seconds {
                    return Err(MuxError::RetryLimitExceeded);
                }
                last_retry_after = retry_after;
                continue;
            }
            let receipt = MuxReadReceipt::new(
                endpoint.kind(),
                request_digest,
                self.scope.digest(),
                endpoint.path_digest(),
                response.status,
                response.response_size,
                response.response_digest.clone(),
                attempt,
                response.retry_after_seconds.or(last_retry_after),
            );
            return Ok((response, receipt));
        }
    }

    fn make_evidence(
        &self,
        proposal: &MuxMediaResultProposal,
        request: &MuxMediaResultRequest,
        asset: AssetMetadataProjection,
        playback: Option<MuxPlaybackProjection>,
        track: Option<MuxTrackProjection>,
        delivery: crate::model::DeliveryReadinessProjection,
        receipts: Vec<MuxReadReceipt>,
    ) -> MuxMediaResultEvidence {
        MuxMediaResultEvidence {
            plugin_version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
            plugin_version_digest: plugin_version_digest(),
            contract_version: MUX_MEDIA_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: MUX_MEDIA_RESULT_PROVIDER_ID.to_owned(),
            provider_revision: MUX_MEDIA_RESULT_PROVIDER_REVISION.to_owned(),
            provider_digest: provider_digest(),
            consumer_id: MISSION_MUX_MEDIA_RESULT_CONSUMER_ID.to_owned(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            static_rendition_digest: self.scope.static_rendition_digest(),
            project_digest: self.scope.project().digest(),
            mission_digest: self.scope.mission().digest(),
            work_product_digest: self.scope.work_product().digest(),
            consent_digest: self.scope.consent().digest(),
            proposal_digest: proposal.digest().clone(),
            request_digest: request.digest(),
            provenance: self.transport.mode(),
            asset,
            playback,
            track,
            delivery,
            receipts,
            native_connected: false,
            external_write_performed: false,
            media_bytes_retained: false,
            viewer_identifiers_retained: false,
            playback_success_proven: false,
            content_correctness_proven: false,
            publication_authority: false,
            evidence_digest: Digest::sha256([]),
        }
        .with_digest()
    }

    fn access_lost_evidence(
        &self,
        proposal: &MuxMediaResultProposal,
        request: &MuxMediaResultRequest,
        receipt: MuxReadReceipt,
    ) -> Result<MuxMediaResultEvidence, MuxError> {
        let asset = access_lost_asset(&self.scope);
        let delivery = delivery_projection(&asset, None, None);
        let evidence = self.make_evidence(
            proposal,
            request,
            asset,
            None,
            None,
            delivery,
            vec![receipt],
        );
        evidence.verify_integrity()?;
        Ok(evidence)
    }
}

/// Keep the failure classifier public for host adapters without exposing raw
/// provider messages.
pub fn classify_status(status: u16) -> ProviderFailureClass {
    match status {
        401 => ProviderFailureClass::Unauthorized,
        403 => ProviderFailureClass::Forbidden,
        404 => ProviderFailureClass::NotFound,
        408 | 504 => ProviderFailureClass::Timeout,
        429 => ProviderFailureClass::RateLimited,
        500..=599 => ProviderFailureClass::ServerError,
        200..=299 => ProviderFailureClass::TransportUnavailable,
        _ => ProviderFailureClass::UnexpectedStatus,
    }
}

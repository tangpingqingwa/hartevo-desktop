//! Bounded GET-only transport seams.
//!
//! `MuxJsonResponse` accepts provider JSON for fixtures and immediately
//! projects it into typed metadata.  The original bytes are used only for a
//! response size/digest and are not stored in any returned value.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, MuxAssetId, MuxAssetPayload, MuxError, MuxPlaybackAssociationPayload, MuxPlaybackId,
    MuxPlaybackPayload, MuxProgressPayload, MuxScope, MuxTrackId, MuxTrackPayload,
    MuxTransportMode, domain_digest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MuxEndpoint {
    AssetListMetadata {
        page: u16,
        limit: u16,
        cursor: Option<crate::model::MuxCursor>,
    },
    AssetMetadata {
        asset_id: MuxAssetId,
    },
    PlaybackAssociation {
        playback_id: MuxPlaybackId,
    },
}

impl MuxEndpoint {
    pub fn kind(&self) -> MuxEndpointKind {
        match self {
            Self::AssetListMetadata { .. } => MuxEndpointKind::AssetListMetadata,
            Self::AssetMetadata { .. } => MuxEndpointKind::AssetMetadata,
            Self::PlaybackAssociation { .. } => MuxEndpointKind::PlaybackAssociation,
        }
    }

    pub fn path_and_query(&self) -> String {
        match self {
            Self::AssetListMetadata {
                page,
                limit,
                cursor,
            } => {
                let cursor = cursor
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.digest().to_string());
                format!("/video/v1/assets?limit={limit}&page={page}&cursor_digest={cursor}")
            }
            Self::AssetMetadata { asset_id } => {
                format!("/video/v1/assets/{}", asset_id.as_str())
            }
            Self::PlaybackAssociation { playback_id } => {
                format!("/video/v1/playback-ids/{}", playback_id.as_str())
            }
        }
    }

    pub fn path_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:request-path:v1",
            &(self.kind(), self.path_and_query()),
        )
    }
}

pub use crate::model::MuxEndpointKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxHttpRequest {
    pub endpoint: MuxEndpoint,
    pub method: String,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub max_response_bytes: usize,
}

impl MuxHttpRequest {
    pub fn get(
        endpoint: MuxEndpoint,
        request_digest: Digest,
        scope_digest: Digest,
        max_response_bytes: usize,
    ) -> Result<Self, MuxTransportError> {
        if max_response_bytes == 0 {
            return Err(MuxTransportError::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            method: "GET".to_owned(),
            request_digest,
            scope_digest,
            max_response_bytes,
        })
    }

    pub fn path_digest(&self) -> Digest {
        self.endpoint.path_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum MuxResponseBody {
    AssetList {
        assets: Vec<MuxAssetPayload>,
        next_cursor_digest: Option<Digest>,
    },
    Asset(MuxAssetPayload),
    PlaybackAssociation(MuxPlaybackAssociationPayload),
    Empty,
}

impl MuxResponseBody {
    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:mux-media-result:response-body:v1", self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxHttpResponse {
    pub status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub body: MuxResponseBody,
    pub retry_after_seconds: Option<u32>,
}

impl MuxHttpResponse {
    pub fn from_body(status: u16, body: MuxResponseBody, retry_after_seconds: Option<u32>) -> Self {
        let response_digest = body.digest();
        let response_size = serde_json::to_vec(&body).map_or(0, |bytes| bytes.len());
        Self {
            status,
            response_size,
            response_digest,
            body,
            retry_after_seconds,
        }
    }

    pub fn empty(status: u16, retry_after_seconds: Option<u32>) -> Self {
        Self::from_body(status, MuxResponseBody::Empty, retry_after_seconds)
    }
}

/// Parse only the allowlisted Mux metadata fields, then drop the provider
/// JSON bytes.  Unknown fields include the URL/token/bytes/viewer surfaces
/// explicitly excluded by the contract.
#[derive(Debug)]
pub struct MuxJsonResponse;

impl MuxJsonResponse {
    pub fn from_bytes(
        request: &MuxHttpRequest,
        status: u16,
        bytes: &[u8],
        retry_after_seconds: Option<u32>,
    ) -> Result<MuxHttpResponse, MuxTransportError> {
        let response_size = bytes.len();
        let response_digest = Digest::sha256(bytes);
        if response_size > request.max_response_bytes {
            return Err(MuxTransportError::ResponseTooLarge);
        }
        let body = match &request.endpoint {
            MuxEndpoint::AssetListMetadata { .. } => {
                let (assets, next_cursor_digest) =
                    parse_asset_list(bytes).map_err(|_| MuxTransportError::MalformedResponse)?;
                MuxResponseBody::AssetList {
                    assets,
                    next_cursor_digest,
                }
            }
            MuxEndpoint::AssetMetadata { .. } => MuxResponseBody::Asset(
                parse_asset(bytes).map_err(|_| MuxTransportError::MalformedResponse)?,
            ),
            MuxEndpoint::PlaybackAssociation { .. } => MuxResponseBody::PlaybackAssociation(
                parse_playback_association(bytes)
                    .map_err(|_| MuxTransportError::MalformedResponse)?,
            ),
        };
        Ok(MuxHttpResponse {
            status,
            response_size,
            response_digest,
            body,
            retry_after_seconds,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MuxTransportError {
    BlockedEnv,
    CredentialUnavailable,
    InvalidRequest,
    ResponseTooLarge,
    MalformedResponse,
    RateLimited { retry_after_seconds: Option<u32> },
    Timeout,
    TransportUnavailable,
    HttpStatus(u16),
}

impl fmt::Display for MuxTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockedEnv => formatter.write_str("BLOCKED_ENV"),
            Self::CredentialUnavailable => formatter.write_str("credential unavailable"),
            Self::InvalidRequest => formatter.write_str("invalid request"),
            Self::ResponseTooLarge => formatter.write_str("response too large"),
            Self::MalformedResponse => formatter.write_str("malformed response"),
            Self::RateLimited { .. } => formatter.write_str("rate limited"),
            Self::Timeout => formatter.write_str("timeout"),
            Self::TransportUnavailable => formatter.write_str("transport unavailable"),
            Self::HttpStatus(status) => write!(formatter, "HTTP status {status}"),
        }
    }
}

impl std::error::Error for MuxTransportError {}

/// A transport trait with one method: bounded metadata GET.  There is no
/// POST/PATCH/DELETE/upload/download/signing/webhook method in this root.
pub trait MuxTransport: fmt::Debug {
    fn mode(&self) -> MuxTransportMode;

    fn get(&mut self, request: &MuxHttpRequest) -> Result<MuxHttpResponse, MuxTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingMuxTransport {
    responses: VecDeque<Result<MuxHttpResponse, MuxTransportError>>,
    requests: Vec<MuxHttpRequest>,
}

impl RecordingMuxTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<MuxHttpResponse, MuxTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(responses: impl IntoIterator<Item = MuxHttpResponse>) -> Self {
        Self::new(responses.into_iter().map(Ok))
    }

    pub fn fixture_json(
        responses: impl IntoIterator<Item = (MuxHttpRequest, u16, Vec<u8>)>,
    ) -> Result<Self, MuxTransportError> {
        let mut typed = Vec::new();
        for (request, status, bytes) in responses {
            typed.push(MuxJsonResponse::from_bytes(&request, status, &bytes, None)?);
        }
        Ok(Self::fixture(typed))
    }

    pub fn requests(&self) -> &[MuxHttpRequest] {
        &self.requests
    }
}

impl MuxTransport for RecordingMuxTransport {
    fn mode(&self) -> MuxTransportMode {
        MuxTransportMode::Recording
    }

    fn get(&mut self, request: &MuxHttpRequest) -> Result<MuxHttpResponse, MuxTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(MuxTransportError::TransportUnavailable))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureMuxTransport {
    responses: VecDeque<Result<MuxHttpResponse, MuxTransportError>>,
}

impl FixtureMuxTransport {
    pub fn new(responses: impl IntoIterator<Item = MuxHttpResponse>) -> Self {
        Self {
            responses: responses.into_iter().map(Ok).collect(),
        }
    }

    pub fn with_errors(
        responses: impl IntoIterator<Item = Result<MuxHttpResponse, MuxTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
        }
    }
}

impl MuxTransport for FixtureMuxTransport {
    fn mode(&self) -> MuxTransportMode {
        MuxTransportMode::Fixture
    }

    fn get(&mut self, _request: &MuxHttpRequest) -> Result<MuxHttpResponse, MuxTransportError> {
        self.responses
            .pop_front()
            .unwrap_or(Err(MuxTransportError::TransportUnavailable))
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_field_names)]
pub struct LoopbackMuxTransport {
    asset_id: MuxAssetId,
    playback_id: Option<MuxPlaybackId>,
    track_id: Option<MuxTrackId>,
}

impl LoopbackMuxTransport {
    pub fn new(
        asset_id: MuxAssetId,
        playback_id: Option<MuxPlaybackId>,
        track_id: Option<MuxTrackId>,
    ) -> Self {
        Self {
            asset_id,
            playback_id,
            track_id,
        }
    }

    pub fn for_scope(scope: &MuxScope) -> Self {
        Self::new(
            scope.asset().id.clone(),
            scope.playback().map(|binding| binding.id.clone()),
            scope.track().map(|binding| binding.id.clone()),
        )
    }
}

impl MuxTransport for LoopbackMuxTransport {
    fn mode(&self) -> MuxTransportMode {
        MuxTransportMode::Loopback
    }

    fn get(&mut self, request: &MuxHttpRequest) -> Result<MuxHttpResponse, MuxTransportError> {
        match &request.endpoint {
            MuxEndpoint::AssetListMetadata { .. } => {
                let asset_request = MuxHttpRequest {
                    endpoint: MuxEndpoint::AssetMetadata {
                        asset_id: self.asset_id.clone(),
                    },
                    method: request.method.clone(),
                    request_digest: request.request_digest.clone(),
                    scope_digest: request.scope_digest.clone(),
                    max_response_bytes: request.max_response_bytes,
                };
                let response = self.get(&asset_request)?;
                let MuxResponseBody::Asset(asset) = response.body else {
                    return Ok(response);
                };
                Ok(MuxHttpResponse::from_body(
                    response.status,
                    MuxResponseBody::AssetList {
                        assets: vec![asset],
                        next_cursor_digest: None,
                    },
                    response.retry_after_seconds,
                ))
            }
            MuxEndpoint::AssetMetadata { asset_id } if asset_id == &self.asset_id => {
                let track_id = self.track_id.clone().unwrap_or_else(|| {
                    MuxTrackId::new("loopback-video-track").expect("static loopback track ID")
                });
                let mut tracks = vec![MuxTrackPayload {
                    id: track_id,
                    kind: "video".to_owned(),
                    status: Some("ready".to_owned()),
                    max_width: Some(1920),
                    max_height: Some(1080),
                    max_frame_rate_milli: Some(30_000),
                    max_channels: None,
                    duration_ms: Some(12_000),
                    language_code: None,
                    text_type: None,
                }];
                tracks.push(MuxTrackPayload {
                    id: MuxTrackId::new("loopback-audio-track").expect("static loopback audio ID"),
                    kind: "audio".to_owned(),
                    status: Some("ready".to_owned()),
                    max_width: None,
                    max_height: None,
                    max_frame_rate_milli: None,
                    max_channels: Some(2),
                    duration_ms: Some(12_000),
                    language_code: None,
                    text_type: None,
                });
                let playback_ids = self
                    .playback_id
                    .clone()
                    .map(|id| {
                        vec![MuxPlaybackPayload {
                            id,
                            policy: Some("public".to_owned()),
                        }]
                    })
                    .unwrap_or_default();
                Ok(MuxHttpResponse::from_body(
                    200,
                    MuxResponseBody::Asset(MuxAssetPayload {
                        id: asset_id.clone(),
                        status: "ready".to_owned(),
                        tracks,
                        playback_ids,
                        duration_ms: Some(12_000),
                        created_at_epoch_seconds: Some(1_787_000_000),
                        max_stored_resolution: Some("HD".to_owned()),
                        resolution_tier: Some("1080p".to_owned()),
                        encoding_tier: Some("baseline".to_owned()),
                        video_quality: Some("basic".to_owned()),
                        progress: Some(MuxProgressPayload {
                            state: Some("completed".to_owned()),
                            progress: Some(100),
                        }),
                    }),
                    None,
                ))
            }
            MuxEndpoint::PlaybackAssociation { playback_id }
                if self.playback_id.as_ref() == Some(playback_id) =>
            {
                Ok(MuxHttpResponse::from_body(
                    200,
                    MuxResponseBody::PlaybackAssociation(MuxPlaybackAssociationPayload {
                        id: playback_id.clone(),
                        policy: Some("public".to_owned()),
                        object_type: "asset".to_owned(),
                        object_id: self.asset_id.clone(),
                    }),
                    None,
                ))
            }
            _ => Ok(MuxHttpResponse::empty(404, None)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvMuxTransport;

impl BlockedEnvMuxTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl MuxTransport for BlockedEnvMuxTransport {
    fn mode(&self) -> MuxTransportMode {
        MuxTransportMode::BlockedEnv
    }

    fn get(&mut self, _request: &MuxHttpRequest) -> Result<MuxHttpResponse, MuxTransportError> {
        Err(MuxTransportError::BlockedEnv)
    }
}

/// The native HTTPS seam is explicit but deliberately disabled in Layer 1.
/// This makes a missing native credential/HTTPS implementation observable as
/// BLOCKED_ENV rather than allowing a fake Connected claim.
#[derive(Clone, Debug, Default)]
pub struct NativeMuxHttpsTransport;

impl NativeMuxHttpsTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl MuxTransport for NativeMuxHttpsTransport {
    fn mode(&self) -> MuxTransportMode {
        MuxTransportMode::BlockedEnv
    }

    fn get(&mut self, _request: &MuxHttpRequest) -> Result<MuxHttpResponse, MuxTransportError> {
        Err(MuxTransportError::BlockedEnv)
    }
}

#[derive(Debug, Deserialize)]
struct RawEnvelope<T> {
    data: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawAssetPayload {
    id: String,
    status: String,
    tracks: Vec<RawTrackPayload>,
    playback_ids: Vec<RawPlaybackPayload>,
    duration: Option<f64>,
    created_at: Option<serde_json::Value>,
    max_stored_resolution: Option<String>,
    resolution_tier: Option<String>,
    encoding_tier: Option<String>,
    video_quality: Option<String>,
    progress: Option<RawProgressPayload>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawTrackPayload {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    status: Option<String>,
    max_width: Option<u32>,
    max_height: Option<u32>,
    max_frame_rate: Option<f64>,
    max_channels: Option<u16>,
    duration: Option<f64>,
    language_code: Option<String>,
    text_type: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawPlaybackPayload {
    id: String,
    policy: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawProgressPayload {
    state: Option<String>,
    progress: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawPlaybackAssociationPayload {
    id: String,
    policy: Option<String>,
    object: RawPlaybackObject,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawPlaybackObject {
    #[serde(rename = "type")]
    object_type: String,
    id: String,
}

fn parse_asset(bytes: &[u8]) -> Result<MuxAssetPayload, MuxError> {
    let envelope = serde_json::from_slice::<RawEnvelope<RawAssetPayload>>(bytes)
        .map_err(|_| MuxError::MalformedResponse)?;
    raw_asset_payload(envelope.data)
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", default)]
struct RawAssetListEnvelope {
    data: Vec<RawAssetPayload>,
    next_cursor: Option<String>,
}

fn parse_asset_list(bytes: &[u8]) -> Result<(Vec<MuxAssetPayload>, Option<Digest>), MuxError> {
    let envelope = serde_json::from_slice::<RawAssetListEnvelope>(bytes)
        .map_err(|_| MuxError::MalformedResponse)?;
    let assets = envelope
        .data
        .into_iter()
        .map(raw_asset_payload)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor_digest = envelope
        .next_cursor
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| Digest::sha256(value.as_bytes()));
    Ok((assets, next_cursor_digest))
}

fn raw_asset_payload(raw: RawAssetPayload) -> Result<MuxAssetPayload, MuxError> {
    let id = MuxAssetId::new(raw.id)?;
    let tracks = raw
        .tracks
        .into_iter()
        .map(|track| {
            Ok(MuxTrackPayload {
                id: MuxTrackId::new(track.id)?,
                kind: track.kind,
                status: track.status,
                max_width: track.max_width,
                max_height: track.max_height,
                max_frame_rate_milli: track
                    .max_frame_rate
                    .map(|value| (value * 1000.0).round() as u32),
                max_channels: track.max_channels,
                duration_ms: track.duration.map(|value| (value * 1000.0).round() as u64),
                language_code: track.language_code,
                text_type: track.text_type,
            })
        })
        .collect::<Result<Vec<_>, MuxError>>()?;
    let playback_ids = raw
        .playback_ids
        .into_iter()
        .map(|playback| {
            Ok(MuxPlaybackPayload {
                id: MuxPlaybackId::new(playback.id)?,
                policy: playback.policy,
            })
        })
        .collect::<Result<Vec<_>, MuxError>>()?;
    let created_at_epoch_seconds = raw.created_at.and_then(|value| match value {
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(value) => value.parse::<i64>().ok(),
        _ => None,
    });
    let progress = raw.progress.map(|value| MuxProgressPayload {
        state: value.state,
        progress: value.progress.map(|number| number.round() as u8),
    });
    let payload = MuxAssetPayload {
        id,
        status: raw.status,
        tracks,
        playback_ids,
        duration_ms: raw.duration.map(|value| (value * 1000.0).round() as u64),
        created_at_epoch_seconds,
        max_stored_resolution: raw.max_stored_resolution,
        resolution_tier: raw.resolution_tier,
        encoding_tier: raw.encoding_tier,
        video_quality: raw.video_quality,
        progress,
    };
    payload.validate()?;
    Ok(payload)
}

fn parse_playback_association(bytes: &[u8]) -> Result<MuxPlaybackAssociationPayload, MuxError> {
    let envelope = serde_json::from_slice::<RawEnvelope<RawPlaybackAssociationPayload>>(bytes)
        .map_err(|_| MuxError::MalformedResponse)?;
    let raw = envelope.data;
    Ok(MuxPlaybackAssociationPayload {
        id: MuxPlaybackId::new(raw.id)?,
        policy: raw.policy,
        object_type: raw.object.object_type,
        object_id: MuxAssetId::new(raw.object.id)?,
    })
}

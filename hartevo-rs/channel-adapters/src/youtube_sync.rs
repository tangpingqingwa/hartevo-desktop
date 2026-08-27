//! Durable YouTube read cursors and webhook-to-poll reconciliation.
//!
//! YouTube notifications are hints only: they identify a video that needs a
//! read, but they do not prove the video's current visibility, moderation, or
//! content state. The poll path below is therefore the only path that creates
//! an exact revision head.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{
    ContentIdentity, ProviderId, RevisionIdentity, WebhookEventId, YoutubeChannelIdentity,
    YoutubeRevisionIdentity, YoutubeVideoIdentity,
};
use crate::transport::{
    ChannelAdapterError, CredentialReference, ProviderReadRequest, ProviderResponse,
    ReadOnlyTransport, TransportError, hex_digest,
};
use crate::youtube::{
    YoutubePageToken, YoutubeQuotaLedger, YoutubeReadObservation, YoutubeReadResult,
    YoutubeReadTarget, YoutubeVideoObservation, parse_read_response,
};

pub const YOUTUBE_REAL_READ_ENABLE_ENV: &str = "HARTEVO_YOUTUBE_REAL_READ";
pub const YOUTUBE_REAL_READ_CREDENTIAL_ENV: &str = "HARTEVO_YOUTUBE_CREDENTIAL_REF";

const YOUTUBE_UPLOADS_STREAM: &str = "uploads";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeCursorStream {
    Uploads,
}

impl YoutubeCursorStream {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uploads => YOUTUBE_UPLOADS_STREAM,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YoutubeFreshnessPolicy {
    valid_for: Duration,
}

impl Default for YoutubeFreshnessPolicy {
    fn default() -> Self {
        Self::new(Duration::minutes(5)).expect("the default freshness window is valid")
    }
}

impl YoutubeFreshnessPolicy {
    pub fn new(valid_for: Duration) -> Result<Self, ChannelAdapterError> {
        if valid_for <= Duration::zero() {
            return Err(ChannelAdapterError::InvalidRequest(
                "YouTube freshness window must be positive",
            ));
        }
        Ok(Self { valid_for })
    }

    pub const fn valid_for(&self) -> Duration {
        self.valid_for
    }

    fn valid_until(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, ChannelAdapterError> {
        observed_at
            .checked_add_signed(self.valid_for)
            .ok_or(ChannelAdapterError::InvalidRequest(
                "YouTube freshness timestamp overflow",
            ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeFreshness {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_generation: u64,
}

impl YoutubeFreshness {
    pub const fn observed_at(self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn source_generation(self) -> u64 {
        self.source_generation
    }

    pub fn validate_at(self, now: DateTime<Utc>) -> Result<(), ChannelAdapterError> {
        if now < self.observed_at || now >= self.valid_until {
            return Err(ChannelAdapterError::FreshnessExpired {
                provider: ProviderId::Youtube,
                observed_at: self.observed_at,
                valid_until: self.valid_until,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct YoutubeDurableCursor {
    channel: YoutubeChannelIdentity,
    stream: YoutubeCursorStream,
    next_page_token: Option<YoutubePageToken>,
    generation: u64,
    last_page_digest: Option<String>,
    updated_at: DateTime<Utc>,
    fresh_until: DateTime<Utc>,
}

impl YoutubeDurableCursor {
    pub fn new(
        channel: YoutubeChannelIdentity,
        now: DateTime<Utc>,
        freshness: &YoutubeFreshnessPolicy,
    ) -> Result<Self, ChannelAdapterError> {
        if channel.uploads_playlist_id().is_none() {
            return Err(ChannelAdapterError::UnsupportedSurface {
                provider: ProviderId::Youtube,
                surface: "uploads playlist incremental cursor",
            });
        }
        let cursor = Self {
            channel,
            stream: YoutubeCursorStream::Uploads,
            next_page_token: None,
            generation: 0,
            last_page_digest: None,
            updated_at: now,
            fresh_until: freshness.valid_until(now)?,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub const fn channel(&self) -> &YoutubeChannelIdentity {
        &self.channel
    }

    pub const fn stream(&self) -> YoutubeCursorStream {
        self.stream
    }

    pub fn next_page_token(&self) -> Option<&YoutubePageToken> {
        self.next_page_token.as_ref()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn last_page_digest(&self) -> Option<&str> {
        self.last_page_digest.as_deref()
    }

    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub const fn fresh_until(&self) -> DateTime<Utc> {
        self.fresh_until
    }

    pub fn freshness(&self) -> YoutubeFreshness {
        YoutubeFreshness {
            observed_at: self.updated_at,
            valid_until: self.fresh_until,
            source_generation: self.generation,
        }
    }

    pub fn require_fresh(
        &self,
        now: DateTime<Utc>,
    ) -> Result<YoutubeFreshness, ChannelAdapterError> {
        let freshness = self.freshness();
        freshness.validate_at(now)?;
        Ok(freshness)
    }

    pub fn validate(&self) -> Result<(), ChannelAdapterError> {
        if self.channel.uploads_playlist_id().is_none()
            || self.stream != YoutubeCursorStream::Uploads
            || self.fresh_until <= self.updated_at
            || (self.generation == 0 && self.last_page_digest.is_some())
            || self
                .last_page_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "invalid YouTube durable cursor",
            ));
        }
        Ok(())
    }

    pub fn checkpoint_json(&self) -> Result<String, ChannelAdapterError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| {
            ChannelAdapterError::InvalidRequest("YouTube durable cursor serialization failed")
        })
    }

    pub fn from_checkpoint_json(value: &str) -> Result<Self, ChannelAdapterError> {
        let cursor: Self = serde_json::from_str(value).map_err(|_| {
            ChannelAdapterError::InvalidRequest("invalid YouTube durable cursor checkpoint")
        })?;
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn durable_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut digest = Sha256::new();
        digest.update(bytes);
        hex_digest(digest.finalize())
    }

    pub fn read_target(&self, max_results: u8) -> Result<YoutubeReadTarget, ChannelAdapterError> {
        let playlist_id = self.channel.uploads_playlist_id().cloned().ok_or(
            ChannelAdapterError::UnsupportedSurface {
                provider: ProviderId::Youtube,
                surface: "uploads playlist incremental cursor",
            },
        )?;
        Ok(YoutubeReadTarget::Uploads {
            channel_id: self.channel.channel_id().clone(),
            playlist_id,
            page_token: self.next_page_token.clone(),
            max_results,
        })
    }

    pub fn apply_page(
        &mut self,
        expected_generation: u64,
        page: &YoutubeIncrementalPage,
        freshness: &YoutubeFreshnessPolicy,
    ) -> Result<YoutubeCursorDisposition, ChannelAdapterError> {
        self.validate()?;
        page.validate()?;
        if page.channel != self.channel || page.stream != self.stream {
            return Err(ChannelAdapterError::CursorStale {
                provider: ProviderId::Youtube,
                stream: self.stream.as_str(),
            });
        }
        if self
            .last_page_digest
            .as_deref()
            .is_some_and(|digest| digest == page.response_digest)
        {
            return Ok(YoutubeCursorDisposition::Duplicate);
        }
        if expected_generation != self.generation || page.observed_at < self.updated_at {
            return Err(ChannelAdapterError::CursorStale {
                provider: ProviderId::Youtube,
                stream: self.stream.as_str(),
            });
        }
        let generation =
            self.generation
                .checked_add(1)
                .ok_or(ChannelAdapterError::CursorStale {
                    provider: ProviderId::Youtube,
                    stream: self.stream.as_str(),
                })?;
        self.next_page_token.clone_from(&page.next_page_token);
        self.generation = generation;
        self.last_page_digest = Some(page.response_digest.clone());
        self.updated_at = page.observed_at;
        self.fresh_until = freshness.valid_until(page.observed_at)?;
        Ok(YoutubeCursorDisposition::Applied)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeCursorDisposition {
    Applied,
    Duplicate,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeIncrementalObservation {
    identity: YoutubeVideoIdentity,
    revision: YoutubeRevisionIdentity,
}

impl YoutubeIncrementalObservation {
    pub fn new(
        identity: YoutubeVideoIdentity,
        revision: YoutubeRevisionIdentity,
    ) -> Result<Self, ChannelAdapterError> {
        let content = ContentIdentity::YoutubeVideo(identity.clone());
        if revision.content() != &content {
            return Err(ChannelAdapterError::InvalidResponse {
                provider: ProviderId::Youtube,
                field: "playlistItem.revision.content".to_owned(),
            });
        }
        Ok(Self { identity, revision })
    }

    pub const fn identity(&self) -> &YoutubeVideoIdentity {
        &self.identity
    }

    pub const fn revision(&self) -> &YoutubeRevisionIdentity {
        &self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeIncrementalPage {
    channel: YoutubeChannelIdentity,
    stream: YoutubeCursorStream,
    observations: Vec<YoutubeIncrementalObservation>,
    next_page_token: Option<YoutubePageToken>,
    observed_at: DateTime<Utc>,
    response_digest: String,
}

impl YoutubeIncrementalPage {
    pub const fn channel(&self) -> &YoutubeChannelIdentity {
        &self.channel
    }

    pub const fn stream(&self) -> YoutubeCursorStream {
        self.stream
    }

    pub fn observations(&self) -> &[YoutubeIncrementalObservation] {
        &self.observations
    }

    pub fn next_page_token(&self) -> Option<&YoutubePageToken> {
        self.next_page_token.as_ref()
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    fn validate(&self) -> Result<(), ChannelAdapterError> {
        if self.stream != YoutubeCursorStream::Uploads
            || !is_sha256(&self.response_digest)
            || self
                .observations
                .iter()
                .any(|observation| observation.identity.channel_id() != self.channel.channel_id())
        {
            return Err(ChannelAdapterError::InvalidResponse {
                provider: ProviderId::Youtube,
                field: "playlistItems.incremental_page".to_owned(),
            });
        }
        Ok(())
    }
}

pub fn parse_incremental_page(
    cursor: &YoutubeDurableCursor,
    response: &ProviderResponse,
) -> Result<YoutubeIncrementalPage, ChannelAdapterError> {
    let target = cursor.read_target(50)?;
    let result = parse_read_response(&target, response)?;
    let mut observations = Vec::with_capacity(result.observations().len());
    for observation in result.observations() {
        let YoutubeReadObservation::Video(video) = observation else {
            return Err(ChannelAdapterError::InvalidResponse {
                provider: ProviderId::Youtube,
                field: "playlistItems.observation".to_owned(),
            });
        };
        observations.push(YoutubeIncrementalObservation::new(
            video.identity().clone(),
            video.revision().clone(),
        )?);
    }
    let next_page_token = result
        .next_page_token()
        .map(str::to_owned)
        .map(YoutubePageToken::new)
        .transpose()?;
    let page = YoutubeIncrementalPage {
        channel: cursor.channel.clone(),
        stream: cursor.stream,
        observations,
        next_page_token,
        observed_at: response.observed_at(),
        response_digest: response.body_digest(),
    };
    page.validate()?;
    Ok(page)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YoutubeRealReadGate {
    credential: CredentialReference,
}

impl YoutubeRealReadGate {
    pub fn from_env() -> Result<Self, ChannelAdapterError> {
        let enabled = std::env::var(YOUTUBE_REAL_READ_ENABLE_ENV).ok();
        let credential = std::env::var(YOUTUBE_REAL_READ_CREDENTIAL_ENV).ok();
        Self::from_environment_values(enabled.as_deref(), credential.as_deref())
    }

    pub fn from_environment_values(
        enabled: Option<&str>,
        credential: Option<&str>,
    ) -> Result<Self, ChannelAdapterError> {
        if enabled != Some("1") {
            return Err(ChannelAdapterError::BlockedEnvironment {
                provider: ProviderId::Youtube,
                requirement: "HARTEVO_YOUTUBE_REAL_READ=1",
            });
        }
        let credential = credential.ok_or(ChannelAdapterError::BlockedEnvironment {
            provider: ProviderId::Youtube,
            requirement: "HARTEVO_YOUTUBE_CREDENTIAL_REF",
        })?;
        Ok(Self {
            credential: CredentialReference::new(credential.to_owned())?,
        })
    }

    pub const fn credential(&self) -> &CredentialReference {
        &self.credential
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YoutubeRealReadOutcome {
    page: YoutubeIncrementalPage,
    cursor_disposition: YoutubeCursorDisposition,
    freshness: YoutubeFreshness,
}

impl YoutubeRealReadOutcome {
    pub const fn page(&self) -> &YoutubeIncrementalPage {
        &self.page
    }

    pub const fn cursor_disposition(&self) -> YoutubeCursorDisposition {
        self.cursor_disposition
    }

    pub const fn freshness(&self) -> YoutubeFreshness {
        self.freshness
    }
}

pub fn execute_env_gated_incremental_read<T: ReadOnlyTransport>(
    gate: &YoutubeRealReadGate,
    transport: &mut T,
    cursor: &mut YoutubeDurableCursor,
    quota: &mut YoutubeQuotaLedger,
    freshness: &YoutubeFreshnessPolicy,
    max_results: u8,
) -> Result<YoutubeRealReadOutcome, ChannelAdapterError> {
    cursor.validate()?;
    let target = cursor.read_target(max_results)?;
    let request = target.request(gate.credential.clone())?;
    let response = transport.send(&request).map_err(|error| match error {
        TransportError::Unavailable | TransportError::TimedOut => {
            ChannelAdapterError::TransportUnavailable {
                provider: ProviderId::Youtube,
            }
        }
    })?;
    quota.reserve(target.operation(), response.observed_at())?;
    let page = parse_incremental_page(cursor, &response)?;
    let cursor_disposition = cursor.apply_page(cursor.generation(), &page, freshness)?;
    Ok(YoutubeRealReadOutcome {
        page,
        cursor_disposition,
        freshness: cursor.freshness(),
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeWebhookHint {
    event_id: WebhookEventId,
    content: ContentIdentity,
    occurred_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
}

impl YoutubeWebhookHint {
    pub fn new(
        event_id: WebhookEventId,
        channel_id: crate::identity::YoutubeChannelId,
        video_id: crate::identity::YoutubeVideoId,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<Self, ChannelAdapterError> {
        if received_at < occurred_at {
            return Err(ChannelAdapterError::InvalidRequest(
                "YouTube webhook hint was received before it occurred",
            ));
        }
        Ok(Self {
            event_id,
            content: ContentIdentity::YoutubeVideo(YoutubeVideoIdentity::new(channel_id, video_id)),
            occurred_at,
            received_at,
        })
    }

    pub const fn event_id(&self) -> &WebhookEventId {
        &self.event_id
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub const fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubePollObservation {
    content: ContentIdentity,
    revision: RevisionIdentity,
}

impl YoutubePollObservation {
    pub fn new(
        content: ContentIdentity,
        revision: RevisionIdentity,
    ) -> Result<Self, ChannelAdapterError> {
        if content.provider() != ProviderId::Youtube
            || revision.provider() != ProviderId::Youtube
            || revision.content() != &content
        {
            return Err(ChannelAdapterError::InvalidResponse {
                provider: ProviderId::Youtube,
                field: "reconciliation.revision".to_owned(),
            });
        }
        Ok(Self { content, revision })
    }

    fn from_video_observation(
        observation: &YoutubeVideoObservation,
    ) -> Result<Self, ChannelAdapterError> {
        Self::new(
            ContentIdentity::YoutubeVideo(observation.identity().clone()),
            RevisionIdentity::Youtube(observation.revision().clone()),
        )
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeReconciliationSource {
    WebhookHint,
    Poll,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeReconciliationDisposition {
    Applied,
    Duplicate,
    Late,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeReconciliationHead {
    content: ContentIdentity,
    revision: RevisionIdentity,
    source: YoutubeReconciliationSource,
    observed_at: DateTime<Utc>,
}

impl YoutubeReconciliationHead {
    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }

    pub const fn source(&self) -> YoutubeReconciliationSource {
        self.source
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeReconciliationOutcome {
    disposition: YoutubeReconciliationDisposition,
    source: YoutubeReconciliationSource,
    content: ContentIdentity,
    head: Option<YoutubeReconciliationHead>,
    poll_required: bool,
}

impl YoutubeReconciliationOutcome {
    pub const fn disposition(&self) -> YoutubeReconciliationDisposition {
        self.disposition
    }

    pub const fn source(&self) -> YoutubeReconciliationSource {
        self.source
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn head(&self) -> Option<&YoutubeReconciliationHead> {
        self.head.as_ref()
    }

    pub const fn poll_required(&self) -> bool {
        self.poll_required
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeReconciliationLedger {
    seen_webhook_events: BTreeSet<WebhookEventId>,
    seen_poll_revisions: BTreeSet<RevisionIdentity>,
    latest_signal_at: BTreeMap<ContentIdentity, DateTime<Utc>>,
    heads: BTreeMap<ContentIdentity, YoutubeReconciliationHead>,
    pending_poll: BTreeSet<ContentIdentity>,
}

impl YoutubeReconciliationLedger {
    pub fn ingest_webhook_hint(
        &mut self,
        hint: &YoutubeWebhookHint,
    ) -> YoutubeReconciliationOutcome {
        let duplicate = !self.seen_webhook_events.insert(hint.event_id.clone());
        let late = self
            .latest_signal_at
            .get(hint.content())
            .is_some_and(|latest| hint.occurred_at < *latest);
        if !duplicate {
            self.latest_signal_at
                .entry(hint.content.clone())
                .and_modify(|latest| *latest = (*latest).max(hint.occurred_at))
                .or_insert(hint.occurred_at);
            self.pending_poll.insert(hint.content.clone());
        }
        self.outcome(
            if duplicate {
                YoutubeReconciliationDisposition::Duplicate
            } else if late {
                YoutubeReconciliationDisposition::Late
            } else {
                YoutubeReconciliationDisposition::Applied
            },
            YoutubeReconciliationSource::WebhookHint,
            hint.content.clone(),
        )
    }

    pub fn ingest_poll_observation(
        &mut self,
        observation: YoutubePollObservation,
    ) -> YoutubeReconciliationOutcome {
        let duplicate = !self
            .seen_poll_revisions
            .insert(observation.revision.clone());
        let late_by_signal = self
            .latest_signal_at
            .get(observation.content())
            .is_some_and(|latest| observation.revision.observed_at() < *latest);
        let late_by_head = self
            .heads
            .get(observation.content())
            .is_some_and(|head| observation.revision.observed_at() < head.observed_at);
        let late = late_by_signal || late_by_head;
        if !duplicate {
            self.latest_signal_at
                .entry(observation.content.clone())
                .and_modify(|latest| *latest = (*latest).max(observation.revision.observed_at()))
                .or_insert(observation.revision.observed_at());
            if !late {
                let head = YoutubeReconciliationHead {
                    content: observation.content.clone(),
                    revision: observation.revision.clone(),
                    source: YoutubeReconciliationSource::Poll,
                    observed_at: observation.revision.observed_at(),
                };
                self.heads.insert(observation.content.clone(), head);
                self.pending_poll.remove(observation.content());
            }
        }
        self.outcome(
            if duplicate {
                YoutubeReconciliationDisposition::Duplicate
            } else if late {
                YoutubeReconciliationDisposition::Late
            } else {
                YoutubeReconciliationDisposition::Applied
            },
            YoutubeReconciliationSource::Poll,
            observation.content,
        )
    }

    pub fn apply_poll_result(
        &mut self,
        result: &YoutubeReadResult,
    ) -> Result<Vec<YoutubeReconciliationOutcome>, ChannelAdapterError> {
        let mut outcomes = Vec::new();
        for observation in result.observations() {
            let YoutubeReadObservation::Video(video) = observation else {
                return Err(ChannelAdapterError::UnsupportedSurface {
                    provider: ProviderId::Youtube,
                    surface: "non-video YouTube reconciliation observation",
                });
            };
            outcomes.push(
                self.ingest_poll_observation(YoutubePollObservation::from_video_observation(
                    video,
                )?),
            );
        }
        Ok(outcomes)
    }

    pub fn pending_poll_count(&self) -> usize {
        self.pending_poll.len()
    }

    pub fn pending_poll_content(&self) -> impl Iterator<Item = &ContentIdentity> {
        self.pending_poll.iter()
    }

    pub fn head(&self, content: &ContentIdentity) -> Option<&YoutubeReconciliationHead> {
        self.heads.get(content)
    }

    pub fn poll_request(
        &self,
        credential: CredentialReference,
        max_results: u8,
    ) -> Result<ProviderReadRequest, ChannelAdapterError> {
        if !(1..=50).contains(&max_results) {
            return Err(ChannelAdapterError::InvalidRequest(
                "YouTube reconciliation poll requires one to fifty IDs",
            ));
        }
        let mut ids = Vec::new();
        for content in self.pending_poll.iter().take(usize::from(max_results)) {
            let ContentIdentity::YoutubeVideo(video) = content else {
                return Err(ChannelAdapterError::UnsupportedSurface {
                    provider: ProviderId::Youtube,
                    surface: "non-video YouTube webhook poll",
                });
            };
            ids.push(video.video_id().clone());
        }
        if ids.is_empty() {
            return Err(ChannelAdapterError::InvalidRequest(
                "YouTube reconciliation has no pending poll",
            ));
        }
        YoutubeReadTarget::Videos { ids }.request(credential)
    }

    fn outcome(
        &self,
        disposition: YoutubeReconciliationDisposition,
        source: YoutubeReconciliationSource,
        content: ContentIdentity,
    ) -> YoutubeReconciliationOutcome {
        YoutubeReconciliationOutcome {
            disposition,
            source,
            head: self.heads.get(&content).cloned(),
            poll_required: self.pending_poll.contains(&content),
            content,
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

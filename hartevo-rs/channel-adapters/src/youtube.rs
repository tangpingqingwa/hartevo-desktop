//! YouTube Data API and Analytics API read-only boundary.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, YoutubeChannelId, YoutubeChannelIdentity,
    YoutubeCommentIdentity, YoutubeCommentThreadId, YoutubeEtag, YoutubePlaylistId,
    YoutubeRevisionIdentity, YoutubeVideoId, YoutubeVideoIdentity,
};
use crate::transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOperation, ScopeName, provider_code, retry_after,
};

pub const DATA_API_BASE_URL: &str = "https://www.googleapis.com/youtube/v3/";
pub const ANALYTICS_API_BASE_URL: &str = "https://youtubeanalytics.googleapis.com/v2/reports";
pub const YOUTUBE_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/youtube.readonly";
pub const YOUTUBE_MANAGE_SCOPE: &str = "https://www.googleapis.com/auth/youtube";
pub const YOUTUBE_ANALYTICS_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/yt-analytics.readonly";
pub const YOUTUBE_ANALYTICS_MONETARY_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/yt-analytics-monetary.readonly";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeScope {
    YoutubeReadonly,
    YoutubeManage,
    AnalyticsReadonly,
    AnalyticsMonetaryReadonly,
}

impl YoutubeScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::YoutubeReadonly => YOUTUBE_READONLY_SCOPE,
            Self::YoutubeManage => YOUTUBE_MANAGE_SCOPE,
            Self::AnalyticsReadonly => YOUTUBE_ANALYTICS_READONLY_SCOPE,
            Self::AnalyticsMonetaryReadonly => YOUTUBE_ANALYTICS_MONETARY_READONLY_SCOPE,
        }
    }

    fn name(self) -> Result<ScopeName, ChannelAdapterError> {
        ScopeName::new(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeQuotaOperation {
    ChannelsList,
    VideosList,
    CommentThreadsList,
    PlaylistItemsList,
    AnalyticsReportQuery,
}

impl YoutubeQuotaOperation {
    const fn documented_data_api_cost(self) -> Option<u32> {
        match self {
            Self::AnalyticsReportQuery => None,
            Self::ChannelsList
            | Self::VideosList
            | Self::CommentThreadsList
            | Self::PlaylistItemsList => Some(1),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YoutubePageToken(String);

impl YoutubePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ChannelAdapterError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(|character| {
                !character.is_ascii() || character.is_ascii_control() || character.is_whitespace()
            })
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "invalid YouTube page token",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeQuotaEntry {
    operation: YoutubeQuotaOperation,
    observed_at: DateTime<Utc>,
    data_api_units: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeQuotaLedger {
    data_api_daily_limit: u32,
    data_api_units_used: u32,
    analytics_request_count: u64,
    entries: Vec<YoutubeQuotaEntry>,
}

impl Default for YoutubeQuotaLedger {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl YoutubeQuotaLedger {
    pub const fn new(data_api_daily_limit: u32) -> Self {
        Self {
            data_api_daily_limit,
            data_api_units_used: 0,
            analytics_request_count: 0,
            entries: Vec::new(),
        }
    }

    pub const fn data_api_daily_limit(&self) -> u32 {
        self.data_api_daily_limit
    }

    pub const fn data_api_units_used(&self) -> u32 {
        self.data_api_units_used
    }

    pub const fn data_api_units_remaining(&self) -> u32 {
        self.data_api_daily_limit
            .saturating_sub(self.data_api_units_used)
    }

    pub const fn analytics_request_count(&self) -> u64 {
        self.analytics_request_count
    }

    pub fn entries(&self) -> &[YoutubeQuotaEntry] {
        &self.entries
    }

    pub fn reserve(
        &mut self,
        operation: YoutubeQuotaOperation,
        observed_at: DateTime<Utc>,
    ) -> Result<(), ChannelAdapterError> {
        let data_api_units = operation.documented_data_api_cost();
        if let Some(units) = data_api_units {
            let Some(next) = self.data_api_units_used.checked_add(units) else {
                return Err(quota_exhausted());
            };
            if next > self.data_api_daily_limit {
                return Err(quota_exhausted());
            }
            self.data_api_units_used = next;
        } else {
            // YouTube Analytics query quotas are not represented as YouTube
            // Data API units in the public quota calculator. Keep the request
            // count, but never invent a provider-unit cost.
            self.analytics_request_count = self.analytics_request_count.saturating_add(1);
        }
        self.entries.push(YoutubeQuotaEntry {
            operation,
            observed_at,
            data_api_units,
        });
        Ok(())
    }
}

fn quota_exhausted() -> ChannelAdapterError {
    ChannelAdapterError::QuotaExhausted {
        provider: crate::identity::ProviderId::Youtube,
        bucket: "youtube_data_api_daily_units".to_owned(),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeChannelProbeObservation {
    account: AccountIdentity,
    channel: ChannelIdentity,
    observed_at: DateTime<Utc>,
}

impl YoutubeChannelProbeObservation {
    pub const fn account(&self) -> &AccountIdentity {
        &self.account
    }

    pub const fn channel(&self) -> &ChannelIdentity {
        &self.channel
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

pub fn channel_identity_request(
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    let mut url = Url::parse(DATA_API_BASE_URL).map_err(|_| invalid_endpoint())?;
    url.path_segments_mut()
        .map_err(|()| invalid_endpoint())?
        .push("channels");
    url.query_pairs_mut()
        .append_pair("part", "id,contentDetails,snippet,statistics,status")
        .append_pair("mine", "true");
    ProviderReadRequest::new(
        crate::identity::ProviderId::Youtube,
        ReadOperation::Probe,
        HttpMethod::Get,
        url,
        [YoutubeScope::YoutubeReadonly.name()?],
        credential,
        None,
    )
}

pub fn parse_channel_identity(
    response: &ProviderResponse,
) -> Result<Vec<YoutubeChannelProbeObservation>, ChannelAdapterError> {
    let body = successful_json(response)?;
    let items = body
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or(ChannelAdapterError::InvalidResponse {
            provider: crate::identity::ProviderId::Youtube,
            field: "items".to_owned(),
        })?;
    let mut observations = Vec::with_capacity(items.len());
    for item in items {
        let channel_id = YoutubeChannelId::new(required_string(item, "id")?)
            .map_err(|_| invalid_response("channel.id"))?;
        let etag = YoutubeEtag::new(required_string(item, "etag")?)
            .map_err(|_| invalid_response("channel.etag"))?;
        let uploads_playlist_id = item
            .pointer("/contentDetails/relatedPlaylists/uploads")
            .and_then(serde_json::Value::as_str)
            .map(|value| YoutubePlaylistId::new(value.to_owned()))
            .transpose()
            .map_err(|_| invalid_response("channel.contentDetails.relatedPlaylists.uploads"))?;
        let identity = YoutubeChannelIdentity::new(channel_id, etag, uploads_playlist_id);
        let account = AccountIdentity::Youtube(identity.account().clone());
        observations.push(YoutubeChannelProbeObservation {
            account,
            channel: ChannelIdentity::Youtube(identity),
            observed_at: response.observed_at(),
        });
    }
    if observations.is_empty() {
        return Err(ChannelAdapterError::AuthorizationRequired {
            provider: crate::identity::ProviderId::Youtube,
            reason: AuthorizationReason::CredentialRejected,
        });
    }
    Ok(observations)
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YoutubeAnalyticsMetric(String);

impl YoutubeAnalyticsMetric {
    pub fn new(value: impl Into<String>) -> Result<Self, ChannelAdapterError> {
        let value = value.into();
        if value.is_empty()
            || value
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || character == '_'))
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "invalid YouTube Analytics metric",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YoutubeAnalyticsDimension(String);

impl YoutubeAnalyticsDimension {
    pub fn new(value: impl Into<String>) -> Result<Self, ChannelAdapterError> {
        let value = value.into();
        if value.is_empty()
            || value
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || character == '_'))
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "invalid YouTube Analytics dimension",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeAnalyticsQuery {
    channel_id: YoutubeChannelId,
    start_date: NaiveDate,
    end_date: NaiveDate,
    metrics: Vec<YoutubeAnalyticsMetric>,
    dimensions: Vec<YoutubeAnalyticsDimension>,
    filters: BTreeMap<String, String>,
    monetary: bool,
}

impl YoutubeAnalyticsQuery {
    pub fn new(
        channel_id: YoutubeChannelId,
        start_date: NaiveDate,
        end_date: NaiveDate,
        metrics: Vec<YoutubeAnalyticsMetric>,
        dimensions: Vec<YoutubeAnalyticsDimension>,
        filters: BTreeMap<String, String>,
        monetary: bool,
    ) -> Result<Self, ChannelAdapterError> {
        if start_date > end_date || metrics.is_empty() {
            return Err(ChannelAdapterError::InvalidRequest(
                "invalid YouTube Analytics date range or metrics",
            ));
        }
        Ok(Self {
            channel_id,
            start_date,
            end_date,
            metrics,
            dimensions,
            filters,
            monetary,
        })
    }

    pub const fn channel_id(&self) -> &YoutubeChannelId {
        &self.channel_id
    }

    pub const fn start_date(&self) -> NaiveDate {
        self.start_date
    }

    pub const fn end_date(&self) -> NaiveDate {
        self.end_date
    }

    pub const fn monetary(&self) -> bool {
        self.monetary
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeCommentModerationFilter {
    Published,
    HeldForReview,
    LikelySpam,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum YoutubeReadTarget {
    Videos {
        ids: Vec<YoutubeVideoId>,
    },
    Uploads {
        channel_id: YoutubeChannelId,
        playlist_id: YoutubePlaylistId,
        page_token: Option<YoutubePageToken>,
        max_results: u8,
    },
    CommentThreads {
        channel_id: Option<YoutubeChannelId>,
        video_id: Option<YoutubeVideoId>,
        page_token: Option<String>,
        moderation: YoutubeCommentModerationFilter,
    },
    Analytics(YoutubeAnalyticsQuery),
}

impl YoutubeReadTarget {
    pub const fn operation(&self) -> YoutubeQuotaOperation {
        match self {
            Self::Videos { .. } => YoutubeQuotaOperation::VideosList,
            Self::Uploads { .. } => YoutubeQuotaOperation::PlaylistItemsList,
            Self::CommentThreads { .. } => YoutubeQuotaOperation::CommentThreadsList,
            Self::Analytics(_) => YoutubeQuotaOperation::AnalyticsReportQuery,
        }
    }

    pub fn request(
        &self,
        credential: CredentialReference,
    ) -> Result<ProviderReadRequest, ChannelAdapterError> {
        match self {
            Self::Videos { ids } => videos_request(ids, credential),
            Self::Uploads {
                playlist_id,
                page_token,
                max_results,
                ..
            } => uploads_request(playlist_id, page_token.as_ref(), *max_results, credential),
            Self::CommentThreads {
                channel_id,
                video_id,
                page_token,
                moderation,
            } => comment_threads_request(
                channel_id.as_ref(),
                video_id.as_ref(),
                page_token.as_deref(),
                moderation,
                credential,
            ),
            Self::Analytics(query) => analytics_request(query, credential),
        }
    }
}

fn uploads_request(
    playlist_id: &YoutubePlaylistId,
    page_token: Option<&YoutubePageToken>,
    max_results: u8,
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    if !(1..=50).contains(&max_results) {
        return Err(ChannelAdapterError::InvalidRequest(
            "YouTube playlistItems.list requires one to fifty results",
        ));
    }
    let mut url = Url::parse(DATA_API_BASE_URL).map_err(|_| invalid_endpoint())?;
    url.path_segments_mut()
        .map_err(|()| invalid_endpoint())?
        .push("playlistItems");
    url.query_pairs_mut()
        .append_pair("part", "contentDetails,snippet,status")
        .append_pair("playlistId", playlist_id.as_str())
        .append_pair("maxResults", &max_results.to_string());
    if let Some(page_token) = page_token {
        url.query_pairs_mut()
            .append_pair("pageToken", page_token.as_str());
    }
    ProviderReadRequest::new(
        crate::identity::ProviderId::Youtube,
        ReadOperation::Content,
        HttpMethod::Get,
        url,
        [YoutubeScope::YoutubeReadonly.name()?],
        credential,
        None,
    )
}

fn videos_request(
    ids: &[YoutubeVideoId],
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    if ids.is_empty() || ids.len() > 50 {
        return Err(ChannelAdapterError::InvalidRequest(
            "YouTube videos.list requires one to fifty IDs",
        ));
    }
    let mut url = Url::parse(DATA_API_BASE_URL).map_err(|_| invalid_endpoint())?;
    url.path_segments_mut()
        .map_err(|()| invalid_endpoint())?
        .push("videos");
    let ids = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    url.query_pairs_mut()
        .append_pair("part", "id,snippet,statistics,status")
        .append_pair("id", &ids);
    ProviderReadRequest::new(
        crate::identity::ProviderId::Youtube,
        ReadOperation::Content,
        HttpMethod::Get,
        url,
        [YoutubeScope::YoutubeReadonly.name()?],
        credential,
        None,
    )
}

fn comment_threads_request(
    channel_id: Option<&YoutubeChannelId>,
    video_id: Option<&YoutubeVideoId>,
    page_token: Option<&str>,
    moderation: &YoutubeCommentModerationFilter,
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    if channel_id.is_some() == video_id.is_some() {
        return Err(ChannelAdapterError::InvalidRequest(
            "YouTube commentThreads.list requires exactly one channel or video",
        ));
    }
    let mut url = Url::parse(DATA_API_BASE_URL).map_err(|_| invalid_endpoint())?;
    url.path_segments_mut()
        .map_err(|()| invalid_endpoint())?
        .push("commentThreads");
    url.query_pairs_mut()
        .append_pair("part", "id,snippet,replies");
    if let Some(channel_id) = channel_id {
        url.query_pairs_mut()
            .append_pair("allThreadsRelatedToChannelId", channel_id.as_str());
    }
    if let Some(video_id) = video_id {
        url.query_pairs_mut()
            .append_pair("videoId", video_id.as_str());
    }
    if let Some(page_token) = page_token {
        url.query_pairs_mut().append_pair("pageToken", page_token);
    }
    let scope = match moderation {
        YoutubeCommentModerationFilter::Published => YoutubeScope::YoutubeReadonly,
        YoutubeCommentModerationFilter::HeldForReview
        | YoutubeCommentModerationFilter::LikelySpam => YoutubeScope::YoutubeManage,
    };
    url.query_pairs_mut().append_pair(
        "moderationStatus",
        match moderation {
            YoutubeCommentModerationFilter::Published => "published",
            YoutubeCommentModerationFilter::HeldForReview => "heldForReview",
            YoutubeCommentModerationFilter::LikelySpam => "likelySpam",
        },
    );
    ProviderReadRequest::new(
        crate::identity::ProviderId::Youtube,
        ReadOperation::Content,
        HttpMethod::Get,
        url,
        [scope.name()?],
        credential,
        None,
    )
}

fn analytics_request(
    query: &YoutubeAnalyticsQuery,
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    let mut url = Url::parse(ANALYTICS_API_BASE_URL).map_err(|_| invalid_endpoint())?;
    let metrics = query
        .metrics
        .iter()
        .map(YoutubeAnalyticsMetric::as_str)
        .collect::<Vec<_>>()
        .join(",");
    let dimensions = query
        .dimensions
        .iter()
        .map(YoutubeAnalyticsDimension::as_str)
        .collect::<Vec<_>>()
        .join(",");
    url.query_pairs_mut()
        .append_pair("ids", &format!("channel=={}", query.channel_id.as_str()))
        .append_pair("startDate", &query.start_date.to_string())
        .append_pair("endDate", &query.end_date.to_string())
        .append_pair("metrics", &metrics);
    if !dimensions.is_empty() {
        url.query_pairs_mut().append_pair("dimensions", &dimensions);
    }
    if !query.filters.is_empty() {
        let filters = query
            .filters
            .iter()
            .map(|(key, value)| format!("{key}=={value}"))
            .collect::<Vec<_>>()
            .join(";");
        url.query_pairs_mut().append_pair("filters", &filters);
    }
    let scope = if query.monetary {
        YoutubeScope::AnalyticsMonetaryReadonly
    } else {
        YoutubeScope::AnalyticsReadonly
    };
    ProviderReadRequest::new(
        crate::identity::ProviderId::Youtube,
        ReadOperation::Analytics,
        HttpMethod::Get,
        url,
        [scope.name()?],
        credential,
        None,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeVisibility {
    Public,
    Unlisted,
    Private,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeModerationState {
    Published,
    HeldForReview,
    LikelySpam,
    Rejected,
    Removed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeVideoObservation {
    identity: YoutubeVideoIdentity,
    revision: YoutubeRevisionIdentity,
    visibility: YoutubeVisibility,
    moderation: YoutubeModerationState,
    views: Option<u64>,
    likes: Option<u64>,
    comments: Option<u64>,
}

impl YoutubeVideoObservation {
    pub const fn identity(&self) -> &YoutubeVideoIdentity {
        &self.identity
    }

    pub const fn revision(&self) -> &YoutubeRevisionIdentity {
        &self.revision
    }

    pub const fn visibility(&self) -> YoutubeVisibility {
        self.visibility
    }

    pub const fn moderation(&self) -> YoutubeModerationState {
        self.moderation
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeCommentObservation {
    identity: YoutubeCommentIdentity,
    revision: YoutubeRevisionIdentity,
    moderation: YoutubeModerationState,
}

impl YoutubeCommentObservation {
    pub const fn identity(&self) -> &YoutubeCommentIdentity {
        &self.identity
    }

    pub const fn revision(&self) -> &YoutubeRevisionIdentity {
        &self.revision
    }

    pub const fn moderation(&self) -> YoutubeModerationState {
        self.moderation
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeAnalyticsObservation {
    channel_id: YoutubeChannelId,
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
    observed_at: DateTime<Utc>,
}

impl YoutubeAnalyticsObservation {
    pub const fn channel_id(&self) -> &YoutubeChannelId {
        &self.channel_id
    }

    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    pub fn rows(&self) -> &[Vec<String>] {
        &self.rows
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum YoutubeReadObservation {
    Video(YoutubeVideoObservation),
    Comment(YoutubeCommentObservation),
    Analytics(YoutubeAnalyticsObservation),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct YoutubeReadResult {
    observations: Vec<YoutubeReadObservation>,
    next_page_token: Option<String>,
}

impl YoutubeReadResult {
    pub fn observations(&self) -> &[YoutubeReadObservation] {
        &self.observations
    }

    pub fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }
}

pub fn parse_read_response(
    target: &YoutubeReadTarget,
    response: &ProviderResponse,
) -> Result<YoutubeReadResult, ChannelAdapterError> {
    let body = successful_json(response)?;
    match target {
        YoutubeReadTarget::Videos { .. } => parse_videos(&body, response.observed_at()),
        YoutubeReadTarget::Uploads { channel_id, .. } => {
            parse_uploads(&body, channel_id, response.observed_at())
        }
        YoutubeReadTarget::CommentThreads { .. } => parse_comments(&body, response.observed_at()),
        YoutubeReadTarget::Analytics(query) => {
            parse_analytics(&body, query, response.observed_at())
        }
    }
}

fn parse_uploads(
    body: &serde_json::Value,
    channel_id: &YoutubeChannelId,
    observed_at: DateTime<Utc>,
) -> Result<YoutubeReadResult, ChannelAdapterError> {
    let items = response_items(body)?;
    let mut observations = Vec::with_capacity(items.len());
    for item in items {
        let video_id = YoutubeVideoId::new(required_string_at(item, "/contentDetails/videoId")?)
            .map_err(|_| invalid_response("playlistItem.contentDetails.videoId"))?;
        let item_channel_id =
            YoutubeChannelId::new(required_string_at(item, "/snippet/channelId")?)
                .map_err(|_| invalid_response("playlistItem.snippet.channelId"))?;
        if &item_channel_id != channel_id {
            return Err(invalid_response("playlistItem.snippet.channelId"));
        }
        let etag = YoutubeEtag::new(required_string(item, "etag")?)
            .map_err(|_| invalid_response("playlistItem.etag"))?;
        let identity = YoutubeVideoIdentity::new(item_channel_id, video_id);
        let content = ContentIdentity::YoutubeVideo(identity.clone());
        let revision = YoutubeRevisionIdentity::new(content, etag, observed_at)
            .map_err(|_| invalid_response("playlistItem.revision"))?;
        observations.push(YoutubeReadObservation::Video(YoutubeVideoObservation {
            identity,
            revision,
            visibility: YoutubeVisibility::Unknown,
            moderation: YoutubeModerationState::Unknown,
            views: None,
            likes: None,
            comments: None,
        }));
    }
    Ok(YoutubeReadResult {
        observations,
        next_page_token: next_page_token(body),
    })
}

fn parse_videos(
    body: &serde_json::Value,
    observed_at: DateTime<Utc>,
) -> Result<YoutubeReadResult, ChannelAdapterError> {
    let items = response_items(body)?;
    let mut observations = Vec::with_capacity(items.len());
    for item in items {
        let video_id = YoutubeVideoId::new(required_string(item, "id")?)
            .map_err(|_| invalid_response("video.id"))?;
        let channel_id = YoutubeChannelId::new(required_string_at(item, "/snippet/channelId")?)
            .map_err(|_| invalid_response("video.snippet.channelId"))?;
        let etag = YoutubeEtag::new(required_string(item, "etag")?)
            .map_err(|_| invalid_response("video.etag"))?;
        let identity = YoutubeVideoIdentity::new(channel_id, video_id);
        let content = ContentIdentity::YoutubeVideo(identity.clone());
        let revision = YoutubeRevisionIdentity::new(content, etag, observed_at)
            .map_err(|_| invalid_response("video.revision"))?;
        let status = item.get("status").unwrap_or(&serde_json::Value::Null);
        let visibility = match status
            .get("privacyStatus")
            .and_then(serde_json::Value::as_str)
        {
            Some("public") => YoutubeVisibility::Public,
            Some("unlisted") => YoutubeVisibility::Unlisted,
            Some("private") => YoutubeVisibility::Private,
            _ => YoutubeVisibility::Unknown,
        };
        let moderation = match status
            .get("rejectionReason")
            .and_then(serde_json::Value::as_str)
        {
            Some(_) => YoutubeModerationState::Rejected,
            None => match status
                .get("uploadStatus")
                .and_then(serde_json::Value::as_str)
            {
                Some("processed") => YoutubeModerationState::Published,
                Some("rejected") => YoutubeModerationState::Rejected,
                _ => YoutubeModerationState::Unknown,
            },
        };
        let statistics = item.get("statistics").unwrap_or(&serde_json::Value::Null);
        observations.push(YoutubeReadObservation::Video(YoutubeVideoObservation {
            identity,
            revision,
            visibility,
            moderation,
            views: optional_u64(statistics, "viewCount"),
            likes: optional_u64(statistics, "likeCount"),
            comments: optional_u64(statistics, "commentCount"),
        }));
    }
    Ok(YoutubeReadResult {
        observations,
        next_page_token: next_page_token(body),
    })
}

fn parse_comments(
    body: &serde_json::Value,
    observed_at: DateTime<Utc>,
) -> Result<YoutubeReadResult, ChannelAdapterError> {
    let items = response_items(body)?;
    let mut observations = Vec::with_capacity(items.len());
    for item in items {
        let thread_id = YoutubeCommentThreadId::new(required_string(item, "id")?)
            .map_err(|_| invalid_response("commentThread.id"))?;
        let snippet = item
            .get("snippet")
            .ok_or(invalid_response("commentThread.snippet"))?;
        let channel_id = snippet
            .get("channelId")
            .and_then(serde_json::Value::as_str)
            .map(|value| YoutubeChannelId::new(value.to_owned()))
            .transpose()
            .map_err(|_| invalid_response("commentThread.snippet.channelId"))?;
        let video_id = snippet
            .get("videoId")
            .and_then(serde_json::Value::as_str)
            .map(|value| YoutubeVideoId::new(value.to_owned()))
            .transpose()
            .map_err(|_| invalid_response("commentThread.snippet.videoId"))?;
        let etag = YoutubeEtag::new(required_string(item, "etag")?)
            .map_err(|_| invalid_response("commentThread.etag"))?;
        let identity = YoutubeCommentIdentity::new(channel_id, video_id, thread_id);
        let content = ContentIdentity::YoutubeComment(identity.clone());
        let revision = YoutubeRevisionIdentity::new(content, etag, observed_at)
            .map_err(|_| invalid_response("commentThread.revision"))?;
        let moderation = match snippet
            .get("moderationStatus")
            .and_then(serde_json::Value::as_str)
        {
            Some("published") => YoutubeModerationState::Published,
            Some("heldForReview") => YoutubeModerationState::HeldForReview,
            Some("likelySpam") => YoutubeModerationState::LikelySpam,
            Some("rejected") => YoutubeModerationState::Rejected,
            _ => YoutubeModerationState::Unknown,
        };
        observations.push(YoutubeReadObservation::Comment(YoutubeCommentObservation {
            identity,
            revision,
            moderation,
        }));
    }
    Ok(YoutubeReadResult {
        observations,
        next_page_token: next_page_token(body),
    })
}

fn parse_analytics(
    body: &serde_json::Value,
    query: &YoutubeAnalyticsQuery,
    observed_at: DateTime<Utc>,
) -> Result<YoutubeReadResult, ChannelAdapterError> {
    let headers = body
        .get("columnHeaders")
        .and_then(serde_json::Value::as_array)
        .ok_or(invalid_response("analytics.columnHeaders"))?;
    let columns = headers
        .iter()
        .map(|header| required_string(header, "name"))
        .collect::<Result<Vec<_>, _>>()?;
    let rows = body
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    row.as_array()
                        .ok_or(invalid_response("analytics.rows"))
                        .and_then(|values| {
                            if values.len() != columns.len() {
                                return Err(invalid_response("analytics.row_width"));
                            }
                            Ok(values.iter().map(json_scalar_string).collect())
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(YoutubeReadResult {
        observations: vec![YoutubeReadObservation::Analytics(
            YoutubeAnalyticsObservation {
                channel_id: query.channel_id.clone(),
                columns,
                rows,
                observed_at,
            },
        )],
        next_page_token: None,
    })
}

pub(crate) fn successful_json(
    response: &ProviderResponse,
) -> Result<serde_json::Value, ChannelAdapterError> {
    let provider = crate::identity::ProviderId::Youtube;
    if (200..300).contains(&response.status()) {
        return response.json(provider);
    }
    let body = response.json(provider).ok();
    let code = body.as_ref().and_then(provider_code);
    if response.status() == 401 {
        return Err(ChannelAdapterError::AuthorizationRequired {
            provider,
            reason: if code
                .as_deref()
                .is_some_and(|code| code.contains("invalid") || code.contains("revok"))
            {
                AuthorizationReason::ScopeRevoked
            } else {
                AuthorizationReason::CredentialExpired
            },
        });
    }
    if response.status() == 403
        && code
            .as_deref()
            .is_some_and(|code| code.eq_ignore_ascii_case("quotaExceeded"))
    {
        return Err(quota_exhausted());
    }
    if response.status() == 403
        && code
            .as_deref()
            .is_some_and(|code| code.contains("permission") || code.contains("auth"))
    {
        return Err(ChannelAdapterError::AuthorizationRequired {
            provider,
            reason: AuthorizationReason::MissingScope,
        });
    }
    if response.status() == 404 {
        return Err(ChannelAdapterError::ContentNotFound { provider });
    }
    if response.status() == 429 {
        return Err(ChannelAdapterError::RateLimited {
            provider,
            retry_after_seconds: retry_after(response),
        });
    }
    Err(ChannelAdapterError::ProviderRejected {
        provider,
        status: response.status(),
        code,
    })
}

fn response_items(body: &serde_json::Value) -> Result<&[serde_json::Value], ChannelAdapterError> {
    body.get("items")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or(invalid_response("items"))
}

fn next_page_token(body: &serde_json::Value) -> Option<String> {
    body.get("nextPageToken")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn required_string(object: &serde_json::Value, key: &str) -> Result<String, ChannelAdapterError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(invalid_response(key))
}

fn required_string_at(
    object: &serde_json::Value,
    pointer: &str,
) -> Result<String, ChannelAdapterError> {
    object
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(invalid_response(pointer))
}

fn optional_u64(object: &serde_json::Value, key: &str) -> Option<u64> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok())
        .or_else(|| object.get(key).and_then(serde_json::Value::as_u64))
}

fn json_scalar_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn invalid_endpoint() -> ChannelAdapterError {
    ChannelAdapterError::InvalidRequest("invalid provider endpoint")
}

fn invalid_response(field: impl Into<String>) -> ChannelAdapterError {
    ChannelAdapterError::InvalidResponse {
        provider: crate::identity::ProviderId::Youtube,
        field: field.into(),
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum YoutubeReadError {
    #[error("YouTube read boundary requires a channel identity before content reads")]
    MissingChannelIdentity,
}

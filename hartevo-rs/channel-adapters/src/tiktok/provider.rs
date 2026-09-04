//! Official TikTok Display API request and response boundary.

use chrono::{DateTime, Utc};
use serde_json::Value;
use url::Url;

use crate::transport::{
    HttpMethod, ProviderReadRequest, ProviderResponse, ReadOnlyTransport, SecretReference,
    TransportError, sha256_json,
};

use super::{
    DISPLAY_API_BASE_URL, EvidenceProvenance, ProviderId, TiktokAccountIdentity,
    TiktokApiOperation, TiktokCursor, TiktokError, TiktokFreshness, TiktokOAuthScope,
    TiktokObservationEnvelope, TiktokPerformanceObservation, TiktokReadObservation,
    TiktokReadScope, TiktokRevisionIdentity, TiktokVideoIdentity, TiktokVideoObservation,
    TiktokVideoPage, USER_INFO_PATH, VIDEO_LIST_PATH, VIDEO_QUERY_PATH,
    video_list_request_fingerprint,
};

#[derive(Debug)]
pub struct TiktokDisplayApiProvider<T> {
    transport: T,
    provenance: EvidenceProvenance,
    production_secret_reference: Option<SecretReference>,
}

impl<T> TiktokDisplayApiProvider<T> {
    pub fn fixture(transport: T) -> Self {
        Self {
            transport,
            provenance: EvidenceProvenance::Fixture,
            production_secret_reference: None,
        }
    }

    pub fn controlled(transport: T) -> Self {
        Self {
            transport,
            provenance: EvidenceProvenance::ControlledProvider,
            production_secret_reference: None,
        }
    }

    pub(crate) fn production(transport: T, secret_reference: SecretReference) -> Self {
        Self {
            transport,
            provenance: EvidenceProvenance::ProductionProvider,
            production_secret_reference: Some(secret_reference),
        }
    }

    pub const fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn require_credential_reference(
        &self,
        credential: &SecretReference,
    ) -> Result<(), TiktokError> {
        if let Some(expected) = &self.production_secret_reference
            && expected != credential
        {
            return Err(TiktokError::CredentialReferenceMismatch);
        }
        Ok(())
    }
}

impl<T: ReadOnlyTransport> TiktokDisplayApiProvider<T> {
    pub fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TiktokError> {
        self.transport_mut()
            .send(request)
            .map_err(|error| match error {
                TransportError::Unavailable | TransportError::TimedOut => TiktokError::Disconnected,
            })
    }
}

pub fn probe_request(credential: SecretReference) -> Result<ProviderReadRequest, TiktokError> {
    let url = endpoint(USER_INFO_PATH)?;
    let url = with_fields(url, &["open_id", "display_name"]);
    Ok(ProviderReadRequest::new(
        ProviderId::Tiktok,
        TiktokApiOperation::UserInfo,
        HttpMethod::Get,
        url,
        [TiktokOAuthScope::UserInfoBasic.name()?],
        credential,
        None,
    )?)
}

pub fn video_list_request(
    credential: SecretReference,
    cursor: Option<TiktokCursor>,
    max_count: u8,
) -> Result<ProviderReadRequest, TiktokError> {
    if !(1..=20).contains(&max_count) {
        return Err(TiktokError::InvalidRequest(
            "TikTok video.list max_count must be one through twenty",
        ));
    }
    let url = with_fields(endpoint(VIDEO_LIST_PATH)?, &video_fields());
    let mut body = serde_json::Map::new();
    body.insert("max_count".to_owned(), Value::from(u64::from(max_count)));
    if let Some(cursor) = cursor {
        body.insert("cursor".to_owned(), Value::from(cursor.value()));
    }
    Ok(ProviderReadRequest::new(
        ProviderId::Tiktok,
        TiktokApiOperation::VideoList,
        HttpMethod::Post,
        url,
        [TiktokOAuthScope::VideoList.name()?],
        credential,
        Some(Value::Object(body)),
    )?)
}

pub fn video_query_request(
    credential: SecretReference,
    video_ids: &[super::TiktokVideoId],
) -> Result<ProviderReadRequest, TiktokError> {
    if video_ids.is_empty() || video_ids.len() > 20 {
        return Err(TiktokError::InvalidRequest(
            "TikTok video.query accepts one through twenty video IDs",
        ));
    }
    let url = with_fields(endpoint(VIDEO_QUERY_PATH)?, &video_fields());
    let body = serde_json::json!({
        "filters": {
            "video_ids": video_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }
    });
    Ok(ProviderReadRequest::new(
        ProviderId::Tiktok,
        TiktokApiOperation::VideoQuery,
        HttpMethod::Post,
        url,
        [TiktokOAuthScope::VideoList.name()?],
        credential,
        Some(body),
    )?)
}

pub fn parse_probe_response(
    expected_scope: &TiktokReadScope,
    response: &ProviderResponse,
    freshness: TiktokFreshness,
    provenance: EvidenceProvenance,
) -> Result<TiktokObservationEnvelope, TiktokError> {
    let body = successful_json(response, TiktokApiOperation::UserInfo)?;
    let user = body
        .pointer("/data/user")
        .ok_or_else(|| invalid_response("data.user"))?;
    let open_id = required_string(user, "open_id")?;
    let account_id = super::TiktokAccountId::new(open_id)?;
    if &account_id != expected_scope.account() {
        return Err(TiktokError::IdentityMismatch);
    }
    let account = TiktokAccountIdentity::new(
        account_id.clone(),
        optional_string(user, "display_name"),
        optional_string(user, "username"),
    )?;
    let revision =
        TiktokRevisionIdentity::account(account_id, sha256_json(user), response.observed_at());
    TiktokObservationEnvelope::new(
        expected_scope.clone(),
        account,
        revision,
        freshness,
        provenance,
        TiktokReadObservation::Account(super::TiktokAccountObservation {
            identity: TiktokAccountIdentity::new(
                expected_scope.account().clone(),
                optional_string(user, "display_name"),
                optional_string(user, "username"),
            )?,
        }),
    )
}

pub fn parse_video_page_response(
    expected_scope: &TiktokReadScope,
    requested_cursor: Option<TiktokCursor>,
    max_count: u8,
    response: &ProviderResponse,
    freshness: TiktokFreshness,
    provenance: EvidenceProvenance,
) -> Result<TiktokVideoPage, TiktokError> {
    let body = successful_json(response, TiktokApiOperation::VideoList)?;
    let data = body.get("data").ok_or_else(|| invalid_response("data"))?;
    let videos = data
        .get("videos")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response("data.videos"))?;
    let has_more = data
        .get("has_more")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_response("data.has_more"))?;
    let cursor_value = data
        .get("cursor")
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid_response("data.cursor"))?;
    let next_cursor = if has_more {
        Some(TiktokCursor::new(cursor_value)?)
    } else {
        None
    };
    let account = account_for_scope(expected_scope);
    let mut observations = videos
        .iter()
        .map(|video| {
            parse_video_observation(expected_scope, &account, video, freshness, provenance)
        })
        .collect::<Result<Vec<_>, _>>()?;
    sort_video_observations(&mut observations)?;
    Ok(TiktokVideoPage {
        scope: expected_scope.clone(),
        requested_cursor,
        next_cursor,
        has_more,
        page_digest: response.body_digest(),
        request_fingerprint: video_list_request_fingerprint(max_count),
        observed_at: response.observed_at(),
        observations,
        freshness,
    })
}

pub fn parse_video_query_response(
    expected_scope: &TiktokReadScope,
    response: &ProviderResponse,
    freshness: TiktokFreshness,
    provenance: EvidenceProvenance,
) -> Result<Vec<TiktokObservationEnvelope>, TiktokError> {
    let body = successful_json(response, TiktokApiOperation::VideoQuery)?;
    let videos = body
        .pointer("/data/videos")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response("data.videos"))?;
    let account = account_for_scope(expected_scope);
    videos
        .iter()
        .map(|video| {
            parse_video_observation(expected_scope, &account, video, freshness, provenance)
        })
        .collect()
}

fn parse_video_observation(
    expected_scope: &TiktokReadScope,
    account: &TiktokAccountIdentity,
    video: &Value,
    freshness: TiktokFreshness,
    provenance: EvidenceProvenance,
) -> Result<TiktokObservationEnvelope, TiktokError> {
    let video_id = super::TiktokVideoId::new(required_string(video, "id")?)?;
    let identity = TiktokVideoIdentity::new(account.open_id().clone(), video_id.clone());
    let created_at = video.get("create_time").map(parse_timestamp).transpose()?;
    let observation = TiktokVideoObservation {
        identity,
        created_at,
        title: optional_string(video, "title"),
        description: optional_string(video, "video_description"),
        share_url: optional_string(video, "share_url"),
        performance: TiktokPerformanceObservation {
            like_count: optional_u64(video, "like_count")?,
            comment_count: optional_u64(video, "comment_count")?,
            share_count: optional_u64(video, "share_count")?,
            view_count: optional_u64(video, "view_count")?,
        },
    };
    let revision = TiktokRevisionIdentity::video(
        account.open_id().clone(),
        video_id,
        sha256_json(video),
        freshness.observed_at(),
    );
    TiktokObservationEnvelope::new(
        expected_scope.clone(),
        account.clone(),
        revision,
        freshness,
        provenance,
        TiktokReadObservation::Video(observation),
    )
}

fn successful_json(
    response: &ProviderResponse,
    operation: TiktokApiOperation,
) -> Result<Value, TiktokError> {
    let body = response
        .json_value()
        .map_err(|_| TiktokError::InvalidResponse {
            field: "json".to_owned(),
        })?;
    let code = body
        .pointer("/error/code")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty() && *code != "ok")
        .map(str::to_owned);
    if (200..300).contains(&response.status()) && code.is_none() {
        return Ok(body);
    }
    if code.as_deref() == Some("access_token_invalid") {
        return Err(TiktokError::CredentialRevoked);
    }
    if matches!(
        code.as_deref(),
        Some("scope_not_authorized" | "scope_permission_missed")
    ) {
        return Err(TiktokError::MissingScope {
            scope: operation.required_scope(),
        });
    }
    if response.status() == 429 || code.as_deref() == Some("rate_limit_exceeded") {
        return Err(TiktokError::RateLimited {
            operation,
            retry_after_seconds: response
                .header("retry-after")
                .and_then(|value| value.parse().ok()),
        });
    }
    if response.status() >= 500 {
        return Err(TiktokError::Disconnected);
    }
    if response.status() == 401 {
        return Err(TiktokError::CredentialRevoked);
    }
    Err(TiktokError::ProviderRejected {
        status: response.status(),
        code,
    })
}

fn endpoint(path: &str) -> Result<Url, TiktokError> {
    Url::parse(&format!("{DISPLAY_API_BASE_URL}{path}"))
        .map_err(|_| TiktokError::InvalidRequest("invalid TikTok API endpoint"))
}

fn with_fields(mut url: Url, fields: &[&str]) -> Url {
    url.query_pairs_mut()
        .append_pair("fields", &fields.join(","));
    url
}

fn video_fields() -> Vec<&'static str> {
    vec![
        "id",
        "create_time",
        "title",
        "video_description",
        "share_url",
        "like_count",
        "comment_count",
        "share_count",
        "view_count",
    ]
}

fn account_for_scope(scope: &TiktokReadScope) -> TiktokAccountIdentity {
    TiktokAccountIdentity {
        open_id: scope.account().clone(),
        display_name: None,
        username: None,
    }
}

fn required_string(object: &Value, key: &str) -> Result<String, TiktokError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid_response(key))
}

fn optional_string(object: &Value, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn optional_u64(object: &Value, key: &str) -> Result<Option<u64>, TiktokError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if let Some(value) = value.as_u64() {
        return Ok(Some(value));
    }
    if let Some(value) = value.as_str() {
        return value.parse().map(Some).map_err(|_| invalid_response(key));
    }
    Err(invalid_response(key))
}

fn parse_timestamp(value: &Value) -> Result<DateTime<Utc>, TiktokError> {
    let seconds = value
        .as_i64()
        .ok_or_else(|| invalid_response("create_time"))?;
    DateTime::from_timestamp(seconds, 0).ok_or_else(|| invalid_response("create_time"))
}

fn sort_video_observations(
    observations: &mut [TiktokObservationEnvelope],
) -> Result<(), TiktokError> {
    if observations
        .iter()
        .any(|observation| matches!(observation.observation(), TiktokReadObservation::Account(_)))
    {
        return Err(TiktokError::CursorDrift);
    }
    observations.sort_by(|left, right| {
        let TiktokReadObservation::Video(left_video) = left.observation() else {
            return std::cmp::Ordering::Equal;
        };
        let TiktokReadObservation::Video(right_video) = right.observation() else {
            return std::cmp::Ordering::Equal;
        };
        left_video
            .identity()
            .video_id()
            .cmp(right_video.identity().video_id())
    });
    if observations.windows(2).any(|pair| {
        let left = match pair[0].observation() {
            TiktokReadObservation::Video(video) => video.identity().video_id(),
            TiktokReadObservation::Account(_) => return true,
        };
        let right = match pair[1].observation() {
            TiktokReadObservation::Video(video) => video.identity().video_id(),
            TiktokReadObservation::Account(_) => return true,
        };
        left == right
    }) {
        return Err(TiktokError::CursorDrift);
    }
    Ok(())
}

fn invalid_response(field: impl Into<String>) -> TiktokError {
    TiktokError::InvalidResponse {
        field: field.into(),
    }
}

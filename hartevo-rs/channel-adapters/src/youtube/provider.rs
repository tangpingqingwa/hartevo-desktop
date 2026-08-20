//! Official YouTube Data API request/response boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use url::Url;

use crate::transport::{TransportError, YouTubeSecretReference};

use super::{
    DraftVideoPublishRequest, YOUTUBE_API_BASE_URL, YOUTUBE_UPLOAD_BASE_URL,
    YouTubeAuthenticatedProbe, YouTubeChannelId, YouTubeCredential, YouTubeDispatchOperation,
    YouTubeError, YouTubeEvidenceProvenance, YouTubeOAuthScope, YouTubeProviderId,
    YouTubeProviderReceipt, YouTubePublishBinding, YouTubeReadbackReceipt,
    YouTubeRetryAfterReceipt, YouTubeSchedule, YouTubeUploadProgress,
    YouTubeUploadSessionReference, YouTubeVideoId, YouTubeVideoProcessingState,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum YouTubeHttpMethod {
    Get,
    Post,
    Put,
}

impl fmt::Display for YouTubeHttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        })
    }
}

#[derive(Clone)]
pub struct YouTubeProviderRequest {
    operation: YouTubeDispatchOperation,
    method: YouTubeHttpMethod,
    url: Url,
    required_scopes: BTreeSet<YouTubeOAuthScope>,
    credential: YouTubeSecretReference,
    body: Option<Value>,
    asset_digest: Option<String>,
    asset_byte_length: Option<u64>,
    session: Option<YouTubeUploadSessionReference>,
    upload_offset: Option<u64>,
    request_digest: String,
}

impl YouTubeProviderRequest {
    #[allow(clippy::too_many_arguments)]
    fn new(
        operation: YouTubeDispatchOperation,
        method: YouTubeHttpMethod,
        url: Url,
        required_scopes: impl IntoIterator<Item = YouTubeOAuthScope>,
        credential: YouTubeSecretReference,
        body: Option<Value>,
        asset_digest: Option<String>,
        asset_byte_length: Option<u64>,
        session: Option<YouTubeUploadSessionReference>,
        upload_offset: Option<u64>,
        request_digest: String,
    ) -> Result<Self, YouTubeError> {
        if url.scheme() != "https" || body_contains_secret_key(body.as_ref()) {
            return Err(YouTubeError::InvalidRequest(
                "YouTube provider request must be https and secret-free",
            ));
        }
        Ok(Self {
            operation,
            method,
            url,
            required_scopes: required_scopes.into_iter().collect(),
            credential,
            body,
            asset_digest,
            asset_byte_length,
            session,
            upload_offset,
            request_digest,
        })
    }

    pub const fn operation(&self) -> YouTubeDispatchOperation {
        self.operation
    }

    pub const fn method(&self) -> YouTubeHttpMethod {
        self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn required_scopes(&self) -> &BTreeSet<YouTubeOAuthScope> {
        &self.required_scopes
    }

    pub const fn credential(&self) -> &YouTubeSecretReference {
        &self.credential
    }

    pub fn body(&self) -> Option<&Value> {
        self.body.as_ref()
    }

    pub fn asset_digest(&self) -> Option<&str> {
        self.asset_digest.as_deref()
    }

    pub const fn asset_byte_length(&self) -> Option<u64> {
        self.asset_byte_length
    }

    pub const fn session(&self) -> Option<&YouTubeUploadSessionReference> {
        self.session.as_ref()
    }

    pub const fn upload_offset(&self) -> Option<u64> {
        self.upload_offset
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn digest(&self) -> String {
        super::sha256_json(&serde_json::json!({
            "operation": self.operation,
            "method": self.method.to_string(),
            "url": self.url.as_str(),
            "required_scopes": self.required_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "body": self.body,
            "asset_digest": self.asset_digest,
            "asset_byte_length": self.asset_byte_length,
            "session": self.session.as_ref().map(YouTubeUploadSessionReference::as_str),
            "upload_offset": self.upload_offset,
            "request_digest": self.request_digest,
        }))
    }
}

impl fmt::Debug for YouTubeProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YouTubeProviderRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("required_scopes", &self.required_scopes)
            .field("credential", &self.credential)
            .field("body_present", &self.body.is_some())
            .field("asset_digest", &self.asset_digest)
            .field("asset_byte_length", &self.asset_byte_length)
            .field("session", &self.session)
            .field("upload_offset", &self.upload_offset)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl fmt::Display for YouTubeProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.url)
    }
}

#[derive(Clone)]
pub struct YouTubeProviderResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    observed_at: DateTime<Utc>,
    upload_session: Option<YouTubeUploadSessionReference>,
}

impl YouTubeProviderResponse {
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            status,
            headers: headers.into_iter().collect(),
            body: body.into(),
            observed_at,
            upload_session: None,
        }
    }

    #[must_use]
    pub fn with_upload_session(mut self, session: YouTubeUploadSessionReference) -> Self {
        self.upload_session = Some(session);
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn json(&self) -> Result<Value, YouTubeError> {
        serde_json::from_str(&self.body)
            .map_err(|_| YouTubeError::InvalidResponse("YouTube JSON body"))
    }

    pub fn body_digest(&self) -> String {
        super::hex_digest(self.body.as_bytes())
    }

    pub const fn upload_session(&self) -> Option<&YouTubeUploadSessionReference> {
        self.upload_session.as_ref()
    }
}

impl fmt::Debug for YouTubeProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YouTubeProviderResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .field("body_digest", &self.body_digest())
            .field("observed_at", &self.observed_at)
            .field("upload_session", &self.upload_session)
            .finish()
    }
}

pub trait YouTubePublishTransport {
    fn send(
        &mut self,
        request: &YouTubeProviderRequest,
    ) -> Result<YouTubeProviderResponse, TransportError>;
}

/// Explicit opt-in marker for a transport backed by the first-party API.
///
/// Fixture and controlled transports implement only [`YouTubePublishTransport`]
/// and therefore cannot be passed to the production gate accidentally.
pub trait YouTubeProductionTransport: YouTubePublishTransport {}

#[derive(Debug)]
pub struct YouTubeDataApiProvider<T> {
    transport: T,
    provenance: YouTubeEvidenceProvenance,
    production_secret_reference: Option<YouTubeSecretReference>,
}

impl<T> YouTubeDataApiProvider<T> {
    pub fn fixture(transport: T) -> Self {
        Self {
            transport,
            provenance: YouTubeEvidenceProvenance::Fixture,
            production_secret_reference: None,
        }
    }

    pub fn controlled(transport: T) -> Self {
        Self {
            transport,
            provenance: YouTubeEvidenceProvenance::ControlledProvider,
            production_secret_reference: None,
        }
    }

    pub(crate) fn production(transport: T, secret_reference: YouTubeSecretReference) -> Self
    where
        T: YouTubeProductionTransport,
    {
        Self {
            transport,
            provenance: YouTubeEvidenceProvenance::ProductionProvider,
            production_secret_reference: Some(secret_reference),
        }
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: YouTubePublishTransport> YouTubeDataApiProvider<T> {
    pub fn authenticated_probe(
        &mut self,
        credential: &YouTubeCredential,
        binding: &YouTubePublishBinding,
        valid_for: Duration,
    ) -> Result<YouTubeAuthenticatedProbe, YouTubeError> {
        let request = authenticated_probe_request(credential, binding)?;
        let response = self.send(&request)?;
        ensure_success(
            &response,
            YouTubeDispatchOperation::AuthenticatedProbe,
            binding,
            "probe",
        )?;
        parse_probe_response(
            binding,
            credential.generation(),
            &response,
            valid_for,
            self.provenance,
        )
    }

    pub fn begin_upload(
        &mut self,
        credential: &YouTubeCredential,
        request: &DraftVideoPublishRequest,
    ) -> Result<YouTubeUploadSessionReference, YouTubeError> {
        let provider_request = begin_upload_request(credential, request)?;
        let response = self.send(&provider_request)?;
        ensure_success(
            &response,
            YouTubeDispatchOperation::BeginResumableUpload,
            request.binding(),
            &request.request_digest(),
        )?;
        if !matches!(response.status(), 200 | 201) {
            return Err(YouTubeError::InvalidResponse(
                "YouTube resumable upload session response",
            ));
        }
        response
            .upload_session()
            .cloned()
            .or_else(|| {
                response
                    .header("location")
                    .and_then(|location| YouTubeUploadSessionReference::new(location).ok())
            })
            .ok_or(YouTubeError::InvalidResponse(
                "YouTube resumable upload session reference",
            ))
    }

    pub fn upload_chunk(
        &mut self,
        credential: &YouTubeCredential,
        request: &DraftVideoPublishRequest,
        session: &YouTubeUploadSessionReference,
        uploaded_bytes: u64,
    ) -> Result<YouTubeUploadProgress, YouTubeError> {
        if uploaded_bytes > request.asset().byte_length() {
            return Err(YouTubeError::InvalidRequest(
                "YouTube upload offset exceeds asset length",
            ));
        }
        let provider_request = upload_chunk_request(credential, request, session, uploaded_bytes)?;
        let response = self.send(&provider_request)?;
        if response.status() == 308 {
            let next_offset = parse_uploaded_offset(&response)?;
            if next_offset < uploaded_bytes || next_offset > request.asset().byte_length() {
                return Err(YouTubeError::InvalidResponse("YouTube upload range"));
            }
            return Ok(YouTubeUploadProgress::InProgress {
                session: session.clone(),
                uploaded_bytes: next_offset,
                response_digest: response.body_digest(),
                observed_at: response.observed_at(),
            });
        }
        ensure_success(
            &response,
            YouTubeDispatchOperation::UploadChunk,
            request.binding(),
            &request.request_digest(),
        )?;
        if !matches!(response.status(), 200 | 201) {
            return Err(YouTubeError::InvalidResponse("YouTube upload completion"));
        }
        let provider_request_digest = provider_request.digest();
        Ok(YouTubeUploadProgress::Completed(parse_provider_receipt(
            request,
            session,
            &response,
            &provider_request_digest,
            self.provenance,
        )?))
    }

    pub fn readback(
        &mut self,
        credential: &YouTubeCredential,
        request: &DraftVideoPublishRequest,
        provider_receipt: &YouTubeProviderReceipt,
        valid_for: Duration,
    ) -> Result<YouTubeReadbackReceipt, YouTubeError> {
        let provider_request = readback_request(credential, request, provider_receipt.video_id())?;
        let provider_request_digest = provider_request.digest();
        let response = self.send(&provider_request)?;
        ensure_success(
            &response,
            YouTubeDispatchOperation::Readback,
            request.binding(),
            &request.request_digest(),
        )?;
        parse_readback_response(
            request,
            provider_receipt,
            &response,
            &provider_request_digest,
            valid_for,
            self.provenance,
        )
    }

    fn send(
        &mut self,
        request: &YouTubeProviderRequest,
    ) -> Result<YouTubeProviderResponse, YouTubeError> {
        if let Some(expected) = &self.production_secret_reference
            && expected != request.credential()
        {
            return Err(YouTubeError::ScopeMismatch);
        }
        self.transport_mut()
            .send(request)
            .map_err(|error| match error {
                TransportError::Unavailable | TransportError::TimedOut => {
                    YouTubeError::Disconnected
                }
                TransportError::InvalidSecretReference => YouTubeError::InvalidRequest(
                    "YouTube transport received an invalid secret reference",
                ),
            })
    }
}

fn authenticated_probe_request(
    credential: &YouTubeCredential,
    binding: &YouTubePublishBinding,
) -> Result<YouTubeProviderRequest, YouTubeError> {
    let mut url = endpoint(YOUTUBE_API_BASE_URL, "/channels")?;
    url.query_pairs_mut()
        .append_pair("part", "id,snippet")
        .append_pair("mine", "true");
    YouTubeProviderRequest::new(
        YouTubeDispatchOperation::AuthenticatedProbe,
        YouTubeHttpMethod::Get,
        url,
        [YouTubeOAuthScope::YoutubeReadonly],
        credential.secret_reference().clone(),
        None,
        None,
        None,
        None,
        None,
        super::sha256_json(&serde_json::json!({
            "binding": binding,
            "operation": "authenticated_probe",
        })),
    )
}

fn begin_upload_request(
    credential: &YouTubeCredential,
    request: &DraftVideoPublishRequest,
) -> Result<YouTubeProviderRequest, YouTubeError> {
    let mut url = endpoint(YOUTUBE_UPLOAD_BASE_URL, "/videos")?;
    url.query_pairs_mut()
        .append_pair("uploadType", "resumable")
        .append_pair("part", "snippet,status");
    let mut status = serde_json::Map::from_iter([(
        "privacyStatus".to_owned(),
        Value::String(request.visibility().as_api_value().to_owned()),
    )]);
    if let Some(schedule) = request.schedule() {
        status.insert(
            "publishAt".to_owned(),
            Value::String(schedule.publish_at().to_rfc3339()),
        );
    }
    let body = serde_json::json!({
        "snippet": {"title": request.title()},
        "status": status,
    });
    YouTubeProviderRequest::new(
        YouTubeDispatchOperation::BeginResumableUpload,
        YouTubeHttpMethod::Post,
        url,
        [YouTubeOAuthScope::YoutubeUpload],
        credential.secret_reference().clone(),
        Some(body),
        Some(request.asset().digest().as_str().to_owned()),
        Some(request.asset().byte_length()),
        None,
        Some(0),
        request.request_digest(),
    )
}

fn upload_chunk_request(
    credential: &YouTubeCredential,
    request: &DraftVideoPublishRequest,
    session: &YouTubeUploadSessionReference,
    uploaded_bytes: u64,
) -> Result<YouTubeProviderRequest, YouTubeError> {
    let url = endpoint(YOUTUBE_UPLOAD_BASE_URL, "/videos")?;
    YouTubeProviderRequest::new(
        YouTubeDispatchOperation::UploadChunk,
        YouTubeHttpMethod::Put,
        url,
        [YouTubeOAuthScope::YoutubeUpload],
        credential.secret_reference().clone(),
        None,
        Some(request.asset().digest().as_str().to_owned()),
        Some(request.asset().byte_length()),
        Some(session.clone()),
        Some(uploaded_bytes),
        request.request_digest(),
    )
}

fn readback_request(
    credential: &YouTubeCredential,
    request: &DraftVideoPublishRequest,
    video_id: &YouTubeVideoId,
) -> Result<YouTubeProviderRequest, YouTubeError> {
    let mut url = endpoint(YOUTUBE_API_BASE_URL, "/videos")?;
    url.query_pairs_mut()
        .append_pair("part", "id,snippet,status,processingDetails")
        .append_pair("id", video_id.as_str());
    YouTubeProviderRequest::new(
        YouTubeDispatchOperation::Readback,
        YouTubeHttpMethod::Get,
        url,
        [YouTubeOAuthScope::YoutubeReadonly],
        credential.secret_reference().clone(),
        None,
        Some(request.asset().digest().as_str().to_owned()),
        Some(request.asset().byte_length()),
        None,
        None,
        request.request_digest(),
    )
}

fn endpoint(base: &str, path: &str) -> Result<Url, YouTubeError> {
    Url::parse(&format!("{base}{path}"))
        .map_err(|_| YouTubeError::InvalidRequest("invalid YouTube API endpoint"))
}

fn ensure_success(
    response: &YouTubeProviderResponse,
    operation: YouTubeDispatchOperation,
    binding: &YouTubePublishBinding,
    request_digest: &str,
) -> Result<(), YouTubeError> {
    if response.status() == 429 {
        return Err(YouTubeError::RetryAfter(Box::new(rate_limit_receipt(
            response,
            operation,
            binding,
            request_digest,
        )?)));
    }
    if (200..300).contains(&response.status()) {
        return Ok(());
    }
    if response.status() >= 500 {
        return Err(YouTubeError::RetryableProvider { operation });
    }
    let body = response.json().ok();
    let reason = body
        .as_ref()
        .and_then(|value| value.pointer("/error/errors/0/reason"))
        .and_then(Value::as_str)
        .or_else(|| {
            body.as_ref()
                .and_then(|value| value.pointer("/error/status"))
                .and_then(Value::as_str)
        });
    match reason {
        Some("quotaExceeded" | "dailyLimitExceeded") => Err(YouTubeError::QuotaExhausted {
            bucket: operation.quota_bucket(),
        }),
        Some("insufficientPermissions") => Err(YouTubeError::MissingScope {
            scope: match operation {
                YouTubeDispatchOperation::AuthenticatedProbe
                | YouTubeDispatchOperation::Readback => YouTubeOAuthScope::YoutubeReadonly,
                YouTubeDispatchOperation::BeginResumableUpload
                | YouTubeDispatchOperation::UploadChunk => YouTubeOAuthScope::YoutubeUpload,
            },
        }),
        Some("rateLimitExceeded" | "userRateLimitExceeded") => {
            Err(YouTubeError::RetryAfter(Box::new(rate_limit_receipt(
                response,
                operation,
                binding,
                request_digest,
            )?)))
        }
        Some(reason) => Err(YouTubeError::ProviderRejected(reason.to_owned())),
        None if response.status() == 401 => Err(YouTubeError::CredentialRevoked),
        None => Err(YouTubeError::ProviderRejected(format!(
            "HTTP {}",
            response.status()
        ))),
    }
}

fn rate_limit_receipt(
    response: &YouTubeProviderResponse,
    operation: YouTubeDispatchOperation,
    binding: &YouTubePublishBinding,
    request_digest: &str,
) -> Result<YouTubeRetryAfterReceipt, YouTubeError> {
    let retry_after_seconds = response
        .header("retry-after")
        .and_then(|value| value.parse::<u64>().ok());
    let provider_reset_at = response
        .header("x-ratelimit-reset")
        .or_else(|| response.header("x-rate-limit-reset"))
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .or_else(|| {
            retry_after_seconds.and_then(|seconds| {
                i64::try_from(seconds).ok().and_then(|seconds| {
                    response
                        .observed_at()
                        .checked_add_signed(Duration::seconds(seconds))
                })
            })
        });
    if provider_reset_at.is_some_and(|reset| reset <= response.observed_at()) {
        return Err(YouTubeError::InvalidResponse("YouTube rate-limit reset"));
    }
    Ok(YouTubeRetryAfterReceipt {
        provider: YouTubeProviderId::YouTube,
        operation,
        binding: binding.clone(),
        request_digest: request_digest.to_owned(),
        observed_at: response.observed_at(),
        response_digest: response.body_digest(),
        retry_after_seconds,
        provider_reset_at,
    })
}

fn parse_probe_response(
    binding: &YouTubePublishBinding,
    credential_generation: u64,
    response: &YouTubeProviderResponse,
    valid_for: Duration,
    provenance: YouTubeEvidenceProvenance,
) -> Result<YouTubeAuthenticatedProbe, YouTubeError> {
    let body = response.json()?;
    let items = body
        .get("items")
        .and_then(Value::as_array)
        .ok_or(YouTubeError::InvalidResponse("YouTube channels.items"))?;
    if items.len() != 1 {
        return Err(YouTubeError::ScopeMismatch);
    }
    let channel_id = YouTubeChannelId::new(
        items[0]
            .get("id")
            .and_then(Value::as_str)
            .ok_or(YouTubeError::InvalidResponse("YouTube channel id"))?,
    )?;
    if channel_id != *binding.channel_id() {
        return Err(YouTubeError::ScopeMismatch);
    }
    let channel_title = items[0]
        .pointer("/snippet/title")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let valid_until = response
        .observed_at()
        .checked_add_signed(valid_for)
        .ok_or(YouTubeError::InvalidResponse("YouTube probe freshness"))?;
    let probe = YouTubeAuthenticatedProbe {
        provider: YouTubeProviderId::YouTube,
        binding: binding.clone(),
        credential_generation,
        channel_title,
        response_digest: response.body_digest(),
        observed_at: response.observed_at(),
        valid_until,
        provenance,
    };
    probe.validate_at(response.observed_at())?;
    Ok(probe)
}

fn parse_provider_receipt(
    request: &DraftVideoPublishRequest,
    session: &YouTubeUploadSessionReference,
    response: &YouTubeProviderResponse,
    provider_request_digest: &str,
    provenance: YouTubeEvidenceProvenance,
) -> Result<YouTubeProviderReceipt, YouTubeError> {
    let body = response.json()?;
    let video_id = YouTubeVideoId::new(
        body.get("id")
            .and_then(Value::as_str)
            .ok_or(YouTubeError::InvalidResponse("YouTube upload video id"))?,
    )?;
    Ok(YouTubeProviderReceipt {
        provider: YouTubeProviderId::YouTube,
        binding: request.binding().clone(),
        request_digest: request.request_digest(),
        provider_request_digest: provider_request_digest.to_owned(),
        idempotency_key: request.idempotency_key().clone(),
        video_id,
        session: session.clone(),
        response_digest: response.body_digest(),
        observed_at: response.observed_at(),
        provenance,
    })
}

fn parse_readback_response(
    request: &DraftVideoPublishRequest,
    provider_receipt: &YouTubeProviderReceipt,
    response: &YouTubeProviderResponse,
    provider_request_digest: &str,
    valid_for: Duration,
    provenance: YouTubeEvidenceProvenance,
) -> Result<YouTubeReadbackReceipt, YouTubeError> {
    let body = response.json()?;
    let items = body
        .get("items")
        .and_then(Value::as_array)
        .ok_or(YouTubeError::InvalidResponse("YouTube readback items"))?;
    if items.len() != 1 {
        return Err(YouTubeError::ReadbackMismatch);
    }
    let item = &items[0];
    let video_id = YouTubeVideoId::new(
        item.get("id")
            .and_then(Value::as_str)
            .ok_or(YouTubeError::InvalidResponse("YouTube readback video id"))?,
    )?;
    if video_id != *provider_receipt.video_id() {
        return Err(YouTubeError::ReadbackMismatch);
    }
    let channel_id = YouTubeChannelId::new(
        item.pointer("/snippet/channelId")
            .and_then(Value::as_str)
            .ok_or(YouTubeError::InvalidResponse("YouTube readback channel id"))?,
    )?;
    let title = item
        .pointer("/snippet/title")
        .and_then(Value::as_str)
        .ok_or(YouTubeError::InvalidResponse("YouTube readback title"))?
        .to_owned();
    let visibility = match item
        .pointer("/status/privacyStatus")
        .and_then(Value::as_str)
    {
        Some("public") => super::YouTubeVisibility::Public,
        Some("private") => super::YouTubeVisibility::Private,
        Some("unlisted") => super::YouTubeVisibility::Unlisted,
        _ => return Err(YouTubeError::InvalidResponse("YouTube privacy status")),
    };
    let schedule = item
        .pointer("/status/publishAt")
        .and_then(Value::as_str)
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| YouTubeError::InvalidResponse("YouTube publishAt"))?
        .map(|value| value.with_timezone(&Utc))
        .map(YouTubeSchedule::new);
    let upload_status = item
        .pointer("/status/uploadStatus")
        .and_then(Value::as_str)
        .ok_or(YouTubeError::InvalidResponse("YouTube upload status"))?
        .to_owned();
    let processing_state = match item
        .pointer("/processingDetails/processingStatus")
        .and_then(Value::as_str)
    {
        Some("succeeded") => YouTubeVideoProcessingState::Uploaded,
        Some("processing") => YouTubeVideoProcessingState::Processing,
        Some("failed") => YouTubeVideoProcessingState::Failed,
        Some(_) | None if upload_status == "uploaded" => YouTubeVideoProcessingState::Uploaded,
        Some(_) | None => YouTubeVideoProcessingState::Unknown,
    };
    let valid_until = response
        .observed_at()
        .checked_add_signed(valid_for)
        .ok_or(YouTubeError::InvalidResponse("YouTube readback freshness"))?;
    Ok(YouTubeReadbackReceipt {
        provider: YouTubeProviderId::YouTube,
        binding: request.binding().clone(),
        request_digest: request.request_digest(),
        provider_request_digest: provider_request_digest.to_owned(),
        video_id,
        channel_id,
        title,
        visibility,
        schedule,
        upload_status,
        processing_state,
        response_digest: response.body_digest(),
        observed_at: response.observed_at(),
        valid_until,
        provenance,
    })
}

fn parse_uploaded_offset(response: &YouTubeProviderResponse) -> Result<u64, YouTubeError> {
    let Some(range) = response.header("range") else {
        return Ok(0);
    };
    let Some(last_byte) = range.strip_prefix("bytes=0-") else {
        return Err(YouTubeError::InvalidResponse("YouTube upload range"));
    };
    let last_byte = last_byte
        .parse::<u64>()
        .map_err(|_| YouTubeError::InvalidResponse("YouTube upload range"))?;
    last_byte
        .checked_add(1)
        .ok_or(YouTubeError::InvalidResponse("YouTube upload range"))
}

fn body_contains_secret_key(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Object(map)) => map.iter().any(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            lower.contains("token")
                || lower.contains("secret")
                || lower.contains("authorization")
                || body_contains_secret_key(Some(value))
        }),
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| body_contains_secret_key(Some(value))),
        _ => false,
    }
}
